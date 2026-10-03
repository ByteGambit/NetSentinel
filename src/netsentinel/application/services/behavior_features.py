"""NS-070 in-memory, monotonic application behavior feature accumulator."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from math import isfinite
from threading import RLock
from time import monotonic
from uuid import UUID

from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.domain.application_identity import ApplicationScope
from netsentinel.domain.behavior_features import (
    BehaviorAccumulatorSnapshot,
    BehaviorFeatureSnapshot,
    BehaviorScopeKey,
    FeatureCount,
)
from netsentinel.domain.connections import (
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionRoundObservation,
    ConnectionSnapshot,
    NetworkScopeStatus,
    ObservationOrigin,
    ObservationQuality,
    ProcessInfo,
    TransportProtocol,
)


@dataclass(frozen=True, slots=True)
class BehaviorCapacity:
    bucket_seconds: int = 60
    bucket_count: int = 12
    applications: int = 64
    networks_per_application: int = 4
    scopes: int = 128
    destinations: int = 64
    ports: int = 32
    protocols: int = 2

    def __post_init__(self) -> None:
        for value in vars_by_slot(self):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError("all behavior capacities must be positive integers")


def vars_by_slot(value: BehaviorCapacity) -> tuple[int, ...]:
    return tuple(getattr(value, name) for name in value.__slots__)


@dataclass(slots=True)
class _Bucket:
    index: int
    appearances: int = 0
    reduced: int = 0
    monitored: float = 0.0
    destinations: dict[str, int] = field(default_factory=dict)
    ports: dict[int, int] = field(default_factory=dict)
    protocols: dict[TransportProtocol, int] = field(default_factory=dict)
    other_destinations: int = 0
    other_ports: int = 0
    other_protocols: int = 0
    unknown_destinations: int = 0


@dataclass(slots=True)
class _ScopeState:
    buckets: dict[int, _Bucket] = field(default_factory=dict)
    destinations: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    protocols: set[TransportProtocol] = field(default_factory=set)
    last_touched: float = 0.0
    gap_seen: bool = False
    capacity_loss: bool = False


class BehaviorFeatureAccumulator:
    """Consume one complete tracker round atomically; never infer OS connect time.

    All feature maps and buckets are hard bounded. Scope eviction is oldest-touch
    first, with the lexical scope key as tie breaker. The owner engine calls this
    once per round; a lock also makes external snapshots safe across threads.
    """

    def __init__(
        self,
        *,
        capacity: BehaviorCapacity | None = None,
        polling_interval: float = 1.0,
        monotonic_clock: Callable[[], float] = monotonic,
        application_scope_resolver: Callable[[ProcessInfo], ApplicationScope] = resolve_application_scope,
    ) -> None:
        if not isfinite(polling_interval) or polling_interval <= 0:
            raise ValueError("polling_interval must be positive and finite")
        self.capacity = capacity or BehaviorCapacity()
        self._polling_interval = polling_interval
        self._clock = monotonic_clock
        self._resolve_application = application_scope_resolver
        self._lock = RLock()
        self._scopes: dict[BehaviorScopeKey, _ScopeState] = {}
        self._previous_complete: tuple[UUID, float] | None = None
        self._previous_visible: set[BehaviorScopeKey] = set()
        self._last_tick: float | None = None
        self._evicted = 0
        self._skipped_unknown = 0

    def observe_round(
        self,
        round_observation: ConnectionRoundObservation,
        events: Iterable[ConnectionLifecycleEvent] = (),
        snapshots: Iterable[ConnectionSnapshot] = (),
    ) -> tuple[BehaviorFeatureSnapshot, ...]:
        """Apply a round and return bounded learning contributions, without buckets.

        Contributions contain only this round's eligible samples and coverage.
        NS-071 can accumulate them without differencing a rotating window.
        """
        if not isinstance(round_observation, ConnectionRoundObservation):
            raise TypeError("round_observation must be ConnectionRoundObservation")
        tick = self._clock()
        if not isfinite(tick):
            raise ValueError("monotonic clock must be finite")
        with self._lock:
            if self._last_tick is not None and tick < self._last_tick:
                tick = self._last_tick
                self._mark_gap()
            self._last_tick = tick
            index = int(tick // self.capacity.bucket_seconds)
            self._rotate(index)
            deltas: dict[BehaviorScopeKey, _ScopeState] = {}
            def delta(scope: BehaviorScopeKey) -> _Bucket:
                if scope not in deltas:
                    if len(deltas) >= self.capacity.scopes:
                        del deltas[next(iter(deltas))]
                    deltas[scope] = _ScopeState()
                return self._bucket(deltas[scope], 0)
            visible: set[BehaviorScopeKey] = set()
            if round_observation.quality is ObservationQuality.COMPLETE:
                scoped = {
                    scope
                    for snapshot in snapshots
                    if (scope := self._scope(snapshot, round_observation.session_id)) is not None
                }
                for scope in sorted(scoped, key=self._sort_key):
                    self._state(scope, tick)
                    delta(scope)
                    visible.add(scope)
                visible.intersection_update(self._scopes)
            if round_observation.quality is ObservationQuality.COMPLETE:
                previous = self._previous_complete
                if previous is not None and previous[0] == round_observation.session_id:
                    elapsed = tick - previous[1]
                    if 0 < elapsed <= self._polling_interval * 2:
                        for scope in visible & self._previous_visible:
                            state = self._scopes.get(scope)
                            if state is not None:
                                self._bucket(state, index).monitored += min(elapsed, self._polling_interval)
                                delta(scope).monitored += min(elapsed, self._polling_interval)
                                if elapsed > self._polling_interval:
                                    state.gap_seen = True
                    else:
                        self._mark_gap()
                elif previous is not None:
                    self._mark_gap()
                self._previous_complete = (round_observation.session_id, tick)
                self._previous_visible = visible
            else:
                self._mark_gap()
            if round_observation.discarded_observations:
                for state in self._scopes.values():
                    state.capacity_loss = True
            if round_observation.quality is ObservationQuality.FAILED:
                return ()
            for event in events:
                if not isinstance(event, ConnectionOpened):
                    continue
                if event.session_id != round_observation.session_id:
                    continue
                scope = self._scope(event.snapshot, round_observation.session_id)
                if scope is None:
                    self._skipped_unknown += 1
                    continue
                state = self._state(scope, tick)
                contribution = delta(scope)
                if round_observation.quality is ObservationQuality.REDUCED:
                    state.gap_seen = True
                if round_observation.discarded_observations:
                    state.capacity_loss = True
                if event.origin is ObservationOrigin.INITIAL:
                    continue
                bucket = self._bucket(state, index)
                bucket.appearances += 1
                contribution.appearances += 1
                if round_observation.quality is ObservationQuality.REDUCED:
                    bucket.reduced += 1
                    contribution.reduced += 1
                remote = event.snapshot.remote_endpoint
                if remote is None:
                    bucket.unknown_destinations += 1
                    contribution.unknown_destinations += 1
                else:
                    self._count(state.destinations, bucket.destinations, remote.address, self.capacity.destinations, bucket, "other_destinations", state)
                    self._count(state.ports, bucket.ports, remote.port, self.capacity.ports, bucket, "other_ports", state)
                    self._count(deltas[scope].destinations, contribution.destinations, remote.address, self.capacity.destinations, contribution, "other_destinations", deltas[scope])
                    self._count(deltas[scope].ports, contribution.ports, remote.port, self.capacity.ports, contribution, "other_ports", deltas[scope])
                self._count(state.protocols, bucket.protocols, event.snapshot.protocol, self.capacity.protocols, bucket, "other_protocols", state)
                self._count(deltas[scope].protocols, contribution.protocols, event.snapshot.protocol, self.capacity.protocols, contribution, "other_protocols", deltas[scope])
            self._previous_visible.intersection_update(self._scopes)
            result = []
            for key, value in sorted(deltas.items(), key=lambda item: self._sort_key(item[0])):
                state = self._scopes.get(key)
                value.gap_seen = state.gap_seen if state is not None else True
                value.capacity_loss |= state.capacity_loss if state is not None else True
                result.append(self._snapshot_scope(key, value))
            return tuple(result)

    def snapshot(self) -> BehaviorAccumulatorSnapshot:
        with self._lock:
            if self._last_tick is not None:
                self._rotate(int(self._clock() // self.capacity.bucket_seconds))
            scopes = tuple(
                self._snapshot_scope(key, state)
                for key, state in sorted(self._scopes.items(), key=lambda item: self._sort_key(item[0]))
            )
            return BehaviorAccumulatorSnapshot(
                scopes, self._evicted, self._skipped_unknown,
                self.capacity.bucket_seconds, self.capacity.bucket_count,
            )

    def _snapshot_scope(self, scope: BehaviorScopeKey, state: _ScopeState) -> BehaviorFeatureSnapshot:
        buckets = tuple(state.buckets.values())
        def counts(name: str, values: set[object]) -> tuple[FeatureCount, ...]:
            return tuple(
                FeatureCount(value, sum(getattr(bucket, name).get(value, 0) for bucket in buckets))
                for value in sorted(values, key=str)
                if any(getattr(bucket, name).get(value, 0) for bucket in buckets)
            )
        destinations = counts("destinations", set(state.destinations))
        ports = counts("ports", set(state.ports))
        protocols = counts("protocols", set(state.protocols))
        return BehaviorFeatureSnapshot(
            scope=scope,
            observed_appearances=sum(bucket.appearances for bucket in buckets),
            reduced_appearances=sum(bucket.reduced for bucket in buckets),
            monitored_seconds=sum(bucket.monitored for bucket in buckets),
            destinations=destinations,
            ports=ports,
            protocols=protocols,
            other_destinations=sum(bucket.other_destinations for bucket in buckets),
            other_ports=sum(bucket.other_ports for bucket in buckets),
            other_protocols=sum(bucket.other_protocols for bucket in buckets),
            unknown_destinations=sum(bucket.unknown_destinations for bucket in buckets),
            destination_diversity=len(destinations),
            port_diversity=len(ports),
            protocol_diversity=len(protocols),
            gap_seen=state.gap_seen,
            capacity_loss=state.capacity_loss,
        )

    def _scope(self, snapshot: ConnectionSnapshot, session_id: UUID) -> BehaviorScopeKey | None:
        application = self._resolve_application(snapshot.process)
        identity = application.identity
        if identity.key is None:
            return None
        network = snapshot.network_scope
        token = (
            network.fingerprint
            if network.status is NetworkScopeStatus.RESOLVED
            else f"{session_id}:{snapshot.local_endpoint.address}"
        )
        assert token is not None
        return BehaviorScopeKey(
            identity.key, identity.quality, application.revision.digest,
            network.status, token,
        )

    def _state(self, scope: BehaviorScopeKey, tick: float) -> _ScopeState:
        state = self._scopes.get(scope)
        if state is None:
            same_app = [key for key in self._scopes if key.application_key == scope.application_key]
            if len({key.application_key for key in self._scopes}) >= self.capacity.applications and not same_app:
                oldest_app = min(
                    {key.application_key for key in self._scopes},
                    key=lambda app: (min(value.last_touched for key, value in self._scopes.items() if key.application_key == app), app),
                )
                for key in tuple(self._scopes):
                    if key.application_key == oldest_app:
                        del self._scopes[key]
                        self._evicted += 1
                state = _ScopeState(capacity_loss=True)
            elif len(same_app) >= self.capacity.networks_per_application:
                self._evict(same_app)
            elif len(self._scopes) >= self.capacity.scopes:
                self._evict(list(self._scopes))
            if state is None:
                state = _ScopeState(capacity_loss=self._evicted > 0)
            self._scopes[scope] = state
        state.last_touched = tick
        return state

    def _evict(self, keys: list[BehaviorScopeKey]) -> None:
        victim = min(keys, key=lambda key: (self._scopes[key].last_touched, self._sort_key(key)))
        del self._scopes[victim]
        self._evicted += 1

    def _bucket(self, state: _ScopeState, index: int) -> _Bucket:
        bucket = state.buckets.get(index)
        if bucket is None:
            bucket = _Bucket(index)
            state.buckets[index] = bucket
        return bucket

    def _rotate(self, index: int) -> None:
        earliest = index - self.capacity.bucket_count + 1
        for state in self._scopes.values():
            for old in tuple(state.buckets):
                if old < earliest:
                    del state.buckets[old]
            state.destinations = {key for bucket in state.buckets.values() for key in bucket.destinations}
            state.ports = {key for bucket in state.buckets.values() for key in bucket.ports}
            state.protocols = {key for bucket in state.buckets.values() for key in bucket.protocols}

    def _mark_gap(self) -> None:
        self._previous_complete = None
        self._previous_visible.clear()
        for state in self._scopes.values():
            state.gap_seen = True

    @staticmethod
    def _count(catalog: set, counts: dict, value: object, cap: int, bucket: _Bucket, other_name: str, state: _ScopeState) -> None:
        if value not in catalog:
            if len(catalog) >= cap:
                setattr(bucket, other_name, getattr(bucket, other_name) + 1)
                state.capacity_loss = True
                return
            catalog.add(value)
        counts[value] = counts.get(value, 0) + 1

    @staticmethod
    def _sort_key(scope: BehaviorScopeKey) -> tuple[str, str, str, str]:
        return (scope.application_key, scope.revision_digest or "", scope.network_status.value, scope.network_token)
