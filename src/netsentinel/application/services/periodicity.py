"""NS-074 bounded session-only appearance tracking; no engine subscription."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from threading import RLock
from uuid import UUID

from netsentinel.application.detectors.periodicity import evaluate_periodicity
from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.connections import DEFAULT_ACTIVE_CAPACITY
from netsentinel.domain.application_identity import ApplicationScope
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.connections import (
    ConnectionLifecycleEvent, ConnectionOpened, ConnectionRoundObservation,
    NetworkScopeStatus, ObservationOrigin, ObservationQuality, ProcessInfo,
)
from netsentinel.domain.periodicity import (
    PeriodicityEvidence, PeriodicityPolicy, PeriodicityReset as Reset,
    PeriodicityScope, PeriodicitySequence, validate_monotonic,
)


@dataclass(slots=True)
class _SequenceState:
    times: deque[float] = field(default_factory=deque)
    lifecycle_ids: deque[UUID] = field(default_factory=deque)
    truncated: bool = False
    history_unavailable: bool = False
    last_reset: Reset | None = None
    last_appearance: float = 0.0


class PeriodicityService:
    """Consume every tracker round in order, including empty/failing rounds.

    One explicit monotonic observation time per round; UTC is metadata only.
    Tracker/dispatcher provides one synchronous delivery per lifecycle. A bounded
    33-ID recent cache additionally tolerates accidental duplicate deliveries;
    this is not a durable replay bus. RLock serializes mutation and snapshots.
    No polling/worker/I/O is started here. Unknown scope/instance is not evaluated.
    """

    def __init__(
        self, *, polling_interval_seconds: float,
        policy: PeriodicityPolicy = PeriodicityPolicy(),
        application_scope_resolver: Callable[[ProcessInfo], ApplicationScope] = resolve_application_scope,
    ) -> None:
        validate_monotonic(polling_interval_seconds)
        if not 0 < polling_interval_seconds <= 3600:
            raise ValueError("invalid observation cadence")
        if not isinstance(policy, PeriodicityPolicy):
            raise TypeError("typed policy required")
        self.policy = policy
        self._poll = polling_interval_seconds
        self._resolve = application_scope_resolver
        self._states: OrderedDict[PeriodicityScope, _SequenceState] = OrderedDict()
        self._session: UUID | None = None
        self._last_round: float | None = None
        self._last_reset: Reset | None = None
        self._history_unavailable = False
        self._lock = RLock()

    @property
    def scope_count(self) -> int:
        with self._lock:
            return len(self._states)

    def reset(self, scope: PeriodicityScope) -> None:
        with self._lock:
            self._states.pop(scope, None)

    def snapshot(self, scope: PeriodicityScope, *, round_observation: ConnectionRoundObservation) -> PeriodicityEvidence | None:
        """No clock read or mutation; caller uses its latest round reference."""
        with self._lock:
            state = self._states.get(scope)
            if state is None or round_observation.session_id != self._session:
                return None
            return self._evidence(scope, state, round_observation)

    def observe_round(
        self, observation: ConnectionRoundObservation,
        events: Iterable[ConnectionLifecycleEvent] = (), *, now_monotonic: float,
    ) -> tuple[PeriodicityEvidence, ...]:
        if not isinstance(observation, ConnectionRoundObservation):
            raise TypeError("typed round required")
        validate_monotonic(now_monotonic)
        with self._lock:
            if self._session != observation.session_id:
                changed = self._session is not None
                self._states.clear()
                self._session = observation.session_id
                self._last_round = None
                self._history_unavailable = False
                self._last_reset = Reset.SESSION_CHANGED if changed else None
            if self._last_round is not None:
                elapsed = now_monotonic - self._last_round
                if elapsed < 0:
                    self._break_sequences(Reset.CLOCK_REGRESSION)
                    self._last_round = now_monotonic
                    return ()
                if elapsed > self._poll * 2:
                    self._break_sequences(Reset.MONITORING_GAP)
            self._last_round = now_monotonic
            self._expire(now_monotonic)
            if observation.quality is not ObservationQuality.COMPLETE or observation.discarded_observations:
                reason = (Reset.CAPACITY_LOSS if observation.discarded_observations
                          else Reset.REDUCED_QUALITY if observation.quality is ObservationQuality.REDUCED
                          else Reset.MONITORING_GAP)
                self._break_sequences(reason)
                return ()
            touched: OrderedDict[PeriodicityScope, None] = OrderedDict()
            for index, event in enumerate(events):
                # A full 4096-key replacement can produce 4096 opens + closes.
                if index >= DEFAULT_ACTIVE_CAPACITY * 2:
                    self._break_sequences(Reset.CAPACITY_LOSS)
                    return ()
                if not isinstance(event, ConnectionOpened) or event.origin is not ObservationOrigin.OBSERVED or event.session_id != self._session:
                    continue
                scope = self._scope(event)
                if scope is None:
                    continue
                state = self._states.get(scope)
                if state is not None and event.lifecycle_id in state.lifecycle_ids:
                    continue
                if state is None:
                    if len(self._states) >= self.policy.maximum_scopes:
                        self._states.popitem(last=False)
                        self._history_unavailable = True
                    state = _SequenceState(history_unavailable=self._history_unavailable,
                                           last_reset=self._last_reset)
                    self._states[scope] = state
                self._states.move_to_end(scope)
                state.lifecycle_ids.append(event.lifecycle_id)
                while len(state.lifecycle_ids) > self.policy.maximum_intervals + 1:
                    state.lifecycle_ids.popleft()
                if state.times and now_monotonic == state.times[-1]:
                    # Concurrent appearances do not become a zero interval or
                    # silently disappear from an otherwise regular sequence.
                    state.times.clear()
                    state.truncated = False
                    state.last_reset = Reset.CONCURRENT_APPEARANCES
                state.times.append(now_monotonic)
                state.last_appearance = now_monotonic
                while len(state.times) > self.policy.maximum_intervals + 1:
                    state.times.popleft()
                    state.truncated = True
                while state.times and now_monotonic - state.times[0] > self.policy.horizon_seconds:
                    state.times.popleft()
                    state.truncated = True
                touched[scope] = None
                # Output key catalog is bounded even during scope churn.
                while len(touched) > self.policy.maximum_scopes:
                    touched.popitem(last=False)
            return tuple(self._evidence(scope, self._states[scope], observation)
                         for scope in touched if scope in self._states)

    def _scope(self, event: ConnectionOpened) -> PeriodicityScope | None:
        snapshot = event.snapshot
        remote, instance, network = snapshot.remote_endpoint, snapshot.process.identity, snapshot.network_scope
        application = self._resolve(snapshot.process)
        if (remote is None or instance is None or instance.create_time is None
                or application.process_identity != instance or application.identity.key is None
                or network.status is not NetworkScopeStatus.RESOLVED or network.fingerprint is None):
            return None
        behavior = BehaviorScopeKey(application.identity.key, application.identity.quality,
                                    application.revision.digest, network.status, network.fingerprint)
        try:
            return PeriodicityScope(behavior, instance, remote, snapshot.protocol)
        except ValueError:
            return None

    def _break_sequences(self, reason: Reset) -> None:
        self._last_reset = reason
        for state in self._states.values():
            state.times.clear()
            state.truncated = False
            state.last_reset = reason
            # Keep bounded recent IDs so retrying an old event after a gap does
            # not fabricate a fresh observation. Coverage must rebuild anyway.

    def _expire(self, tick: float) -> None:
        for scope, state in tuple(self._states.items()):
            if tick - state.last_appearance > self.policy.inactivity_seconds:
                del self._states[scope]
                self._history_unavailable = True
                self._last_reset = Reset.INACTIVITY

    def _evidence(self, scope: PeriodicityScope, state: _SequenceState,
                  observation: ConnectionRoundObservation) -> PeriodicityEvidence:
        assert self._session is not None
        times = tuple(state.times)
        return evaluate_periodicity(PeriodicitySequence(
            scope, self._session, tuple(b - a for a, b in zip(times, times[1:])),
            self._poll, observation.observed_at, state.truncated, state.history_unavailable,
            state.last_reset,
        ), self.policy)
