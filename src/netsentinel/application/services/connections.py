"""Deterministic application service for connection snapshot lifecycle diffing."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionKey,
    ConnectionLifecycleEvent,
    ConnectionRoundObservation,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionUpdated,
    ObservationOrigin,
    ObservationQuality,
    ProcessInfoStatus,
    ParentProcessStatus,
    TrackedConnection,
)


Clock = Callable[[], datetime]
DEFAULT_ACTIVE_CAPACITY = 4_096


_PROCESS_STATUS_PREFERENCE = {
    ProcessInfoStatus.UNAVAILABLE: 0,
    ProcessInfoStatus.NOT_FOUND: 1,
    ProcessInfoStatus.ACCESS_DENIED: 2,
    ProcessInfoStatus.AVAILABLE: 3,
}
_PARENT_STATUS_PREFERENCE = {
    ParentProcessStatus.UNAVAILABLE: 0,
    ParentProcessStatus.NOT_FOUND: 1,
    ParentProcessStatus.ACCESS_DENIED: 2,
    ParentProcessStatus.REUSED: 3,
    ParentProcessStatus.ABSENT: 4,
    ParentProcessStatus.OBSERVED: 5,
}


class ConnectionTrackingService:
    """Compare complete observation rounds and retain active lifecycle state.

    The first complete round marks visible keys as initial observations. Later rounds emit
    updates only when observable state or process metadata changes. A missing
    key emits ``ConnectionClosed`` with ``NOT_OBSERVED`` semantics; this is not
    evidence of a TCP FIN/RST or a real UDP session close.

    Duplicate keys are collapsed before diffing. The newest observation wins;
    equal-time conflicts prefer richer process metadata and then a canonical
    state/metadata ordering. This makes results independent of input ordering.
    Events are returned in stable OPENED, UPDATED, CLOSED groups, with each
    group sorted by ``ConnectionKey`` fields.
    """

    def __init__(self, *, clock: Clock | None = None, capacity: int = DEFAULT_ACTIVE_CAPACITY) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._capacity = capacity
        self._session_id = uuid4()
        self._active: dict[ConnectionKey, TrackedConnection] = {}
        self._last_observation_at: datetime | None = None
        self._first_complete_seen = False
        self._last_round: ConnectionRoundObservation | None = None

    @property
    def session_id(self) -> UUID:
        return self._session_id

    @property
    def last_round(self) -> ConnectionRoundObservation | None:
        return self._last_round

    def reset_session(self) -> None:
        """Start a fresh in-memory session after a stopped engine restarts."""
        self._session_id = uuid4()
        self._active.clear()
        self._last_observation_at = None
        self._first_complete_seen = False
        self._last_round = None

    def record_failure(self, *, observed_at: datetime | None = None) -> ConnectionRoundObservation:
        at = _require_utc(observed_at if observed_at is not None else self._clock(), "observed_at")
        self._last_round = ConnectionRoundObservation(self._session_id, at, ObservationQuality.FAILED)
        return self._last_round

    @property
    def active_connections(self) -> tuple[TrackedConnection, ...]:
        """Return an immutable, deterministically ordered active-state view."""

        return tuple(
            self._active[key]
            for key in sorted(self._active, key=_connection_key_sort_key)
        )

    def track(
        self,
        snapshots: Iterable[ConnectionSnapshot],
        *,
        observed_at: datetime | None = None,
        quality: ObservationQuality = ObservationQuality.COMPLETE,
        discarded_rows: int = 0,
    ) -> tuple[ConnectionLifecycleEvent, ...]:
        """Apply one complete snapshot round and return its lifecycle events.

        ``observed_at`` is the round timestamp used for CLOSED events. When it
        is omitted, the latest input observation is used; an empty round uses
        the injected clock. Passing it explicitly keeps empty-round processing
        fully deterministic without relying on wall-clock time.
        """

        if not isinstance(quality, ObservationQuality) or quality is ObservationQuality.FAILED:
            raise ValueError("track quality must be complete or reduced")
        if isinstance(discarded_rows, bool) or not isinstance(discarded_rows, int) or discarded_rows < 0:
            raise ValueError("discarded_rows must be non-negative")
        current, capacity_drops, latest = _deduplicate_snapshots(snapshots, self._capacity, self._active)
        effective_quality = ObservationQuality.REDUCED if capacity_drops or discarded_rows or quality is ObservationQuality.REDUCED else ObservationQuality.COMPLETE
        if effective_quality is ObservationQuality.REDUCED:
            reserved = len(set(self._active) - set(current))
            for key in sorted((set(current) - set(self._active)), key=_connection_key_sort_key, reverse=True):
                if len(current) + reserved <= self._capacity:
                    break
                del current[key]
                capacity_drops += 1
        observation_time = self._observation_time(current, observed_at if observed_at is not None else latest)
        self._validate_round(current, observation_time)

        previous_keys = set(self._active)
        current_keys = set(current)

        opened_keys = sorted(
            current_keys - previous_keys,
            key=_connection_key_sort_key,
        )
        common_keys = sorted(
            current_keys & previous_keys,
            key=_connection_key_sort_key,
        )
        closed_keys = sorted(
            previous_keys - current_keys if effective_quality is ObservationQuality.COMPLETE else (),
            key=_connection_key_sort_key,
        )
        lifecycle_ids = {key: uuid4() for key in opened_keys}

        opened_events = tuple(
            ConnectionOpened(
                snapshot=current[key],
                origin=ObservationOrigin.OBSERVED if self._first_complete_seen else ObservationOrigin.INITIAL,
                session_id=self._session_id,
                lifecycle_id=lifecycle_ids[key],
            ) for key in opened_keys
        )
        updated_events = tuple(
            ConnectionUpdated(
                previous=self._active[key].snapshot,
                current=current[key],
                session_id=self._session_id,
                lifecycle_id=self._active[key].lifecycle_id,
            )
            for key in common_keys
            if _observable_metadata_changed(
                self._active[key].snapshot,
                current[key],
            )
        )
        closed_events = tuple(
            ConnectionClosed(
                last_snapshot=self._active[key].snapshot,
                occurred_at=observation_time,
                session_id=self._session_id,
                lifecycle_id=self._active[key].lifecycle_id,
            )
            for key in closed_keys
        )

        next_active: dict[ConnectionKey, TrackedConnection] = {}
        for key in opened_keys:
            snapshot = current[key]
            next_active[key] = TrackedConnection(
                first_seen=snapshot.observed_at,
                last_seen=snapshot.observed_at,
                snapshot=snapshot,
                session_id=self._session_id,
                lifecycle_id=lifecycle_ids[key],
                origin=ObservationOrigin.OBSERVED if self._first_complete_seen else ObservationOrigin.INITIAL,
            )
        for key in common_keys:
            previous = self._active[key]
            snapshot = current[key]
            next_active[key] = TrackedConnection(
                first_seen=previous.first_seen,
                last_seen=snapshot.observed_at,
                snapshot=snapshot,
                session_id=previous.session_id,
                lifecycle_id=previous.lifecycle_id,
                origin=previous.origin,
            )

        if effective_quality is ObservationQuality.REDUCED:
            for key in sorted(previous_keys - current_keys, key=_connection_key_sort_key):
                if len(next_active) >= self._capacity:
                    break
                next_active[key] = self._active[key]

        self._active = next_active
        self._last_observation_at = observation_time
        if effective_quality is ObservationQuality.COMPLETE:
            self._first_complete_seen = True
        self._last_round = ConnectionRoundObservation(
            self._session_id, observation_time, effective_quality,
            discarded_rows + capacity_drops,
            capacity_drops,
        )
        return opened_events + updated_events + closed_events

    def _observation_time(
        self,
        current: dict[ConnectionKey, ConnectionSnapshot],
        explicit: datetime | None,
    ) -> datetime:
        if explicit is not None:
            return _require_utc(explicit, "observed_at")
        if current:
            return max(snapshot.observed_at for snapshot in current.values())
        return _require_utc(self._clock(), "clock result")

    def _validate_round(
        self,
        current: dict[ConnectionKey, ConnectionSnapshot],
        observation_time: datetime,
    ) -> None:
        if (
            self._last_observation_at is not None
            and observation_time < self._last_observation_at
        ):
            raise ValueError("observation rounds cannot move backwards in time")

        for key, snapshot in current.items():
            if snapshot.observed_at > observation_time:
                raise ValueError(
                    "snapshot observation time cannot follow the round time"
                )
            previous = self._active.get(key)
            if previous is not None and snapshot.observed_at < previous.last_seen:
                raise ValueError(
                    "connection observation cannot precede its last observation"
                )

        for tracked in self._active.values():
            if tracked.last_seen > observation_time:
                raise ValueError(
                    "round time cannot precede an active connection observation"
                )


def _deduplicate_snapshots(
    snapshots: Iterable[ConnectionSnapshot],
    capacity: int,
    active: dict[ConnectionKey, TrackedConnection],
) -> tuple[dict[ConnectionKey, ConnectionSnapshot], int, datetime | None]:
    grouped: dict[ConnectionKey, ConnectionSnapshot] = {}
    discarded = 0
    latest: datetime | None = None
    for snapshot in snapshots:
        if not isinstance(snapshot, ConnectionSnapshot):
            raise TypeError("snapshots must contain ConnectionSnapshot values")
        if latest is None or snapshot.observed_at > latest:
            latest = snapshot.observed_at
        key = snapshot.key
        prior = grouped.get(key)
        if prior is not None:
            grouped[key] = max((prior, snapshot), key=_duplicate_preference)
            continue
        if len(grouped) < capacity:
            grouped[key] = snapshot
            continue
        # Existing lifecycles win, then the lowest canonical key. Every
        # discarded observation is accounted for without retaining its key.
        worst = max(grouped, key=lambda candidate: (candidate not in active, _connection_key_sort_key(candidate)))
        if (key not in active, _connection_key_sort_key(key)) < (worst not in active, _connection_key_sort_key(worst)):
            del grouped[worst]
            grouped[key] = snapshot
        discarded += 1
    return grouped, discarded, latest


def _duplicate_preference(snapshot: ConnectionSnapshot) -> tuple[object, ...]:
    process = snapshot.process
    parent = process.parent
    return (
        snapshot.observed_at,
        _PROCESS_STATUS_PREFERENCE[process.status],
        process.name is not None,
        process.name or "",
        parent is not None,
        _PARENT_STATUS_PREFERENCE[parent.status] if parent is not None else -1,
        parent.parent_pid
        if parent is not None and parent.parent_pid is not None
        else -1,
        parent.identity.create_time.isoformat()
        if parent is not None
        and parent.identity is not None
        and parent.identity.create_time is not None
        else "",
        parent.name if parent is not None and parent.name is not None else "",
        parent.observed_at.isoformat() if parent is not None else "",
        snapshot.state.value,
    )


def _observable_metadata_changed(
    previous: ConnectionSnapshot,
    current: ConnectionSnapshot,
) -> bool:
    old_process = previous.process
    new_parent = current.process.parent
    if old_process.parent is not None and new_parent is not None:
        old_process = replace(
            old_process,
            parent=replace(old_process.parent, observed_at=new_parent.observed_at),
        )
    return previous.state != current.state or old_process != current.process


def _connection_key_sort_key(key: ConnectionKey) -> tuple[object, ...]:
    remote = key.remote_endpoint
    identity = key.process_identity
    create_time = identity.create_time if identity is not None else None
    return (
        key.protocol.value,
        key.local_endpoint.ip_version,
        key.local_endpoint.address,
        key.local_endpoint.port,
        remote is not None,
        remote.address if remote is not None else "",
        remote.port if remote is not None else -1,
        identity is not None,
        identity.pid if identity is not None else -1,
        create_time is not None,
        create_time.isoformat() if create_time is not None else "",
    )


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


__all__ = ("ConnectionTrackingService",)
