"""Deterministic application service for connection snapshot lifecycle diffing."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionKey,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionUpdated,
    ProcessInfoStatus,
    ParentProcessStatus,
    TrackedConnection,
)


Clock = Callable[[], datetime]


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

    The first round treats every visible key as newly opened. Later rounds emit
    updates only when observable state or process metadata changes. A missing
    key emits ``ConnectionClosed`` with ``NOT_OBSERVED`` semantics; this is not
    evidence of a TCP FIN/RST or a real UDP session close.

    Duplicate keys are collapsed before diffing. The newest observation wins;
    equal-time conflicts prefer richer process metadata and then a canonical
    state/metadata ordering. This makes results independent of input ordering.
    Events are returned in stable OPENED, UPDATED, CLOSED groups, with each
    group sorted by ``ConnectionKey`` fields.
    """

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._active: dict[ConnectionKey, TrackedConnection] = {}
        self._last_observation_at: datetime | None = None

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
    ) -> tuple[ConnectionLifecycleEvent, ...]:
        """Apply one complete snapshot round and return its lifecycle events.

        ``observed_at`` is the round timestamp used for CLOSED events. When it
        is omitted, the latest input observation is used; an empty round uses
        the injected clock. Passing it explicitly keeps empty-round processing
        fully deterministic without relying on wall-clock time.
        """

        current = _deduplicate_snapshots(snapshots)
        observation_time = self._observation_time(current, observed_at)
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
            previous_keys - current_keys,
            key=_connection_key_sort_key,
        )

        opened_events = tuple(
            ConnectionOpened(snapshot=current[key]) for key in opened_keys
        )
        updated_events = tuple(
            ConnectionUpdated(
                previous=self._active[key].snapshot,
                current=current[key],
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
            )
        for key in common_keys:
            previous = self._active[key]
            snapshot = current[key]
            next_active[key] = TrackedConnection(
                first_seen=previous.first_seen,
                last_seen=snapshot.observed_at,
                snapshot=snapshot,
            )

        self._active = next_active
        self._last_observation_at = observation_time
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
) -> dict[ConnectionKey, ConnectionSnapshot]:
    grouped: dict[ConnectionKey, list[ConnectionSnapshot]] = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, ConnectionSnapshot):
            raise TypeError("snapshots must contain ConnectionSnapshot values")
        grouped.setdefault(snapshot.key, []).append(snapshot)

    return {
        key: max(candidates, key=_duplicate_preference)
        for key, candidates in grouped.items()
    }


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
