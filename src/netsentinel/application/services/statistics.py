"""Bounded rolling statistics for connection lifecycle events."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import isfinite

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ObservationOrigin,
)


WallClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class StatisticsSnapshot:
    """Immutable counts for the configured short rolling window."""

    window: timedelta
    opened_events: int
    closed_events: int
    retained_events: int
    capacity_drops: int
    next_expiry_in_seconds: float | None


class StatisticsService:
    """Count recent opened/closed events without retaining unbounded history.

    Updates are deterministic and framework-independent. ``ConnectionUpdated``
    events intentionally do not contribute to either lifecycle counter.
    """

    def __init__(
        self,
        *,
        window: timedelta = timedelta(seconds=60),
        capacity: int = 10_000,
        clock: WallClock | None = None,
    ) -> None:
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be an integer")
        if capacity <= 0:
            raise ValueError("capacity must be greater than zero")

        self._window = window
        self._capacity = capacity
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)
        self._events: deque[tuple[datetime, bool]] = deque()
        self._capacity_drops = 0

    @property
    def window(self) -> timedelta:
        return self._window

    @property
    def capacity(self) -> int:
        return self._capacity

    def record(self, event: ConnectionLifecycleEvent) -> None:
        """Record one opened/closed event and ignore updates."""

        now = self._utc_now()
        self._prune(now)
        if isinstance(event, ConnectionOpened):
            if event.origin is ObservationOrigin.INITIAL:
                return
            is_opened = True
        elif isinstance(event, ConnectionClosed):
            is_opened = False
        else:
            return

        if len(self._events) >= self._capacity:
            self._events.popleft()
            self._capacity_drops += 1
        # The window measures when this process observed the lifecycle event.
        # This keeps pruning monotonic with the injected clock even if a
        # delayed bridge batch contains older domain observation timestamps.
        self._events.append((now, is_opened))
        self._prune(now)

    def record_many(self, events: Iterable[ConnectionLifecycleEvent]) -> None:
        for event in events:
            self.record(event)

    def snapshot(self) -> StatisticsSnapshot:
        """Return current counts after discarding entries outside the window."""

        now = self._utc_now()
        self._prune(now)
        opened_events = sum(1 for _occurred_at, opened in self._events if opened)
        closed_events = len(self._events) - opened_events
        next_expiry = None
        if self._events:
            expiry = self._events[0][0] + self._window
            next_expiry = max(0.0, (expiry - now).total_seconds())
        return StatisticsSnapshot(
            window=self._window,
            opened_events=opened_events,
            closed_events=closed_events,
            retained_events=len(self._events),
            capacity_drops=self._capacity_drops,
            next_expiry_in_seconds=next_expiry,
        )

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._window
        while self._events and self._events[0][0] <= cutoff:
            self._events.popleft()

    def _utc_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        seconds = value.utcoffset().total_seconds()
        if not isfinite(seconds):  # pragma: no cover - datetime guards this
            raise ValueError("clock returned an invalid UTC offset")
        return value.astimezone(UTC)


__all__ = ("StatisticsService", "StatisticsSnapshot")
