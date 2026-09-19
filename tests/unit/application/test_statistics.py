"""NS-012 deterministic bounded rolling statistics tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessInfo,
    TransportProtocol,
)


BASE_TIME = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


@dataclass
class FakeClock:
    now: datetime = BASE_TIME

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _snapshot(*, state: ConnectionState = ConnectionState.ESTABLISHED) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", 50_000),
        remote_endpoint=Endpoint("198.51.100.4", 443),
        state=state,
        process=ProcessInfo.unavailable(),
        observed_at=BASE_TIME,
    )


def test_counts_opened_and_closed_but_not_updated() -> None:
    clock = FakeClock()
    service = StatisticsService(window=timedelta(seconds=10), clock=clock)
    first = _snapshot()
    current = ConnectionSnapshot(
        protocol=first.protocol,
        local_endpoint=first.local_endpoint,
        remote_endpoint=first.remote_endpoint,
        state=ConnectionState.CLOSE_WAIT,
        process=first.process,
        observed_at=BASE_TIME + timedelta(seconds=1),
    )

    service.record_many(
        (
            ConnectionOpened(first),
            ConnectionUpdated(first, current),
            ConnectionClosed(current, BASE_TIME + timedelta(seconds=2)),
        )
    )

    snapshot = service.snapshot()
    assert snapshot.opened_events == 1
    assert snapshot.closed_events == 1
    assert snapshot.retained_events == 2


def test_window_discards_expired_events_at_boundary() -> None:
    clock = FakeClock()
    service = StatisticsService(window=timedelta(seconds=10), clock=clock)
    service.record(ConnectionOpened(_snapshot()))
    clock.advance(9.999)
    assert service.snapshot().opened_events == 1

    clock.advance(0.001)
    snapshot = service.snapshot()
    assert snapshot.opened_events == 0
    assert snapshot.next_expiry_in_seconds is None


def test_capacity_is_bounded_and_reports_drops() -> None:
    clock = FakeClock()
    service = StatisticsService(capacity=2, clock=clock)
    event = ConnectionOpened(_snapshot())

    service.record_many((event, event, event))

    snapshot = service.snapshot()
    assert snapshot.retained_events == 2
    assert snapshot.opened_events == 2
    assert snapshot.capacity_drops == 1


def test_configuration_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        StatisticsService(window=timedelta(0))
    with pytest.raises(ValueError):
        StatisticsService(capacity=0)
    with pytest.raises(TypeError):
        StatisticsService(capacity=True)  # type: ignore[arg-type]
