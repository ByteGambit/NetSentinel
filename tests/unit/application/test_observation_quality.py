"""NS-056 observation identity, gap and capacity contracts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

from netsentinel.application.events import EventDispatcher
from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.ports import ConnectionCollectionRound, ConnectionCollectionTransientError
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.statistics import StatisticsService
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionOpened, ConnectionRoundObservation,
    ConnectionSnapshot, ConnectionState, ConnectionUpdated, Endpoint,
    ObservationOrigin, ObservationQuality, ProcessIdentity, ProcessInfo,
    ProcessInfoStatus, TransportProtocol, ParentProcessInfo, ParentProcessStatus,
)
from netsentinel.shared.diagnostics import DiagnosticCode

T0 = datetime(2026, 9, 30, tzinfo=UTC)


def row(port: int, second: int = 0, *, process: ProcessInfo | None = None) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint("192.0.2.1", port),
        Endpoint("203.0.113.2", 443), ConnectionState.ESTABLISHED,
        process or ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(7, T0 - timedelta(hours=1)), "browser"),
        T0 + timedelta(seconds=second),
    )


def test_initial_then_observed_open_and_statistics() -> None:
    tracker = ConnectionTrackingService()
    stats = StatisticsService(clock=lambda: T0)
    first = tracker.track((row(100), row(101)), observed_at=T0)
    assert all(isinstance(event, ConnectionOpened) and event.origin is ObservationOrigin.INITIAL for event in first)
    stats.record_many(first)
    assert stats.snapshot().opened_events == 0
    second = tracker.track((row(100, 1), row(101, 1), row(102, 1)))
    assert len(second) == 1 and isinstance(second[0], ConnectionOpened)
    assert second[0].origin is ObservationOrigin.OBSERVED
    stats.record_many(second)
    assert stats.snapshot().opened_events == 1
    assert tracker.track((row(100, 2), row(101, 2), row(102, 2))) == ()


def test_lifecycle_identity_update_close_reuse_and_session_reset() -> None:
    tracker = ConnectionTrackingService()
    first = tracker.track((row(100),))[0]
    assert isinstance(first, ConnectionOpened)
    identity = first.lifecycle_id
    path = replace(row(100, 1).process, executable_path="C:\\browser.exe", executable_path_status=ProcessInfoStatus.AVAILABLE)
    update = tracker.track((row(100, 1, process=path),))[0]
    assert isinstance(update, ConnectionUpdated)
    assert update.lifecycle_id == identity
    assert tracker.active_connections[0].lifecycle_id == identity
    close = tracker.track((), observed_at=T0 + timedelta(seconds=2))[0]
    assert isinstance(close, ConnectionClosed) and close.lifecycle_id == identity
    reopened = tracker.track((row(100, 3),))[0]
    assert isinstance(reopened, ConnectionOpened) and reopened.lifecycle_id != identity
    assert reopened.session_id == first.session_id
    tracker.reset_session()
    assert tracker.session_id != first.session_id
    assert tracker.active_connections == ()


def test_reduced_and_failed_rounds_preserve_state_until_complete_recovery() -> None:
    tracker = ConnectionTrackingService()
    tracker.track((row(100), row(101), row(102)))
    assert tracker.track((row(100, 1),), quality=ObservationQuality.REDUCED) == ()
    assert tracker.last_round is not None and tracker.last_round.quality is ObservationQuality.REDUCED
    failure = tracker.record_failure(observed_at=T0 + timedelta(seconds=2))
    assert failure.quality is ObservationQuality.FAILED
    assert len(tracker.active_connections) == 3
    recovered = tracker.track((row(100, 3), row(102, 3)))
    assert len(recovered) == 1 and isinstance(recovered[0], ConnectionClosed)
    assert recovered[0].key == row(101).key
    assert recovered[0].occurred_at == T0 + timedelta(seconds=3)


def test_capacity_loss_is_deterministic_bounded_and_does_not_close() -> None:
    first = row(100)
    second = row(101)
    third = row(102)
    for incoming in ((third, second, first), (first, third, second)):
        tracker = ConnectionTrackingService(capacity=2)
        events = tracker.track(incoming)
        assert len(events) == 2
        assert all(isinstance(event, ConnectionOpened) for event in events)
        assert [item.key for item in tracker.active_connections] == [first.key, second.key]
        assert tracker.last_round is not None
        assert tracker.last_round.quality is ObservationQuality.REDUCED
        assert tracker.last_round.discarded_observations == 1
        assert tracker.track((third,), quality=ObservationQuality.REDUCED) == ()
        assert len(tracker.active_connections) == 2


def test_pid_reuse_keeps_distinct_lifecycle_ids() -> None:
    tracker = ConnectionTrackingService()
    old = row(100)
    new_process = replace(old.process, identity=ProcessIdentity(7, T0 - timedelta(minutes=1)))
    opened = tracker.track((old,))[0]
    changed = tracker.track((row(100, 1, process=new_process),))
    assert isinstance(opened, ConnectionOpened)
    assert isinstance(changed[0], ConnectionOpened)
    assert isinstance(changed[1], ConnectionClosed)
    assert changed[0].lifecycle_id != opened.lifecycle_id
    assert changed[1].lifecycle_id == opened.lifecycle_id


def test_parent_timestamp_revision_keeps_lifecycle_identity() -> None:
    tracker = ConnectionTrackingService()
    first = tracker.track((row(100),))[0]
    assert isinstance(first, ConnectionOpened)
    parent = ParentProcessInfo(
        ParentProcessStatus.OBSERVED, T0 + timedelta(seconds=1), 3,
        ProcessIdentity(3, T0 - timedelta(hours=2)), "parent",
        ProcessInfoStatus.AVAILABLE, ProcessInfoStatus.AVAILABLE,
        ProcessInfoStatus.AVAILABLE,
    )
    enriched = replace(row(100, 1).process, parent=parent)
    update = tracker.track((row(100, 1, process=enriched),))[0]
    assert isinstance(update, ConnectionUpdated) and update.lifecycle_id == first.lifecycle_id
    later = replace(enriched, parent=replace(parent, observed_at=T0 + timedelta(seconds=2)))
    assert tracker.track((row(100, 2, process=later),)) == ()
    assert tracker.active_connections[0].lifecycle_id == first.lifecycle_id


def test_first_complete_after_reduced_is_still_initial() -> None:
    tracker = ConnectionTrackingService()
    first = tracker.track((row(100),), quality=ObservationQuality.REDUCED)
    second = tracker.track((row(100, 1), row(101, 1)))
    assert isinstance(first[0], ConnectionOpened)
    assert first[0].origin is ObservationOrigin.INITIAL
    assert len(second) == 1 and isinstance(second[0], ConnectionOpened)
    assert second[0].origin is ObservationOrigin.INITIAL
    assert ConnectionTrackingService().session_id != tracker.session_id


def test_engine_failure_and_reduced_round_publish_typed_quality() -> None:
    class Collector:
        def __init__(self) -> None:
            self.outcomes: list[object] = [
                ConnectionCollectionRound((row(100), row(101))),
                ConnectionCollectionTransientError("private OS detail"),
                ConnectionCollectionRound((row(100, 1),), ObservationQuality.REDUCED, 1),
                ConnectionCollectionRound((row(100, 2),)),
            ]

        def collect_round(self) -> ConnectionCollectionRound:
            value = self.outcomes.pop(0)
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, ConnectionCollectionRound)
            return value

    class Enricher:
        def enrich(self, snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[ConnectionSnapshot, ...]:
            return snapshots

    clock = iter((0.0, 1.0, 2.0, 3.0))
    dispatcher = EventDispatcher()
    reports: list[ConnectionRoundObservation] = []
    closes: list[ConnectionClosed] = []
    dispatcher.subscribe(ConnectionRoundObservation, reports.append)
    dispatcher.subscribe(ConnectionClosed, closes.append)
    engine = MonitoringEngine(
        collector=Collector(),  # type: ignore[arg-type]
        enricher=Enricher(), tracker=ConnectionTrackingService(),
        dispatcher=dispatcher, clock=lambda: T0 + timedelta(seconds=3),
        monotonic_clock=lambda: next(clock),
    )
    for _ in range(4):
        engine._poll_once()
    assert [report.quality for report in reports] == [
        ObservationQuality.COMPLETE, ObservationQuality.FAILED,
        ObservationQuality.REDUCED, ObservationQuality.COMPLETE,
    ]
    assert len(closes) == 1 and closes[0].occurred_at == T0 + timedelta(seconds=2)
    assert engine.health.counters.collection_gaps == 2
    assert engine.health.counters.discarded_observations == 1
    assert engine.health.last_error is not None
    assert engine.health.last_error.code is DiagnosticCode.CONNECTION_REDUCED_ROUND


def test_engine_restart_changes_session_without_shutdown_regression() -> None:
    reached = Event()

    class Collector:
        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            reached.set()
            return ()

    class Enricher:
        def enrich(self, snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[ConnectionSnapshot, ...]:
            return snapshots

    tracker = ConnectionTrackingService()
    engine = MonitoringEngine(
        collector=Collector(), enricher=Enricher(), tracker=tracker,
        polling_interval=10.0, clock=lambda: T0,
    )
    first_session = engine.session_id
    assert engine.start() and reached.wait(1)
    assert engine.stop(timeout=1)
    reached.clear()
    assert engine.start() and reached.wait(1)
    assert engine.session_id != first_session
    assert engine.session_id == tracker.session_id
    assert engine.stop(timeout=1)


def test_engine_capacity_loss_has_sanitized_diagnostic() -> None:
    class Collector:
        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            return (row(100), row(101))

    class Enricher:
        def enrich(self, snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[ConnectionSnapshot, ...]:
            return snapshots

    tracker = ConnectionTrackingService(capacity=1)
    engine = MonitoringEngine(
        collector=Collector(), enricher=Enricher(), tracker=tracker,
        clock=lambda: T0,
    )
    engine._poll_once()
    assert len(tracker.active_connections) == 1
    assert engine.health.counters.discarded_observations == 1
    assert engine.health.counters.collection_gaps == 1
    assert engine.health.last_error is not None
    assert engine.health.last_error.code is DiagnosticCode.CONNECTION_CAPACITY_LOSS
    assert "192.0.2.1" not in repr(engine.health.last_error)
