"""Lifecycle, scheduling, isolation and health tests for MonitoringEngine."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, enumerate as enumerate_threads
from time import monotonic

import pytest

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.ports import (
    ConnectionCollectionPermissionDenied,
    ConnectionCollectionTransientError,
)
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.shared.diagnostics import (
    CapabilityStatus,
    DiagnosticCode,
    EngineState,
)


def test_dns_config_poll_failure_is_isolated_on_existing_engine_worker():
    class FailingDnsPoller:
        calls = 0

        def poll(self):
            self.calls += 1
            raise RuntimeError("private Windows API detail")

    poller = FailingDnsPoller()
    collector = SequenceCollector(((),), reached=2)
    engine = MonitoringEngine(
        collector=collector,
        enricher=PassthroughEnricher(),
        tracker=ConnectionTrackingService(),
        polling_interval=0.001,
        dns_config_poller=poller,
    )
    assert engine.start()
    assert collector.ready.wait(1)
    assert engine.stop(timeout=1)
    assert poller.calls >= 2
    assert engine.health.counters.successful_rounds >= 2
    assert engine.health.last_error.code is DiagnosticCode.DNS_CONFIG_UNAVAILABLE
    assert engine.health.worker_alive is False


T0 = datetime(2026, 9, 18, 9, 0, tzinfo=UTC)
T1 = T0 + timedelta(seconds=1)
T2 = T0 + timedelta(seconds=2)


def wait_until(predicate: Callable[[], bool], *, timeout: float = 1.0) -> bool:
    """Wait in short interruptible steps without fixed test sleeps."""

    deadline = monotonic() + timeout
    wake = Event()
    while monotonic() < deadline:
        if predicate():
            return True
        wake.wait(0.001)
    return predicate()


def snapshot(
    *,
    port: int = 50_000,
    observed_at: datetime = T0,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    process_status: ProcessInfoStatus = ProcessInfoStatus.AVAILABLE,
) -> ConnectionSnapshot:
    identity = ProcessIdentity(42, T0 - timedelta(hours=1))
    process = ProcessInfo(
        status=process_status,
        identity=identity,
        name="browser.exe" if process_status is ProcessInfoStatus.AVAILABLE else None,
    )
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", port),
        remote_endpoint=Endpoint("203.0.113.20", 443),
        state=state,
        process=process,
        observed_at=observed_at,
    )


class PassthroughEnricher:
    def enrich(
        self, snapshots: Iterable[ConnectionSnapshot]
    ) -> tuple[ConnectionSnapshot, ...]:
        return tuple(snapshots)


class SequenceCollector:
    def __init__(
        self,
        outcomes: Iterable[tuple[ConnectionSnapshot, ...] | Exception],
        *,
        reached: int = 1,
    ) -> None:
        self._outcomes = list(outcomes)
        self._lock = Lock()
        self.calls = 0
        self.reached = reached
        self.ready = Event()

    def collect(self) -> tuple[ConnectionSnapshot, ...]:
        with self._lock:
            index = min(self.calls, len(self._outcomes) - 1)
            self.calls += 1
            if self.calls >= self.reached:
                self.ready.set()
            outcome = self._outcomes[index]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def engine_for(
    collector: object,
    *,
    dispatcher: EventDispatcher | None = None,
    enricher: object | None = None,
    tracker: object | None = None,
    interval: float = 10.0,
    timeout: float = 0.2,
) -> MonitoringEngine:
    return MonitoringEngine(
        collector=collector,  # type: ignore[arg-type]
        enricher=enricher or PassthroughEnricher(),  # type: ignore[arg-type]
        tracker=tracker or ConnectionTrackingService(),  # type: ignore[arg-type]
        dispatcher=dispatcher,
        polling_interval=interval,
        shutdown_timeout=timeout,
        clock=lambda: T2,
    )


def test_start_twice_creates_only_one_worker() -> None:
    entered = Event()
    release = Event()

    class BlockingCollector:
        calls = 0

        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            self.calls += 1
            entered.set()
            release.wait(1)
            return ()

    collector = BlockingCollector()
    engine = engine_for(collector)

    assert engine.start() is True
    assert entered.wait(1)
    assert engine.start() is False
    release.set()
    assert engine.stop() is True
    assert collector.calls == 1


def test_stop_twice_is_idempotent() -> None:
    collector = SequenceCollector([()])
    engine = engine_for(collector)
    engine.start()
    assert collector.ready.wait(1)

    assert engine.stop() is True
    assert engine.stop() is True
    assert engine.health.state is EngineState.STOPPED


def test_start_poll_publish_and_stop_updates_health() -> None:
    item = snapshot()
    collector = SequenceCollector([(item,)])
    dispatcher = EventDispatcher()
    received: list[ConnectionOpened] = []
    delivered = Event()

    def subscriber(event: ConnectionOpened) -> None:
        received.append(event)
        delivered.set()

    dispatcher.subscribe(ConnectionOpened, subscriber)
    engine = engine_for(collector, dispatcher=dispatcher)

    assert engine.start() is True
    assert delivered.wait(1)
    assert wait_until(lambda: engine.health.counters.successful_rounds == 1)
    assert engine.stop() is True

    assert received == [ConnectionOpened(item)]
    health = engine.health
    assert health.state is EngineState.STOPPED
    assert health.last_successful_poll_at == T2
    assert health.counters.polling_rounds == 1
    assert health.counters.successful_rounds == 1
    assert health.counters.lifecycle_events == 1
    assert health.capabilities.connection_monitoring is CapabilityStatus.AVAILABLE


def test_consecutive_polling_rounds_preserve_lifecycle_event_order() -> None:
    closing = snapshot(port=50_002, observed_at=T0)
    updating = snapshot(port=50_003, observed_at=T0)
    unchanged = snapshot(port=50_004, observed_at=T0)
    opened = snapshot(port=50_001, observed_at=T1)
    updated = snapshot(
        port=50_003,
        observed_at=T1,
        state=ConnectionState.CLOSE_WAIT,
    )
    same = snapshot(port=50_004, observed_at=T1)
    collector = SequenceCollector(
        [(closing, updating, unchanged), (same, opened, updated)],
        reached=2,
    )
    dispatcher = EventDispatcher()
    received: list[ConnectionLifecycleEvent] = []
    completed = Event()

    def on_closed(event: ConnectionClosed) -> None:
        received.append(event)
        completed.set()

    for event_type in (ConnectionOpened, ConnectionUpdated, ConnectionClosed):
        if event_type is ConnectionClosed:
            dispatcher.subscribe(ConnectionClosed, on_closed)
        else:
            dispatcher.subscribe(event_type, received.append)
    engine = engine_for(collector, dispatcher=dispatcher, interval=0.01)

    engine.start()
    assert completed.wait(1)
    assert engine.stop() is True

    assert [type(event) for event in received[:3]] == [
        ConnectionOpened,
        ConnectionOpened,
        ConnectionOpened,
    ]
    assert [type(event) for event in received[3:]] == [
        ConnectionOpened,
        ConnectionUpdated,
        ConnectionClosed,
    ]
    assert [event.key.local_endpoint.port for event in received[3:]] == [
        50_001,
        50_003,
        50_002,
    ]


def test_slow_round_never_overlaps_and_records_overrun() -> None:
    first_entered = Event()
    release_first = Event()
    second_entered = Event()

    class SlowCollector:
        def __init__(self) -> None:
            self.calls = 0
            self.active = 0
            self.max_active = 0
            self.lock = Lock()

        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            with self.lock:
                self.calls += 1
                call = self.calls
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            if call == 1:
                first_entered.set()
                release_first.wait(1)
            else:
                second_entered.set()
            with self.lock:
                self.active -= 1
            return ()

    collector = SlowCollector()
    engine = engine_for(collector, interval=0.01)
    engine.start()
    assert first_entered.wait(1)
    assert not second_entered.wait(0.03)
    release_first.set()
    assert second_entered.wait(1)
    assert engine.stop() is True

    assert collector.max_active == 1
    assert engine.health.counters.polling_overruns >= 1


def test_subscriber_failure_does_not_stop_later_subscriber_or_worker() -> None:
    item = snapshot()
    collector = SequenceCollector([(item,)])
    dispatcher = EventDispatcher()
    received: list[ConnectionOpened] = []
    delivered = Event()

    def failing(event: ConnectionOpened) -> None:
        raise RuntimeError("private failure")

    def succeeding(event: ConnectionOpened) -> None:
        received.append(event)
        delivered.set()

    dispatcher.subscribe(ConnectionOpened, failing)
    dispatcher.subscribe(ConnectionOpened, succeeding)
    engine = engine_for(collector, dispatcher=dispatcher)
    engine.start()
    assert delivered.wait(1)
    assert wait_until(lambda: engine.health.counters.subscriber_failures == 1)

    assert engine.health.worker_alive is True
    assert engine.stop() is True
    assert received == [ConnectionOpened(item)]
    assert engine.health.counters.subscriber_failures == 1
    assert engine.health.last_error is not None
    assert engine.health.last_error.code is DiagnosticCode.SUBSCRIBER_ERROR


@pytest.mark.parametrize(
    ("error", "code", "capability"),
    [
        (
            ConnectionCollectionPermissionDenied("denied"),
            DiagnosticCode.COLLECTOR_PERMISSION_DENIED,
            CapabilityStatus.UNAVAILABLE,
        ),
        (
            ConnectionCollectionTransientError("changed"),
            DiagnosticCode.COLLECTOR_TRANSIENT_ERROR,
            CapabilityStatus.DEGRADED,
        ),
        (
            RuntimeError("unexpected private detail"),
            DiagnosticCode.COLLECTOR_UNEXPECTED_ERROR,
            CapabilityStatus.DEGRADED,
        ),
    ],
)
def test_collector_errors_are_typed_degraded_and_worker_survives(
    error: Exception,
    code: DiagnosticCode,
    capability: CapabilityStatus,
) -> None:
    collector = SequenceCollector([error])
    engine = engine_for(collector)
    engine.start()
    assert wait_until(lambda: engine.health.counters.failed_rounds == 1)

    health = engine.health
    assert health.worker_alive is True
    assert health.counters.failed_rounds == 1
    assert health.last_error is not None
    assert health.last_error.code is code
    assert health.capabilities.connection_monitoring is capability
    assert engine.stop() is True


def test_process_metadata_record_failure_is_visible_without_failing_round() -> None:
    unresolved = snapshot(process_status=ProcessInfoStatus.UNAVAILABLE)

    class FailingResolver:
        def resolve(self, pid: int) -> ProcessInfo:
            raise RuntimeError("resolver-private detail")

    collector = SequenceCollector([(unresolved,)])
    engine = engine_for(
        collector,
        enricher=ProcessMetadataEnricher(FailingResolver()),
    )
    engine.start()
    assert wait_until(lambda: engine.health.counters.successful_rounds == 1)
    assert engine.stop() is True

    health = engine.health
    assert health.counters.successful_rounds == 1
    assert health.counters.process_metadata_unavailable == 1
    assert health.capabilities.process_metadata is CapabilityStatus.DEGRADED


def test_transient_collection_error_retries_after_interval_and_recovers() -> None:
    item = snapshot()
    collector = SequenceCollector(
        [ConnectionCollectionTransientError("changed"), (item,)],
        reached=2,
    )
    dispatcher = EventDispatcher()
    recovered = Event()
    dispatcher.subscribe(ConnectionOpened, lambda event: recovered.set())
    engine = engine_for(collector, dispatcher=dispatcher, interval=0.01)

    engine.start()
    assert recovered.wait(1)
    assert wait_until(lambda: engine.health.counters.successful_rounds == 1)
    assert engine.stop() is True

    health = engine.health_snapshot()
    assert collector.calls == 2
    assert health.counters.failed_rounds == 1
    assert health.counters.successful_rounds == 1
    assert health.capabilities.connection_monitoring is CapabilityStatus.AVAILABLE
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.COLLECTOR_TRANSIENT_ERROR


@pytest.mark.parametrize(
    ("component", "code"),
    [
        ("enricher", DiagnosticCode.PROCESS_ENRICHMENT_ERROR),
        ("tracker", DiagnosticCode.TRACKER_ERROR),
    ],
)
def test_pipeline_stage_exception_isolated_and_worker_survives(
    component: str, code: DiagnosticCode
) -> None:
    class FailingEnricher(PassthroughEnricher):
        def enrich(
            self, snapshots: Iterable[ConnectionSnapshot]
        ) -> tuple[ConnectionSnapshot, ...]:
            raise RuntimeError("private")

    class FailingTracker:
        def track(
            self, snapshots: Iterable[ConnectionSnapshot]
        ) -> tuple[ConnectionLifecycleEvent, ...]:
            raise RuntimeError("private")

    collector = SequenceCollector([()])
    engine = engine_for(
        collector,
        enricher=FailingEnricher() if component == "enricher" else None,
        tracker=FailingTracker() if component == "tracker" else None,
    )
    engine.start()
    assert wait_until(lambda: engine.health.counters.failed_rounds == 1)

    assert engine.health.worker_alive is True
    assert engine.health.last_error is not None
    assert engine.health.last_error.code is code
    assert engine.stop() is True


def test_stop_during_poll_is_bounded_and_prevents_another_round() -> None:
    entered = Event()
    release = Event()

    class BlockingCollector:
        calls = 0

        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            self.calls += 1
            entered.set()
            release.wait(1)
            return (snapshot(),)

    collector = BlockingCollector()
    engine = engine_for(collector, timeout=0.01)
    engine.start()
    assert entered.wait(1)

    started = monotonic()
    assert engine.stop() is False
    elapsed = monotonic() - started

    assert elapsed < 0.2
    assert engine.health.state is EngineState.STOPPING
    assert engine.health.last_error is not None
    assert engine.health.last_error.code is DiagnosticCode.SHUTDOWN_TIMEOUT
    assert engine.start() is False
    release.set()
    assert engine.stop(timeout=1) is True
    assert collector.calls == 1
    assert engine.health.counters.successful_rounds == 0


def test_normal_stop_leaves_no_named_worker_and_engine_can_restart() -> None:
    collector = SequenceCollector([(), ()])
    engine = engine_for(collector)
    engine.start()
    assert wait_until(lambda: engine.health.counters.successful_rounds == 1)
    assert engine.stop() is True

    assert engine.start() is True
    assert wait_until(lambda: engine.health.counters.successful_rounds == 2)
    assert engine.stop() is True

    assert collector.calls == 2
    assert engine.health.counters.successful_rounds == 2
    assert not any(
        thread.name == "netsentinel-connection-poller" and thread.is_alive()
        for thread in enumerate_threads()
    )


def test_subscriber_cannot_stop_engine_from_worker_callback() -> None:
    collector = SequenceCollector([(snapshot(),)])
    dispatcher = EventDispatcher()
    callback_finished = Event()
    engine = engine_for(collector, dispatcher=dispatcher)

    def subscriber(event: ConnectionOpened) -> None:
        engine.stop()
        callback_finished.set()  # unreachable; dispatcher isolates the exception

    dispatcher.subscribe(ConnectionOpened, subscriber)
    engine.start()
    assert wait_until(lambda: engine.health.counters.subscriber_failures == 1)

    assert callback_finished.is_set() is False
    assert engine.health.worker_alive is True
    assert engine.stop() is True
    assert engine.health.counters.subscriber_failures == 1


def test_constructor_rejects_invalid_timing_values() -> None:
    collector = SequenceCollector([()])
    for invalid_interval in (0, -1, float("inf"), float("nan"), True):
        with pytest.raises(ValueError):
            engine_for(collector, interval=invalid_interval)
    for invalid_timeout in (-1, float("inf"), float("nan"), True):
        with pytest.raises(ValueError):
            engine_for(collector, timeout=invalid_timeout)
