"""NS-016 unit coverage for the bounded connection-history writer."""

from __future__ import annotations

import ast
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread, enumerate as enumerate_threads, get_ident
from time import monotonic
from typing import Iterator
from uuid import uuid4

from netsentinel.application.events import EventDispatcher
from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.ports import HistoryRepositoryError
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.history import (
    ConnectionHistoryPersistence,
    ConnectionHistoryWriter,
)
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionHistoryRecord,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessInfo,
    TransportProtocol,
)
from netsentinel.shared.diagnostics import DiagnosticCode, PersistenceState


BASE = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _snapshot(index: int, *, at: datetime | None = None) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", 20_000 + index),
        remote_endpoint=Endpoint("198.51.100.20", 443),
        state=ConnectionState.ESTABLISHED,
        process=ProcessInfo.unavailable(),
        observed_at=BASE if at is None else at,
    )


def _lifecycle() -> tuple[ConnectionOpened, ConnectionUpdated, ConnectionClosed]:
    first = _snapshot(1)
    current = ConnectionSnapshot(
        protocol=first.protocol,
        local_endpoint=first.local_endpoint,
        remote_endpoint=first.remote_endpoint,
        state=ConnectionState.CLOSE_WAIT,
        process=first.process,
        observed_at=BASE + timedelta(seconds=1),
    )
    return (
        ConnectionOpened(first),
        ConnectionUpdated(first, current),
        ConnectionClosed(current, BASE + timedelta(seconds=2)),
    )


class ControlledSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.batch_calls = 0
        self.thread_ids: set[int] = set()
        self.entered_write = Event()
        self.release_write = Event()
        self.release_write.set()
        self.failures_remaining = 0
        self.unexpected_ports: set[int] = set()
        self._lock = Lock()

    @contextmanager
    def batch(self) -> Iterator[None]:
        with self._lock:
            self.batch_calls += 1
        yield

    def record_opened(self, event: ConnectionOpened) -> ConnectionHistoryRecord:
        return self._record("opened", event, event.snapshot)

    def record_updated(self, event: ConnectionUpdated) -> ConnectionHistoryRecord:
        return self._record("updated", event, event.current)

    def record_closed(self, event: ConnectionClosed) -> ConnectionHistoryRecord:
        return self._record("closed", event, event.last_snapshot)

    def _record(
        self,
        kind: str,
        event: object,
        snapshot: ConnectionSnapshot,
    ) -> ConnectionHistoryRecord:
        self.thread_ids.add(get_ident())
        self.entered_write.set()
        self.release_write.wait()
        if snapshot.local_endpoint.port in self.unexpected_ports:
            raise RuntimeError("sensitive database path and SQL detail")
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise HistoryRepositoryError("sanitized repository failure")
        with self._lock:
            self.calls.append((kind, event))
        return ConnectionHistoryRecord(
            record_id=uuid4(),
            first_seen=snapshot.observed_at,
            last_seen=snapshot.observed_at,
            snapshot=snapshot,
        )


class ControlledFactory:
    def __init__(self, session: ControlledSession) -> None:
        self.session = session
        self.opened = Event()
        self.closed = Event()
        self.calls = 0
        self.owner_thread_ids: list[int] = []

    @contextmanager
    def __call__(self) -> Iterator[ControlledSession]:
        self.calls += 1
        self.owner_thread_ids.append(get_ident())
        self.opened.set()
        try:
            yield self.session
        finally:
            self.closed.set()


def _writer(
    session: ControlledSession,
    **options: object,
) -> tuple[ConnectionHistoryWriter, ControlledFactory]:
    factory = ControlledFactory(session)
    defaults: dict[str, object] = {
        "queue_capacity": 8,
        "batch_size": 4,
        "batch_interval": 0.01,
        "retry_limit": 0,
        "shutdown_timeout": 0.5,
    }
    defaults.update(options)
    return ConnectionHistoryWriter(factory, **defaults), factory


def test_writer_start_double_start_mapping_fifo_counters_and_clean_stop() -> None:
    session = ControlledSession()
    writer, factory = _writer(session)
    opened, updated, closed = _lifecycle()

    assert writer.health.state is PersistenceState.STOPPED
    assert writer.start() is True
    assert writer.start() is False
    assert factory.opened.wait(1.0)
    assert writer.submit(opened) is True
    assert writer.submit(updated) is True
    assert writer.submit(closed) is True
    assert writer.stop() is True
    assert writer.stop() is True

    assert [kind for kind, _ in session.calls] == ["opened", "updated", "closed"]
    assert [event for _, event in session.calls] == [opened, updated, closed]
    assert session.batch_calls == 1
    assert factory.calls == 1
    assert factory.closed.is_set()
    assert len(session.thread_ids) == 1
    assert session.thread_ids == set(factory.owner_thread_ids)
    health = writer.health
    assert health.state is PersistenceState.STOPPED
    assert health.worker_alive is False
    assert health.queue_depth == 0
    assert health.counters.accepted_events == 3
    assert health.counters.persisted_events == 3
    assert health.counters.dropped_events == 0
    assert health.counters.failed_writes == 0
    assert health.last_successful_write_at is not None
    assert not any(
        thread.name == "netsentinel-history-writer" and thread.is_alive()
        for thread in enumerate_threads()
    )


def test_slow_repository_never_blocks_producer_and_overflow_is_visible() -> None:
    session = ControlledSession()
    session.release_write.clear()
    writer, _ = _writer(
        session,
        queue_capacity=2,
        batch_size=1,
        batch_interval=0.0,
    )
    writer.start()
    assert writer.submit(ConnectionOpened(_snapshot(0)))
    assert session.entered_write.wait(1.0)

    started = monotonic()
    assert writer.submit(ConnectionOpened(_snapshot(1)))
    assert writer.submit(ConnectionOpened(_snapshot(2)))
    assert writer.submit(ConnectionOpened(_snapshot(3))) is False
    elapsed = monotonic() - started

    health = writer.health
    assert elapsed < 0.1
    assert health.queue_depth == health.queue_capacity == 2
    assert health.counters.accepted_events == 3
    assert health.counters.dropped_events == 1
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.PERSISTENCE_OVERFLOW

    session.release_write.set()
    assert writer.stop() is True
    assert writer.health.counters.persisted_events == 3


def test_bounded_retry_succeeds_without_reordering() -> None:
    session = ControlledSession()
    session.failures_remaining = 2
    writer, _ = _writer(
        session,
        batch_size=1,
        retry_limit=2,
        retry_backoff=0.001,
    )
    events = tuple(ConnectionOpened(_snapshot(index)) for index in range(2))

    writer.start()
    for event in events:
        assert writer.submit(event)
    assert writer.stop()

    assert [event for _, event in session.calls] == list(events)
    health = writer.health
    assert health.counters.retry_attempts == 2
    assert health.counters.persisted_events == 2
    assert health.counters.failed_writes == 0


def test_exhausted_repository_error_does_not_kill_writer_or_block_next_event() -> None:
    session = ControlledSession()
    # One failed batch attempt plus the single-event isolation attempt.
    session.failures_remaining = 2
    writer, _ = _writer(session, batch_size=1, retry_limit=0)
    bad = ConnectionOpened(_snapshot(1))
    good = ConnectionOpened(_snapshot(2))

    writer.start()
    assert writer.submit(bad)
    assert writer.submit(good)
    assert writer.stop()

    assert session.calls == [("opened", good)]
    health = writer.health
    assert health.counters.failed_writes == 1
    assert health.counters.persisted_events == 1
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.PERSISTENCE_WRITE_FAILED


def test_repository_and_unexpected_errors_are_isolated_and_sanitized() -> None:
    session = ControlledSession()
    session.unexpected_ports.add(20_001)
    writer, _ = _writer(session, batch_size=1)
    bad = ConnectionOpened(_snapshot(1))
    good = ConnectionOpened(_snapshot(2))

    writer.start()
    assert writer.submit(bad)
    assert writer.submit(good)
    assert writer.stop()

    assert session.calls == [("opened", good)]
    health = writer.health
    assert health.counters.failed_writes == 1
    assert health.counters.persisted_events == 1
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR
    assert not hasattr(health.last_error, "message")


def test_stop_timeout_is_bounded_discards_queued_events_and_worker_later_exits() -> None:
    session = ControlledSession()
    session.release_write.clear()
    writer, factory = _writer(
        session,
        queue_capacity=4,
        batch_size=1,
        shutdown_timeout=0.02,
    )
    writer.start()
    assert writer.submit(ConnectionOpened(_snapshot(0)))
    assert session.entered_write.wait(1.0)
    assert writer.submit(ConnectionOpened(_snapshot(1)))
    assert writer.submit(ConnectionOpened(_snapshot(2)))

    started = monotonic()
    assert writer.stop() is False
    elapsed = monotonic() - started
    health = writer.health

    assert elapsed < 0.2
    assert health.state is PersistenceState.STOPPING
    assert health.queue_depth == 0
    assert health.counters.dropped_events == 2
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.PERSISTENCE_SHUTDOWN_TIMEOUT
    assert writer.submit(ConnectionOpened(_snapshot(3))) is False

    session.release_write.set()
    assert factory.closed.wait(1.0)
    assert writer.stop(timeout=1.0) is True
    assert writer.health.state is PersistenceState.STOPPED
    assert writer.health.worker_alive is False


def test_health_snapshot_can_be_read_concurrently() -> None:
    session = ControlledSession()
    writer, _ = _writer(session, queue_capacity=64, batch_size=8)
    failures: list[BaseException] = []
    stop_reader = Event()

    def read_health() -> None:
        try:
            while not stop_reader.is_set():
                snapshot = writer.health_snapshot()
                assert 0 <= snapshot.queue_depth <= snapshot.queue_capacity
        except BaseException as error:  # pragma: no cover - assertion transport
            failures.append(error)

    reader = Thread(target=read_health, name="ns016-health-reader")
    writer.start()
    reader.start()
    for index in range(40):
        writer.submit(ConnectionOpened(_snapshot(index)))
    assert writer.stop()
    stop_reader.set()
    reader.join(1.0)

    assert not reader.is_alive()
    assert failures == []


def test_last_successful_write_uses_portable_utc_clock() -> None:
    session = ControlledSession()
    written_at = BASE + timedelta(hours=3)
    writer, _ = _writer(session, batch_size=1, clock=lambda: written_at)

    writer.start()
    assert writer.submit(ConnectionOpened(_snapshot(1)))
    assert writer.stop()

    assert writer.health.last_successful_write_at == written_at


def test_repository_session_start_failure_is_visible_and_worker_exits() -> None:
    @contextmanager
    def failing_factory() -> Iterator[ControlledSession]:
        raise RuntimeError("private database location")
        yield ControlledSession()  # pragma: no cover - contextmanager shape

    writer = ConnectionHistoryWriter(
        failing_factory,
        queue_capacity=2,
        batch_size=1,
        batch_interval=0.0,
        retry_limit=0,
        shutdown_timeout=0.2,
    )

    assert writer.start()
    assert writer.stop(timeout=1.0)
    health = writer.health
    assert health.worker_alive is False
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.PERSISTENCE_START_FAILED
    assert not hasattr(health.last_error, "message")


def test_cleanly_stopped_writer_can_restart_without_reusing_a_worker() -> None:
    session = ControlledSession()
    writer, factory = _writer(session, batch_size=1)

    assert writer.start()
    assert writer.submit(ConnectionOpened(_snapshot(1)))
    assert writer.stop()
    assert writer.start()
    assert writer.submit(ConnectionOpened(_snapshot(2)))
    assert writer.stop()

    assert factory.calls == 2
    assert [event.snapshot.local_endpoint.port for _, event in session.calls] == [
        20_001,
        20_002,
    ]
    assert writer.health.counters.accepted_events == 2
    assert writer.health.counters.persisted_events == 2


def test_persistence_subscriptions_are_idempotent_and_detach_on_stop() -> None:
    session = ControlledSession()
    writer, _ = _writer(session)
    dispatcher = EventDispatcher()
    persistence = ConnectionHistoryPersistence(dispatcher, writer)
    event = ConnectionOpened(_snapshot(1))

    assert persistence.start() is True
    assert persistence.start() is False
    report = dispatcher.publish(event)
    assert report.delivered == 1
    assert persistence.stop() is True
    assert session.calls == [("opened", event)]
    assert dispatcher.publish(ConnectionOpened(_snapshot(2))).delivered == 0


def test_monitoring_engine_integration_persists_each_dispatched_event_once() -> None:
    class Collector:
        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            return (_snapshot(1),)

    class Enricher:
        def enrich(
            self,
            snapshots: tuple[ConnectionSnapshot, ...],
        ) -> tuple[ConnectionSnapshot, ...]:
            return snapshots

    session = ControlledSession()
    writer, _ = _writer(session, batch_size=1)
    dispatcher = EventDispatcher()
    persistence = ConnectionHistoryPersistence(dispatcher, writer)
    engine = MonitoringEngine(
        collector=Collector(),
        enricher=Enricher(),
        tracker=ConnectionTrackingService(),
        dispatcher=dispatcher,
        persistence=persistence,
        polling_interval=0.5,
        shutdown_timeout=1.0,
    )

    assert engine.start()
    assert session.entered_write.wait(1.0)
    assert engine.stop(timeout=1.0)

    assert [kind for kind, _ in session.calls] == ["opened"]
    persistence_health = engine.persistence_health_snapshot()
    assert persistence_health is not None
    assert persistence_health.counters.accepted_events == 1
    assert persistence_health.counters.persisted_events == 1


def test_application_domain_and_presentation_preserve_sqlite_and_writer_boundaries() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    forbidden: dict[Path, set[str]] = {
        repository_root / "src" / "netsentinel" / "domain": {"sqlite3"},
        repository_root / "src" / "netsentinel" / "application": {"sqlite3"},
        repository_root / "src" / "netsentinel" / "presentation": {
            "sqlite3",
            "netsentinel.infrastructure.sqlite",
            "netsentinel.application.services.history",
        },
    }
    violations: list[str] = []
    for root, blocked in forbidden.items():
        for source_path in root.rglob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                module_names: list[str] = []
                if isinstance(node, ast.Import):
                    module_names.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    module_names.append(node.module)
                if any(
                    name == item or name.startswith(f"{item}.")
                    for name in module_names
                    for item in blocked
                ):
                    violations.append(str(source_path))

    assert violations == []
