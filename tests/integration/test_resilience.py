"""NS-049 deterministic failure and repeated-lifecycle integration checks."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from logging import getLogger
from threading import Event, enumerate as threads
from time import monotonic

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.dns_history import DnsHistoryWriter
from netsentinel.application.services.history import ConnectionHistoryWriter
from netsentinel.shared.config import AppConfig
from netsentinel.shared.diagnostics import DiagnosticCode, EngineState
from netsentinel.shared.logging import close_logging, configure_logging, log_event
from tests.integration.sqlite.test_dns_repository import _tx
from tests.unit.application.test_engine import PassthroughEnricher
from tests.unit.application.test_history_writer import ControlledFactory, ControlledSession, _snapshot
from netsentinel.domain.connections import ConnectionOpened


def test_slow_writers_bound_both_queues_and_refuse_new_work_after_stop() -> None:
    history_session = ControlledSession()
    history_session.release_write.clear()
    history_factory = ControlledFactory(history_session)
    history = ConnectionHistoryWriter(history_factory, queue_capacity=8,
                                      batch_size=2, batch_interval=0,
                                      retry_limit=0, shutdown_timeout=.05)
    dns_entered, dns_release = Event(), Event()

    @contextmanager
    def dns_factory():
        class Session:
            def write_batch(self, records):
                dns_entered.set()
                assert dns_release.wait(5)
        yield Session()

    dns = DnsHistoryWriter(dns_factory, queue_capacity=8, batch_size=2,
                           batch_interval=0, retry_limit=0, shutdown_timeout=.05)
    assert history.start() and dns.start()
    try:
        assert history.submit(ConnectionOpened(_snapshot(0)))
        assert dns.submit(_tx()) is not None
        assert history_session.entered_write.wait(2) and dns_entered.wait(2)
        start = monotonic()
        history_accepted = sum(history.submit(ConnectionOpened(_snapshot(i + 1))) for i in range(500))
        dns_accepted = sum(dns.submit(_tx()) is not None for _ in range(500))
        assert monotonic() - start < 2  # generous nonblocking regression guard
        assert history_accepted == dns_accepted == 8
        assert history.health.queue_depth == dns.health_snapshot().queue_depth == 8
        assert history.health.counters.dropped_events == 492
        assert dns.health_snapshot().dropped == 492
        assert history.health.last_error.code is DiagnosticCode.PERSISTENCE_OVERFLOW
        assert dns.health_snapshot().error_code == "overflow"
        assert not history.stop() and not dns.stop()
        assert not history.submit(ConnectionOpened(_snapshot(999)))
        assert dns.submit(_tx()) is None
    finally:
        history_session.release_write.set()
        dns_release.set()
        assert history.stop(5) and dns.stop(5)
    assert not history.health.worker_alive and not dns.health_snapshot().running
    assert history_factory.closed.is_set()


def test_connection_churn_repeated_engine_start_stop_leaves_no_owned_worker() -> None:
    class ChurnCollector:
        def __init__(self) -> None:
            self.calls = 0
            self.reached = Event()

        def collect(self):
            self.calls += 1
            if self.calls >= 30:
                self.reached.set()
            return (_snapshot(self.calls % 20, at=datetime(2026, 9, 27, 12, 0, tzinfo=UTC)),)

    collector = ChurnCollector()
    tracker = ConnectionTrackingService(clock=lambda: datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
    engine = MonitoringEngine(collector=collector, enricher=PassthroughEnricher(),
                              tracker=tracker, polling_interval=.001, shutdown_timeout=.5)
    before = {t.ident for t in threads() if t.name == "netsentinel-connection-poller"}
    for cycle in range(5):
        assert engine.start()
        assert not engine.start()
        target = (cycle + 1) * 6
        deadline = monotonic() + 2
        while collector.calls < target and monotonic() < deadline:
            collector.reached.wait(.005)
        assert collector.calls >= target
        assert engine.stop()
        assert engine.stop()
        assert engine.health.state is EngineState.STOPPED
        assert len(tracker.active_connections) <= 1
    assert collector.reached.is_set()
    assert {t.ident for t in threads() if t.name == "netsentinel-connection-poller"} == before


def test_log_storm_rotates_redacts_and_reconfigure_does_not_multiply_handlers(tmp_path) -> None:
    path = tmp_path / "app.log"
    config = AppConfig(log_max_bytes=512, log_backups=2)
    logger = configure_logging(path, config)
    try:
        for _ in range(10):
            logger = configure_logging(path, config)
            assert len(logger.handlers) == 1
        for _ in range(2_000):
            logger.error("token=SECRET raw packet user note SQL C:/private/db.sqlite",
                         exc_info=RuntimeError("credential SECRET"),
                         extra={"safe_component": "capture", "safe_code": "capture_queue_overflow"})
        log_event(logger, component="capture", code="capture_queue_overflow")
    finally:
        close_logging(logger)
    files = tuple(tmp_path.glob("app.log*"))
    assert len(files) <= 3
    assert all(path.stat().st_size <= 512 for path in files)
    payload = "".join(path.read_text(encoding="utf-8") for path in files)
    assert all(secret not in payload for secret in ("SECRET", "token=", "raw packet", "user note", "SQL", "db.sqlite"))
    assert all(set(json.loads(line)) == {"timestamp", "level", "component", "code"}
               for line in payload.splitlines())
    assert getLogger("netsentinel").handlers == []
