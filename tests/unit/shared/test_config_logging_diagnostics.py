from __future__ import annotations

from datetime import UTC, datetime
import json
import logging

import pytest

from netsentinel.application.ports import HistoryStorageDiagnostics
from netsentinel.bootstrap import collect_diagnostics, initialize_runtime
from netsentinel.shared.config import AppConfig, load_config_file, load_config_values
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot, CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState, DatabaseStatus,
    EngineCounters, EngineHealthSnapshot, EngineState, PersistenceCounters,
    PersistenceHealthSnapshot, PersistenceState,
)
from netsentinel.shared.logging import close_logging, configure_logging, log_event


@pytest.mark.parametrize("field,bad", [
    ("capture_queue_capacity", 0), ("capture_queue_capacity", True),
    ("history_queue_capacity", 65_537), ("history_batch_size", 501),
    ("dns_queue_capacity", -1), ("dns_batch_size", 501),
    ("log_max_bytes", 16_777_217),
    ("log_backups", 11), ("polling_interval", float("nan")),
    ("shutdown_timeout", 0),
])
def test_invalid_config_field_is_reported_and_falls_back(field, bad):
    result = load_config_values({field: bad, "log_backups": 2} if field != "log_backups" else {field: bad})
    assert any(issue.field == field for issue in result.issues)
    assert getattr(result.config, field) == getattr(AppConfig(), field)


def test_config_field_boundary_and_cross_field_validation():
    assert load_config_values({"capture_queue_capacity": 1, "polling_interval": 0.05}).config.capture_queue_capacity == 1
    result = load_config_values({"history_queue_capacity": 8, "history_batch_size": 9})
    assert result.config == AppConfig()
    assert {issue.field for issue in result.issues} == {"history_batch_size", "history_queue_capacity"}


def test_config_file_malformed_oversized_and_unknown_values_do_not_leak(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"secret_token":"SECRET", "log_backups":2}', encoding="utf-8")
    result = load_config_file(path)
    assert result.config.log_backups == 2
    assert result.issues[0].field == "unknown"
    path.write_text("{bad", encoding="utf-8")
    assert load_config_file(path).config == AppConfig()
    path.write_text("x" * 16_385, encoding="utf-8")
    assert load_config_file(path).issues[0].code == "file_too_large"


def test_rotating_log_is_bounded_and_drops_messages_exceptions_and_payload(tmp_path):
    logger = configure_logging(tmp_path / "app.log", AppConfig(log_max_bytes=256, log_backups=2))
    try:
        for _ in range(25):
            log_event(logger, component="capture", code="capture_queue_overflow")
        try:
            raise RuntimeError("SECRET payload /private/path")
        except RuntimeError:
            logger.error("SECRET payload", exc_info=True, extra={"safe_component": "evil\nSECRET", "safe_code": "bad/path", "payload": "SECRET"})
    finally:
        close_logging(logger)
    files = list(tmp_path.glob("app.log*"))
    assert len(files) <= 3
    assert all(file.stat().st_size <= 256 for file in files)
    contents = "".join(file.read_text(encoding="utf-8") for file in files)
    assert "SECRET" not in contents and "payload" not in contents and "/private/path" not in contents
    assert "capture_queue_overflow" in contents
    assert "redacted" in contents
    assert all(set(json.loads(line)) == {"timestamp", "level", "component", "code"} for line in contents.splitlines())


class FakeEngine:
    def health_snapshot(self):
        return EngineHealthSnapshot(EngineState.RUNNING, CapabilitySnapshot(), EngineCounters(), worker_alive=True)

    def persistence_health_snapshot(self):
        return PersistenceHealthSnapshot(PersistenceState.RUNNING, 2, 8, PersistenceCounters(), worker_alive=True)


class FakeCapture:
    def health_snapshot(self):
        return CaptureHealthSnapshot(
            CaptureState.RUNNING,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, datetime.now(UTC)),
            1, 4, CaptureCounters(), worker_alive=True,
        )


class FakeDnsWriter:
    def health_snapshot(self):
        from netsentinel.application.services.dns_history import DnsWriterHealth
        return DnsWriterHealth(True, 3, 16, 0, 0, 0, 0, 0, 0, None)


def test_diagnostics_aggregates_existing_health_and_sanitizes_db_failure():
    def probe():
        return HistoryStorageDiagnostics(100, 20, 3, 1, 2)
    snapshot = collect_diagnostics(FakeEngine(), capture=FakeCapture(), dns_writer=FakeDnsWriter(), storage_probe=probe)
    assert snapshot.engine.worker_alive
    assert snapshot.persistence.queue_depth == 2
    assert snapshot.capture.queue_depth == 1
    assert snapshot.capture.capability.status is CapabilityStatus.AVAILABLE
    assert snapshot.dns_queue_depth == 3
    assert snapshot.database.status is DatabaseStatus.AVAILABLE
    assert snapshot.database.history_rows == 3

    def broken():
        raise RuntimeError("SECRET /private/db.sqlite SQL")

    failed = collect_diagnostics(FakeEngine(), storage_probe=broken)
    assert failed.database.status is DatabaseStatus.UNAVAILABLE
    assert "SECRET" not in repr(failed)


def test_runtime_initialization_reads_config_and_logs_only_codes(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"polling_interval":0.2,"secret":"SECRET"}', encoding="utf-8")
    log = tmp_path / "app.log"
    try:
        result = initialize_runtime(config_path=config, log_path=log)
        assert result.config.polling_interval == 0.2
    finally:
        close_logging(logging.getLogger("netsentinel"))
    assert "SECRET" not in log.read_text(encoding="utf-8")
