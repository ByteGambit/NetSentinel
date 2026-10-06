"""NS-099 offline integrated evidence; never native browser/VPN/OS acceptance."""

from dataclasses import asdict
from datetime import timedelta
import json
from time import perf_counter

import pytest

from netsentinel.application.services.notifications import (
    NotificationDeliveryOutcome as Outcome,
    PersistedNotificationIntent,
)
from netsentinel.application.services.storage_privacy import StoragePrivacyService
from netsentinel.domain.incident_persistence import IncidentStatus
from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
from netsentinel.shared.config import (
    AppConfig, WindowCloseBehavior, complete_onboarding, load_config_file,
    onboarding_pending, save_config_file,
)
from tests.fixtures.incident_acceptance import Story, all_pages, deny_network, table_state
from tests.fixtures.notifications import candidate
from tests.integration.test_desktop_notifications import compose


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    deny_network(monkeypatch)


def test_soak_delivery_replay_cooldown_escalation_and_three_restarts(tmp_path):
    """One hour of injected time, real commits, bounded delivery and no replay."""
    started = perf_counter()
    path = tmp_path / "beta.db"
    repo, sink, clock, delivery, events, service = compose(path, enabled=False)
    service.record(candidate())
    assert not sink.requests and delivery.drain_one() is None
    delivery.set_enabled(True)
    assert delivery.drain_one() is None  # disabled history is not a backlog
    clock.value = 121
    record, _ = service.record(candidate(2, seconds=121))
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    stable = events[-1]
    for _ in range(100):
        delivery.enqueue(stable)
        assert delivery.drain_one() is Outcome.POLICY_SKIPPED
    # Next committed LOW observation inside cooldown, then real HIGH escalation.
    clock.value = 122
    changed, _ = repo.record(candidate(2, seconds=122), candidate(2, seconds=122).evidence.observed_at,
                             timedelta(seconds=120))
    delivery.enqueue(PersistedNotificationIntent.from_alert(changed, record, eligible=True))
    assert delivery.drain_one() is Outcome.POLICY_SKIPPED
    clock.value = 123
    escalated, _ = repo.record(candidate(2, seconds=123, severity="high"),
                              candidate(2, seconds=123).evidence.observed_at, timedelta(seconds=120))
    delivery.enqueue(PersistedNotificationIntent.from_alert(escalated, changed, eligible=True))
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    # Repeat the exact persisted occurrence for 3600 rounds: no count churn.
    for second in range(124, 3724):
        clock.value = second
        unchanged, _ = service.record(candidate(2, seconds=123, severity="high"))
        assert unchanged.occurrence_count == escalated.occurrence_count
        assert delivery.drain_one() is None
        assert delivery.sizes[0] <= 32 and delivery.sizes[1] <= 512
    diagnostics = delivery.diagnostics()
    assert diagnostics.submitted_to_sink == 2
    assert diagnostics.duplicate_skipped == 100
    assert diagnostics.cooldown_skipped == 1
    assert diagnostics.escalation_notifications == 1
    assert diagnostics.queue_dropped == diagnostics.sink_failure == 0
    for request in sink.requests:
        assert all(value not in request.body for value in
                   ("192.0.2.123", "private.example", "private-user", "C:/private"))
    delivery.close()
    for _ in range(3):
        _, next_sink, _, next_delivery, next_events, next_service = compose(path)
        assert next_delivery.drain_one() is None
        next_service.record(candidate(2, seconds=123, severity="high"))
        assert next_events == [] and next_sink.attempts == 0
        next_delivery.close()
    print("NS099_SYNTHETIC_DELIVERY " + json.dumps({
        "injected_seconds": 3600, "replay_rounds": 3600,
        "wall_seconds": round(perf_counter() - started, 3),
        "native_delivered": None, "benign_fp_measurement": None,
        "diagnostics": asdict(diagnostics), "restart_historical_submissions": 0,
    }, sort_keys=True))


def test_risk_incident_export_and_guide_survive_three_restarts_together(tmp_path):
    """Read-only restart of the real accepted story through support export."""
    started = perf_counter()
    story = Story(tmp_path / "story.db").build()
    config_path = tmp_path / "config.json"
    save_config_file(config_path, AppConfig())
    complete_onboarding(config_path, AppConfig())
    state = table_state(story.db)
    incident_id, inputs = story.record.incident_id, story.inputs
    rows = all_pages(story.query, incident_id)[0]
    before_bytes = story.path.stat().st_size
    with story.db.connection() as connection:
        measurements = {
            "assessments": connection.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "alerts_by_severity": dict(connection.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")),
        }
    for index in range(3):
        story = story.restart()
        assert table_state(story.db) == state
        with story.db.connection() as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert all_pages(story.query, incident_id)[0] == rows
        config = load_config_file(config_path).config
        assert not onboarding_pending(config)
        assert not config.desktop_notifications_enabled
        assert not config.threat_intel_consents
        assert config.window_close_behavior is WindowCloseBehavior.QUIT_APPLICATION
        for value in inputs:
            assert story.incidents.append(incident_id, value, now=value.observed_at + timedelta(hours=1)).status is IncidentStatus.NO_CHANGE
        privacy = StoragePrivacyService(SQLiteStorageMaintenanceRepository(story.db))
        export = privacy.preview_export()
        body = json.loads(export.content)
        assert body["manifest"]["schema_version"] == 19
        assert body["manifest"]["format"] == "support-export-v1"
        assert body["manifest"]["redaction_policy"] == "allowlist-v1"
        assert len(export.content) <= 65536
        for value in ("example.test", "edge.test", "8.8.8.8", "192.0.2.20", "C:\\Apps", "example.exe"):
            assert value not in export.content.decode()
        target = tmp_path / f"support-{index}-ü.json"
        assert privacy.save_export(export, target)
        assert target.read_bytes() == export.content
        assert table_state(story.db) == state
    print("NS099_SYNTHETIC_STORY " + json.dumps({
        "wall_seconds": round(perf_counter() - started, 3), "restarts": 3,
        "db_bytes_before": before_bytes, "db_bytes_after": story.path.stat().st_size,
        "db_growth_bytes": story.path.stat().st_size - before_bytes,
        "native_fp_measurement": None, "external_requests": 0,
        "measurements": measurements,
    }, sort_keys=True))
