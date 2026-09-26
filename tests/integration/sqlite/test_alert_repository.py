"""NS-028 real SQLite assessment-to-alert and lifecycle coverage."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from netsentinel.application.ports import AlertDataCorrupt, AlertQuery, AlertRepositoryError
from netsentinel.application.services.alerts import AlertService
from netsentinel.domain.alerts import (
    AlertCandidate, AlertEvidence, AlertStatus, ArpIdentityConflictDetected, ArpIdentityEvidence,
    ArpIdentityReason, ArpIdentityRule, ArpRiskAssessment,
    ArpScoreComponent, ArpScoreRule,
)
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.devices import GatewayBaselineStatus
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteConnectionFactory, SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations


T0 = datetime(2026, 9, 23, 12, 0, 0, 123456, tzinfo=UTC)
NETWORK = "a" * 64
OTHER_NETWORK = "b" * 64
A = MacAddress("00:11:22:33:44:55")
B = MacAddress("00:11:22:33:44:66")
C = MacAddress("00:11:22:33:44:77")


def assessment(*, at=T0, network=NETWORK, ip="192.168.1.20", observed=B,
               rule=ArpIdentityRule.IP_MAC_CONFLICT, confidence="low", severity="low"):
    source = ArpIdentityConflictDetected(
        rule,
        (ArpIdentityReason.RECENT_SENDER_CONFLICT if rule is ArpIdentityRule.IP_MAC_CONFLICT else
         ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT if severity == "medium" else ArpIdentityReason.LEARNED_GATEWAY_CONFLICT),
        ArpIdentityEvidence(network, ip, A, observed, T0 - timedelta(seconds=1), at,
                            (GatewayBaselineStatus.VERIFIED if severity == "medium" else GatewayBaselineStatus.LEARNED)
                            if rule is ArpIdentityRule.GATEWAY_MAC_CHANGE else None),
        severity, "low",
    )
    parts = [ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2)]
    if rule is ArpIdentityRule.GATEWAY_MAC_CHANGE and severity == "medium":
        parts.append(ArpScoreComponent(ArpScoreRule.VERIFIED_GATEWAY, 1))
    if confidence == "moderate":
        parts.append(ArpScoreComponent(ArpScoreRule.REPEATED_OBSERVATION, 1))
    return ArpRiskAssessment(source, at, at, 3 if confidence == "moderate" else 1,
                             tuple(parts), sum(part.points for part in parts), confidence)


def service(path: Path, now: list[datetime]) -> AlertService:
    return AlertService(SQLiteAlertRepository(SQLiteDatabase(path)), clock=lambda: now[0])


def test_assessment_round_trip_dedup_restart_ack_rate_limit_and_out_of_order(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    now = [T0 + timedelta(seconds=1)]
    alerts = service(path, now)
    first, notify = alerts.record(assessment())
    assert notify and first.status is AlertStatus.OPEN
    assert first.first_seen == first.last_seen == T0
    assert first.occurrence_count == 1
    assert first.severity == first.confidence == "low"
    assert first.evidence[0].breakdown[0].rule is ArpScoreRule.IDENTITY_CONFLICT
    assert alerts.record(assessment()) == (first, False)
    assert alerts.acknowledge(first.id).status is AlertStatus.ACKNOWLEDGED

    now[0] += timedelta(seconds=2)
    restarted = service(path, now)
    stronger, notify = restarted.record(assessment(at=T0 + timedelta(seconds=2), confidence="moderate"))
    assert notify
    assert stronger.id == first.id
    assert stronger.status is AlertStatus.ACKNOWLEDGED
    assert stronger.first_seen == T0
    assert stronger.last_seen == T0 + timedelta(seconds=2)
    assert stronger.occurrence_count == 2
    assert stronger.confidence == "moderate" and stronger.severity == "low"
    assert stronger.evidence[-1].breakdown[-1].rule is ArpScoreRule.REPEATED_OBSERVATION
    assert restarted.record(assessment(at=T0 + timedelta(seconds=1))) == (stronger, False)
    assert restarted.get(first.id) == stronger

    now[0] += timedelta(seconds=3)
    later, notify = restarted.record(assessment(at=T0 + timedelta(seconds=4), confidence="moderate"))
    assert not notify and later.occurrence_count == 3
    assert len(restarted.query(AlertQuery(limit=10))) == 1
    assert restarted.resolve(first.id).status is AlertStatus.RESOLVED
    reopened, notify = restarted.record(assessment(at=T0 + timedelta(seconds=5)))
    assert notify and reopened.status is AlertStatus.OPEN and reopened.id == first.id
    assert reopened.first_seen == T0


def test_scope_rules_bounded_evidence_queries_and_corruption(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    now = [T0 + timedelta(minutes=1)]
    alerts = service(path, now)
    variants = (
        assessment(), assessment(observed=C), assessment(rule=ArpIdentityRule.GATEWAY_MAC_CHANGE),
        assessment(network=OTHER_NETWORK), assessment(ip="192.168.1.21"),
    )
    ids = {alerts.record(item)[0].id for item in variants}
    assert len(ids) == len(variants)
    assert len(alerts.query(AlertQuery(limit=2))) == 2
    assert len(alerts.query(AlertQuery(limit=10, network_fingerprint=OTHER_NETWORK))) == 1
    with pytest.raises(ValueError):
        AlertQuery(limit=101)
    for i in range(1, 16):
        alerts.record(assessment(at=T0 + timedelta(seconds=i)))
    item = alerts.get(next(iter(ids)))
    assert all(len(alert.evidence) <= 8 for alert in alerts.query(AlertQuery(limit=10)))
    with SQLiteDatabase(path).connection() as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")}
        assert not columns.intersection({"raw_packet", "payload", "frame_bytes"})
        connection.execute("UPDATE alerts SET evidence_json = ? WHERE id = ?", ('{"payload":"secret"}', str(item.id)))
    with pytest.raises(AlertDataCorrupt):
        alerts.get(item.id)


def test_utc_validation_and_parameterized_query(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    now = [T0]
    alerts = service(path, now)
    with pytest.raises(ValueError):
        assessment(at=T0.replace(tzinfo=None))
    with pytest.raises(ValueError):
        service(path, [T0.replace(tzinfo=None)]).record(assessment())
    alerts.record(assessment())
    assert alerts.query(AlertQuery(limit=10, rule_id="x' OR 1=1 --")) == ()
    assert len(alerts.query(AlertQuery(limit=10))) == 1


def test_verified_gateway_severity_is_not_changed_by_persistence(tmp_path):
    alerts = service(tmp_path / "gateway.sqlite3", [T0])
    event = assessment(rule=ArpIdentityRule.GATEWAY_MAC_CHANGE, ip="192.168.1.1", severity="medium")
    saved, _ = alerts.record(event)
    assert saved.severity == "medium"
    assert saved.confidence == "low"
    assert saved.evidence[0].baseline_status is GatewayBaselineStatus.VERIFIED


def test_existing_version_four_database_upgrades_to_alert_schema(tmp_path):
    path = tmp_path / "old.sqlite3"
    connection = SQLiteConnectionFactory(path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:4]).migrate(connection) == 4
    finally:
        connection.close()
    alerts = service(path, [T0])
    assert alerts.query(AlertQuery(limit=10)) == ()
    with SQLiteDatabase(path).connection() as upgraded:
        assert upgraded.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 7
        assert upgraded.execute("SELECT 1 FROM sqlite_master WHERE name = 'alerts'").fetchone() is not None


def test_common_candidate_supports_bounded_non_arp_evidence(tmp_path):
    alerts = service(tmp_path / "generic.sqlite3", [T0])
    candidate = AlertCandidate("c" * 64, "config_change", NETWORK, "dns_config",
                               "low", "low", AlertEvidence(T0, details=(("server", "192.0.2.53"),)))
    saved, _ = alerts.record(candidate)
    assert saved.evidence[0].ip_address is None and saved.evidence[0].observed_mac is None
    assert alerts.get(saved.id).evidence[0].details == (("server", "192.0.2.53"),)
    with pytest.raises(ValueError):
        AlertEvidence(T0, details=(("raw_payload", "private"),))


def test_concurrent_duplicate_and_failed_write_rolls_back(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    now = [T0 + timedelta(minutes=1)]
    alerts = service(path, now)
    with SQLiteDatabase(path).connection():
        pass
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: alerts.record(assessment())[0], range(12)))
    assert len({item.id for item in results}) == 1
    before = alerts.get(results[0].id)
    assert before.occurrence_count == 1
    with SQLiteDatabase(path).connection() as connection:
        connection.execute("""CREATE TRIGGER block_alert_update BEFORE UPDATE ON alerts
            BEGIN SELECT RAISE(ABORT, 'test failure'); END""")
    with pytest.raises(AlertRepositoryError) as error:
        alerts.record(assessment(at=T0 + timedelta(seconds=2)))
    assert "test failure" not in str(error.value)
    assert alerts.get(before.id) == before
