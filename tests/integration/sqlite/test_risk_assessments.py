"""NS-078 real SQLite concurrency, retention, corruption and compatibility."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import json
import sqlite3
from threading import Barrier
from uuid import UUID

import pytest

from netsentinel.application.services.risk_assessments import RiskAssessmentService
from netsentinel.domain.risk_assessment import (
    AssessmentPersistenceError, AssessmentReadStatus as ReadStatus, AssessmentSourceStatus as SourceStatus,
    AssessmentStoragePolicy, canonical_json,
)
from netsentinel.domain.risk_evidence import (
    EvidenceReference, EvidenceReferenceKind, EvidenceScope, EvidenceScopeKind,
    EvidenceSubject, EvidenceSubjectKind,
)
from netsentinel.domain.connections import NetworkScopeStatus, ProcessIdentity
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.risk_scoring import Freshness
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
from tests.fixtures.risk_assessments import NOW, evidence, key, scoring, snapshot


@pytest.fixture
def database(tmp_path):
    return SQLiteDatabase(tmp_path / "assessment.db")


@pytest.fixture
def repository(database):
    return SQLiteAssessmentRepository(database)


def test_new_latest_history_restart_and_duplicate_times(database, repository):
    k, s = key(), snapshot()
    assert repository.latest(k.assessment_id).status is ReadStatus.NOT_FOUND
    assert repository.history(k.assessment_id).status is ReadStatus.NOT_FOUND
    first = repository.save(k, s, NOW)
    assert first.created and first.revision.revision == 1
    assert repository.latest(k.assessment_id).revision == first.revision
    assert repository.save(k, s, NOW + timedelta(hours=1)) == replace(first, created=False)
    changed = snapshot(evidence(reason_code="new_reason"))
    second = repository.save(k, changed, NOW + timedelta(hours=2))
    assert second.revision.revision == 2
    assert second.revision.key.original_observed_at == NOW
    assert second.revision.assessed_at == NOW + timedelta(hours=2)
    restarted = SQLiteAssessmentRepository(SQLiteDatabase(database.path))
    assert restarted.latest(k.assessment_id).revision == second.revision
    assert [r.revision for r in restarted.history(k.assessment_id).entries] == [second.revision, first.revision]
    # Replaying a retained old request returns its historical revision; does not
    # make it latest, overwrite history, or allocate another number.
    assert restarted.save(k, s, NOW + timedelta(hours=3)).revision == first.revision
    assert restarted.latest(k.assessment_id).revision == second.revision


def test_service_explicit_operations(repository):
    service = RiskAssessmentService(repository)
    value, result = scoring()
    saved = service.persist(key(), value, result, assessed_at=NOW)
    assert service.latest(key().assessment_id).revision == saved.revision
    assert service.history(key().assessment_id).entries[0].revision == saved.revision
    assert service.cleanup(NOW) == 0


@pytest.mark.parametrize("change", ["added", "removed", "reason", "contributor", "freshness", "policy", "score", "severity", "confidence", "quality", "availability", "contract"])
def test_meaningful_changes_create_revision_even_if_score_unchanged(repository, change):
    from netsentinel.domain.risk_scoring import RiskSeverity, AssessmentAvailability
    from netsentinel.domain.risk_evidence import EvidenceConfidence
    from netsentinel.domain.connections import ObservationQuality
    old = snapshot(evidence(), evidence(2)) if change == "removed" else snapshot()
    variants = {
        "added": lambda: snapshot(evidence(), evidence(2)),
        "removed": snapshot,
        "reason": lambda: snapshot(evidence(reason_code="another_reason")),
        "contributor": lambda: replace(old, contributors=(replace(old.contributors[0], raw_points=21),)),
        "freshness": lambda: replace(old, evidence=(replace(old.evidence[0], freshness=Freshness.UNKNOWN),)),
        "policy": lambda: replace(old, policy_version=2, contributors=tuple(replace(c, policy_version=2) for c in old.contributors)),
        "score": lambda: snapshot(evidence(result_code="rare")),
        "severity": lambda: replace(old, severity=RiskSeverity.INFO),
        "confidence": lambda: replace(old, confidence=EvidenceConfidence.LOW),
        "quality": lambda: replace(old, measurement_quality=ObservationQuality.REDUCED),
        "availability": lambda: replace(old, availability=AssessmentAvailability.PARTIAL),
        "contract": lambda: replace(old, evidence=(replace(old.evidence[0], contract_version=2),)),
    }
    repository.save(key(), old, NOW)
    newer = variants[change]()
    saved = repository.save(key(), newer, NOW + timedelta(seconds=1))
    assert saved.created and saved.revision.revision == 2
    assert repository.latest(key().assessment_id).revision.snapshot == newer
    assert repository.history(key().assessment_id).entries[1].revision.snapshot == old


@pytest.mark.parametrize("different", [False, True])
def test_concurrent_save_serializes_revision_allocation(repository, different):
    barrier = Barrier(8)
    def save(i):
        s = snapshot(evidence(reason_code=f"reason_{i}")) if different else snapshot()
        barrier.wait()
        return repository.save(key(), s, NOW)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(save, range(8)))
    assert sum(r.created for r in results) == (8 if different else 1)
    assert {r.revision.revision for r in results} == (set(range(1, 9)) if different else {1})


def test_revision_numbers_are_assessment_local(repository):
    assert repository.save(key(), snapshot(), NOW).revision.revision == 1
    assert repository.save(key(), snapshot(evidence(2)), NOW).revision.revision == 2
    assert repository.save(key(2), snapshot(), NOW).revision.revision == 1


def test_transaction_failure_rolls_back_parent_counter_and_retention(database, repository):
    repository.save(key(), snapshot(), NOW)
    with database.connection() as c:
        c.execute("CREATE TRIGGER fail_assessment BEFORE INSERT ON risk_assessment_revisions BEGIN SELECT RAISE(ABORT, 'sensitive payload'); END")
    for k in (key(), key(2)):
        with pytest.raises(AssessmentPersistenceError) as error:
            repository.save(k, snapshot(evidence(2)), NOW)
        assert "sensitive" not in str(error.value)
    assert repository.latest(key().assessment_id).revision.revision == 1
    assert repository.latest(key(2).assessment_id).status is ReadStatus.NOT_FOUND
    with database.connection() as c:
        assert c.execute("SELECT last_revision FROM risk_assessments").fetchone()[0] == 1
        c.execute("DROP TRIGGER fail_assessment")
    retry = repository.save(key(), snapshot(evidence(2)), NOW)
    assert retry.revision.revision == 2 and retry.created
    assert not repository.save(key(), snapshot(evidence(2)), NOW).created


def test_supported_sources_expire_without_cascading_or_rescoring(database, repository):
    lifecycle = EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=1))
    dns = EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=2))
    with database.connection() as c:
        c.execute("INSERT INTO connection_history (id, protocol, local_address, local_port, process_status, connection_state, first_seen_utc_us, last_seen_utc_us, lifecycle_id) VALUES (?, 'tcp', '127.0.0.1', 5000, 'unavailable', 'listen', 100, 100, ?)", (str(UUID(int=3)), str(lifecycle.value)))
        c.execute("INSERT INTO dns_history (id,status,network_fingerprint,transport,client_ip,client_port,server_ip,server_port,transaction_id,questions_json,query_at_utc_us,event_at_utc_us,truncated,answers_json,retry_count,evidence_id) VALUES (?, 'timed_out', ?, 'udp','127.0.0.1',5000,'192.0.2.1',53,1,'[]',100,100,0,'[]',0,?)", (str(UUID(int=4)), "a" * 64, str(dns.value)))
    saved = repository.save(key(), snapshot(evidence(references=(lifecycle, dns))), NOW)
    assert all(r.status is SourceStatus.AVAILABLE for r in repository.latest(key().assessment_id).references)
    with database.connection() as c:
        c.execute("DELETE FROM connection_history")
        c.execute("DELETE FROM dns_history")
        assert c.execute("SELECT COUNT(*) FROM risk_assessment_revisions").fetchone()[0] == 1
    expired = repository.latest(key().assessment_id)
    assert expired.status is ReadStatus.FOUND and expired.revision == saved.revision
    assert all(r.status is SourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE for r in expired.references)
    assert expired.revision.snapshot.evidence[0].reason_code == "test_observation"
    assert not repository.save(key(), saved.revision.snapshot, NOW).created


def test_unowned_sources_remain_explicitly_unresolved(repository):
    ref = EvidenceReference(EvidenceReferenceKind.EVIDENCE, "a" * 64)
    repository.save(key(observation_reference=ref), snapshot(evidence(references=(ref,))), NOW)
    read = repository.latest(key(observation_reference=ref).assessment_id)
    assert read.references[0].status is SourceStatus.UNRESOLVED


@pytest.mark.parametrize("scope", [EvidenceScope(EvidenceScopeKind.UNKNOWN, NetworkScopeStatus.UNKNOWN),
                                  EvidenceScope(EvidenceScopeKind.UNKNOWN, NetworkScopeStatus.AMBIGUOUS),
                                  EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64)])
@pytest.mark.parametrize("ip", ["192.0.2.2", "2001:db8::1"])
def test_scope_subject_round_trip(repository, scope, ip):
    subject = EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=ip)
    k = key(scope=scope, subject=subject)
    s = snapshot(evidence(scope=scope, subject=subject))
    saved = repository.save(k, s, NOW)
    assert repository.latest(k.assessment_id).revision == saved.revision


def test_process_application_revision_round_trip(repository):
    from tests.fixtures.risk_assessments import APP
    subject = EvidenceSubject(EvidenceSubjectKind.PROCESS, application=APP,
                              revision=ApplicationRevision("a" * 64, ExecutableHashStatus.AVAILABLE),
                              process=ProcessIdentity(42, NOW), session_id=UUID(int=42))
    k = key(subject=subject)
    saved = repository.save(k, snapshot(evidence(subject=subject)), NOW)
    assert repository.latest(k.assessment_id).revision == saved.revision


def test_maximum_64_contributors_adjustments_and_exclusions_round_trip(repository):
    from netsentinel.domain.risk_evidence import EvidenceLimitation, EvidenceQuality, EvidenceSource
    from netsentinel.domain.connections import ObservationQuality
    items = tuple(evidence(i + 1, source=EvidenceSource.PERIODICITY,
        rule_id="observed_appearance_periodicity", result_code="periodic_candidate",
        subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=f"192.0.2.{i+1}"),
        quality=EvidenceQuality(ObservationQuality.COMPLETE, (EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE,)))
        for i in range(32))
    s = snapshot(*items)
    assert len(s.contributors) == 64
    assert any(c.adjustments for c in s.contributors)
    saved = repository.save(key(), s, NOW)
    assert repository.latest(key().assessment_id).revision == saved.revision
    excluded = snapshot(evidence(), evidence(2, policy_version=99))
    assert any(not c.eligible for c in excluded.contributors)
    repository.save(key(), excluded, NOW)
    assert repository.latest(key().assessment_id).revision.snapshot == excluded


@pytest.mark.parametrize("gateway,corroborated", [(False, False), (False, True), (True, True)])
def test_legacy_arp_minimum_explanation_does_not_copy_source_graph(repository, gateway, corroborated):
    from tests.unit.domain.test_risk_scoring import legacy
    e = legacy(gateway=gateway, corroborated=corroborated)
    s = snapshot(e)
    saved = repository.save(key(subject=e.subject, scope=e.scope), s, NOW)
    assert repository.latest(saved.revision.key.assessment_id).revision == saved.revision
    assert s.evidence[0].expected_mac == e.legacy_arp.source.evidence.expected_mac
    payload = canonical_json(s)
    assert '"legacy_arp":' not in payload and "observation_count" not in payload


def test_monitoring_session_reference_round_trip_and_expiry(database, repository):
    session = EvidenceReference(EvidenceReferenceKind.MONITORING_SESSION, UUID(int=99))
    with database.connection() as c:
        c.execute("INSERT INTO connection_history (id, protocol, local_address, local_port, process_status, connection_state, first_seen_utc_us, last_seen_utc_us, monitoring_session_id) VALUES (?, 'tcp', '127.0.0.1', 5000, 'unavailable', 'listen', 100, 100, ?)", (str(UUID(int=3)), str(session.value)))
    k = key(observation_reference=session)
    saved = repository.save(k, snapshot(), NOW)
    assert repository.latest(k.assessment_id).references[0].status is SourceStatus.AVAILABLE
    with database.connection() as c:
        c.execute("DELETE FROM connection_history")
    assert repository.latest(k.assessment_id).references[0].status is SourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE
    assert repository.latest(k.assessment_id).revision == saved.revision


def test_corrupt_latest_number_not_silently_replaced_by_prior_revision(database, repository):
    repository.save(key(), snapshot(), NOW)
    repository.save(key(), snapshot(evidence(2)), NOW)
    with database.connection() as c:
        c.execute("DELETE FROM risk_assessment_revisions WHERE revision = 2")
    assert repository.latest(key().assessment_id).status is ReadStatus.CORRUPT
    assert repository.history(key().assessment_id).entries[0].status is ReadStatus.CORRUPT


def test_persisted_snapshots_never_invoke_current_scorer(repository, monkeypatch):
    s = snapshot()
    repository.save(key(), s, NOW)
    def forbidden(*args):
        raise AssertionError("historical read invoked scorer")
    monkeypatch.setattr("netsentinel.domain.risk_scoring.score_risk", forbidden)
    assert repository.latest(key().assessment_id).revision.snapshot == s
    assert repository.history(key().assessment_id).entries[0].revision.snapshot == s


def test_snapshot_schema_limits_payload_and_query_budgets(database, repository):
    repository.save(key(), snapshot(), NOW)
    with database.connection() as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("UPDATE risk_assessment_revisions SET snapshot = ?", ("a" * 65537,))
        # Known source lookup uses an index, rather than scanning history.
        plan = c.execute("EXPLAIN QUERY PLAN SELECT 1 FROM connection_history WHERE monitoring_session_id = ? LIMIT 1", (str(UUID(int=1)),)).fetchall()
        assert any("idx_connection_history_monitoring_session" in row[3] for row in plan)
    for limit in (0, -1, 9, True, 1.5):
        with pytest.raises(ValueError):
            repository.history(key().assessment_id, limit=limit)
    for bad in ("bad", "x" * 64, "a" * 63, "a" * 65):
        with pytest.raises(ValueError):
            repository.latest(bad)


def test_failed_new_assessment_rolls_back_capacity_eviction(database):
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_assessments=1))
    first = repo.save(key(), snapshot(), NOW)
    with database.connection() as c:
        c.execute("CREATE TRIGGER fail_assessment BEFORE INSERT ON risk_assessment_revisions BEGIN SELECT RAISE(ABORT, 'fail'); END")
    with pytest.raises(AssessmentPersistenceError):
        repo.save(key(2), snapshot(), NOW)
    assert repo.latest(key().assessment_id).revision == first.revision


def test_identity_and_duplicate_corruption_fail_closed(database, repository):
    repository.save(key(), snapshot(), NOW)
    with database.connection() as c:
        c.execute("UPDATE risk_assessment_revisions SET snapshot = '{}' ")
    with pytest.raises(AssessmentPersistenceError, match="duplicate"):
        repository.save(key(), snapshot(), NOW)
    with database.connection() as c:
        c.execute("UPDATE risk_assessments SET identity_payload = '{}' ")
    assert repository.latest(key().assessment_id).status is ReadStatus.CORRUPT
    with pytest.raises(AssessmentPersistenceError, match="identity"):
        repository.save(key(), snapshot(), NOW)


def test_old_migrations_001_to_014_are_unchanged():
    from hashlib import sha256
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    # Frozen from 95badf2, LF-normalized for Windows and shallow CI checkouts.
    hashes = (
        "8a36cda5baf00b7bbb60251eb274f19673c8545d73449e69c060fb322292b0bc",
        "12828999a74be19d4a03fe2461e1355fde8bcba177de924d584db13914163c44",
        "8fd10cd4e34a9265be7ff19058f8c205e6007a9cbbc051b5740f6e79dba5a178",
        "76ca23d0d9fde2e137b2515432c1ce5397cc1633316f50b6d1e244c482f4750c",
        "eb15ba956b1ebff1277377550d9ec3b9782c6c6ddf0fbc2ea80fc7f51a385ea8",
        "43adeed083488a1c3313931d53da818b8f02acd62bd204424b36e99e60f72b85",
        "1818720330d7454f41656c3e7018b44beb53f5885eb53172229b1358d3286f19",
        "02d7c2a8a07d758e2d0a528d2450bb311eadef4c01681b3ced1aeb3043226b26",
        "70f37de7f8c8920878b6dc5a7a1f1540d17b7d45ea6d1672f5b6a8f87ece3764",
        "87dfd0a282ea427f46830f3ec353a0b63756bd1ce934b9fad33a2a9e1c93a26d",
        "0bc6895ed29c26ae3128e624bcb17f8d1d3a09c0a7322930ae3705f8217ce107",
        "0fd3ba15230f794eea8b6ddefa03df73a392c8efeb5ed29922687caf2a708926",
        "7d34dd3d71a25f0dffada72185a62926786790e884248d62bec31de067c2bb9a",
        "36109f45a87ecd28d68366d74c2dfef665528ed46fd1855d5e0cb21b9a0b498b",
    )
    for migration, expected in zip(builtin_migrations()[:14], hashes, strict=True):
        path = next((root / "src/netsentinel/infrastructure/sqlite/schema").glob(f"{migration.version:03}_*.sql"))
        assert sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() == expected


def test_retention_keeps_latest_bounded_history_and_counter(database):
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_revisions=3))
    for i in range(12):
        repo.save(key(), snapshot(evidence(reason_code=f"reason_{i}")), NOW + timedelta(seconds=i))
    history = repo.history(key().assessment_id, limit=3)
    assert [r.revision.revision for r in history.entries] == [12, 11, 10]
    assert history.truncated
    assert len(repo.history(key().assessment_id, limit=1).entries) == 1
    with pytest.raises(ValueError):
        repo.history(key().assessment_id, limit=4)
    with database.connection() as c:
        assert c.execute("SELECT COUNT(*) FROM risk_assessment_revisions").fetchone()[0] == 3
        assert c.execute("SELECT last_revision FROM risk_assessments").fetchone()[0] == 12


def test_global_bound_and_deterministic_eviction(database):
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_assessments=2))
    for i in range(1, 8):
        repo.save(key(i, original_observed_at=NOW + timedelta(seconds=i)), snapshot(), NOW)
    with database.connection() as c:
        assert c.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0] == 2
        assert c.execute("SELECT COUNT(*) FROM risk_assessment_revisions").fetchone()[0] == 2
    assert repo.latest(key(1, original_observed_at=NOW + timedelta(seconds=1)).assessment_id).status is ReadStatus.NOT_FOUND
    assert repo.latest(key(7, original_observed_at=NOW + timedelta(seconds=7)).assessment_id).status is ReadStatus.FOUND


def test_age_cleanup_is_chunked_clock_jump_safe_and_restart_safe(database):
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_revisions=2, cleanup_chunk_size=4))
    for i in range(1, 7):
        repo.save(key(i), snapshot(), NOW)
        repo.save(key(i), snapshot(evidence(reason_code="changed")), NOW)
    assert repo.cleanup(NOW - timedelta(days=100)) == 0
    assert repo.cleanup(NOW + timedelta(days=100)) == 4
    assert repo.cleanup(NOW + timedelta(days=100)) == 4
    assert repo.cleanup(NOW + timedelta(days=100)) == 4
    assert repo.cleanup(NOW + timedelta(days=100)) == 0


@pytest.mark.parametrize("bad", ["{", "[]", '{"score":1,"score":2}', "null", "NaN"])
def test_corrupt_json_does_not_hide_latest_or_break_other_assessments(database, repository, bad):
    repository.save(key(), snapshot(), NOW)
    repository.save(key(), snapshot(evidence(2)), NOW)
    valid = repository.save(key(2), snapshot(), NOW)
    with database.connection() as c:
        c.execute("UPDATE risk_assessment_revisions SET snapshot = ? WHERE assessment_id = ? AND revision = 2", (bad, key().assessment_id))
    assert repository.latest(key().assessment_id).status is ReadStatus.CORRUPT
    entries = repository.history(key().assessment_id).entries
    assert [r.status for r in entries] == [ReadStatus.CORRUPT, ReadStatus.FOUND]
    assert repository.latest(key(2).assessment_id).revision == valid.revision


@pytest.mark.parametrize("field,value", [("score", 101), ("severity", "critical"), ("policy_version", None),
    ("extra", "payload"), ("confidence", 1), ("evidence", [{}]), ("contributors", [{}])])
def test_strict_snapshot_corruption(database, repository, field, value):
    repository.save(key(), snapshot(), NOW)
    data = json.loads(canonical_json(snapshot()))
    data[field] = value
    with database.connection() as c:
        c.execute("UPDATE risk_assessment_revisions SET snapshot = ?", (json.dumps(data),))
    assert repository.latest(key().assessment_id).status is ReadStatus.CORRUPT


@pytest.mark.parametrize("column,value,status", [("format_version", 3, ReadStatus.UNSUPPORTED_VERSION),
    ("assessed_at", "2026-10-03T00:00:00", ReadStatus.CORRUPT),
    ("assessed_at", "2026-10-03T00:00:00+03:00", ReadStatus.CORRUPT),
    ("content_fingerprint", "x" * 64, ReadStatus.CORRUPT), ("revision", 0, ReadStatus.CORRUPT),
    ("format_version", 0, ReadStatus.CORRUPT), ("snapshot", "a" * 65537, ReadStatus.CORRUPT)], ids=lambda v: str(v)[:25])
def test_row_corruption_and_future_format(database, repository, column, value, status):
    repository.save(key(), snapshot(), NOW)
    queries = {c: f"UPDATE risk_assessment_revisions SET {c} = ?" for c in ("format_version", "assessed_at", "content_fingerprint", "revision", "snapshot")}
    with database.connection() as c:
        c.execute("PRAGMA ignore_check_constraints = ON")
        c.execute(queries[column], (value,))
    assert repository.latest(key().assessment_id).status is status


def test_unique_constraints_prevent_duplicate_revision_and_content(database, repository):
    repository.save(key(), snapshot(), NOW)
    with database.connection() as c:
        for query in (
            "INSERT INTO risk_assessment_revisions SELECT assessment_id, revision, format_version, assessed_at, content_fingerprint, snapshot FROM risk_assessment_revisions",
            "INSERT INTO risk_assessment_revisions SELECT assessment_id, revision+1, format_version, assessed_at, content_fingerprint, snapshot FROM risk_assessment_revisions",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                c.execute(query)


def test_unavailable_database_is_typed_and_sanitized(tmp_path):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"not SQLite")
    repo = SQLiteAssessmentRepository(SQLiteDatabase(path))
    assert repo.latest(key().assessment_id).status is ReadStatus.UNAVAILABLE
    assert repo.history(key().assessment_id).status is ReadStatus.UNAVAILABLE
    with pytest.raises(AssessmentPersistenceError, match="could not be persisted"):
        repo.save(key(), snapshot(), NOW)
    with pytest.raises(AssessmentPersistenceError, match="cleanup"):
        repo.cleanup(NOW)


def test_migration_014_preserves_legacy_alerts_no_fabrication_or_lifecycle_change(tmp_path):
    from tests.integration.sqlite.test_alert_repository import assessment
    from netsentinel.application.services.alerts import AlertService
    from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
    path = tmp_path / "legacy.db"
    old = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:14]))
    alerts = AlertService(SQLiteAlertRepository(old), clock=lambda: NOW)
    alert, _ = alerts.record(assessment())
    alerts.acknowledge(alert.id)
    alerts.resolve(alert.id)
    before = alerts.get(alert.id)
    database = SQLiteDatabase(path)
    repo = SQLiteAssessmentRepository(database)
    assert repo.latest(key().assessment_id).status is ReadStatus.NOT_FOUND
    with database.connection() as c:
        assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 18
        assert c.execute("SELECT COUNT(*) FROM risk_assessment_revisions").fetchone()[0] == 0
    for i in range(3):
        repo.save(key(), snapshot(evidence(reason_code=f"reason_{i}")), NOW + timedelta(seconds=i))
    upgraded_alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: NOW)
    assert upgraded_alerts.get(alert.id) == before
    assert upgraded_alerts.record(assessment()) == (before, False)
