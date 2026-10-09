"""NS-095 real SQLite maintenance, source expiry, physical bounds and redaction."""

from dataclasses import replace
from datetime import timedelta
import json
from time import monotonic
from uuid import UUID

import pytest

from netsentinel.application.services.storage_privacy import StoragePrivacyService, PrivacyOperationError
from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incident_persistence import IncidentSourceStatus
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.risk_assessment import AssessmentStoragePolicy, AssessmentReadStatus, AssessmentPersistenceError
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from netsentinel.domain.storage_privacy import MaintenanceStatus, StorageScope, Store, StorageRetentionPolicy
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.shared.config import StorageMaintenanceConfig
from tests.fixtures.storage_privacy import NOW, connection, dns, alert, count
from tests.fixtures.incidents import item
from tests.fixtures.risk_assessments import key, snapshot, evidence


@pytest.fixture
def database(tmp_path):
    return SQLiteDatabase(tmp_path / "storage.sqlite3", busy_timeout_ms=100)


@pytest.fixture
def service(database):
    return StoragePrivacyService(SQLiteStorageMaintenanceRepository(database), clock=lambda: NOW)


def rule(store, *, quota=None):
    value = next(r for r in StorageRetentionPolicy().rules if r.store is store)
    return value if quota is None else replace(value, max_rows=quota)


@pytest.mark.parametrize("delta,deleted", [(-1, 1), (0, 0), (1, 0)])
@pytest.mark.parametrize("store", [Store.CONNECTIONS, Store.DNS])
def test_strict_utc_cutoff_and_microseconds(database, service, delta, deleted, store):
    at = NOW - timedelta(days=30) + timedelta(microseconds=delta)
    (connection if store is Store.CONNECTIONS else dns)(database, 1, at)
    result = service.run_retention()
    assert result.deleted_rows == deleted
    assert count(database, store.value) == 1 - deleted


def test_connection_active_and_gap_semantics(database, service):
    old = NOW - timedelta(days=100)
    connection(database, 1, old, active=True)
    connection(database, 2, old, active=True, gap=True)
    connection(database, 3, NOW)
    result = service.run_retention()
    assert result.deleted_rows == 1
    assert count(database, 'connection_history') == 2


@pytest.mark.parametrize("rows,expected", [(2, 0), (3, 1), (8, 2)])
def test_quota_at_and_above_boundary_oldest_first(database, rows, expected):
    repo = SQLiteStorageMaintenanceRepository(database)
    for number in range(1, rows + 1):
        connection(database, number, NOW - timedelta(seconds=number))
    selected = rule(Store.CONNECTIONS, quota=2)
    assert repo.cleanup_chunk(selected, NOW, 2, False, lambda: False) == expected
    with database.connection() as c:
        ids = {r[0] for r in c.execute('SELECT id FROM connection_history')}
    assert str(UUID(int=rows)) not in ids if expected else str(UUID(int=rows)) in ids


def test_protected_only_pressure_never_deletes(database):
    for i in range(1, 5):
        connection(database, i, NOW - timedelta(days=100), active=True)
    repo = SQLiteStorageMaintenanceRepository(database)
    selected = rule(Store.CONNECTIONS, quota=2)
    assert repo.cleanup_chunk(selected, NOW, 128, False, lambda: False) == 0
    summary = repo.summary((selected,), NOW, lambda: False).stores[0]
    assert summary.pressure and summary.protected == 4 and summary.eligible == 0


def test_lifecycle_aware_alert_purge_protects_reopen_and_active(database, service):
    old = NOW - timedelta(days=100)
    for i, state in enumerate(('open', 'acknowledged', 'resolved'), 1):
        alert(database, i, old, state=state)
    alert(database, 4, NOW - timedelta(minutes=5), state='resolved')
    preview = service.preview_purge(StorageScope.ALERTS)
    assert preview.eligible == 1
    result = service.purge(preview)
    assert result.deleted_rows == 1 and count(database, 'alerts') == 3


def test_confirmation_cancel_zero_write_and_token_scope_binding(database, service):
    connection(database, 1, NOW - timedelta(days=100))
    preview = service.preview_purge(StorageScope.CONNECTIONS)
    assert count(database, 'connection_history') == 1
    with pytest.raises(PrivacyOperationError):
        service.purge(replace(preview, scope=StorageScope.ALL))
    service.purge(preview)
    with pytest.raises(PrivacyOperationError):
        service.purge(preview)


def test_purge_execution_rechecks_new_protected_state(database, service):
    record = alert(database, 1, NOW - timedelta(days=100), state='resolved')
    preview = service.preview_purge(StorageScope.ALERTS)
    with database.connection() as c:
        c.execute("UPDATE alerts SET status='open' WHERE id=?", (str(record.id),))
    assert service.purge(preview).deleted_rows == 0


def test_time_delete_and_chunk_budget_partial_truth(database):
    for i in range(1, 10):
        connection(database, i, NOW - timedelta(days=100))
    budgets = StorageMaintenanceConfig(max_chunks=2, max_deletes=3)
    service = StoragePrivacyService(SQLiteStorageMaintenanceRepository(database), clock=lambda: NOW, budgets=budgets)
    result = service.purge(service.preview_purge(StorageScope.CONNECTIONS))
    assert result.status is MaintenanceStatus.LIMITED
    assert result.deleted_rows == 3 and count(database, 'connection_history') == 6


def test_cancel_between_chunks_reports_commits(database, service):
    for i in range(1, 131):
        connection(database, i, NOW - timedelta(days=100))
    preview = service.preview_purge(StorageScope.CONNECTIONS)
    def stop():
        return count(database, 'connection_history') < 130
    result = service.purge(preview, stop)
    assert result.status is MaintenanceStatus.CANCELLED
    assert result.deleted_rows == 128 and count(database, 'connection_history') == 2


def test_busy_db_short_defer_and_retry_after_restart(database, service):
    connection(database, 1, NOW - timedelta(days=100))
    preview = service.preview_purge(StorageScope.CONNECTIONS)
    with database.connection() as blocker:
        blocker.execute('BEGIN IMMEDIATE')
        started = monotonic()
        result = service.purge(preview)
        assert monotonic() - started < 1.5
        assert result.status is MaintenanceStatus.PARTIAL and result.deleted_rows == 0
        blocker.execute('ROLLBACK')
    restarted = StoragePrivacyService(SQLiteStorageMaintenanceRepository(database), clock=lambda: NOW)
    assert restarted.run_retention().deleted_rows == 1


def test_one_store_failure_isolated_and_error_sanitized(database, service):
    connection(database, 1, NOW - timedelta(days=100))
    dns(database, 2, NOW - timedelta(days=100))
    with database.connection() as c:
        c.execute("CREATE TRIGGER no_connection_delete BEFORE DELETE ON connection_history BEGIN SELECT RAISE(ABORT,'secret.example 192.0.2.123'); END")
    result = service.run_retention()
    assert result.status is MaintenanceStatus.PARTIAL
    assert count(database, 'connection_history') == 1 and count(database, 'dns_history') == 0
    assert 'secret.example' not in repr(result)


def test_current_baseline_and_expired_baseline_and_user_state(database, service):
    from netsentinel.infrastructure.sqlite.behavior_baselines import SQLiteBaselineRepository
    from netsentinel.domain.behavior_baseline import BaselineSummary
    from tests.integration.sqlite.test_behavior_baselines import features, key as baseline_key

    with database.connection() as c:
        repo = SQLiteBaselineRepository(c)
        for index, age in enumerate((0, 90, 91)):
            stamp = NOW - timedelta(days=age)
            scope = baseline_key(str(index))
            repo.write(BaselineSummary(features(scope), stamp, stamp, 'policy'), scope)
    result = service.purge(service.preview_purge(StorageScope.BASELINES))
    assert result.deleted_rows == 1 and count(database, 'behavior_baselines') == 2


def test_incident_source_expiry_snapshot_and_restart(database, service):
    reference = EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=888))
    dns(database, 888, NOW - timedelta(days=100))
    connection(database, 1, NOW - timedelta(days=100))
    value = item(evidence=(reference,))
    persistence = IncidentPersistenceService(SQLiteIncidentRepository(database))
    snapshot_value = IncidentCorrelator().correlate(value).incident
    record = persistence.create_or_get(snapshot_value, now=NOW).record
    before = persistence.get(record.incident_id)
    assert any(r.status is IncidentSourceStatus.AVAILABLE for r in before.references)
    service.run_retention()
    after = SQLiteIncidentRepository(SQLiteDatabase(database.path)).get(record.incident_id)
    assert after.record == before.record
    assert any(r.status is IncidentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE for r in after.references)
    assert [r.link for r in before.references] == [r.link for r in after.references]
    from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
    timeline = SQLiteIncidentTimelineRepository(SQLiteDatabase(database.path)).read_snapshot(record.incident_id)
    assert timeline.incident.record == before.record
    assert any(r.status is IncidentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE for r in timeline.incident.references)


def test_incident_physical_cascade_budget_and_active_protection(database, service):
    persistence = IncidentPersistenceService(SQLiteIncidentRepository(database))
    record = persistence.create_or_get(IncidentCorrelator().correlate(item()).incident, now=NOW).record
    assert service.purge(service.preview_purge(StorageScope.INCIDENTS)).deleted_rows == 0
    persistence.resolve(record.incident_id, expected_revision=record.revision, now=NOW)
    later = NOW + timedelta(minutes=6)
    service.clock = lambda: later
    physical = sum(count(database, table) for table in ('incidents', 'incident_revisions', 'incident_references'))
    small = StoragePrivacyService(service.repository, clock=lambda: later,
                                 budgets=StorageMaintenanceConfig(max_deletes=1))
    assert small.purge(small.preview_purge(StorageScope.INCIDENTS)).deleted_rows == 0
    assert count(database, 'incidents') == 1
    assert service.purge(service.preview_purge(StorageScope.INCIDENTS)).deleted_rows == physical


def test_alert_assessment_parent_and_revision_protected_during_eviction(database, service):
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_assessments=1, max_revisions=2))
    assessment = repo.save(key(), snapshot(), NOW)
    reference = AlertAssessmentReference(key().assessment_id, 1, NetworkScopeStatus.RESOLVED)
    alert(database, 1, NOW, assessment=reference)
    service.clock = lambda: NOW + timedelta(days=100)
    service.run_retention()
    assert repo.revision(key().assessment_id, 1).status is AssessmentReadStatus.FOUND
    with pytest.raises(AssessmentPersistenceError):
        repo.save(key(2), snapshot(evidence(2)), NOW)
    repo.save(key(), snapshot(evidence(reason_code='different')), NOW)
    repo.save(key(), snapshot(evidence(reason_code='third')), NOW)
    assert repo.revision(key().assessment_id, 1).revision == assessment.revision
    assert len(repo.history(key().assessment_id, limit=2).entries) == 2


def test_assessment_source_expiry_minimum_explanation_preserved(database, service):
    from netsentinel.domain.risk_assessment import AssessmentSourceStatus
    connection(database, 1, NOW - timedelta(days=100))
    repo = SQLiteAssessmentRepository(database)
    saved = repo.save(key(), snapshot(), NOW)
    service.purge(service.preview_purge(StorageScope.CONNECTIONS))
    after = SQLiteAssessmentRepository(SQLiteDatabase(database.path)).latest(key().assessment_id)
    assert after.revision == saved.revision
    assert any(s.status is AssessmentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE for s in after.references)


def test_export_allowlist_privacy_manifest_and_exact_atomic_save(database, service, tmp_path):
    connection(database, 1, NOW)
    dns(database, 2, NOW)
    alert(database, 1, NOW)
    export = service.preview_export()
    body = json.loads(export.content)
    assert body['manifest']['format'] == 'support-export-v1'
    assert body['manifest']['schema_version'] == 20
    assert body['manifest']['redaction_policy'] == 'allowlist-v1'
    for sensitive in ('192.0.2.123', '203.0.113.123', 'private.example', 'private-user', 'C:/private', 'tool.exe', 'evidence_json'):
        assert sensitive not in export.content.decode() and sensitive not in export.sample
    target = tmp_path / 'support-ü.json'
    assert service.save_export(export, target)
    assert target.read_bytes() == export.content
    assert not list(tmp_path.glob('.netsentinel-export-*'))


def test_export_record_byte_page_and_preview_caps(database, service):
    for i in range(1, 56):
        alert(database, i, NOW)
    export = service.preview_export()
    assert export.record_count == 50 and len(export.content) <= 65536
    assert len(json.loads(export.sample)['sample_records']) == 10
    tiny = StoragePrivacyService(service.repository, clock=lambda: NOW,
                                budgets=StorageMaintenanceConfig(export_bytes=1))
    with pytest.raises(PrivacyOperationError):
        tiny.preview_export()


@pytest.mark.parametrize('phase', ['before', 'after_temp', 'write_failure'])
def test_export_cancel_or_failure_leaves_existing_target_and_no_temp(database, service, tmp_path, monkeypatch, phase):
    target = tmp_path / 'support.json'
    target.write_text('existing')
    export = service.preview_export()
    calls = 0
    def stop():
        nonlocal calls
        calls += 1
        return phase == 'before' or (phase == 'after_temp' and calls >= 2)
    if phase == 'write_failure':
        def fail(*args):
            raise OSError('private-user secret.example')
        monkeypatch.setattr('netsentinel.application.services.storage_privacy.os.replace', fail)
        with pytest.raises(PrivacyOperationError, match='No sensitive'):
            service.save_export(export, target)
    else:
        assert service.save_export(export, target, stop) is False
    assert target.read_text() == 'existing'
    assert not list(tmp_path.glob('.netsentinel-export-*'))


def test_summary_path_free_approximate_sizes_no_vacuum_or_new_migration(database, service):
    connection(database, 1, NOW)
    summary = service.summary()
    assert summary.schema_version == 20 and summary.database_bytes > 0 and summary.wal_bytes >= 0
    assert str(database.path) not in repr(summary)
    assert len(summary.stores) == len(Store)


def test_device_history_profile_trust_and_current_observations_protected(database, service):
    old = NOW - timedelta(days=100)
    from netsentinel.infrastructure.sqlite.repositories import datetime_to_epoch_microseconds as us
    with database.connection() as c:
        for i, stamp in ((1, old), (2, old), (3, NOW)):
            c.execute('INSERT INTO devices VALUES(?,?,?,?,?)', (str(UUID(int=i)), 'a' * 64, f'00:11:22:33:44:{i:02x}', us(stamp), us(stamp)))
            c.execute('INSERT INTO device_bindings VALUES(?,?,?,?,?)', (str(UUID(int=i)), str(UUID(int=i)), f'192.0.2.{i}', us(stamp), us(stamp)))
        c.execute("INSERT INTO device_profiles VALUES(?,?,'private-label','private-note','trusted',?,?,NULL,'[]','[]',NULL)", (str(UUID(int=9)), 'a' * 64, us(old), us(old)))
        c.execute('INSERT INTO device_profile_members VALUES(?,?)', (str(UUID(int=1)), str(UUID(int=9))))
    result = service.purge(service.preview_purge(StorageScope.DEVICES))
    assert result.deleted_rows == 2
    assert count(database, 'devices') == 2 and count(database, 'device_bindings') == 2
    assert count(database, 'device_profiles') == 1 and count(database, 'device_profile_members') == 1


@pytest.mark.parametrize('status', ['hit', 'no_hit'])
def test_cache_existing_ttl_and_scoped_purge_do_not_touch_preferences(database, service, status):
    from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
    from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
    from netsentinel.domain.threat_intelligence import ThreatIntelResultStatus
    from tests.fixtures.threat_intelligence import DESCRIPTORS
    from tests.integration.sqlite.test_threat_intel_cache import result
    cache = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), DESCRIPTORS)
    value = result(status=ThreatIntelResultStatus(status), at=NOW)
    cache.put(value, NOW)
    assert service.run_retention().deleted_rows == 0
    assert service.purge(service.preview_purge(StorageScope.CACHE)).deleted_rows == 1
    assert count(database, 'threat_intel_cache') == 0


def test_cache_expired_cleanup_has_original_inclusive_boundary(database, service):
    from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
    from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
    from tests.fixtures.threat_intelligence import DESCRIPTORS
    from tests.integration.sqlite.test_threat_intel_cache import result
    cache = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), DESCRIPTORS)
    cache.put(result(at=NOW - timedelta(days=2)), NOW)
    assert service.run_retention().deleted_rows == 1


@pytest.mark.parametrize('permanent', [False, True])
def test_all_history_preserves_suppression_mark_normal_and_audit(database, service, permanent):
    from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
    from tests.fixtures.preferences import definition, ORIGIN
    repo = SQLiteScopedPreferenceRepository(database)
    from tests.fixtures.preferences import NOW as preference_time
    created = repo.create(UUID(int=99), definition(permanent=permanent), now=preference_time, origin=ORIGIN)
    assert count(database, 'scoped_preferences') == 1
    with database.connection() as c:
        before = tuple(tuple(row) for row in c.execute('SELECT * FROM scoped_preference_revisions'))
    service.purge(service.preview_purge(StorageScope.ALL))
    assert count(database, 'scoped_preferences') == 1
    with database.connection() as c:
        assert tuple(tuple(row) for row in c.execute('SELECT * FROM scoped_preference_revisions')) == before
    assert created is not None


def test_corrupt_source_and_alert_explanation_do_not_break_cleanup_or_leak_export(database, service):
    saved = SQLiteAssessmentRepository(database).save(key(), snapshot(), NOW)
    record = alert(database, 1, NOW)
    with database.connection() as c:
        c.execute("UPDATE alerts SET evidence_json='invalid secret.example' WHERE id=?", (str(record.id),))
        c.execute("UPDATE risk_assessment_revisions SET snapshot='invalid private-user' WHERE assessment_id=?", (saved.revision.key.assessment_id,))
    service.clock = lambda: NOW + timedelta(days=100)
    result = service.run_retention()
    assert not any(s.failed for s in result.stores)
    assert count(database, 'risk_assessments') == 1
    export = service.preview_export()
    assert b'secret.example' not in export.content and b'private-user' not in export.content


def test_cancel_mid_sql_rolls_back_current_chunk(database):
    for i in range(1, 4):
        connection(database, i, NOW - timedelta(days=100))
    ticks = 0
    def stop():
        nonlocal ticks
        ticks += 1
        return ticks >= 3
    repo = SQLiteStorageMaintenanceRepository(database)
    with pytest.raises(Exception):
        repo.cleanup_chunk(rule(Store.CONNECTIONS), NOW, 128, True, stop)
    assert count(database, 'connection_history') == 3


def test_export_uses_four_bounded_pages_without_evidence_queries(database, service, monkeypatch):
    original = service.repository.export_page
    pages = []
    def page(category, offset, limit, stop):
        pages.append((category, offset, limit))
        return original(category, offset, limit, stop)
    monkeypatch.setattr(service.repository, 'export_page', page)
    service.preview_export()
    assert len(pages) == 4 and all(limit == 25 for _, _, limit in pages)


def test_setup_lock_timeout_defers_without_waiting_for_other_owner(database):
    from netsentinel.infrastructure.sqlite.database import _MIGRATION_LOCK, DatabaseOpenError
    bounded = SQLiteDatabase(database.path, busy_timeout_ms=100, setup_timeout_ms=100)
    with _MIGRATION_LOCK:
        started = monotonic()
        with pytest.raises(DatabaseOpenError, match='busy'):
            bounded.connect()
        assert monotonic() - started < 1
    with bounded.connection():
        pass


def test_active_connection_assessment_parent_remains_after_age_cleanup(database, service):
    connection(database, 1, NOW - timedelta(days=100), active=True)
    repo = SQLiteAssessmentRepository(database)
    saved = repo.save(key(original_observed_at=NOW - timedelta(days=100)), snapshot(), NOW)
    result = service.run_retention()
    assert result.deleted_rows == 0
    assert repo.latest(saved.revision.key.assessment_id).revision == saved.revision


def test_new_device_admission_at_capacity_preserves_existing_state(database):
    from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
    from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, MacAddress
    from netsentinel.application.ports import DeviceRepositoryError
    stamp = int(NOW.timestamp() * 1_000_000)
    with database.connection() as c:
        c.executemany('INSERT INTO devices VALUES(?,?,?,?,?)', (
            (str(UUID(int=i)), 'a' * 64, ':'.join(f'{i:012x}'[j:j+2] for j in range(0,12,2)), stamp, stamp)
            for i in range(1,4097)))
    repo = SQLiteDeviceRepository(database)
    device = DeviceIdentity('a' * 64, MacAddress('12:22:33:44:55:66'), NOW, NOW)
    binding = IdentityBinding(device.network_fingerprint, device.mac, '192.0.2.1', NOW, NOW)
    with pytest.raises(DeviceRepositoryError):
        repo.record_binding(device, binding)
    assert count(database, 'devices') == 4096 and count(database, 'device_bindings') == 0


def test_protected_only_pressure_is_returned_in_maintenance_diagnostics(database, service):
    stamp = int(NOW.timestamp() * 1_000_000)
    with database.connection() as c:
        c.executemany('INSERT INTO devices VALUES(?,?,?,?,?)', (
            (str(UUID(int=i)), 'a' * 64, ':'.join(f'{i:012x}'[j:j+2] for j in range(0,12,2)), stamp, stamp)
            for i in range(1,4098)))
    result = service.run_retention()
    assert result.status is MaintenanceStatus.CAPACITY_PRESSURE
    assert result.deleted_rows == 0
    assert any(s.store is Store.DEVICES and s.protected == 4097 for s in result.capacity_pressure)


def test_dns_admission_cap_allows_idempotent_replay_but_rejects_new(database, monkeypatch):
    from netsentinel.infrastructure.sqlite.dns_repository import SQLiteDnsHistoryRepository
    from netsentinel.application.ports import DnsHistoryRepositoryError
    from netsentinel.domain.dns import DnsHistoryRecord
    from tests.integration.sqlite.test_dns_repository import _tx
    monkeypatch.setattr('netsentinel.infrastructure.sqlite.dns_repository.HISTORY_ROW_QUOTA', 1)
    repository = SQLiteDnsHistoryRepository(database)
    first = DnsHistoryRecord(UUID(int=1), _tx(at=NOW))
    repository.record(first)
    repository.record(first)
    with pytest.raises(DnsHistoryRepositoryError):
        repository.record(DnsHistoryRecord(UUID(int=2), _tx(at=NOW)))
    assert repository.get(first.id) == first and count(database, 'dns_history') == 1


def test_connection_admission_cap_preserves_existing_active_lifecycle(database, monkeypatch):
    from netsentinel.infrastructure.sqlite.repositories import SQLiteConnectionHistoryRepository
    from netsentinel.application.ports import HistoryRepositoryError
    from tests.integration.sqlite.test_behavior_baselines import event
    monkeypatch.setattr('netsentinel.infrastructure.sqlite.repositories.HISTORY_ROW_QUOTA', 1)
    repository = SQLiteConnectionHistoryRepository(database)
    first = event(UUID(int=1000))
    saved = repository.record_opened(first)
    assert repository.record_opened(first) == saved
    with pytest.raises(HistoryRepositoryError):
        repository.record_opened(event(UUID(int=2000)))
    assert count(database, 'connection_history') == 1


def test_alert_admission_capacity_does_not_evict_active_explanation(database, monkeypatch):
    from netsentinel.application.ports import AlertRepositoryError
    monkeypatch.setattr('netsentinel.infrastructure.sqlite.alert_repository.ALERT_ROW_QUOTA', 1)
    saved = alert(database, 1, NOW)
    with pytest.raises(AlertRepositoryError):
        alert(database, 2, NOW)
    assert alert(database, 1, NOW).id == saved.id and count(database, 'alerts') == 1


def test_association_large_overflow_rolls_back_instead_of_giant_trim(database, monkeypatch):
    from netsentinel.infrastructure.sqlite.dns_association_repository import prune_associations
    from netsentinel.infrastructure.sqlite.database import transaction
    monkeypatch.setattr('netsentinel.infrastructure.sqlite.dns_association_repository.MAX_STORED_ASSOCIATIONS', 1)
    with database.connection() as c:
        # Keep the fixture metadata bounded and valid; 130 rows would need
        # 129 deletes, exceeding the write-time 128-row cleanup budget.
        with pytest.raises(ValueError, match='bounded maintenance'):
            with transaction(c):
                c.executemany("INSERT INTO dns_associations VALUES(?,0,'private.example','192.0.2.123',1,'direct_answer','private.example','private.example','[]',100,200,1,1,1,?,'192.0.2.123','192.0.2.53','udp',1,100)",
                              ((str(UUID(int=i)), 'a' * 64) for i in range(1,131)))
                prune_associations(c)
    assert count(database, 'dns_associations') == 0


def test_invalid_enum_never_leaks_as_support_projection(database, service):
    record = alert(database, 1, NOW)
    with database.connection() as c:
        c.execute('PRAGMA ignore_check_constraints = ON')
        c.execute("UPDATE alerts SET severity='secret.example' WHERE id=?", (str(record.id),))
    export = service.preview_export()
    assert export.record_count == 0 and b'secret.example' not in export.content
