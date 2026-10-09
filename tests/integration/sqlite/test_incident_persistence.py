"""NS-090 real SQLite restart, lifecycle, retention, races and atomic failures."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import json
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.incidents import IncidentLimitation, IncidentPolicy
from netsentinel.domain.incident_persistence import (
    IncidentAction, IncidentSourceStatus as Source, IncidentState as State,
    IncidentStatus as Status, IncidentStoragePolicy, stable_incident_id,
)
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations, default_migration_runner
from tests.fixtures.incidents import NOW, SESSION, item


@pytest.fixture
def database(tmp_path):
    return SQLiteDatabase(tmp_path / "incidents.db")


@pytest.fixture
def repository(database):
    return SQLiteIncidentRepository(database)


@pytest.fixture
def service(repository):
    return IncidentPersistenceService(repository)


def create(service, value=None):
    value = value or item()
    snapshot = IncidentCorrelator(service.repository.policy.correlation).correlate(value).incident
    return service.create_or_get(snapshot, now=max(NOW, value.observed_at)).record


def linked(number=2, *, stamp=NOW + timedelta(seconds=1), **kwargs):
    return item(number, stamp=stamp, evidence=(item().observation.reference,), **kwargs)


def test_stable_seed_retry_with_different_runtime_ids(service, repository, database):
    a, b = IncidentCorrelator().correlate(item()).incident, IncidentCorrelator().correlate(item()).incident
    assert a.incident_id != b.incident_id
    saved = service.create_or_get(a, now=NOW)
    assert saved.status is Status.CHANGED
    assert saved.record.incident_id == stable_incident_id(a) == stable_incident_id(b)
    assert service.create_or_get(b, now=NOW + timedelta(hours=1)).status is Status.NO_CHANGE
    restarted = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
    assert restarted.create_or_get(b, now=NOW).status is Status.NO_CHANGE
    assert repository.get(saved.record.incident_id).record == saved.record


@pytest.mark.parametrize("lifecycle", ["open", "ack", "resolved", "reopened"])
def test_restart_all_states_refs_revisions_times(database, service, lifecycle):
    record = create(service)
    if lifecycle == "ack":
        record = service.acknowledge(record.incident_id, expected_revision=1, now=NOW).record
    if lifecycle in ("resolved", "reopened"):
        record = service.resolve(record.incident_id, expected_revision=1, now=NOW).record
    if lifecycle == "reopened":
        record = service.reopen(record.incident_id, linked(), expected_revision=2, now=NOW + timedelta(seconds=1)).record
    restarted = SQLiteIncidentRepository(SQLiteDatabase(database.path))
    read = restarted.get(record.incident_id)
    assert read.status is Status.FOUND and read.record == record
    assert read.references and restarted.history(record.incident_id).entries[0].revision == record.revision
    assert record.state is (State.ACKNOWLEDGED if lifecycle == "ack" else State.RESOLVED if lifecycle == "resolved" else State.OPEN)
    assert IncidentPersistenceService(restarted).append(record.incident_id, item(), now=NOW + timedelta(hours=1)).status is Status.NO_CHANGE


def test_out_of_order_append_and_retries_do_not_fake_times(service, repository):
    first = item(stamp=NOW + timedelta(minutes=2))
    record = create(service, first)
    early = linked(stamp=NOW + timedelta(minutes=1))
    appended = service.append(record.incident_id, early, now=NOW + timedelta(minutes=3))
    assert appended.status is Status.CHANGED
    assert appended.record.snapshot.first_observed_at == early.observed_at
    assert appended.record.snapshot.last_observed_at == first.observed_at
    before = repository.history(record.incident_id)
    assert service.append(record.incident_id, early, now=NOW + timedelta(hours=1)).status is Status.NO_CHANGE
    assert repository.history(record.incident_id) == before
    assert service.create_or_get(IncidentCorrelator().correlate(first).incident, now=NOW + timedelta(hours=1)).status is Status.NO_CHANGE


def test_assessment_and_ti_revisions_use_original_observation_time(service):
    ref = AlertAssessmentReference("c" * 64, 1, NetworkScopeStatus.RESOLVED)
    record = create(service, item(assessment=ref))
    next_ref = replace(ref, revision=2)
    result = service.append(record.incident_id, linked(stamp=NOW, assessment=next_ref), now=NOW + timedelta(days=1))
    assert result.status is Status.CHANGED
    assert len(result.record.snapshot.assessments) == 2
    assert result.record.snapshot.first_observed_at == result.record.snapshot.last_observed_at == NOW
    assert result.record.revision == 2
    assert result.record.incident_id == record.incident_id


@pytest.mark.parametrize("start,command,expected", [
    ("open", "ack", Status.CHANGED), ("ack", "ack", Status.NO_CHANGE),
    ("open", "resolve", Status.CHANGED), ("ack", "resolve", Status.CHANGED),
    ("resolved", "resolve", Status.NO_CHANGE), ("resolved", "ack", Status.INVALID_TRANSITION),
    ("open", "reopen", Status.INVALID_TRANSITION), ("ack", "reopen", Status.INVALID_TRANSITION),
])
def test_lifecycle_matrix(service, start, command, expected):
    record = create(service)
    if start == "ack":
        record = service.acknowledge(record.incident_id, expected_revision=record.revision, now=NOW).record
    if start == "resolved":
        record = service.resolve(record.incident_id, expected_revision=record.revision, now=NOW).record
    kwargs = {"expected_revision": record.revision, "now": NOW + timedelta(seconds=1)}
    result = (service.reopen(record.incident_id, linked(), **kwargs) if command == "reopen" else
              service.acknowledge(record.incident_id, **kwargs) if command == "ack" else
              service.resolve(record.incident_id, **kwargs))
    assert result.status is expected
    current = service.get(record.incident_id).record
    assert current.incident_id == record.incident_id
    if command != "reopen":
        assert current.snapshot == record.snapshot
    if expected is not Status.CHANGED:
        assert current == record


@pytest.mark.parametrize("offset,expected", [(-1, Status.CHANGED), (0, Status.CHANGED), (1, Status.HORIZON_EXCEEDED)])
@pytest.mark.parametrize("restart", [False, True])
def test_reopen_exact_horizon_boundary(database, service, offset, expected, restart):
    record = create(service)
    record = service.resolve(record.incident_id, expected_revision=1, now=NOW).record
    if restart:
        service = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
    stamp = NOW + service.repository.policy.reopen_horizon + timedelta(microseconds=offset)
    result = service.reopen(record.incident_id, linked(stamp=stamp), expected_revision=2, now=stamp)
    assert result.status is expected
    if expected is Status.CHANGED:
        assert result.record.state is State.OPEN and result.record.action is IncidentAction.REOPENED
        assert result.record.resolved_at == NOW and result.record.reopened_at == stamp
        assert result.record.snapshot.last_observed_at == stamp


@pytest.mark.parametrize("case", ["same_ip", "other_process", "bucket", "before_resolution", "duplicate"])
def test_reopen_requires_new_strong_relation_and_same_bucket(service, case):
    record = create(service)
    resolved = NOW + timedelta(minutes=1) if case == "before_resolution" else NOW
    if case == "bucket":
        record = create(service, item(stamp=NOW + timedelta(minutes=8)))
        resolved = NOW + timedelta(minutes=8)
    service.resolve(record.incident_id, expected_revision=1, now=resolved)
    value = (item(2, process=None, connection=None) if case == "same_ip" else
             item(2, process=replace(item().process, identity=replace(item().process.identity, pid=456))) if case == "other_process" else
             linked(stamp=NOW + timedelta(minutes=10)) if case == "bucket" else
             linked(stamp=NOW) if case == "before_resolution" else item())
    result = service.reopen(record.incident_id, value, expected_revision=2, now=max(resolved, value.observed_at))
    assert result.status is (Status.HORIZON_EXCEEDED if case == "before_resolution" else Status.NO_CHANGE if case == "duplicate" else Status.NOT_CORRELATED)
    assert service.get(record.incident_id).record.state is State.RESOLVED


def test_archive_append_does_not_reopen(service):
    record = create(service)
    service.resolve(record.incident_id, expected_revision=1, now=NOW)
    result = service.append(record.incident_id, linked(), now=NOW + timedelta(seconds=1))
    assert result.status is Status.CHANGED and result.record.state is State.RESOLVED
    assert result.record.resolved_at == NOW


def test_restart_observe_continues_canonical_keys_but_not_derived(database, service):
    record = create(service)
    restarted = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
    continuation = restarted.observe(linked(), now=NOW + timedelta(seconds=1))
    assert continuation.record.incident_id == record.incident_id
    assert IncidentLimitation.MONITORING_GAP in continuation.record.snapshot.limitations
    assert IncidentLimitation.CANONICAL_GAP_BRIDGE in continuation.record.snapshot.limitations
    isolated = restarted.observe(item(3, stamp=NOW + timedelta(seconds=2)), now=NOW + timedelta(seconds=2))
    assert isolated.record.incident_id != record.incident_id
    # Next cohort always starts a separate stable identity, even sharing evidence.
    next_bucket = restarted.observe(linked(4, stamp=NOW + timedelta(minutes=10)), now=NOW + timedelta(minutes=10))
    assert next_bucket.record.incident_id not in (record.incident_id, isolated.record.incident_id)


def test_hydration_read_has_no_mutation_and_bound(database):
    policy = IncidentStoragePolicy(max_hydration=1)
    repo = SQLiteIncidentRepository(database, policy)
    service = IncidentPersistenceService(repo)
    a = create(service, item(1, process=None, connection=None))
    b = create(service, item(2, process=None, connection=None))
    before = repo.history(a.incident_id)
    assert service.observe(linked(), now=NOW + timedelta(seconds=1)).status is Status.CAPACITY_REACHED
    assert repo.history(a.incident_id) == before and repo.get(b.incident_id).record.revision == 1


def test_optimistic_conflict_and_monotonic_revision(service):
    record = create(service)
    result = service.append(record.incident_id, linked(), now=NOW + timedelta(seconds=1))
    assert result.record.revision == 2
    conflict = service.resolve(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2))
    assert conflict.status is Status.CONFLICT
    assert service.get(record.incident_id).record.state is State.OPEN
    assert service.resolve(record.incident_id, expected_revision=2, now=NOW + timedelta(seconds=2)).record.revision == 3


def test_revision_prune_keeps_current_explanation_and_number(database):
    repo = SQLiteIncidentRepository(database, IncidentStoragePolicy(max_revisions=2))
    service = IncidentPersistenceService(repo)
    record = create(service)
    for number in range(2, 8):
        result = service.append(record.incident_id, linked(number, stamp=NOW + timedelta(seconds=number)), now=NOW + timedelta(seconds=number))
        assert result.status is Status.CHANGED
    read = repo.get(record.incident_id)
    assert read.record.revision == 7 and len(read.record.snapshot.relations) == 7
    history = repo.history(record.incident_id, limit=2)
    assert [e.revision for e in history.entries] == [7, 6] and history.truncated
    assert service.append(record.incident_id, linked(2, stamp=NOW + timedelta(seconds=2)), now=NOW + timedelta(minutes=1)).status is Status.NO_CHANGE


def test_capacity_active_protection_and_explicit_cleanup(database):
    repo = SQLiteIncidentRepository(database, IncidentStoragePolicy(max_incidents=2, cleanup_chunk=1))
    service = IncidentPersistenceService(repo)
    a = create(service)
    b = create(service, item(2))
    assert service.create_or_get(IncidentCorrelator().correlate(item(3)).incident, now=NOW).status is Status.CAPACITY_REACHED
    assert repo.cleanup(NOW + timedelta(days=1), NOW + timedelta(days=1)) == 0
    service.resolve(a.incident_id, expected_revision=1, now=NOW)
    assert repo.cleanup(NOW + timedelta(days=1), NOW + repo.policy.reopen_horizon) == 0
    assert repo.cleanup(NOW + timedelta(days=1), NOW + repo.policy.reopen_horizon + timedelta(microseconds=1)) == 1
    assert repo.get(a.incident_id).status is Status.NOT_FOUND
    assert repo.get(b.incident_id).record.state is State.OPEN
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM incident_references WHERE incident_id = ?", (str(a.incident_id),)).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM incident_revisions WHERE incident_id = ?", (str(a.incident_id),)).fetchone()[0] == 0


@pytest.mark.parametrize("resource", ["processes", "connections", "destinations", "evidence", "alerts", "assessments", "scopes", "relations", "links"])
def test_append_capacity_is_atomic(database, resource):
    kw = {"max_" + resource: 1} if resource != "links" else {}
    policy = IncidentStoragePolicy(correlation=IncidentPolicy(**kw), max_links=6 if resource == "links" else 320)
    repo = SQLiteIncidentRepository(database, policy)
    service = IncidentPersistenceService(repo)
    ref = AlertAssessmentReference("a" * 64, 1, NetworkScopeStatus.RESOLVED)
    record = create(service, item(assessment=ref, alert_id=UUID(int=55)) if resource in ("alerts", "assessments") else item())
    assert record is not None
    value = linked()
    if resource == "processes":
        value = linked(process=replace(item().process, identity=replace(item().process.identity, pid=456)))
    if resource == "destinations":
        value = linked(destination=replace(item().destination, port=80))
    if resource == "alerts":
        value = linked(alert_id=UUID(int=56))
    if resource == "assessments":
        value = linked(assessment=replace(ref, revision=2))
    if resource == "scopes":
        value = linked(scope=replace(item().scope, network_fingerprint="b" * 64))
    before = repo.get(record.incident_id)
    result = service.append(record.incident_id, value, now=NOW + timedelta(seconds=1))
    assert result.status is Status.CAPACITY_REACHED
    assert repo.get(record.incident_id) == before


@pytest.mark.parametrize("same", [False, True])
def test_concurrent_append_serializes_refs_and_revisions(database, service, same):
    record = create(service)
    barrier = Barrier(8)

    def append(number):
        own = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
        barrier.wait()
        return own.append(record.incident_id, linked(2 if same else number + 2, stamp=NOW), now=NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(append, range(8)))
    assert sum(r.status is Status.CHANGED for r in results) == (1 if same else 8)
    assert all(r.status in (Status.CHANGED, Status.NO_CHANGE) for r in results)
    current = service.get(record.incident_id).record
    assert current.revision == (2 if same else 9)
    assert len(current.snapshot.relations) == current.revision


@pytest.mark.parametrize("race", ["resolve_append", "resolve_reopen"])
def test_lifecycle_races_have_one_winner_with_expected_revision(database, service, race):
    record = create(service)
    if race == "resolve_reopen":
        record = service.resolve(record.incident_id, expected_revision=1, now=NOW).record
    barrier = Barrier(2)

    def run(command):
        own = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
        barrier.wait()
        if command == "resolve":
            return own.resolve(record.incident_id, expected_revision=record.revision, now=NOW + timedelta(seconds=1))
        method = own.reopen if race == "resolve_reopen" else own.append
        return method(record.incident_id, linked(), expected_revision=record.revision, now=NOW + timedelta(seconds=1))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, ("resolve", "append")))
    assert all(r.status in (Status.CHANGED, Status.CONFLICT, Status.NO_CHANGE) for r in results)
    assert sum(r.status is Status.CHANGED for r in results) == 1


@pytest.mark.parametrize("operation", ["create", "append", "ack", "resolve", "reopen"])
def test_injected_transaction_failure_rolls_back_all_rows(database, service, operation):
    record = create(service)
    if operation == "reopen":
        record = service.resolve(record.incident_id, expected_revision=1, now=NOW).record
    before = service.get(record.incident_id)
    history = service.repository.history(record.incident_id)
    with database.connection() as connection:
        connection.execute("CREATE TRIGGER incident_test_failure BEFORE INSERT ON incident_revisions BEGIN SELECT RAISE(ABORT, 'failure'); END")
    if operation == "create":
        result = service.create_or_get(IncidentCorrelator().correlate(item(20)).incident, now=NOW)
    elif operation in ("append", "reopen"):
        result = getattr(service, operation)(record.incident_id, linked(), expected_revision=record.revision, now=NOW + timedelta(seconds=1))
    else:
        result = getattr(service, "acknowledge" if operation == "ack" else "resolve")(record.incident_id, expected_revision=record.revision, now=NOW)
    assert result.status is Status.UNAVAILABLE
    assert service.get(record.incident_id) == before
    assert service.repository.history(record.incident_id) == history
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
        connection.execute("DROP TRIGGER incident_test_failure")
    if operation == "append":
        assert service.append(record.incident_id, linked(), now=NOW + timedelta(seconds=1)).record.revision == 2


@pytest.mark.parametrize("damage,expected", [("json", Status.CORRUPT), ("format", Status.UNSUPPORTED_VERSION),
    ("counter", Status.CORRUPT), ("links", Status.CORRUPT), ("oversize", Status.CORRUPT), ("revision", Status.CORRUPT)])
def test_corrupt_row_is_typed_and_other_list_rows_survive(database, service, damage, expected):
    a, b = create(service), create(service, item(2))
    with database.connection() as connection:
        if damage == "json":
            connection.execute("UPDATE incidents SET payload='{}' WHERE incident_id=?", (str(a.incident_id),))
        elif damage == "format":
            connection.execute("UPDATE incidents SET format_version=2 WHERE incident_id=?", (str(a.incident_id),))
        elif damage == "counter":
            connection.execute("UPDATE incidents SET revision=2 WHERE incident_id=?", (str(a.incident_id),))
        elif damage == "links":
            connection.execute("DELETE FROM incident_references WHERE incident_id=?", (str(a.incident_id),))
        elif damage == "revision":
            connection.execute("DELETE FROM incident_revisions WHERE incident_id=?", (str(a.incident_id),))
        else:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute("UPDATE incidents SET payload=? WHERE incident_id=?", ("x" * 131073, str(a.incident_id)))
    assert service.get(a.incident_id).status is expected
    entries = service.repository.list_current().entries
    assert len(entries) == 2 and any(e.record and e.record.incident_id == b.incident_id for e in entries)


def test_list_and_history_keyset_bounds(service):
    records = [create(service, item(n)) for n in range(1, 5)]
    first = service.repository.list_current(limit=2)
    second = service.repository.list_current(limit=2, after_id=first.after_id)
    assert first.has_more and not second.has_more
    assert {e.record.incident_id for e in first.entries + second.entries} == {r.incident_id for r in records}
    assert service.repository.list_current(state=State.RESOLVED).entries == ()
    for limit in (0, 101, True):
        with pytest.raises(ValueError):
            service.repository.list_current(limit=limit)
    for limit in (0, 33, True):
        with pytest.raises(ValueError):
            service.repository.history(records[0].incident_id, limit=limit)


def test_migration_from_018_full_chain_and_source_fk_independence(tmp_path):
    path = tmp_path / "old.db"
    old = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:18]))
    with old.connection() as connection:
        assert default_migration_runner().current_version(connection) == 18
        source_counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                         for table in ("alerts", "connection_history", "dns_history", "risk_assessments")}
    new = SQLiteDatabase(path)
    with new.connection() as connection:
        assert default_migration_runner().current_version(connection) == 20
        assert [r[0] for r in connection.execute("SELECT version FROM schema_migrations ORDER BY version")] == list(range(1, 21))
        for table, count in source_counts.items():
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == count
        for table in ("incident_references", "incident_revisions"):
            assert {r[2] for r in connection.execute(f"PRAGMA foreign_key_list({table})")} == {"incidents"}
        assert not list(connection.execute("PRAGMA foreign_key_list(incidents)"))
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_missing_unavailable_invalid_transition_and_sanitized_diagnostics(service):
    assert service.get(uuid4()).status is Status.NOT_FOUND
    assert service.append(uuid4(), linked(), now=NOW + timedelta(seconds=1)).status is Status.NOT_FOUND
    record = create(service)
    assert service.resolve(record.incident_id, expected_revision=1, now=NOW - timedelta(seconds=1)).status is Status.INVALID_TRANSITION
    assert all(type(v) is int for v in service.diagnostics().values())
    assert service.diagnostics() == {"live_continuity_incidents": 1}


def test_duplicate_changed_snapshot_is_not_silent_overwrite(service):
    record = create(service)
    changed = replace(item(), destination=replace(item().destination, port=80))
    assert service.append(record.incident_id, changed, now=NOW).status is Status.IDENTITY_CONFLICT
    assert service.get(record.incident_id).record == record


def test_source_missing_remains_readable_and_distinct_from_unresolved(service):
    reference = EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=888))
    record = create(service, item(evidence=(reference,), alert_id=UUID(int=999)))
    read = service.get(record.incident_id)
    assert read.status is Status.FOUND and read.record == record
    statuses = {(r.link.kind, r.link.payload): r.status for r in read.references}
    assert statuses[("evidence", json.dumps({"kind": reference.kind.value, "value": str(reference.value)}, sort_keys=True, separators=(",", ":")))] is Source.SOURCE_EXPIRED_OR_UNAVAILABLE
    assert any(r.status is Source.UNRESOLVED for r in read.references)
    assert all(r.status in (Source.UNRESOLVED, Source.SOURCE_EXPIRED_OR_UNAVAILABLE) for r in read.references)


def test_source_deletion_preserves_incident_and_explanation_after_restart(database, service):
    from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
    from tests.fixtures.risk_assessments import key, snapshot

    dns = EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=888))
    assessment = SQLiteAssessmentRepository(database).save(key(), snapshot(), NOW)
    ref = AlertAssessmentReference(assessment.revision.key.assessment_id, 1, NetworkScopeStatus.RESOLVED)
    value = item(evidence=(dns,), assessment=ref)
    with database.connection() as connection:
        connection.execute("INSERT INTO connection_history(id,protocol,local_address,local_port,process_status,connection_state,first_seen_utc_us,last_seen_utc_us,lifecycle_id,monitoring_session_id) "
            "VALUES(?,'tcp','127.0.0.1',5000,'unavailable','listen',100,100,?,?)",
            (str(UUID(int=50)), str(value.connection.lifecycle_id), str(SESSION)))
        connection.execute("INSERT INTO dns_history(id,status,network_fingerprint,transport,client_ip,client_port,server_ip,server_port,transaction_id,questions_json,query_at_utc_us,event_at_utc_us,truncated,answers_json,retry_count,evidence_id) "
            "VALUES(?,'timed_out',?,'udp','127.0.0.1',5000,'192.0.2.1',53,1,'[]',100,100,0,'[]',0,?)",
            (str(UUID(int=51)), "a" * 64, str(dns.value)))
    record = create(service, value)
    before = service.get(record.incident_id)
    assert {r.status for r in before.references if r.link.kind in ('connection', 'assessment')} == {Source.AVAILABLE}
    assert any(r.link.kind == 'evidence' and r.status is Source.AVAILABLE for r in before.references)
    with database.connection() as connection:
        for table in ('dns_history', 'connection_history', 'risk_assessments'):
            connection.execute(f"DELETE FROM {table}")
    restarted = SQLiteIncidentRepository(SQLiteDatabase(database.path))
    after = restarted.get(record.incident_id)
    assert after.record == before.record and restarted.history(record.incident_id).entries[0].revision == 1
    assert {r.status for r in after.references if r.link.kind in ('connection', 'assessment')} == {Source.SOURCE_EXPIRED_OR_UNAVAILABLE}
    assert [r.link for r in after.references] == [r.link for r in before.references]


@pytest.mark.parametrize("format_version,expected", [(99, Source.UNSUPPORTED_VERSION), (1, Source.CORRUPT)])
def test_source_corruption_is_distinct_from_source_expiry(database, service, format_version, expected):
    from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
    from tests.fixtures.risk_assessments import key, snapshot

    saved = SQLiteAssessmentRepository(database).save(key(), snapshot(), NOW)
    ref = AlertAssessmentReference(saved.revision.key.assessment_id, 1, NetworkScopeStatus.RESOLVED)
    record = create(service, item(assessment=ref))
    with database.connection() as connection:
        connection.execute("UPDATE risk_assessment_revisions SET format_version=?,snapshot='{}'", (format_version,))
    read = service.get(record.incident_id)
    assert read.status is Status.FOUND
    assert {r.status for r in read.references if r.link.kind == 'assessment'} == {expected}


def test_alert_and_incident_lifecycles_are_independent(database, service):
    from netsentinel.application.services.alerts import AlertService
    from netsentinel.domain.alerts import AlertCandidate, AlertEvidence, AlertStatus
    from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository

    clock = [NOW]
    alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: clock[0])
    candidate = AlertCandidate('f' * 64, 'test_rule', 'a' * 64, 'test_entity', 'low', 'low', AlertEvidence(NOW))
    alert, notify = alerts.record(candidate)
    assert notify
    record = create(service, item(alert_id=alert.id))
    before = alerts.get(alert.id)
    acknowledged = service.acknowledge(record.incident_id, expected_revision=1, now=NOW)
    assert acknowledged.status is Status.CHANGED and alerts.get(alert.id) == before
    resolved = service.resolve(record.incident_id, expected_revision=2, now=NOW)
    assert resolved.status is Status.CHANGED and alerts.get(alert.id) == before
    reopened = service.reopen(record.incident_id, linked(alert_id=alert.id), expected_revision=3, now=NOW + timedelta(seconds=1))
    assert reopened.status is Status.CHANGED and alerts.get(alert.id) == before
    baseline = service.get(record.incident_id)
    clock[0] += timedelta(seconds=1)
    assert alerts.acknowledge(alert.id).status is AlertStatus.ACKNOWLEDGED
    assert service.get(record.incident_id).record == baseline.record
    assert alerts.resolve(alert.id).status is AlertStatus.RESOLVED
    assert service.get(record.incident_id).record == baseline.record
    again, notify = alerts.record(replace(candidate, evidence=AlertEvidence(clock[0])))
    assert notify and again.status is AlertStatus.OPEN and again.occurrence_count == 2
    assert service.get(record.incident_id).record == baseline.record


def test_concurrent_create_retries_allocate_one_stable_parent(database):
    barrier = Barrier(8)

    def run(_):
        own = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(database.path)))
        snapshot = IncidentCorrelator().correlate(item()).incident
        barrier.wait()
        return own.create_or_get(snapshot, now=NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(8)))
    assert sum(r.status is Status.CHANGED for r in results) == 1
    assert sum(r.status is Status.NO_CHANGE for r in results) == 7
    assert len({r.record.incident_id for r in results}) == 1


def test_cleanup_chunk_and_active_ack_protection(database):
    repo = SQLiteIncidentRepository(database, IncidentStoragePolicy(cleanup_chunk=1))
    service = IncidentPersistenceService(repo)
    records = [create(service, item(n)) for n in range(1, 5)]
    service.acknowledge(records[0].incident_id, expected_revision=1, now=NOW)
    for record in records[1:3]:
        service.resolve(record.incident_id, expected_revision=1, now=NOW)
    assert repo.cleanup(NOW + timedelta(days=1), NOW + timedelta(days=1)) == 1
    assert repo.cleanup(NOW + timedelta(days=1), NOW + timedelta(days=1)) == 1
    assert repo.cleanup(NOW + timedelta(days=1), NOW + timedelta(days=1)) == 0
    assert repo.get(records[0].incident_id).record.state is State.ACKNOWLEDGED
    assert repo.get(records[3].incident_id).record.state is State.OPEN
