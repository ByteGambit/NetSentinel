"""NS-102 production coordinator + real temporary SQLite + injected firewall.

No native COM import, firewall mutation, sockets or elevation.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
from threading import Event as ThreadEvent
from uuid import uuid4

import pytest

from netsentinel.application.response_lifecycle_service import ResponseLifecycleService, new_response_rule_identity
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallReadStatus, FirewallRemoveRequest, FirewallRuleSnapshot, OwnedFirewallRuleManifest,
    PreparedFirewallOwnershipClaim, ResponseAction, ResponseConfirmation, ResponseOutcome,
    deserialize_owned_firewall_manifest, deserialize_prepared_firewall_claim,
    ownership_description, serialize_owned_firewall_manifest, serialize_prepared_firewall_claim,
)
from netsentinel.domain.response_lifecycle import (
    MAX_RESPONSE_ACTIVE_RULES, MAX_RESPONSE_AUDIT_ROWS, MAX_RESPONSE_OPERATIONS,
    ResponseAuditEvent as Audit, ResponseOperationConflict,
    ResponseOperationStatus as Status, ResponseReconciliation as Reconcile,
    ResponseRemovalPurpose as Purpose, ResponseStorageError,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, SQLiteConnectionFactory, transaction
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations, default_migration_runner
from netsentinel.infrastructure.sqlite.response_repository import SQLiteResponseLifecycleRepository
from netsentinel.infrastructure.windows_response_firewall import FirewallApiError
from tests.unit.domain.test_response import NOW, STORE_ID, command
from tests.unit.domain.test_response_ownership import creation
from tests.unit.infrastructure.test_windows_response_firewall import FakeApi, adapter, raises


class Clock:
    now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def setup(tmp_path):
    db = SQLiteDatabase(tmp_path / "response.sqlite3")
    repo = SQLiteResponseLifecycleRepository(db, STORE_ID)
    api = FakeApi()
    clock = Clock()
    firewall = adapter(api)
    # The existing injected adapter uses the same advancing clock for action-time checks.
    firewall._clock = clock
    service = ResponseLifecycleService(repo, firewall, clock=clock)
    return db, repo, api, clock, service


def restart(setup):
    db, _, api, clock, _ = setup
    repo = SQLiteResponseLifecycleRepository(SQLiteDatabase(db.path), STORE_ID)
    firewall = adapter(api)
    firewall._clock = clock
    return repo, ResponseLifecycleService(repo, firewall, clock=clock)


def remove_request(owned, at=NOW, identity=None):
    c = replace(owned.creation.command, command_id=identity or uuid4(), action=ResponseAction.REMOVE,
                prepared_at=at, selection_generation=2)
    return FirewallRemoveRequest(c, ResponseConfirmation(c.fingerprint, at), owned)


def another_create(at=NOW, ip=None, path=None):
    identity = new_response_rule_identity()
    c = replace(command(), command_id=identity, rule_id=identity, prepared_at=at)
    if ip is not None or path is not None:
        c = replace(c, spec=replace(c.spec, remote_ip=ip or c.spec.remote_ip, program_path=path or c.spec.program_path))
    return FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, at))


def prepared(setup):
    """Stop after PREPARED commit through the real production service path."""
    repo = setup[1]
    save = repo.save
    def stop(operation, event):
        if event is Audit.ATTEMPT:
            raise SystemExit("simulated process death before dispatch")
        return save(operation, event)
    repo.save = stop
    with pytest.raises(SystemExit):
        setup[4].create(creation())
    repo.save = save
    return repo.get(command().command_id)


def ops(api, action):
    return sum(op == action for op, _ in api.calls)


def test_fresh_migration_and_append_only_019_upgrade(tmp_path):
    factory = SQLiteConnectionFactory(tmp_path / "legacy.db")
    with factory.connect() as connection:
        old = MigrationRunner(builtin_migrations()[:19])
        assert old.migrate(connection) == 19
        before = tuple(connection.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall())
        assert default_migration_runner().migrate(connection) == 20
        assert default_migration_runner().migrate(connection) == 20
        assert tuple(connection.execute("SELECT * FROM schema_migrations WHERE version<=19 ORDER BY version").fetchall()) == before
        assert connection.execute("SELECT count(*) FROM response_operations").fetchone()[0] == 0
    with SQLiteDatabase(tmp_path / "fresh.db").connection() as connection:
        assert default_migration_runner().current_version(connection) == 20
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111"])
@pytest.mark.parametrize("path", [r"C:\Example\app.exe", r"C:\Program Files\Örnek 中 & $()\app.exe"])
def test_normal_create_roundtrip_order_and_sensitive_repr(setup, ip, path):
    _, repo, api, _, service = setup
    request = another_create(ip=ip, path=path)
    def add(rule):
        durable = repo.get(request.command.command_id)
        assert durable.status is Status.ATTEMPT and durable.manifest is None
        assert durable.claim.expected_rule == rule
        assert durable.claim.witness in rule.description
        api.rows += (rule,)
    api.hooks["add"] = add
    result = service.create(request)
    assert result.status is Status.VERIFIED and result.result.outcome is ResponseOutcome.VERIFIED
    assert result.manifest.manifest_version == 2
    assert result.manifest.created_at == NOW
    assert repo.get(result.operation_id) == result
    claim = result.claim
    assert claim.creation == request and len(claim.witness) == 64
    assert len(claim.expected_rule.description.encode("ascii")) == 133
    assert serialize_prepared_firewall_claim(deserialize_prepared_firewall_claim(serialize_prepared_firewall_claim(claim))) == serialize_prepared_firewall_claim(claim)
    assert deserialize_owned_firewall_manifest(serialize_owned_firewall_manifest(result.manifest)) == result.manifest
    assert [row.event for row in repo.audit()] == [Audit.PREPARED, Audit.ATTEMPT, Audit.VERIFIED_SUCCESS]
    for value in (claim, result, result.manifest, service.diagnostics(), repo.audit()):
        assert claim.witness not in repr(value) and path not in repr(value)
    assert ops(api, "add") == 1


def test_witness_unique_and_identity_allocated_before_confirmation(setup):
    records = [setup[4].create(another_create()) for _ in range(5)]
    assert len({record.claim.witness for record in records}) == 5
    assert len({record.command.rule_id for record in records}) == 5
    assert all(record.command.rule_id.version == 4 for record in records)
    assert all(record.request.confirmation.command_fingerprint == record.command.fingerprint for record in records)


@pytest.mark.parametrize("field,value", [
    ("claim_version", 2), ("claim_version", True), ("witness", "a" * 63),
    ("witness", "A" * 64), ("witness", None), ("prepared_at", NOW.replace(tzinfo=None)),
    ("prepared_at", NOW - timedelta(seconds=1)), ("prepared_at", NOW + timedelta(minutes=6)),
    ("creation", None), ("expected_rule", None),
])
def test_claim_immutable_strict_validation(setup, field, value):
    claim = prepared(setup).claim
    with pytest.raises(FrozenInstanceError):
        claim.witness = "0" * 64
    with pytest.raises((TypeError, ValueError)):
        replace(claim, **{field: value})
    with pytest.raises(TypeError):
        FirewallRemoveRequest(command(), creation().confirmation, claim)


@pytest.mark.parametrize("mutation", ["version", "unknown", "duplicate", "witness", "description", "time", "oversize", "invalid", "boolean"])
def test_strict_prepared_codec(setup, mutation):
    payload = serialize_prepared_firewall_claim(prepared(setup).claim)
    data = json.loads(payload)
    if mutation == "version":
        data["claim_version"] = 2
    elif mutation == "unknown":
        data["extra"] = True
    elif mutation == "duplicate":
        payload = payload.replace(b'"claim_version":1', b'"claim_version":1,"claim_version":1')
    elif mutation == "witness":
        data["witness"] = "0" * 64
    elif mutation == "description":
        data["rule"]["description"] += " changed"
    elif mutation == "time":
        data["prepared_at"] = "2026-10-08T12:00:00"
    elif mutation == "oversize":
        payload = b" " * 16385
    elif mutation == "invalid":
        payload = b"\xff"
    elif mutation == "boolean":
        data["rule"]["enabled"] = 1
    if mutation not in {"duplicate", "oversize", "invalid"}:
        payload = json.dumps(data).encode("utf-8")
    with pytest.raises(ValueError, match="invalid prepared"):
        deserialize_prepared_firewall_claim(payload)


def test_prepared_no_os_rule_is_not_materialized_and_never_reissued(setup):
    record = prepared(setup)
    repo, service = restart(setup)
    result = service.create(record.request)
    assert result.status is Status.NOT_MATERIALIZED and result.manifest is None
    assert result.reconciliation is Reconcile.NOT_MATERIALIZED
    assert service.create(record.request).status is Status.NOT_MATERIALIZED
    assert ops(setup[2], "add") == 0
    assert repo.audit()[-1].event is Audit.RECOVERY


@pytest.mark.parametrize("phase", ["before_add", "after_add", "after_final"])
def test_create_crashes_recover_only_exact_witness_without_fabricated_time(setup, phase):
    _, repo, api, clock, service = setup
    if phase in {"before_add", "after_add"}:
        def crash(rule):
            if phase == "after_add":
                api.rows += (rule,)
            raise SystemExit("simulated process death")
        api.hooks["add"] = crash
    else:
        save = repo.save
        def crash(operation, event):
            result = save(operation, event)
            if event is Audit.VERIFIED_SUCCESS:
                raise SystemExit("simulated death after commit")
            return result
        repo.save = crash
    with pytest.raises(SystemExit):
        service.create(creation())
    clock.now += timedelta(days=1)
    repo, service = restart(setup)
    result = service.create(creation())
    assert ops(api, "add") == 1
    if phase == "before_add":
        assert result.manifest is None and result.status is Status.NOT_MATERIALIZED
    else:
        assert result.status is Status.VERIFIED
        assert result.manifest.created_at == (NOW if phase == "after_final" else None)
        assert result.manifest.verified_at == (NOW if phase == "after_final" else clock.now)
        if phase == "after_add":
            assert repo.audit()[-1].event is Audit.RECOVERY_PROMOTION


@pytest.mark.parametrize("field", ["program_path", "remote_ip", "remote_port", "profile", "transport"])
def test_prepared_scope_drift_never_promotes(setup, field):
    claim = prepared(setup).claim
    values = {
        "program_path": r"C:\Other\app.exe", "remote_ip": "1.1.1.1", "remote_port": 80,
        "profile": type(claim.expected_rule.spec.profile).PUBLIC,
        "transport": type(claim.expected_rule.spec.transport).UDP,
    }
    setup[2].rows = (replace(claim.expected_rule, spec=replace(claim.expected_rule.spec, **{field: values[field]})),)
    record = restart(setup)[1].create(claim.creation)
    assert record.manifest is None and record.reconciliation is Reconcile.EXTERNAL_MODIFIED
    assert ops(setup[2], "remove") == ops(setup[2], "add") == 0


@pytest.mark.parametrize("field", [field.name for field in fields(FirewallRuleSnapshot)
                                  if field.name not in {"name", "spec"}])
def test_every_prepared_ownership_field_drift_refuses_promotion(setup, field):
    claim = prepared(setup).claim
    values = {"enabled": False, "edge_traversal": True, "edge_traversal_options": 1,
              "secure_flags": 1, "interfaces": ("Other",)}
    setup[2].rows = (replace(claim.expected_rule, **{field: values.get(field, "Other")}),)
    record = restart(setup)[1].create(claim.creation)
    assert record.manifest is None
    assert record.reconciliation is (Reconcile.EXTERNALLY_DISABLED if field == "enabled" else Reconcile.EXTERNAL_MODIFIED)
    assert ops(setup[2], "remove") == 0


@pytest.mark.parametrize("description", ["", "NetSentinel response v1", "wrong_witness", "suffix"])
def test_foreign_missing_wrong_witness_description_never_owned(setup, description):
    claim = prepared(setup).claim
    if description == "wrong_witness":
        description = ownership_description(claim.creation.command.rule_id, "0" * 64)
    if description == "suffix":
        description = claim.expected_rule.description + " changed"
    setup[2].rows = (replace(claim.expected_rule, description=description),)
    result = restart(setup)[1].create(claim.creation)
    assert result.manifest is None and result.reconciliation is Reconcile.EXTERNAL_MODIFIED
    assert ops(setup[2], "add") == ops(setup[2], "remove") == 0


def test_duplicate_identity_never_promoted_or_mutated(setup):
    claim = prepared(setup).claim
    setup[2].rows = (claim.expected_rule, claim.expected_rule)
    result = restart(setup)[1].create(claim.creation)
    assert result.manifest is None and result.reconciliation is Reconcile.AMBIGUOUS
    assert ops(setup[2], "add") == ops(setup[2], "remove") == 0


@pytest.mark.parametrize("status,definite", [
    (FirewallReadStatus.ACCESS_DENIED, True), (FirewallReadStatus.READ_UNAVAILABLE, True),
    (FirewallReadStatus.READ_UNAVAILABLE, False),
])
def test_create_denied_failed_unknown_audited_and_replay_read_only(setup, status, definite):
    api, service = setup[2], setup[4]
    api.hooks["add"] = raises(FirewallApiError(status, definite_failure=definite))
    record = service.create(creation())
    assert record.status is (Status.FAILURE if definite else Status.UNKNOWN)
    assert record.manifest is None
    assert setup[1].audit()[-1].event is (Audit.FAILURE if definite else Audit.UNKNOWN_PARTIAL)
    replay = service.create(creation())
    assert replay.status is Status.NOT_MATERIALIZED and ops(api, "add") == 1


@pytest.mark.parametrize("event", [Audit.PREPARED, Audit.ATTEMPT, Audit.VERIFIED_SUCCESS])
def test_create_database_failures_no_unsafe_success_and_restart_promotion(setup, event):
    _, repo, api, clock, service = setup
    save = repo.save
    def fail(operation, audit):
        if audit is event:
            raise ResponseStorageError("injected bounded storage failure")
        return save(operation, audit)
    repo.save = fail
    if event is Audit.VERIFIED_SUCCESS:
        record = service.create(creation())
        assert record.status is Status.PARTIAL and record.manifest is None
        assert repo.get(record.operation_id).manifest is None
        clock.now += timedelta(hours=1)
        promoted = restart(setup)[1].create(creation())
        assert promoted.status is Status.VERIFIED and promoted.manifest.created_at is None
        assert ops(api, "add") == 1
    else:
        with pytest.raises(ResponseStorageError):
            service.create(creation())
        assert ops(api, "add") == 0
        if event is Audit.ATTEMPT:
            assert restart(setup)[1].create(creation()).status is Status.NOT_MATERIALIZED
        else:
            assert restart(setup)[0].get(command().command_id) is None


def test_final_commit_acknowledgement_failure_replay_observes_durable_result(setup):
    repo, service = setup[1], setup[4]
    save = repo.save
    def commit_then_fail(operation, event):
        result = save(operation, event)
        if event is Audit.VERIFIED_SUCCESS:
            raise ResponseStorageError("injected lost commit acknowledgement")
        return result
    repo.save = commit_then_fail
    receipt = service.create(creation())
    assert receipt.status is Status.PARTIAL and receipt.manifest is None
    replay = restart(setup)[1].create(creation())
    assert replay.status is Status.VERIFIED and replay.manifest.created_at == NOW
    assert ops(setup[2], "add") == 1


def test_unknown_add_that_materialized_is_promoted_on_fresh_restart(setup):
    api, clock, service = setup[2], setup[3], setup[4]
    def unknown(rule):
        api.rows += (rule,)
        raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
    api.hooks["add"] = unknown
    receipt = service.create(creation())
    assert receipt.status is Status.UNKNOWN and receipt.manifest is None
    clock.now += timedelta(days=1)
    recovered = restart(setup)[1].create(creation())
    assert recovered.status is Status.VERIFIED
    assert recovered.manifest.created_at is None
    assert recovered.manifest.dispatch_intent_at == NOW
    assert ops(api, "add") == 1


def test_unknown_remove_that_materialized_remains_unknown_without_durable_receipt(setup):
    api, clock, service = setup[2], setup[3], setup[4]
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    request = remove_request(owned, clock.now)
    def unknown(name):
        api.rows = ()
        raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
    api.hooks["remove"] = unknown
    receipt = service.remove(request)
    assert receipt.status is Status.UNKNOWN
    recovered = restart(setup)[1].remove(request)
    assert recovered.status is Status.UNKNOWN and recovered.reconciliation is Reconcile.ABSENCE_OBSERVED
    assert ops(api, "remove") == 1


def test_reconciliation_page_cursor_and_backward_clock_no_mutation(setup):
    service, clock, api = setup[4], setup[3], setup[2]
    records = [service.create(another_create()) for _ in range(3)]
    cursor, visited = None, []
    while True:
        page = service.reconcile(after=cursor, limit=1)
        if not page:
            break
        visited.append(page[0].operation_id)
        cursor = page[0].operation_id
    assert visited == sorted((record.operation_id for record in records), key=str)
    clock.now -= timedelta(minutes=1)
    calls = len(api.calls)
    observed = service.create(records[0].request)
    assert observed.reconciliation is Reconcile.UNKNOWN
    assert observed.updated_at == NOW and len(api.calls) == calls


def test_changed_store_metadata_refuses_existing_adapter_custody(setup):
    db, repo, api, _, service = setup
    service.create(creation())
    with db.connection() as connection:
        connection.execute("UPDATE response_store SET store_id=?", (str(uuid4()),))
    with pytest.raises(ResponseOperationConflict):
        repo.get(command().command_id)
    with pytest.raises(ResponseOperationConflict):
        service.create(creation())
    assert ops(api, "add") == 1 and ops(api, "remove") == 0


def test_restart_opens_persisted_store_without_caller_memory_and_missing_identity_fails_closed(setup, tmp_path):
    db, _, api, clock, service = setup
    created = service.create(creation())
    opened = SQLiteResponseLifecycleRepository(SQLiteDatabase(db.path))
    assert opened.store_id == STORE_ID
    firewall = adapter(api)
    firewall._clock = clock
    restarted = ResponseLifecycleService(opened, firewall, clock=clock)
    assert restarted.create(creation()).manifest == created.manifest
    new_db = SQLiteDatabase(tmp_path / "new-store.db")
    new_store = SQLiteResponseLifecycleRepository(new_db)
    assert new_store.store_id.version == 4
    assert SQLiteResponseLifecycleRepository(new_db).store_id == new_store.store_id
    with db.connection() as connection:
        connection.execute("DELETE FROM response_store")
    with pytest.raises(ResponseStorageError, match="store identity"):
        SQLiteResponseLifecycleRepository(db)
    assert ops(api, "add") == 1 and ops(api, "remove") == 0


def test_history_privacy_purge_preserves_response_custody(setup):
    from netsentinel.domain.storage_privacy import StorageRetentionPolicy
    from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
    db, repo, api, _, service = setup
    created = service.create(creation())
    maintenance = SQLiteStorageMaintenanceRepository(db)
    for rule in StorageRetentionPolicy().rules:
        maintenance.cleanup_chunk(rule, NOW + timedelta(days=365), rule.chunk_rows, True, lambda: False)
    assert repo.get(created.operation_id).manifest == created.manifest
    assert repo.audit() and ops(api, "remove") == 0


def test_create_same_identity_preflight_never_overwrites_foreign_rule(setup):
    api, service = setup[2], setup[4]
    from netsentinel.domain.response import expected_firewall_rule
    foreign = expected_firewall_rule(command())
    api.rows = (foreign,)
    result = service.create(creation())
    assert result.status is Status.FAILURE and result.result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert result.manifest is None and api.rows == (foreign,)
    replay = service.create(creation())
    assert replay.manifest is None and replay.reconciliation is Reconcile.EXTERNAL_MODIFIED
    assert ops(api, "add") == ops(api, "remove") == 0


def test_process_lock_blocks_another_interpreter_and_releases_on_process_exit(setup):
    db, repo = setup[0], setup[1]
    source = str(Path(__file__).resolve().parents[2] / "src")
    code = f"""
import sys
sys.path.insert(0, {source!r})
from uuid import UUID
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.response_repository import SQLiteResponseLifecycleRepository
from netsentinel.domain.response_lifecycle import ResponseOperationConflict
repo = SQLiteResponseLifecycleRepository(SQLiteDatabase({str(db.path)!r}), UUID({str(STORE_ID)!r}))
try:
    with repo.exclusive():
        pass
except ResponseOperationConflict:
    sys.exit(7)
"""
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    with repo.exclusive():
        blocked = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True, **kwargs)
        assert blocked.returncode == 7, blocked.stderr
    released = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True, **kwargs)
    assert released.returncode == 0, released.stderr
    abrupt = code.replace("        pass", "        __import__('os')._exit(0)")
    assert subprocess.run([sys.executable, "-c", abrupt], timeout=10, capture_output=True, **kwargs).returncode == 0
    after_crash = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True, **kwargs)
    assert after_crash.returncode == 0, after_crash.stderr


@pytest.mark.parametrize("field,value", [
    ("dispatch_intent_at", NOW - timedelta(seconds=1)),
    ("dispatch_intent_at", NOW + timedelta(days=1)),
    ("created_at", NOW - timedelta(seconds=1)), ("prepared_claim", None),
])
def test_witnessed_manifest_binds_dispatch_and_provenance(setup, field, value):
    owned = setup[4].create(creation()).manifest
    with pytest.raises((TypeError, ValueError)):
        replace(owned, **{field: value})
    assert owned.dispatch_intent_at == NOW
    assert setup[4].diagnostics().finalized_owned_count == 1


def test_remove_success_durable_verified_absence_and_idempotent_replay(setup):
    _, repo, api, clock, service = setup
    created = service.create(creation())
    clock.now += timedelta(seconds=1)
    request = remove_request(created.manifest, clock.now)
    removed = service.remove(request)
    assert removed.status is Status.VERIFIED and removed.reconciliation is Reconcile.REMOVED
    assert api.rows == ()
    assert service.diagnostics().finalized_owned_count == 0
    assert [row.event for row in repo.audit()][-4:] == [
        Audit.PREPARED, Audit.ATTEMPT, Audit.READBACK_VERIFIED, Audit.VERIFIED_SUCCESS]
    clock.now += timedelta(days=1)
    replay = restart(setup)[1].remove(request)
    assert replay.status is Status.VERIFIED and ops(api, "remove") == 1
    assert repo.audit()[-1].event is Audit.RECOVERY
    assert sum(row.event is Audit.VERIFIED_SUCCESS for row in repo.audit()) == 2
    reconciled = service.create(creation())
    assert reconciled.reconciliation is Reconcile.REMOVED
    assert ops(api, "add") == 1


@pytest.mark.parametrize("final_write_failed", [False, True])
def test_removal_tombstone_never_readopts_resurrected_metadata_or_allows_stale_new_remove(setup, final_write_failed):
    _, repo, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    request = remove_request(owned, clock.now)
    if final_write_failed:
        save = repo.save
        def fail(operation, event):
            if event is Audit.VERIFIED_SUCCESS:
                raise ResponseStorageError("injected finalization failure")
            return save(operation, event)
        repo.save = fail
    removed = service.remove(request)
    assert removed.status is (Status.OS_VERIFIED if final_write_failed else Status.VERIFIED)
    # A subsequent external restoration of the exact old metadata is still not
    # new ownership. No adversarial interpretation of the witness is necessary.
    api.rows = (owned.rule,)
    clock.now += timedelta(seconds=1)
    repo, service = restart(setup)
    creator = service.create(creation())
    assert creator.reconciliation is Reconcile.EXTERNAL_MODIFIED
    assert service.diagnostics().finalized_owned_count == 0
    replay = service.remove(request)
    assert replay.reconciliation is Reconcile.EXTERNAL_MODIFIED
    with pytest.raises(ResponseOperationConflict, match="archival"):
        service.remove(remove_request(owned, clock.now))
    assert ops(api, "remove") == 1 and api.rows == (owned.rule,)


@pytest.mark.parametrize("drift", ["missing", "description", "witness", "disabled", "scope", "duplicate"])
def test_owned_external_change_refuses_remove_and_preserves_foreign_state(setup, drift):
    _, _, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    rows = {
        "missing": (), "description": (replace(owned.rule, description=owned.rule.description + " changed"),),
        "witness": (replace(owned.rule, description=ownership_description(owned.creation.command.rule_id, "0" * 64)),),
        "disabled": (replace(owned.rule, enabled=False),), "scope": (replace(owned.rule, local_ports="80"),),
        "duplicate": (owned.rule, owned.rule),
    }[drift]
    api.rows = rows
    result = service.remove(remove_request(owned, clock.now))
    assert result.status is Status.FAILURE and result.result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert api.rows == rows and ops(api, "remove") == 0
    creator = service.create(creation())
    assert creator.reconciliation in {Reconcile.EXTERNAL_MISSING, Reconcile.EXTERNAL_MODIFIED,
                                     Reconcile.EXTERNALLY_DISABLED, Reconcile.AMBIGUOUS}


@pytest.mark.parametrize("definite", [True, False])
def test_remove_failure_unknown_replay_never_dispatches_again(setup, definite):
    _, _, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    api.hooks["remove"] = raises(FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE, definite_failure=definite))
    request = remove_request(owned, clock.now)
    result = service.remove(request)
    assert result.status is (Status.FAILURE if definite else Status.UNKNOWN)
    assert service.remove(request).reconciliation is Reconcile.PENDING_REMOVE
    assert ops(api, "remove") == 1 and api.rows == (owned.rule,)


@pytest.mark.parametrize("gap", ["intent", "attempt", "os_remove", "os_receipt", "final"])
def test_remove_crash_phases_without_inventing_own_removal_from_absence(setup, gap):
    _, repo, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    request = remove_request(owned, clock.now)
    if gap == "os_remove":
        def crash(name):
            api.rows = ()
            raise SystemExit("crashed after OS remove before durable receipt")
        api.hooks["remove"] = crash
    else:
        save = repo.save
        event = {"intent": Audit.PREPARED, "attempt": Audit.ATTEMPT,
                 "os_receipt": Audit.READBACK_VERIFIED, "final": Audit.VERIFIED_SUCCESS}[gap]
        def crash(operation, audit):
            value = save(operation, audit)
            if audit is event:
                raise SystemExit("crashed after durable phase")
            return value
        repo.save = crash
    with pytest.raises(SystemExit):
        service.remove(request)
    replay = restart(setup)[1].remove(request)
    if gap in {"os_receipt", "final"}:
        assert replay.status is Status.VERIFIED and replay.reconciliation is Reconcile.REMOVED
    elif gap == "os_remove":
        assert replay.status is Status.UNKNOWN and replay.reconciliation is Reconcile.ABSENCE_OBSERVED
        assert replay.result.outcome is ResponseOutcome.OUTCOME_UNKNOWN
    else:
        assert replay.status is not Status.VERIFIED and api.rows == (owned.rule,)
    assert ops(api, "remove") == (0 if gap in {"intent", "attempt"} else 1)


@pytest.mark.parametrize("event", [Audit.PREPARED, Audit.ATTEMPT, Audit.READBACK_VERIFIED, Audit.VERIFIED_SUCCESS])
def test_remove_db_failure_matrix_and_durable_receipt_recovery(setup, event):
    _, repo, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    request = remove_request(owned, clock.now)
    save = repo.save
    def fail(operation, audit):
        if audit is event:
            raise ResponseStorageError("injected storage failure")
        return save(operation, audit)
    repo.save = fail
    if event in {Audit.PREPARED, Audit.ATTEMPT}:
        with pytest.raises(ResponseStorageError):
            service.remove(request)
        assert ops(api, "remove") == 0
    else:
        receipt = service.remove(request)
        assert receipt.status is not Status.VERIFIED and api.rows == ()
        replay = restart(setup)[1].remove(request)
        if event is Audit.READBACK_VERIFIED:
            assert replay.status is Status.UNKNOWN
        else:
            assert receipt.status is Status.OS_VERIFIED and replay.status is Status.VERIFIED
        assert ops(api, "remove") == 1


@pytest.mark.parametrize("fail", [False, True])
def test_confirmed_rollback_uses_strict_remove_and_audits(setup, fail):
    _, repo, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    if fail:
        api.hooks["remove"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True))
    result = service.rollback(remove_request(owned, clock.now))
    assert result.purpose is Purpose.ROLLBACK
    events = [row.event for row in repo.audit()]
    assert Audit.ROLLBACK_ATTEMPT in events
    assert events[-1] is (Audit.ROLLBACK_FAILURE if fail else Audit.ROLLBACK_SUCCESS)


@pytest.mark.parametrize("elapsed,drift,expected", [
    (30, False, Status.VERIFIED), (0, False, Status.PREPARED),
    (3600, False, Status.PREPARED), (30, True, Status.PREPARED),
])
def test_expiry_observation_strict_confirmed_remove_no_stale_or_drift_cleanup(setup, elapsed, drift, expected):
    _, repo, api, clock, service = setup
    owned = service.create(creation()).manifest
    clock.now += timedelta(seconds=1)
    request = remove_request(owned, clock.now)
    due = clock.now + timedelta(seconds=30)
    service.schedule_expiry(request, due)
    assert repo.get(request.command.command_id).expires_at == due
    if drift:
        api.rows = (replace(owned.rule, description="External"),)
    clock.now += timedelta(seconds=elapsed)
    repo, service = restart(setup)
    records = service.reconcile()
    expiry = next(record for record in records if record.operation_id == request.command.command_id)
    assert expiry.status is expected
    assert ops(api, "remove") == (1 if expected is Status.VERIFIED else 0)
    assert owned.creation.command.spec.lifetime.expires_at is None
    if elapsed == 3600:
        assert expiry.reconciliation is Reconcile.EXPIRY_PENDING
        assert service.diagnostics().expiry_pending_count == 1
    if drift:
        assert expiry.reconciliation is Reconcile.EXTERNAL_MODIFIED


def test_expiry_requires_final_owned_manifest_and_explicit_distinct_confirmation(setup):
    claim = prepared(setup).claim
    with pytest.raises(TypeError):
        setup[4].schedule_expiry(claim, NOW)
    with pytest.raises(TypeError):
        setup[4].remove(claim)
    with pytest.raises(ValueError):
        OwnedFirewallRuleManifest(claim.creation, claim.expected_rule, NOW, NOW)
    with pytest.raises(ValueError):
        PreparedFirewallOwnershipClaim(claim.creation, claim.expected_rule, claim.witness, NOW + timedelta(days=1))


def test_replay_request_store_revision_and_stale_manifest_conflicts(setup):
    _, repo, api, clock, service = setup
    owned = service.create(creation())
    with pytest.raises(ResponseOperationConflict):
        changed = replace(creation().command, selection_generation=2)
        service.create(FirewallCreateRequest(changed, ResponseConfirmation(changed.fingerprint, NOW)))
    with pytest.raises(ResponseOperationConflict):
        repo.save(replace(owned, revision=0), Audit.RECOVERY)
    clock.now += timedelta(seconds=1)
    stale = replace(owned.manifest, verified_at=clock.now)
    with pytest.raises(ResponseOperationConflict):
        service.remove(remove_request(stale, clock.now))
    assert ops(api, "remove") == 0
    with pytest.raises(ResponseOperationConflict):
        SQLiteResponseLifecycleRepository(setup[0], uuid4())


def test_transaction_rolls_back_state_and_audit_together(setup):
    db, repo, api, _, service = setup
    with db.connection() as connection:
        connection.execute("""CREATE TRIGGER fail_response_audit BEFORE INSERT ON response_audit
            BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END""")
    with pytest.raises(ResponseStorageError):
        service.create(creation())
    assert repo.get(command().command_id) is None
    assert repo.audit() == () and ops(api, "add") == 0
    with db.connection() as connection:
        connection.execute("DROP TRIGGER fail_response_audit")
        with pytest.raises(RuntimeError):
            with transaction(connection):
                connection.execute("DELETE FROM response_store")
                raise RuntimeError("synthetic transaction rollback")
        assert connection.execute("SELECT store_id FROM response_store").fetchone()[0] == str(STORE_ID)


@pytest.mark.parametrize("phase", ["create_final", "remove_receipt", "remove_final"])
def test_real_sqlite_post_os_transaction_rollback_preserves_provenance_and_receipt_distinction(setup, phase):
    db, repo, api, clock, service = setup
    if phase == "create_final":
        action, event = "create", "verified_success"
    else:
        owned = service.create(creation()).manifest
        clock.now += timedelta(seconds=1)
        request = remove_request(owned, clock.now)
        action, event = "remove", "readback_verified" if phase == "remove_receipt" else "verified_success"
    with db.connection() as connection:
        connection.execute(f"""CREATE TRIGGER fail_post_os_audit BEFORE INSERT ON response_audit
            WHEN NEW.action='{action}' AND NEW.event='{event}'
            BEGIN SELECT RAISE(ABORT, 'synthetic post-OS failure'); END""")
    record = service.create(creation()) if phase == "create_final" else service.remove(request)
    assert record.status is not Status.VERIFIED
    assert repo.get(record.operation_id) == record
    assert not any(row.action.value == action and row.event.value == event for row in repo.audit())
    if phase == "create_final":
        assert record.manifest is None and record.claim is not None and ops(api, "add") == 1
    else:
        assert api.rows == () and ops(api, "remove") == 1
        assert record.status is (Status.PARTIAL if phase == "remove_receipt" else Status.OS_VERIFIED)
    with db.connection() as connection:
        connection.execute("DROP TRIGGER fail_post_os_audit")
    _, restarted = restart(setup)
    recovered = restarted.create(creation()) if phase == "create_final" else restarted.remove(request)
    if phase == "remove_receipt":
        assert recovered.status is Status.UNKNOWN and recovered.reconciliation is Reconcile.ABSENCE_OBSERVED
    else:
        assert recovered.status is Status.VERIFIED
    assert ops(api, "add") == 1
    assert ops(api, "remove") == (0 if phase == "create_final" else 1)


def test_audit_retention_does_not_prune_active_claim_manifest_or_idempotency(setup):
    db, repo, _, _, service = setup
    record = service.create(creation())
    with db.connection() as connection, transaction(connection):
        connection.executemany("""INSERT INTO response_audit
            (operation_id,rule_id,action,at,event,status,reconciliation)
            VALUES (?,?,'create',?,'recovery','verified','exact')""",
            [(str(record.operation_id), str(record.command.rule_id), NOW.isoformat(timespec="microseconds"))]
            * (MAX_RESPONSE_AUDIT_ROWS + 10))
    updated = service.create(creation())
    with db.connection() as connection:
        assert connection.execute("SELECT count(*) FROM response_audit").fetchone()[0] == MAX_RESPONSE_AUDIT_ROWS
        assert connection.execute("SELECT min(sequence) FROM response_audit").fetchone()[0] > 1
    assert repo.get(record.operation_id).manifest == record.manifest
    assert updated.claim == record.claim and updated.revision > record.revision
    assert [row.sequence for row in repo.audit()] == sorted(row.sequence for row in repo.audit())


def test_duplicate_witness_unique_constraint_rollback(setup, monkeypatch):
    from netsentinel.application import response_lifecycle_service as module
    monkeypatch.setattr(module.secrets, "token_hex", lambda size: "1" * 64)
    setup[4].create(another_create())
    with pytest.raises(ResponseStorageError):
        setup[4].create(another_create())
    assert len(setup[1].page()) == 1 and ops(setup[2], "add") == 1


@pytest.mark.parametrize("corruption", [
    "fingerprint='bad'", "witness='bad'", "status='future'", "reconciliation='future'",
    "request=x'ff'", "manifest=x'ff'", "revision=0",
])
def test_corrupt_custody_refuses_read_replay_and_mutation(setup, corruption):
    db, repo, api, _, service = setup
    service.create(creation())
    with db.connection() as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("UPDATE response_operations SET " + corruption)
    with pytest.raises(ResponseStorageError):
        repo.get(command().command_id)
    with pytest.raises(ResponseStorageError):
        service.create(creation())
    with pytest.raises(ResponseStorageError):
        service.create(another_create())
    assert ops(api, "add") == 1 and ops(api, "remove") == 0


def test_reconciliation_unknown_sanitized_diagnostics_no_repairs(setup):
    _, repo, api, _, service = setup
    service.create(creation())
    api.hooks["read"] = raises(RuntimeError("sensitive backend detail"))
    record = service.reconcile()[0]
    assert record.reconciliation is Reconcile.UNKNOWN
    diagnostics = repo.diagnostics()
    assert diagnostics.reconciliation_error_count == 1
    assert diagnostics.last_reconciliation_at == NOW
    assert "sensitive" not in repr(diagnostics) and "response witness" not in repr(diagnostics)
    assert ops(api, "add") == 1 and ops(api, "remove") == 0


def test_bounded_queries_and_audit_limits(setup):
    repo = setup[1]
    assert MAX_RESPONSE_ACTIVE_RULES == 64 and MAX_RESPONSE_OPERATIONS == 1024
    for bad in (0, -1, 65, True):
        with pytest.raises(ValueError):
            repo.page(limit=bad)
    for bad in (0, -1, 101, True):
        with pytest.raises(ValueError):
            repo.audit(limit=bad)
    with pytest.raises(TypeError):
        repo.get("wrong")
    with pytest.raises(TypeError):
        repo.page(after="wrong")
    with pytest.raises(ValueError):
        repo.audit(after_sequence=-1)


@pytest.mark.parametrize("kind", ["active", "operations"])
def test_admission_capacity_refuses_before_os_mutation(setup, monkeypatch, kind):
    from netsentinel.infrastructure.sqlite import response_repository as module
    monkeypatch.setattr(module, "MAX_RESPONSE_ACTIVE_RULES" if kind == "active" else "MAX_RESPONSE_OPERATIONS",
                        1 if kind == "active" else 2)
    setup[4].create(another_create())
    with pytest.raises(ResponseOperationConflict):
        setup[4].create(another_create())
    assert ops(setup[2], "add") == 1


def test_create_reserves_minimum_cleanup_capacity_without_pruning_idempotency(setup, monkeypatch):
    from netsentinel.infrastructure.sqlite import response_repository as module
    monkeypatch.setattr(module, "MAX_RESPONSE_OPERATIONS", 4)
    service, clock, api = setup[4], setup[3], setup[2]
    first = service.create(another_create())
    second = service.create(another_create())
    with pytest.raises(ResponseOperationConflict, match="reserved"):
        service.create(another_create())
    clock.now += timedelta(seconds=1)
    assert service.remove(remove_request(first.manifest, clock.now)).status is Status.VERIFIED
    assert service.remove(remove_request(second.manifest, clock.now)).status is Status.VERIFIED
    assert len(setup[1].page()) == 4 and ops(api, "add") == ops(api, "remove") == 2
    assert setup[1].get(first.operation_id).claim == first.claim


def test_failed_remove_retries_cannot_consume_other_rules_reserved_first_cleanup(setup, monkeypatch):
    from netsentinel.infrastructure.sqlite import response_repository as module
    monkeypatch.setattr(module, "MAX_RESPONSE_OPERATIONS", 4)
    service, clock, api = setup[4], setup[3], setup[2]
    first = service.create(another_create())
    second = service.create(another_create())
    clock.now += timedelta(seconds=1)
    api.hooks["remove"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True))
    assert service.remove(remove_request(first.manifest, clock.now)).status is Status.FAILURE
    with pytest.raises(ResponseOperationConflict, match="reserved"):
        service.remove(remove_request(first.manifest, clock.now))
    del api.hooks["remove"]
    assert service.remove(remove_request(second.manifest, clock.now)).status is Status.VERIFIED
    assert len(setup[1].page()) == 4 and api.rows == (first.manifest.rule,)


@pytest.mark.parametrize("other", ["replay_create", "reconciliation", "remove", "expiry"])
def test_cross_instance_thread_concurrency_during_com_has_no_sqlite_transaction(setup, other):
    db, repo, api, clock, service = setup
    entered, release = ThreadEvent(), ThreadEvent()
    if other != "replay_create":
        owned = service.create(creation()).manifest
        clock.now += timedelta(seconds=1)
        request = remove_request(owned, clock.now)
        # Block during Remove while a fresh SQLite connection remains writable.
        def hook(name):
            entered.set()
            assert release.wait(5)
            api.rows = ()
        api.hooks["remove"] = hook
        def action():
            return service.remove(request)
    else:
        def hook(rule):
            entered.set()
            assert release.wait(5)
            api.rows += (rule,)
        api.hooks["add"] = hook
        def action():
            return service.create(creation())
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(action)
        assert entered.wait(5)
        try:
            # A short write transaction succeeds while fake COM is blocked.
            with db.connection() as connection, transaction(connection):
                connection.execute("UPDATE response_store SET store_id=store_id")
            _, second = restart(setup)
            with pytest.raises(ResponseOperationConflict, match="busy"):
                if other == "replay_create":
                    second.create(creation())
                elif other == "reconciliation":
                    second.reconcile()
                elif other == "expiry":
                    second.schedule_expiry(request, clock.now + timedelta(seconds=10))
                else:
                    second.remove(request)
        finally:
            release.set()
        assert future.result(timeout=5).status is Status.VERIFIED
    assert ops(api, "add") == 1
    if other != "replay_create":
        assert ops(api, "remove") == 1
    assert repo.get(command().command_id).manifest is not None
