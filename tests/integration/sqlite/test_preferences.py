"""NS-080 real SQLite migration, audit, restart, corruption and race acceptance."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import sqlite3
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from netsentinel.application.services.preferences import ScopedPreferenceService
from netsentinel.domain.preferences import (
    PreferenceAuditAction, PreferenceLifetime, PreferenceLifetimeKind, PreferenceSelector,
    PreferenceResultStatus as Status, PreferenceStatus, PreferenceStoragePolicy,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, SQLiteConnectionFactory
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
from tests.fixtures.preferences import NOW, ORIGIN, FP, RULE, application, definition, destination, revision


@pytest.fixture
def database(tmp_path):
    return SQLiteDatabase(tmp_path / "preferences.sqlite3")


@pytest.fixture
def repository(database):
    return SQLiteScopedPreferenceRepository(database)


def create(repo, d=None, identity=None, now=NOW):
    return repo.create(identity or uuid4(), d if d is not None else definition(), ORIGIN, now)


def edit(repo, old, d, *, now=NOW):
    return repo.edit(old.preference_id, old.revision, d, ORIGIN, now)


def revoke(repo, old, *, now=NOW):
    return repo.revoke(old.preference_id, old.revision, "Explicit undo", ORIGIN, now)


def counts(db):
    with db.connection() as c:
        return (c.execute("SELECT COUNT(*) FROM scoped_preferences").fetchone()[0],
                c.execute("SELECT COUNT(*) FROM scoped_preference_revisions").fetchone()[0])


@pytest.mark.parametrize("selector", [
    PreferenceSelector(rule_id=RULE), PreferenceSelector(application=application()),
    PreferenceSelector(destination=destination()), PreferenceSelector(destination=destination("2001:db8::1")),
    PreferenceSelector(network_fingerprint=FP), PreferenceSelector(application(), destination=destination()),
    PreferenceSelector(application(), network_fingerprint=FP),
    PreferenceSelector(application(), revision(), destination(), FP, RULE),
])
@pytest.mark.parametrize("permanent", [False, True])
def test_create_roundtrip_all_scopes_and_lifetimes(repository, selector, permanent):
    d = definition(selector, permanent=permanent)
    result = create(repository, d)
    assert result.status is Status.CREATED
    p = result.preference
    assert p.definition == d and p.revision == 1
    assert p.created_origin is p.action_origin is ORIGIN
    assert p.action is PreferenceAuditAction.CREATE
    assert p.created_at == p.recorded_at == NOW
    assert repository.get_current(p.preference_id).preference == p
    assert repository.get_history(p.preference_id).entries[0].preference == p


def test_edit_revoke_audit_restart_and_idempotency(database, repository):
    service = ScopedPreferenceService(repository)
    p = service.create(definition(), origin=ORIGIN, now=NOW).preference
    assert create(repository, p.definition, p.preference_id).status is Status.NO_CHANGE
    assert create(repository, definition(reason="different"), p.preference_id).status is Status.CONFLICT
    new = definition(PreferenceSelector(application(), destination=destination("2001:db8::1")), permanent=True, reason="Changed scope and lifetime")
    updated = service.edit(p.preference_id, new, expected_revision=1, origin=ORIGIN, now=NOW + timedelta(minutes=1))
    assert updated.status is Status.UPDATED
    second = updated.preference
    assert second.revision == 2 and second.created_at == p.created_at
    assert second.created_origin is p.created_origin
    assert edit(repository, second, new).status is Status.INVALID  # Backward audit clock.
    assert edit(repository, second, new, now=NOW + timedelta(minutes=2)).status is Status.NO_CHANGE
    assert edit(repository, p, new).status is Status.CONFLICT
    assert revoke(repository, p).status is Status.CONFLICT
    result = service.revoke(p.preference_id, expected_revision=2, reason="Explicit undo", origin=ORIGIN, now=NOW + timedelta(minutes=3))
    assert result.status is Status.REVOKED and result.preference.revision == 3
    assert result.preference.status_at(NOW) is PreferenceStatus.REVOKED
    assert revoke(repository, second, now=NOW + timedelta(minutes=4)).status is Status.ALREADY_REVOKED
    assert revoke(repository, result.preference, now=NOW + timedelta(minutes=4)).status is Status.ALREADY_REVOKED
    assert revoke(repository, p).status is Status.CONFLICT
    assert edit(repository, result.preference, definition()).status is Status.INVALID
    reopened = SQLiteScopedPreferenceRepository(SQLiteDatabase(database.path))
    assert reopened.get_current(p.preference_id).preference == result.preference
    history = reopened.get_history(p.preference_id)
    assert [x.preference.revision for x in history.entries] == [3, 2, 1]
    assert [x.preference.action for x in history.entries] == [PreferenceAuditAction.REVOKE, PreferenceAuditAction.EDIT, PreferenceAuditAction.CREATE]
    assert history.entries[-1].preference == p
    assert history.entries[1].preference == second
    assert counts(database) == (1, 3)


def test_expiry_never_deletes_and_explicit_extension_is_audited(database, repository):
    p = create(repository).preference
    expiry = p.definition.lifetime.expires_at
    assert repository.get_current(p.preference_id).preference.status_at(expiry) is PreferenceStatus.EXPIRED
    assert counts(database) == (1, 1)
    later = expiry + timedelta(hours=1)
    assert edit(repository, p, p.definition, now=later).status is Status.NO_CHANGE
    assert edit(repository, p, replace(p.definition, reason="still expired"), now=later).status is Status.INVALID
    extended = replace(p.definition, lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, later + timedelta(days=1)))
    result = edit(repository, p, extended, now=later)
    assert result.status is Status.UPDATED and result.preference.status_at(later) is PreferenceStatus.ACTIVE
    assert repository.get_history(p.preference_id).entries[-1].preference.definition.lifetime.expires_at == expiry
    assert revoke(repository, result.preference, now=later + timedelta(days=2)).status is Status.REVOKED
    assert counts(database) == (1, 3)


@pytest.mark.parametrize("kind", ["edit", "revoke"])
def test_concurrent_changes_are_serialized_without_lost_update(repository, database, kind):
    p = create(repository).preference
    barrier = Barrier(2)

    def change(index):
        barrier.wait(timeout=5)
        if kind == "revoke":
            return revoke(repository, p)
        return edit(repository, p, definition(reason=f"Change {index}"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, range(2)))
    expected = {Status.REVOKED, Status.ALREADY_REVOKED} if kind == "revoke" else {Status.UPDATED, Status.CONFLICT}
    assert {r.status for r in results} == expected
    assert counts(database) == (1, 2)
    assert repository.get_current(p.preference_id).preference.revision == 2


def test_distinct_ids_identical_definition_remain_distinct_user_decisions(repository):
    first, second = create(repository), create(repository)
    assert first.status is second.status is Status.CREATED
    assert first.preference_id != second.preference_id
    assert len(repository.list_current().entries) == 2


def test_restore_previous_values_is_a_new_audited_edit(repository):
    first = create(repository).preference
    second = edit(repository, first, definition(reason="different")).preference
    third = edit(repository, second, first.definition).preference
    assert third.revision == 3 and third.definition == first.definition
    assert repository.get_current(first.preference_id).preference == third
    assert len(repository.get_history(first.preference_id).entries) == 3


def test_concurrent_create_retries_and_capacity(database):
    repo = SQLiteScopedPreferenceRepository(database, PreferenceStoragePolicy(max_active_preferences=1))
    identity, barrier = uuid4(), Barrier(2)

    def retry(_):
        barrier.wait(timeout=5)
        return create(repo, identity=identity)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(retry, range(2)))
    assert {r.status for r in results} == {Status.CREATED, Status.NO_CHANGE}
    assert counts(database) == (1, 1)
    assert create(repo).status is Status.CAPACITY_REACHED


def test_max_reason_unicode_and_sql_like_note_roundtrip(repository):
    for reason in ("x" * 512, "\U0001f310" * 512, "'; DROP TABLE device_profiles; --"):
        result = create(repository, definition(reason=reason))
        assert result.status is Status.CREATED
        assert repository.get_current(result.preference_id).preference.definition.reason == reason


def test_bounded_deterministic_list_and_history_pagination(repository):
    ids = [UUID(int=i) for i in (3, 1, 2)]
    for identity in ids:
        create(repository, identity=identity)
    page = repository.list_current(limit=2)
    assert [p.preference_id for p in page.entries] == [UUID(int=1), UUID(int=2)] and page.truncated
    rest = repository.list_current(limit=2, after_id=page.entries[-1].preference_id)
    assert [p.preference_id for p in rest.entries] == [UUID(int=3)] and not rest.truncated
    p = repository.get_current(ids[0]).preference
    p = edit(repository, p, definition(reason="second")).preference
    p = revoke(repository, p).preference
    page = repository.get_history(p.preference_id, limit=2)
    assert [x.preference.revision for x in page.entries] == [3, 2] and page.truncated
    rest = repository.get_history(p.preference_id, limit=2, before_revision=2)
    assert [x.preference.revision for x in rest.entries] == [1] and not rest.truncated
    assert repository.get_history(p.preference_id, before_revision=1).entries == ()
    missing = uuid4()
    assert repository.get_current(missing).status is Status.NOT_FOUND
    assert repository.get_history(missing).status is Status.NOT_FOUND
    assert repository.edit(missing, 1, definition(), ORIGIN, NOW).status is Status.NOT_FOUND
    assert repository.revoke(missing, 1, "Undo", ORIGIN, NOW).status is Status.NOT_FOUND


@pytest.mark.parametrize("limit", [0, -1, True, 101, None])
def test_list_bounds_reject_invalid_limit(repository, limit):
    with pytest.raises(ValueError):
        repository.list_current(limit=limit)


@pytest.mark.parametrize("limit", [0, -1, True, 65, None])
def test_history_bounds_reject_invalid_limit(repository, limit):
    with pytest.raises(ValueError):
        repository.get_history(uuid4(), limit=limit)


@pytest.mark.parametrize("reason", ["", "x" * 513, "new\nline"])
def test_revoke_reason_validation_and_no_partial_write(repository, database, reason):
    p = create(repository).preference
    assert repository.revoke(p.preference_id, 1, reason, ORIGIN, NOW).status is Status.INVALID
    assert counts(database) == (1, 1)


def test_invalid_commands_and_expired_create_do_not_write(repository, database):
    identity = uuid4()
    assert repository.create(identity, None, ORIGIN, NOW).status is Status.INVALID
    assert repository.create(identity, definition(), "manual_user", NOW).status is Status.INVALID
    assert repository.create(identity, definition(), ORIGIN, NOW.replace(tzinfo=None)).status is Status.INVALID
    assert repository.create(UUID(int=0), definition(), ORIGIN, NOW).status is Status.INVALID
    expiry = definition().lifetime.expires_at
    assert repository.create(identity, definition(), ORIGIN, expiry).status is Status.INVALID
    p = create(repository).preference
    assert repository.edit(p.preference_id, True, definition(), ORIGIN, NOW).status is Status.INVALID
    assert repository.edit(p.preference_id, 1, None, ORIGIN, NOW).status is Status.INVALID
    assert counts(database) == (1, 1)


def test_active_total_and_revoke_reservation_budgets(database):
    policy = PreferenceStoragePolicy(max_active_preferences=1, max_preferences=2, max_revisions=3, max_audit_revisions=5)
    repo = SQLiteScopedPreferenceRepository(database, policy)
    p = create(repo, definition(permanent=True)).preference
    assert create(repo).status is Status.CAPACITY_REACHED
    p = edit(repo, p, definition(permanent=True, reason="Edited")).preference
    assert edit(repo, p, definition(permanent=True, reason="Another edit")).status is Status.CAPACITY_REACHED
    assert edit(repo, p, p.definition).status is Status.NO_CHANGE
    assert revoke(repo, p).status is Status.REVOKED  # Final slot remains available.
    p2 = create(repo).preference
    assert edit(repo, p2, definition(reason="Global cap")).status is Status.CAPACITY_REACHED
    assert revoke(repo, p2).status is Status.REVOKED
    assert counts(database) == (2, 5)
    assert create(repo).status is Status.CAPACITY_REACHED  # Total logical cap.


def test_expired_policy_consumes_unrevoked_budget(database):
    repo = SQLiteScopedPreferenceRepository(database, PreferenceStoragePolicy(max_active_preferences=1))
    p = create(repo).preference
    later = NOW + timedelta(days=1)
    assert create(repo, definition(permanent=True), now=later).status is Status.CAPACITY_REACHED
    assert revoke(repo, p, now=later).status is Status.REVOKED
    assert create(repo, definition(permanent=True), now=later).status is Status.CREATED


@pytest.mark.parametrize("column,value,status", [
    ("rule_id", "bad*", Status.CORRUPT), ("application_key", "instance:v1:7:1", Status.CORRUPT),
    ("application_key", "x" * 10000, Status.CORRUPT), ("destination_value", "bad", Status.CORRUPT),
    ("destination_value", "x" * 10000, Status.CORRUPT), ("network_fingerprint", "bad", Status.CORRUPT),
    ("lifetime_kind", "permanent", Status.CORRUPT), ("expires_at", None, Status.CORRUPT),
    ("expires_at", "2026-10-04T09:00:00", Status.CORRUPT),
    ("reason", "x" * 10000, Status.CORRUPT), ("reason", "new\nline", Status.CORRUPT),
    ("reason", "tampered", Status.CORRUPT), ("status", "expired", Status.CORRUPT),
    ("format_version", 2, Status.UNSUPPORTED_VERSION), ("format_version", "bad", Status.CORRUPT),
])
def test_corrupt_or_future_row_does_not_hide_other_preferences(repository, database, column, value, status):
    original = create(repository, definition(PreferenceSelector(application(), revision(), destination(), FP, RULE))).preference
    valid = create(repository).preference
    with database.connection() as c:
        c.execute("PRAGMA ignore_check_constraints = ON")
        # column is a fixed test allowlist, never user input.
        c.execute(f"UPDATE scoped_preference_revisions SET {column} = ? WHERE preference_id = ?", (value, str(original.preference_id)))
    assert repository.get_current(original.preference_id).status is status
    assert repository.get_current(valid.preference_id).preference == valid
    assert {r.status for r in repository.list_current().entries} == {status, Status.FOUND}
    assert edit(repository, original, definition()).status is status


def test_corrupt_pointer_and_historical_row_are_explicit(repository, database):
    p = create(repository).preference
    second = edit(repository, p, definition(reason="second")).preference
    with database.connection() as c:
        c.execute("UPDATE scoped_preference_revisions SET reason = 'tampered' WHERE preference_id = ? AND revision = 1", (str(p.preference_id),))
    assert repository.get_current(p.preference_id).preference == second
    assert [r.status for r in repository.get_history(p.preference_id).entries] == [Status.FOUND, Status.CORRUPT]
    c = SQLiteConnectionFactory(database.path).connect()
    try:
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("UPDATE scoped_preferences SET last_revision = 99 WHERE preference_id = ?", (str(p.preference_id),))
    finally:
        c.close()
    assert repository.get_current(p.preference_id).status is Status.CORRUPT
    assert repository.list_current().entries[0].status is Status.CORRUPT


def test_db_failure_and_edit_transaction_rollback_are_sanitized(repository, database):
    p = create(repository).preference
    with database.connection() as c:
        c.execute("""CREATE TRIGGER preference_pointer_failure BEFORE UPDATE ON scoped_preferences
            BEGIN SELECT RAISE(ABORT, 'private path/user note'); END""")
    failed = edit(repository, p, definition(reason="changed"))
    assert failed.status is Status.UNAVAILABLE and "private" not in repr(failed)
    assert counts(database) == (1, 1)
    assert repository.get_current(p.preference_id).preference == p
    with database.connection() as c:
        c.execute("DROP TRIGGER preference_pointer_failure")
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("DROP TABLE scoped_preference_revisions")
    assert repository.get_current(p.preference_id).status is Status.UNAVAILABLE
    assert repository.get_history(p.preference_id).status is Status.UNAVAILABLE
    assert repository.list_current().status is Status.UNAVAILABLE
    assert create(repository).status is Status.UNAVAILABLE
    assert revoke(repository, p).status is Status.UNAVAILABLE


def test_create_failure_rolls_back_parent_and_bad_database_path_is_unavailable(repository, database, tmp_path):
    with database.connection() as c:
        c.execute("""CREATE TRIGGER preference_append_failure BEFORE INSERT ON scoped_preference_revisions
            BEGIN SELECT RAISE(ABORT, 'private note'); END""")
    assert create(repository).status is Status.UNAVAILABLE
    assert counts(database) == (0, 0)
    broken = SQLiteScopedPreferenceRepository(SQLiteDatabase(tmp_path))
    assert create(broken).status is Status.UNAVAILABLE
    assert broken.get_current(uuid4()).status is Status.UNAVAILABLE


def test_stored_preference_does_not_change_risk_alert_notification_or_assessment(tmp_path):
    from tests.integration.test_risk_alert_pipeline import Harness

    control = Harness(tmp_path / "control.db")
    expected = control.process()
    preferred = Harness(tmp_path / "preferred.db")
    repo = SQLiteScopedPreferenceRepository(preferred.database)
    p = create(repo, definition(permanent=True)).preference
    actual = preferred.process()
    assert actual.assessment.revision.snapshot == expected.assessment.revision.snapshot
    assert actual.alert.severity == expected.alert.severity
    assert actual.alert.fingerprint == expected.alert.fingerprint
    assert len(preferred.intents) == len(control.intents) == 1
    old = preferred.assessments.latest(actual.assessment.revision.key.assessment_id)
    p = edit(repo, p, definition(permanent=True, reason="Explicit edit")).preference
    assert revoke(repo, p).status is Status.REVOKED
    assert preferred.assessments.latest(actual.assessment.revision.key.assessment_id) == old
    assert preferred.alerts.get(actual.alert.id) == actual.alert


def test_016_upgrade_leaves_all_existing_rows_and_migrations_unchanged(tmp_path):
    from tests.integration.sqlite.test_device_profiles import observed, profile
    from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository, SQLiteDeviceProfileRepository

    path = tmp_path / "legacy.db"
    old = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:16]))
    device = observed(SQLiteDeviceRepository(old))
    original = SQLiteDeviceProfileRepository(old).create(device.device_id, profile())
    with old.connection() as c:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        before = {t: sorted((tuple(r) for r in c.execute(f'SELECT * FROM "{t}"')), key=repr) for t in tables}
        schema_before = [tuple(r) for r in c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")]
        assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 16
    new = SQLiteDatabase(path)
    with new.connection() as c:
        assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
        for t, rows in before.items():
            current = sorted((tuple(r) for r in c.execute(f'SELECT * FROM "{t}"')), key=repr)
            if t == "schema_migrations":
                current = [row for row in current if row[0] <= 16]
            assert current == rows
        schema_after = [tuple(r) for r in c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")]
        assert all(row in schema_after for row in schema_before)
        assert c.execute("PRAGMA foreign_key_check").fetchall() == []
    assert SQLiteDeviceProfileRepository(new).get(original.profile_id) == original
    repo = SQLiteScopedPreferenceRepository(new)
    assert repo.list_current().entries == ()  # No device trust conversion.
    p = create(repo).preference
    edit(repo, p, definition(reason="changed"))
    assert SQLiteDeviceProfileRepository(new).get(original.profile_id) == original
    assert counts(new) == (1, 2)


def test_original_migration_016_hash_is_frozen():
    data = Path("src/netsentinel/infrastructure/sqlite/schema/016_alert_risk_scope.sql").read_bytes().replace(b"\r\n", b"\n")
    assert sha256(data).hexdigest() == "479e9f002a47f76061a7228ea63ea204750a81cf85b41bf19d76cb008a95aa4f"


@pytest.mark.parametrize("change", [
    {"rule_id": None}, {"lifetime_kind": "permanent"}, {"expires_at": None},
    {"application_revision": "b" * 64}, {"destination_kind": "ipv6"},
    {"status": "revoked"}, {"revision": 0}, {"rule_id": "bad*"},
])
def test_sql_constraints_reject_contradictory_storage(repository, database, change):
    p = create(repository).preference
    column, value = next(iter(change.items()))
    with database.connection() as c, pytest.raises(sqlite3.IntegrityError):
        c.execute(f"UPDATE scoped_preference_revisions SET {column} = ? WHERE preference_id = ?", (value, str(p.preference_id)))


def test_logical_id_cannot_be_null(database):
    with database.connection() as c, pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO scoped_preferences (preference_id, created_at, created_origin, last_revision) VALUES (NULL, ?, 'manual_user', 1)", (NOW.isoformat(timespec="microseconds"),))
