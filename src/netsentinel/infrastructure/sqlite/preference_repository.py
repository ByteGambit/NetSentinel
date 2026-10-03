"""NS-080 parameterized, bounded, atomic preference revision storage."""

from dataclasses import replace
from datetime import datetime
import sqlite3
from uuid import UUID

from netsentinel.domain.application_identity import (
    ApplicationIdentity, ApplicationIdentityEvidence, ApplicationIdentityQuality, ApplicationRevision,
)
from netsentinel.domain.connections import ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.preferences import (
    MAX_PREFERENCE_HISTORY, MAX_PREFERENCE_QUERY, PREFERENCE_FORMAT_VERSION,
    DestinationKind, PreferenceAuditAction, PreferenceDefinition, PreferenceDestination,
    PreferenceEffect, PreferenceLifetime, PreferenceLifetimeKind, PreferenceOrigin,
    PreferencePage, PreferenceResult, PreferenceResultStatus as Status, PreferenceSelector,
    PreferenceStatus, PreferenceStoragePolicy, ScopedPreference,
    preference_id as validate_id, preference_reason, preference_time, revision_number,
)
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction

# Trusted column vocabulary. Gate corrupt/oversize text in SQL before fetching it.
_TEXT_BOUNDS = {
    "action": 6, "status": 7, "recorded_at": 32, "action_origin": 11, "effect": 25,
    "application_key": 4096, "application_revision": 64, "destination_kind": 4,
    "destination_value": 45, "network_fingerprint": 64, "rule_id": 64,
    "lifetime_kind": 10, "expires_at": 32, "reason": 2048, "content_fingerprint": 64,
}
_COLUMNS = ("preference_id", "revision", "format_version", *_TEXT_BOUNDS)
_SELECT = """SELECT p.preference_id, p.last_revision,
 CASE WHEN typeof(p.created_at) = 'text' AND length(p.created_at) = 32 THEN p.created_at END AS created_at,
 CASE WHEN p.created_origin = 'manual_user' THEN p.created_origin END AS created_origin,
 r.revision, r.format_version, """ + ", ".join(
    f"CASE WHEN r.{name} IS NULL OR (typeof(r.{name}) = 'text' AND length(CAST(r.{name} AS BLOB)) <= {bound}) THEN r.{name} END AS {name}"
    for name, bound in _TEXT_BOUNDS.items()
) + ", (" + " OR ".join(
    f"(r.{name} IS NOT NULL AND (typeof(r.{name}) != 'text' OR length(CAST(r.{name} AS BLOB)) > {bound}))"
    for name, bound in _TEXT_BOUNDS.items()
) + """ ) AS invalid_text,
 (SELECT MAX(x.revision) FROM scoped_preference_revisions x WHERE x.preference_id = p.preference_id) AS actual_revision,
 (SELECT COUNT(*) FROM scoped_preference_revisions x WHERE x.preference_id = p.preference_id) AS revision_count
 FROM scoped_preferences p LEFT JOIN scoped_preference_revisions r ON r.preference_id = p.preference_id """
_INSERT = "INSERT INTO scoped_preference_revisions (" + ", ".join(_COLUMNS) + ") VALUES (" + ", ".join("?" for _ in _COLUMNS) + ")"


def _decode(row: sqlite3.Row, *, latest: bool = False) -> PreferenceResult:
    identity = None
    try:
        identity = UUID(row["preference_id"])
        validate_id(identity)
        if str(identity) != row["preference_id"]:
            raise ValueError("noncanonical ID")
        if row["invalid_text"]:
            raise ValueError("invalid or oversized text")
        version = row["format_version"]
        if type(version) is not int or version < 1:
            raise ValueError("invalid format")
        if version != PREFERENCE_FORMAT_VERSION:
            return PreferenceResult(Status.UNSUPPORTED_VERSION, preference_id=identity)
        revision_number(row["last_revision"])
        if row["actual_revision"] != row["last_revision"] or row["revision_count"] != row["last_revision"] or (latest and row["revision"] != row["last_revision"]):
            raise ValueError("inconsistent revision history")
        app = None if row["application_key"] is None else ApplicationIdentity(
            ApplicationIdentityQuality.STABLE, row["application_key"],
            ApplicationIdentityEvidence.EXECUTABLE_PATH, ProcessInfoStatus.AVAILABLE,
        )
        revision = None if row["application_revision"] is None else ApplicationRevision(
            row["application_revision"], ExecutableHashStatus.AVAILABLE,
        )
        if (row["destination_kind"] is None) != (row["destination_value"] is None):
            raise ValueError("incomplete destination")
        destination = None if row["destination_kind"] is None else PreferenceDestination(
            DestinationKind(row["destination_kind"]), row["destination_value"],
        )
        definition = PreferenceDefinition(
            PreferenceSelector(app, revision, destination, row["network_fingerprint"], row["rule_id"]),
            PreferenceLifetime(PreferenceLifetimeKind(row["lifetime_kind"]),
                               datetime.fromisoformat(row["expires_at"]) if row["expires_at"] is not None else None),
            row["reason"], PreferenceEffect(row["effect"]),
        )
        if definition.content_fingerprint != row["content_fingerprint"]:
            raise ValueError("content integrity mismatch")
        value = ScopedPreference(
            identity, row["revision"], definition, datetime.fromisoformat(row["created_at"]),
            PreferenceOrigin(row["created_origin"]), datetime.fromisoformat(row["recorded_at"]),
            PreferenceOrigin(row["action_origin"]), PreferenceAuditAction(row["action"]),
            PreferenceStatus(row["status"]), version,
        )
        return PreferenceResult(Status.FOUND, value, identity)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return PreferenceResult(Status.CORRUPT, preference_id=identity)


class SQLiteScopedPreferenceRepository:
    """Each operation owns a short-lived connection; never use on the GUI thread."""

    def __init__(self, database: SQLiteDatabase, policy: PreferenceStoragePolicy | None = None) -> None:
        self._database = database
        self.policy = policy if policy is not None else PreferenceStoragePolicy()
        if type(self.policy) is not PreferenceStoragePolicy:
            raise TypeError("storage policy must be typed")

    @staticmethod
    def _current(connection: sqlite3.Connection, identity: UUID) -> PreferenceResult:
        row = connection.execute(
            _SELECT + "WHERE p.preference_id = ? AND (r.revision = p.last_revision OR r.revision IS NULL) LIMIT 1",
            (str(identity),),
        ).fetchone()
        if row is None:
            parent = connection.execute("SELECT 1 FROM scoped_preferences WHERE preference_id = ?", (str(identity),)).fetchone()
            return PreferenceResult(Status.CORRUPT if parent else Status.NOT_FOUND, preference_id=identity)
        return _decode(row, latest=True)

    def get_current(self, preference_id: UUID) -> PreferenceResult:
        validate_id(preference_id)
        try:
            with self._database.connection() as connection, transaction(connection):
                return self._current(connection, preference_id)
        except (SQLiteAdapterError, sqlite3.Error):
            return PreferenceResult(Status.UNAVAILABLE, preference_id=preference_id)

    def get_history(self, preference_id: UUID, *, limit: int = 32,
                    before_revision: int | None = None) -> PreferencePage:
        validate_id(preference_id)
        self._limit(limit, MAX_PREFERENCE_HISTORY)
        if before_revision is not None:
            revision_number(before_revision)
        try:
            with self._database.connection() as connection, transaction(connection):
                current = self._current(connection, preference_id)
                if current.status in (Status.NOT_FOUND, Status.CORRUPT):
                    return PreferencePage(current.status)
                rows = connection.execute(
                    _SELECT + "WHERE p.preference_id = ? AND (? IS NULL OR r.revision < ?) ORDER BY r.revision DESC LIMIT ?",
                    (str(preference_id), before_revision, before_revision, limit + 1),
                ).fetchall()
                return PreferencePage(Status.FOUND, tuple(_decode(row) for row in rows[:limit]), len(rows) > limit)
        except (SQLiteAdapterError, sqlite3.Error):
            return PreferencePage(Status.UNAVAILABLE)

    def list_current(self, *, limit: int = 100, after_id: UUID | None = None) -> PreferencePage:
        self._limit(limit, MAX_PREFERENCE_QUERY)
        if after_id is not None:
            validate_id(after_id)
        try:
            with self._database.connection() as connection, transaction(connection):
                # A separate parent page ensures corrupt pointers cannot hide a policy.
                parents = connection.execute(
                    "SELECT CASE WHEN typeof(preference_id) = 'text' AND length(preference_id) = 36 THEN preference_id END FROM scoped_preferences WHERE (? IS NULL OR preference_id > ?) ORDER BY preference_id LIMIT ?",
                    (str(after_id) if after_id else None, str(after_id) if after_id else None, limit + 1),
                ).fetchall()
                entries = []
                for row in parents[:limit]:
                    try:
                        identity = UUID(row[0])
                        validate_id(identity)
                        if str(identity) != row[0]:
                            raise ValueError("noncanonical ID")
                    except (TypeError, ValueError, AttributeError):
                        entries.append(PreferenceResult(Status.CORRUPT))
                    else:
                        entries.append(self._current(connection, identity))
                return PreferencePage(Status.FOUND, tuple(entries), len(parents) > limit)
        except (SQLiteAdapterError, sqlite3.Error):
            return PreferencePage(Status.UNAVAILABLE)

    @staticmethod
    def _limit(limit: int, maximum: int) -> None:
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ValueError("preference query limit exceeds hard bound")

    @staticmethod
    def _input(identity: UUID, origin: PreferenceOrigin, now: datetime) -> datetime:
        validate_id(identity)
        if type(origin) is not PreferenceOrigin:
            raise TypeError("origin must be typed")
        return preference_time(now)

    @staticmethod
    def _definition(definition: PreferenceDefinition, now: datetime) -> None:
        if type(definition) is not PreferenceDefinition:
            raise TypeError("definition must be typed")
        expiry = definition.lifetime.expires_at
        if expiry is not None and expiry <= now:
            raise ValueError("new or changed timed preference must expire in the future")

    @staticmethod
    def _counts(connection: sqlite3.Connection) -> tuple[int, int, int]:
        total = connection.execute("SELECT COUNT(*) FROM scoped_preferences").fetchone()[0]
        # Unknown/corrupt status conservatively consumes a reserved revoke slot.
        active = connection.execute("""SELECT COUNT(*) FROM scoped_preferences p
            LEFT JOIN scoped_preference_revisions r ON r.preference_id = p.preference_id AND r.revision = p.last_revision
            WHERE r.status IS NULL OR r.status != 'revoked'""").fetchone()[0]
        audit = connection.execute("SELECT COUNT(*) FROM scoped_preference_revisions").fetchone()[0]
        return total, active, audit

    @staticmethod
    def _append(connection: sqlite3.Connection, value: ScopedPreference) -> None:
        d, s = value.definition, value.definition.selector
        connection.execute(_INSERT, (
            str(value.preference_id), value.revision, value.format_version,
            value.action.value, value.status.value, value.recorded_at.isoformat(timespec="microseconds"),
            value.action_origin.value, d.effect.value,
            s.application.key if s.application else None,
            s.application_revision.digest if s.application_revision else None,
            s.destination.kind.value if s.destination else None,
            s.destination.value if s.destination else None, s.network_fingerprint, s.rule_id,
            d.lifetime.kind.value, d.lifetime.expires_at.isoformat(timespec="microseconds") if d.lifetime.expires_at else None,
            d.reason, d.content_fingerprint,
        ))

    def create(self, preference_id: UUID, definition: PreferenceDefinition,
               origin: PreferenceOrigin, now: datetime) -> PreferenceResult:
        try:
            now = self._input(preference_id, origin, now)
            if type(definition) is not PreferenceDefinition:
                raise TypeError("definition must be typed")
            value = ScopedPreference(preference_id, 1, definition, now, origin, now, origin,
                                     PreferenceAuditAction.CREATE, PreferenceStatus.ACTIVE)
        except (ValueError, TypeError):
            return PreferenceResult(Status.INVALID)
        try:
            with self._database.connection() as connection, transaction(connection):
                current = self._current(connection, preference_id)
                if current.status is not Status.NOT_FOUND:
                    if current.preference is not None:
                        same = current.preference.revision == 1 and current.preference.definition == definition and current.preference.created_origin is origin
                        return replace(current, status=Status.NO_CHANGE if same else Status.CONFLICT)
                    return current
                try:
                    self._definition(definition, now)
                except (ValueError, TypeError):
                    return PreferenceResult(Status.INVALID, preference_id=preference_id)
                total, active, audit = self._counts(connection)
                if total >= self.policy.max_preferences or active >= self.policy.max_active_preferences or audit + active + 2 > self.policy.max_audit_revisions:
                    return PreferenceResult(Status.CAPACITY_REACHED, preference_id=preference_id)
                connection.execute(
                    "INSERT INTO scoped_preferences (preference_id, created_at, created_origin, last_revision) VALUES (?, ?, ?, 1)",
                    (str(preference_id), now.isoformat(timespec="microseconds"), origin.value),
                )
                self._append(connection, value)
            return PreferenceResult(Status.CREATED, value, preference_id)
        except (SQLiteAdapterError, sqlite3.Error):
            return PreferenceResult(Status.UNAVAILABLE, preference_id=preference_id)

    def edit(self, preference_id: UUID, expected_revision: int,
             definition: PreferenceDefinition, origin: PreferenceOrigin,
             now: datetime) -> PreferenceResult:
        return self._change(preference_id, expected_revision, origin, now, definition=definition)

    def revoke(self, preference_id: UUID, expected_revision: int, reason: str,
               origin: PreferenceOrigin, now: datetime) -> PreferenceResult:
        return self._change(preference_id, expected_revision, origin, now, reason=reason, revoke=True)

    def _change(self, identity: UUID, expected: int, origin: PreferenceOrigin, now: datetime, *,
                definition: PreferenceDefinition | None = None, reason: str = "", revoke: bool = False) -> PreferenceResult:
        try:
            now = self._input(identity, origin, now)
            revision_number(expected)
            if not revoke and type(definition) is not PreferenceDefinition:
                raise TypeError("definition must be typed")
            if revoke:
                preference_reason(reason)
        except (ValueError, TypeError):
            return PreferenceResult(Status.INVALID)
        try:
            with self._database.connection() as connection, transaction(connection):
                current = self._current(connection, identity)
                old = current.preference
                if current.status is not Status.FOUND or old is None:
                    return current
                if old.status is PreferenceStatus.REVOKED:
                    status = Status.ALREADY_REVOKED if revoke and expected in (old.revision, old.revision - 1) else Status.CONFLICT if expected != old.revision else Status.INVALID
                    return replace(current, status=status)
                if old.revision != expected:
                    return replace(current, status=Status.CONFLICT)
                try:
                    content = replace(old.definition, reason=reason) if revoke else definition
                    assert content is not None
                    if now < old.recorded_at:
                        raise ValueError("audit clock cannot rewind")
                    if not revoke and content == old.definition:
                        return replace(current, status=Status.NO_CHANGE)
                    if not revoke:
                        self._definition(content, now)
                    value = replace(old, revision=old.revision + 1, definition=content,
                                    recorded_at=now, action_origin=origin,
                                    action=PreferenceAuditAction.REVOKE if revoke else PreferenceAuditAction.EDIT,
                                    status=PreferenceStatus.REVOKED if revoke else PreferenceStatus.ACTIVE)
                except (ValueError, TypeError):
                    return PreferenceResult(Status.INVALID, preference_id=identity)
                _, active, audit = self._counts(connection)
                # Reserve the last revision and one global audit row per active policy for revoke.
                if (value.revision > self.policy.max_revisions or
                    (not revoke and (value.revision >= self.policy.max_revisions or audit + active + 1 > self.policy.max_audit_revisions)) or
                    (revoke and audit + 1 > self.policy.max_audit_revisions)):
                    return PreferenceResult(Status.CAPACITY_REACHED, preference_id=identity)
                self._append(connection, value)
                cursor = connection.execute("UPDATE scoped_preferences SET last_revision = ? WHERE preference_id = ? AND last_revision = ?",
                                            (value.revision, str(identity), expected))
                if cursor.rowcount != 1:
                    raise sqlite3.IntegrityError("preference revision pointer did not advance")
            return PreferenceResult(Status.REVOKED if revoke else Status.UPDATED, value, identity)
        except (SQLiteAdapterError, sqlite3.Error):
            return PreferenceResult(Status.UNAVAILABLE, preference_id=identity)
