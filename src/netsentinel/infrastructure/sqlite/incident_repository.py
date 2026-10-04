"""NS-090 scoped worker-owned SQLite connections, atomic pure transformations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import sqlite3
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incidents import IncidentConnectionRef, IncidentRelation, incident_time
from netsentinel.domain.incident_persistence import (
    MAX_INCIDENT_BYTES, MAX_LINK_BYTES, MAX_REVISION_BYTES, IncidentCommandError,
    IncidentHistory, IncidentPage, IncidentRecord, IncidentReferenceState,
    IncidentResult, IncidentRevision, IncidentSourceLink, IncidentSourceStatus as Source,
    IncidentState, IncidentStatus as Status, IncidentStoragePolicy, canonical_incident_json,
    validate_incident,
)
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from netsentinel.infrastructure.sqlite.incident_codec import LINK_TYPES, decode_incident, source_links
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction

_SELECT = """SELECT incident_id, state, cohort, updated_at, resolved_at, revision, format_version,
 CASE WHEN length(CAST(payload AS BLOB)) <= 131072 THEN payload ELSE NULL END AS payload
 FROM incidents """
_BAD = (ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError)


def _id(value: UUID) -> str:
    if type(value) is not UUID:
        raise TypeError("canonical incident UUID required")
    return str(value)


class SQLiteIncidentRepository:
    def __init__(self, database: SQLiteDatabase, policy: IncidentStoragePolicy | None = None) -> None:
        self._database = database
        self.policy = policy or IncidentStoragePolicy()

    def _read(self, connection: sqlite3.Connection, row: sqlite3.Row | None,
              *, sources: bool = True) -> IncidentResult:
        if row is None:
            return IncidentResult(Status.NOT_FOUND)
        try:
            if type(row["format_version"]) is not int or row["format_version"] < 1:
                raise ValueError("invalid incident format")
            if row["format_version"] != 1:
                return IncidentResult(Status.UNSUPPORTED_VERSION)
            record = decode_incident(row["payload"])
            if (_id(record.incident_id) != row["incident_id"] or record.revision != row["revision"]
                    or record.state.value != row["state"] or record.snapshot.cohort.isoformat() != row["cohort"]
                    or record.updated_at.isoformat() != row["updated_at"]
                    or (record.resolved_at.isoformat() if record.resolved_at else None) != row["resolved_at"]):
                raise ValueError("inconsistent incident summary")
            links = source_links(record.snapshot)
            if len(links) > self.policy.max_links:
                raise ValueError("incident references exceed quota")
            rows = connection.execute(
                "SELECT kind, identity, CASE WHEN length(CAST(payload AS BLOB)) <= 2048 THEN payload ELSE NULL END AS payload "
                "FROM incident_references WHERE incident_id = ? ORDER BY kind, identity LIMIT ?",
                (row["incident_id"], self.policy.max_links + 1)).fetchall()
            stored = tuple(IncidentSourceLink(r["kind"], r["identity"], r["payload"]) for r in rows)
            if links != stored:
                raise ValueError("inconsistent incident references")
            latest = connection.execute(
                "SELECT format_version, CASE WHEN length(CAST(payload AS BLOB)) <= 2048 THEN payload ELSE NULL END AS payload "
                "FROM incident_revisions WHERE incident_id = ? AND revision = ?",
                (row["incident_id"], record.revision)).fetchone()
            if latest is None or latest[0] != 1 or decode_incident(latest[1], IncidentRevision, MAX_REVISION_BYTES) != self._event(record):
                raise ValueError("inconsistent current revision")
            refs = tuple(IncidentReferenceState(link, self._source(connection, link)) for link in links) if sources else ()
            return IncidentResult(Status.FOUND, record, refs)
        except _BAD:
            return IncidentResult(Status.CORRUPT)

    @staticmethod
    def _event(record: IncidentRecord) -> IncidentRevision:
        return IncidentRevision(record.incident_id, record.revision, record.state, record.action,
            record.origin, record.updated_at, record.snapshot.first_observed_at, record.snapshot.last_observed_at)

    @staticmethod
    def _source(connection: sqlite3.Connection, link: IncidentSourceLink) -> Source:
        value = decode_incident(link.payload, LINK_TYPES[link.kind], MAX_LINK_BYTES)
        if isinstance(value, IncidentRelation):
            value = value.observation.reference
        if isinstance(value, IncidentConnectionRef):
            row = connection.execute("SELECT 1 FROM connection_history WHERE lifecycle_id = ? AND monitoring_session_id = ? LIMIT 1",
                (str(value.lifecycle_id), str(value.session_id))).fetchone()
        elif isinstance(value, EvidenceReference) and value.kind is EvidenceReferenceKind.DNS_EVIDENCE:
            row = connection.execute("SELECT 1 FROM dns_history WHERE evidence_id = ? LIMIT 1", (str(value.value),)).fetchone()
        elif isinstance(value, AlertAssessmentReference):
            row = connection.execute("SELECT format_version, CASE WHEN length(CAST(snapshot AS BLOB)) <= 65536 THEN snapshot ELSE NULL END AS snapshot, content_fingerprint "
                "FROM risk_assessment_revisions WHERE assessment_id = ? AND revision = ? LIMIT 1", (value.assessment_id, value.revision)).fetchone()
            if row is not None:
                if row[0] not in (1, 2):
                    return Source.UNSUPPORTED_VERSION
                try:
                    from netsentinel.domain.risk_assessment import AssessmentSnapshot
                    from netsentinel.infrastructure.sqlite.assessment_codec import decode_value
                    snapshot = decode_value(row[1], AssessmentSnapshot, 65536, format_version=row[0])
                    if snapshot.content_fingerprint != row[2]:
                        return Source.CORRUPT
                except _BAD:
                    return Source.CORRUPT
        elif isinstance(value, UUID):
            row = connection.execute("SELECT 1 FROM alerts WHERE id = ? LIMIT 1", (str(value),)).fetchone()
        else:
            return Source.UNRESOLVED
        return Source.AVAILABLE if row is not None else Source.SOURCE_EXPIRED_OR_UNAVAILABLE

    def get(self, incident_id: UUID) -> IncidentResult:
        key = _id(incident_id)
        try:
            with self._database.connection() as connection, transaction(connection):
                return self._read(connection, connection.execute(_SELECT + "WHERE incident_id = ?", (key,)).fetchone())
        except (SQLiteAdapterError, sqlite3.Error):
            return IncidentResult(Status.UNAVAILABLE)

    def update(self, incident_id: UUID,
               transform: Callable[[IncidentRecord | None], IncidentRecord], *,
               expected_revision: int | None = None) -> IncidentResult:
        key = _id(incident_id)
        if expected_revision is not None and (type(expected_revision) is not int or not 1 <= expected_revision <= 2**63 - 1):
            raise ValueError("invalid expected incident revision")
        try:
            with self._database.connection() as connection, transaction(connection):
                read = self._read(connection, connection.execute(_SELECT + "WHERE incident_id = ?", (key,)).fetchone(), sources=False)
                if read.status not in (Status.FOUND, Status.NOT_FOUND):
                    return read
                current = read.record
                if expected_revision is not None and (current is None or current.revision != expected_revision):
                    return IncidentResult(Status.CONFLICT, current)
                proposed = transform(current)
                if current == proposed:
                    return IncidentResult(Status.NO_CHANGE, current)
                if proposed.incident_id != incident_id or proposed.revision != (current.revision + 1 if current else 1):
                    raise IncidentCommandError(Status.IDENTITY_CONFLICT)
                if current and (proposed.created_at != current.created_at or proposed.correlation_policy != current.correlation_policy
                                or proposed.updated_at < current.updated_at):
                    raise IncidentCommandError(Status.IDENTITY_CONFLICT)
                validate_incident(proposed.snapshot, self.policy.correlation)
                payload = canonical_incident_json(proposed)
                # Admission has the same strict vocabulary/size checks as reads.
                decode_incident(payload, IncidentRecord, MAX_INCIDENT_BYTES)
                links = source_links(proposed.snapshot)
                if len(links) > self.policy.max_links:
                    raise IncidentCommandError(Status.CAPACITY_REACHED)
                count = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                if count > self.policy.max_incidents or (current is None and count >= self.policy.max_incidents):
                    raise IncidentCommandError(Status.CAPACITY_REACHED)
                if current:
                    previous_links = set(source_links(current.snapshot))
                    if not previous_links.issubset(set(links)):
                        raise IncidentCommandError(Status.IDENTITY_CONFLICT)
                connection.execute(
                    "INSERT INTO incidents(incident_id,state,cohort,updated_at,resolved_at,revision,format_version,payload) "
                    "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET "
                    "state=excluded.state,updated_at=excluded.updated_at,resolved_at=excluded.resolved_at,revision=excluded.revision,payload=excluded.payload",
                    (key, proposed.state.value, proposed.snapshot.cohort.isoformat(), proposed.updated_at.isoformat(),
                     proposed.resolved_at.isoformat() if proposed.resolved_at else None, proposed.revision, 1, payload))
                for link in links:
                    connection.execute("INSERT OR IGNORE INTO incident_references(incident_id,kind,identity,payload) VALUES(?,?,?,?)",
                        (key, link.kind, link.identity, link.payload))
                event = canonical_incident_json(self._event(proposed))
                decode_incident(event, IncidentRevision, MAX_REVISION_BYTES)
                connection.execute("INSERT INTO incident_revisions(incident_id,revision,format_version,payload) VALUES(?,?,1,?)",
                    (key, proposed.revision, event))
                connection.execute("DELETE FROM incident_revisions WHERE incident_id = ? AND revision <= ?",
                    (key, proposed.revision - self.policy.max_revisions))
                return IncidentResult(Status.CHANGED, proposed)
        except IncidentCommandError as error:
            return IncidentResult(error.status)
        except (SQLiteAdapterError, sqlite3.Error):
            return IncidentResult(Status.UNAVAILABLE)
        except _BAD:
            return IncidentResult(Status.IDENTITY_CONFLICT)

    def list_current(self, *, limit: int = 100, after_id: UUID | None = None,
                     state: IncidentState | None = None, cohort: datetime | None = None) -> IncidentPage:
        maximum = self.policy.max_hydration if cohort is not None else self.policy.max_query
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ValueError("incident query exceeds bound")
        if state is not None and type(state) is not IncidentState:
            raise TypeError("typed incident state required")
        clauses, args = [], []
        if after_id is not None:
            clauses.append("incident_id > ?")
            args.append(_id(after_id))
        if state is not None:
            clauses.append("state = ?")
            args.append(state.value)
        if cohort is not None:
            clauses.append("cohort = ?")
            args.append(incident_time(cohort).isoformat())
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        try:
            with self._database.connection() as connection, transaction(connection):
                rows = connection.execute(_SELECT + where + " ORDER BY incident_id LIMIT ?", (*args, limit + 1)).fetchall()
                entries = tuple(self._read(connection, row) for row in rows[:limit])
                cursor = UUID(rows[limit - 1]["incident_id"]) if len(rows) > limit else None
                return IncidentPage(entries, len(rows) > limit, cursor)
        except (SQLiteAdapterError, sqlite3.Error):
            return IncidentPage((IncidentResult(Status.UNAVAILABLE),))
        except _BAD:
            return IncidentPage((IncidentResult(Status.CORRUPT),))

    def history(self, incident_id: UUID, *, limit: int = 32,
                before_revision: int | None = None) -> IncidentHistory:
        key = _id(incident_id)
        if type(limit) is not int or not 1 <= limit <= self.policy.max_revisions:
            raise ValueError("revision query exceeds bound")
        if before_revision is not None and (type(before_revision) is not int or not 1 <= before_revision <= 2**63 - 1):
            raise ValueError("invalid history cursor")
        try:
            with self._database.connection() as connection, transaction(connection):
                rows = connection.execute("SELECT revision,format_version,CASE WHEN length(CAST(payload AS BLOB)) <= 2048 THEN payload ELSE NULL END AS payload "
                    "FROM incident_revisions WHERE incident_id = ? AND revision < ? ORDER BY revision DESC LIMIT ?",
                    (key, before_revision or 2**63 - 1, limit + 1)).fetchall()
                entries = []
                for row in rows[:limit]:
                    if row["format_version"] != 1:
                        return IncidentHistory(Status.UNSUPPORTED_VERSION)
                    event = decode_incident(row["payload"], IncidentRevision, MAX_REVISION_BYTES)
                    if event.incident_id != incident_id or event.revision != row["revision"]:
                        raise ValueError("revision identity mismatch")
                    entries.append(event)
                if not rows:
                    exists = connection.execute("SELECT 1 FROM incidents WHERE incident_id = ?", (key,)).fetchone()
                    return IncidentHistory(Status.FOUND if exists else Status.NOT_FOUND)
                return IncidentHistory(Status.FOUND, tuple(entries), len(rows) > limit or rows[-1]["revision"] > 1)
        except (SQLiteAdapterError, sqlite3.Error):
            return IncidentHistory(Status.UNAVAILABLE)
        except _BAD:
            return IncidentHistory(Status.CORRUPT)

    def cleanup(self, cutoff: datetime, now: datetime) -> int:
        cutoff, now = incident_time(cutoff), incident_time(now)
        eligible = min(cutoff, now - self.policy.reopen_horizon)
        try:
            with self._database.connection() as connection, transaction(connection):
                cursor = connection.execute("DELETE FROM incidents WHERE incident_id IN (SELECT incident_id FROM incidents "
                    "WHERE state = 'resolved' AND resolved_at < ? ORDER BY resolved_at,incident_id LIMIT ?)",
                    (eligible.isoformat(), self.policy.cleanup_chunk))
                return cursor.rowcount
        except (SQLiteAdapterError, sqlite3.Error):
            raise IncidentCommandError(Status.UNAVAILABLE) from None
