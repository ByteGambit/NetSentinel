"""NS-091 coherent, bounded incident reads and batched source availability."""

from dataclasses import replace
from uuid import UUID
import sqlite3

from netsentinel.application.services.incident_timeline import TimelineSnapshot
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incidents import IncidentConnectionRef, IncidentRelation
from netsentinel.domain.incident_persistence import (
    IncidentHistory, IncidentPage, IncidentReferenceState, IncidentResult,
    IncidentRevision, IncidentSourceLink, IncidentSourceStatus as Source, IncidentStatus as Status,
    MAX_REVISION_BYTES,
)
from netsentinel.domain.risk_assessment import AssessmentRead, AssessmentReadStatus as ReadStatus
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from netsentinel.infrastructure.sqlite.assessment_repository import (
    SQLiteAssessmentRepository, _SELECT as ASSESSMENT_SELECT,
)
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, transaction
from netsentinel.infrastructure.sqlite.incident_codec import LINK_TYPES, decode_incident, source_links
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository, _SELECT, _BAD, _id


class SQLiteIncidentTimelineRepository(SQLiteIncidentRepository):
    def list_summaries(self, *, limit: int, after_id: UUID | None) -> IncidentPage:
        if type(limit) is not int or not 1 <= limit <= self.policy.max_query:
            raise ValueError("incident list exceeds bound")
        after = _id(after_id) if after_id is not None else ""
        try:
            with self._database.connection() as connection, transaction(connection):
                rows = connection.execute(_SELECT + "WHERE incident_id > ? ORDER BY incident_id LIMIT ?",
                    (after, limit + 1)).fetchall()
                entries = tuple(self._read(connection, row, sources=False) for row in rows[:limit])
                cursor = UUID(rows[limit - 1]["incident_id"]) if len(rows) > limit else None
                return IncidentPage(entries, len(rows) > limit, cursor)
        except (SQLiteAdapterError, sqlite3.Error):
            return IncidentPage((IncidentResult(Status.UNAVAILABLE),))
        except _BAD:
            return IncidentPage((IncidentResult(Status.CORRUPT),))

    def read_snapshot(self, incident_id: UUID) -> TimelineSnapshot:
        key = _id(incident_id)
        try:
            with self._database.connection() as connection, transaction(connection):
                read = self._read(connection, connection.execute(_SELECT + "WHERE incident_id = ?", (key,)).fetchone(), sources=False)
                if read.status is not Status.FOUND or read.record is None:
                    return TimelineSnapshot(read, IncidentHistory(read.status))
                snapshot = read.record.snapshot
                # Up to 16 exact revision pointers; no latest/current substitution.
                assessments = self._assessments(connection, snapshot.assessments)
                states = self._sources(connection, source_links(snapshot), dict(assessments))
                history = self._history(connection, key)
                return TimelineSnapshot(replace(read, references=states), history, assessments)
        except (SQLiteAdapterError, sqlite3.Error):
            return TimelineSnapshot(IncidentResult(Status.UNAVAILABLE), IncidentHistory(Status.UNAVAILABLE))
        except _BAD:
            return TimelineSnapshot(IncidentResult(Status.CORRUPT), IncidentHistory(Status.CORRUPT))

    def _assessments(self, connection: sqlite3.Connection,
                     references: tuple[AlertAssessmentReference, ...]) -> tuple[tuple[AlertAssessmentReference, AssessmentRead], ...]:
        if not references:
            return ()
        clauses = " OR ".join("(r.assessment_id = ? AND r.revision = ?)" for _ in references)
        args = tuple(v for ref in references for v in (ref.assessment_id, ref.revision))
        rows = connection.execute(ASSESSMENT_SELECT + "WHERE " + clauses + " ORDER BY r.assessment_id,r.revision LIMIT 16", args).fetchall()
        decoder = SQLiteAssessmentRepository(self._database)
        values = {(r["assessment_id"], r["revision"]): decoder._decode(connection, r, sources=False) for r in rows}
        result = []
        for ref in references:
            read = values.get((ref.assessment_id, ref.revision), AssessmentRead(ReadStatus.NOT_FOUND))
            if read.revision is not None and read.revision.key.scope.network_status != ref.network_status:
                read = AssessmentRead(ReadStatus.CORRUPT)
            result.append((ref, read))
        return tuple(result)

    def _sources(self, connection: sqlite3.Connection, links: tuple[IncidentSourceLink, ...],
                 assessments: dict[AlertAssessmentReference, AssessmentRead]) -> tuple[IncidentReferenceState, ...]:
        values: dict[tuple[str, str], object] = {}
        for link in links:
            value = decode_incident(link.payload, LINK_TYPES[link.kind], 2048)
            if isinstance(value, IncidentRelation):
                value = value.observation.reference
            values[(link.kind, link.identity)] = value
        connections = sorted({(str(v.session_id), str(v.lifecycle_id)) for v in values.values() if isinstance(v, IncidentConnectionRef)})
        dns = sorted({str(v.value) for v in values.values() if isinstance(v, EvidenceReference) and v.kind is EvidenceReferenceKind.DNS_EVIDENCE})
        alerts = sorted({str(v) for v in values.values() if isinstance(v, UUID)})
        found_connections: set[tuple[str, str]] = set()
        found_dns: set[str] = set()
        found_alerts: set[str] = set()
        if connections:
            clauses = " OR ".join("(monitoring_session_id = ? AND lifecycle_id = ?)" for _ in connections)
            found_connections = {(r[0], r[1]) for r in connection.execute(
                "SELECT DISTINCT monitoring_session_id,lifecycle_id FROM connection_history WHERE " + clauses + " LIMIT 32",
                tuple(v for ref in connections for v in ref)).fetchall()}
        if dns:
            found_dns = {r[0] for r in connection.execute("SELECT DISTINCT evidence_id FROM dns_history WHERE evidence_id IN (" +
                ",".join("?" for _ in dns) + ") LIMIT 64", dns).fetchall()}
        if alerts:
            found_alerts = {r[0] for r in connection.execute("SELECT id FROM alerts WHERE id IN (" +
                ",".join("?" for _ in alerts) + ") LIMIT 16", alerts).fetchall()}
        result = []
        for link in links:
            value = values[(link.kind, link.identity)]
            status = Source.UNRESOLVED
            found = None
            if isinstance(value, IncidentConnectionRef):
                found = (str(value.session_id), str(value.lifecycle_id)) in found_connections
            elif isinstance(value, EvidenceReference) and value.kind is EvidenceReferenceKind.DNS_EVIDENCE:
                found = str(value.value) in found_dns
            elif isinstance(value, UUID):
                found = str(value) in found_alerts
            elif isinstance(value, AlertAssessmentReference):
                read = assessments.get(value, AssessmentRead(ReadStatus.NOT_FOUND))
                status = {ReadStatus.FOUND: Source.AVAILABLE, ReadStatus.NOT_FOUND: Source.SOURCE_EXPIRED_OR_UNAVAILABLE,
                    ReadStatus.CORRUPT: Source.CORRUPT, ReadStatus.UNSUPPORTED_VERSION: Source.UNSUPPORTED_VERSION,
                    ReadStatus.UNAVAILABLE: Source.UNRESOLVED}[read.status]
            if found is not None:
                status = Source.AVAILABLE if found else Source.SOURCE_EXPIRED_OR_UNAVAILABLE
            result.append(IncidentReferenceState(link, status))
        return tuple(result)

    def _history(self, connection: sqlite3.Connection, key: str) -> IncidentHistory:
        rows = connection.execute("SELECT revision,format_version,CASE WHEN length(CAST(payload AS BLOB)) <= 2048 THEN payload ELSE NULL END AS payload "
            "FROM incident_revisions WHERE incident_id = ? ORDER BY revision DESC LIMIT ?", (key, self.policy.max_revisions + 1)).fetchall()
        events = []
        try:
            for row in rows[:self.policy.max_revisions]:
                if row["format_version"] != 1:
                    return IncidentHistory(Status.UNSUPPORTED_VERSION)
                event = decode_incident(row["payload"], IncidentRevision, MAX_REVISION_BYTES)
                if str(event.incident_id) != key or event.revision != row["revision"]:
                    raise ValueError("revision identity mismatch")
                events.append(event)
            return IncidentHistory(Status.FOUND, tuple(events), len(rows) > self.policy.max_revisions or bool(events and events[-1].revision > 1))
        except _BAD:
            return IncidentHistory(Status.CORRUPT)
