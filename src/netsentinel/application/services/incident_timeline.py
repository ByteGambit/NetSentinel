"""NS-091 bounded, read-only historical story; no current telemetry substitution."""

from netsentinel.shared.enum_sources import enum_source
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP


from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incidents import (
    IncidentObservationKind as Observation, IncidentRelationReason as Reason,
    incident_time,
)
from netsentinel.domain.incident_persistence import (
    IncidentAction, IncidentHistory, IncidentPage, IncidentRecord, IncidentResult,
    IncidentSourceStatus as Source, IncidentStatus, canonical_incident_json,
)
from netsentinel.domain.risk_assessment import AssessmentRead, AssessmentReadStatus
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from netsentinel.application.services.risk_explanation import SCORE_SEMANTICS, human
from netsentinel.domain.risk_scoring import AssessmentAvailability

PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
MAX_LOADED_ROWS = 256


class TimelineKind(str, Enum):
    OBSERVATION = "Observation"
    INFERENCE = "Inference / correlation"
    ASSESSMENT = "Assessment"
    USER_ACTION = "User action / lifecycle"


KIND_PRIORITY = {kind: index for index, kind in enumerate(TimelineKind)}
SortKey = tuple[datetime, int, str, str, int, str]

REASONS = {
    Reason.FIRST_OBSERVATION: QT_TRANSLATE_NOOP('IncidentTimeline', 'First retained observation; isolated incident seed.'),
    Reason.SAME_CONNECTION_LIFECYCLE: QT_TRANSLATE_NOOP('IncidentTimeline', 'Same connection lifecycle (exact session and lifecycle reference).'),
    Reason.SAME_CANONICAL_EVIDENCE: QT_TRANSLATE_NOOP('IncidentTimeline', 'Same canonical evidence reference.'),
    Reason.SAME_ASSESSMENT_LINEAGE: QT_TRANSLATE_NOOP('IncidentTimeline', 'Same assessment lineage; revisions remain distinct.'),
    Reason.SAME_ALERT_OBSERVATION: QT_TRANSLATE_NOOP('IncidentTimeline', 'Same alert observation reference; alert lifecycle is separate.'),
    Reason.SAME_PROCESS_AND_DESTINATION: QT_TRANSLATE_NOOP('IncidentTimeline', 'Same process instance and destination (port/protocol and resolved network scope).'),
}
SOURCE_TEXT = {
    Source.AVAILABLE: QT_TRANSLATE_NOOP('IncidentTimeline', 'Source available now.'),
    Source.SOURCE_EXPIRED_OR_UNAVAILABLE: QT_TRANSLATE_NOOP('IncidentTimeline', 'Original source record is no longer retained or available; cause of absence is unknown.'),
    Source.UNRESOLVED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Source reference could not be resolved; retained incident context remains.'),
    Source.CORRUPT: QT_TRANSLATE_NOOP('IncidentTimeline', 'Original source is corrupt; retained incident context remains.'),
    Source.UNSUPPORTED_VERSION: QT_TRANSLATE_NOOP('IncidentTimeline', 'Original source version is unsupported; retained incident context remains.'),
}


@dataclass(frozen=True, slots=True)
class TimelineSnapshot:
    incident: IncidentResult
    history: IncidentHistory
    assessments: tuple[tuple[AlertAssessmentReference, AssessmentRead], ...] = ()


class IncidentTimelineRepository(Protocol):
    def list_summaries(self, *, limit: int, after_id: UUID | None) -> IncidentPage: ...
    def read_snapshot(self, incident_id: UUID) -> TimelineSnapshot: ...


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    entry_id: str
    kind: TimelineKind
    primary_time: datetime
    time_semantics: str
    title: str
    explanation: str
    source_kind: str
    source_id: str
    source_status: Source
    observation_time: datetime | None = None
    assessment_time: datetime | None = None
    action_time: datetime | None = None
    revision: int = 0
    assessment: AlertAssessmentReference | None = None

    @property
    def sort_key(self) -> SortKey:
        return (self.primary_time, KIND_PRIORITY[self.kind], self.source_kind,
                self.source_id, self.revision, self.entry_id)


@dataclass(frozen=True, slots=True)
class TimelineCursor:
    incident_id: UUID
    incident_revision: int
    token: str
    after: SortKey


@dataclass(frozen=True, slots=True)
class TimelineRequest:
    incident_id: UUID | None = None  # None selects list query
    after_id: UUID | None = None
    cursor: TimelineCursor | None = None
    limit: int = PAGE_SIZE

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_PAGE_SIZE:
            raise ValueError("incident page size exceeds bound")
        if self.incident_id is not None and type(self.incident_id) is not UUID:
            raise TypeError("canonical incident ID required")
        if self.after_id is not None and type(self.after_id) is not UUID:
            raise TypeError("canonical list cursor required")
        if self.incident_id is None and self.cursor is not None:
            raise ValueError("timeline cursor requires incident")
        if self.incident_id is not None and self.after_id is not None:
            raise ValueError("list cursor cannot select detail")


class TimelineStatus(str, Enum):
    FOUND = "found"
    UPDATED = "updated_refresh_required"
    INVALID_CURSOR = "invalid_cursor"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class TimelinePage:
    status: TimelineStatus
    record: IncidentRecord | None = None
    entries: tuple[TimelineEntry, ...] = ()
    next_cursor: TimelineCursor | None = None
    limitations: tuple[str, ...] = ()
    context: tuple[str, ...] = ()
    message: str = ""


def canonical_id(value: object) -> str:
    return sha256(canonical_incident_json(value).encode("ascii")).hexdigest()


def source_identity(value: object) -> str:
    if isinstance(value, AlertAssessmentReference):
        return f"{value.assessment_id}:{value.revision}"
    if isinstance(value, EvidenceReference):
        return f"{value.kind.value}:{value.value}"
    return canonical_incident_json(value)


def map_snapshot(bundle: TimelineSnapshot) -> tuple[tuple[TimelineEntry, ...], tuple[str, ...], tuple[str, ...]]:
    record = bundle.incident.record
    assert record is not None
    snapshot = record.snapshot
    states = {(r.link.kind, r.link.identity): r.status for r in bundle.incident.references}
    entries: list[TimelineEntry] = []
    observations: dict[AlertAssessmentReference, datetime] = {}
    for relation in snapshot.relations:
        obs = relation.observation
        source_id = source_identity(obs.reference)
        status = states.get(("relation", canonical_id(relation)), Source.UNRESOLVED)
        observation_id = canonical_id(obs)
        if obs.kind is Observation.ASSESSMENT_PRODUCED:
            assert isinstance(obs.reference, AlertAssessmentReference)
            observations[obs.reference] = obs.observed_at
        else:
            title = {
                Observation.CONNECTION_OBSERVED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Connection observed'),
                Observation.CONNECTION_UPDATED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Connection observation updated'),
                Observation.CONNECTION_NOT_OBSERVED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Connection no longer observed (polling)'),
                Observation.EVIDENCE_OBSERVED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Evidence observed'),
                Observation.ALERT_OBSERVED: QT_TRANSLATE_NOOP('IncidentTimeline', 'Alert observation reference'),
            }[obs.kind]
            if isinstance(obs.reference, EvidenceReference) and obs.reference.kind is EvidenceReferenceKind.DNS_EVIDENCE:
                title = QT_TRANSLATE_NOOP('IncidentTimeline', 'DNS evidence observed')
            entries.append(TimelineEntry("observation:" + observation_id, TimelineKind.OBSERVATION,
                obs.observed_at, QT_TRANSLATE_NOOP('IncidentTimeline', 'Observation time'), title,
                QT_TRANSLATE_NOOP('IncidentTimeline', 'Recorded observation; polling does not establish exact OS creation or closure time.'),
                obs.kind.value, source_id, status, observation_time=obs.observed_at))
        matched = ""
        if relation.matched_key:
            key = relation.matched_key
            matched = QT_TRANSLATE_NOOP('IncidentTimeline', ' Matched identity: ') + source_identity(key.identity)
            source_kind = {Reason.SAME_CONNECTION_LIFECYCLE: "connection",
                Reason.SAME_CANONICAL_EVIDENCE: "evidence", Reason.SAME_ALERT_OBSERVATION: "alert"}.get(key.reason)
            if source_kind:
                matched += QT_TRANSLATE_NOOP('IncidentTimeline', ' Matched target: ') + SOURCE_TEXT[states.get((source_kind, canonical_id(key.identity)), Source.UNRESOLVED)]
            elif key.reason is Reason.SAME_ASSESSMENT_LINEAGE:
                for ref in snapshot.assessments:
                    if ref.assessment_id == key.identity:
                        matched += QT_TRANSLATE_NOOP('IncidentTimeline', ' Matched assessment revision {value1}: ').format(value1=ref.revision) + SOURCE_TEXT[states.get(("assessment", canonical_id(ref)), Source.UNRESOLVED)]
            else:
                matched += QT_TRANSLATE_NOOP('IncidentTimeline', ' Process/destination identity is retained incident context; original entity links are unresolved.')
        entries.append(TimelineEntry("inference:" + canonical_id(relation), TimelineKind.INFERENCE,
            obs.observed_at, QT_TRANSLATE_NOOP('IncidentTimeline', 'Original observation anchor; inference computation time not recorded'),
            QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident correlation'), REASONS[relation.reason] + matched,
            obs.kind.value, source_id, status, observation_time=obs.observed_at))

    reads = dict(bundle.assessments)
    for reference in snapshot.assessments:
        read = reads.get(reference, AssessmentRead(AssessmentReadStatus.UNAVAILABLE))
        retained = read.revision if read.status is AssessmentReadStatus.FOUND else None
        observed = retained.key.original_observed_at if retained else observations.get(reference)
        # Aggregate pointers lack per-observation provenance; never assign the incident's first time.
        fallback = observed or snapshot.first_observed_at
        primary = retained.assessed_at if retained else fallback
        status = states.get(("assessment", canonical_id(reference)), Source.UNRESOLVED)
        description = QT_TRANSLATE_NOOP('IncidentTimeline', 'Assessment time and score unavailable; exact retained reference shown.')
        if retained:
            risk = retained.snapshot
            score = QT_TRANSLATE_NOOP('IncidentTimeline', 'Unavailable / insufficient evidence') if risk.availability is AssessmentAvailability.UNKNOWN else f"{risk.score} / 100"
            description = (QT_TRANSLATE_NOOP('IncidentTimeline', 'Stored score: {value1}; {value2} Effective severity: {value3}; confidence: {value4}; measurement quality: {value5}. Select this revision for stored contributor, freshness and external reputation context.').format(value1=score, value2=SCORE_SEMANTICS, value3=human(risk.severity), value4=human(risk.confidence), value5=human(risk.measurement_quality)))
        entries.append(TimelineEntry("assessment:" + canonical_id(reference), TimelineKind.ASSESSMENT,
            primary, QT_TRANSLATE_NOOP('IncidentTimeline', 'Assessment time') if retained else
            (QT_TRANSLATE_NOOP('IncidentTimeline', 'Assessment time unknown; ordered by original observation') if observed else
             QT_TRANSLATE_NOOP('IncidentTimeline', 'Assessment and observation time unknown; ordered by incident observation bound')),
            QT_TRANSLATE_NOOP('IncidentTimeline', 'Risk assessment revision {value1}').format(value1=reference.revision), description, "assessment",
            reference.assessment_id, status, observation_time=observed,
            assessment_time=retained.assessed_at if retained else None,
            revision=reference.revision, assessment=reference))

    for event in bundle.history.entries:
        if event.action not in (IncidentAction.ACKNOWLEDGED, IncidentAction.RESOLVED, IncidentAction.REOPENED):
            continue
        entries.append(TimelineEntry(f"action:{event.revision}", TimelineKind.USER_ACTION,
            event.changed_at, QT_TRANSLATE_NOOP('IncidentTimeline', 'Lifecycle action time'), QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident {value1}').format(value1=enum_source(event.action)),
            QT_TRANSLATE_NOOP('IncidentTimeline', 'Origin: {value1}; incident state: {value2}. Alert lifecycle is separate.').format(value1=enum_source(event.origin), value2=enum_source(event.state)),
            "incident_action", str(record.incident_id), Source.AVAILABLE,
            action_time=event.changed_at, revision=event.revision))
    limitations = tuple(enum_source(limitation, 'words') for limitation in snapshot.limitations)
    if bundle.history.truncated:
        limitations += (QT_TRANSLATE_NOOP('IncidentTimeline', 'Older incident revisions are no longer retained; timeline is incomplete.'),)
    if bundle.history.status is not IncidentStatus.FOUND:
        limitations += (QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident action history unavailable: ') + bundle.history.status.value,)
    context = [QT_TRANSLATE_NOOP('IncidentTimeline', 'Aggregate incident context; exact links/times for these entities were not retained:')]
    for process in snapshot.processes:
        context.append(QT_TRANSLATE_NOOP('IncidentTimeline', 'Process observed: PID {value1}; session {value2}; instance create-time (identity only): {value3}; name unavailable.').format(value1=process.identity.pid, value2=process.session_id, value3=process.identity.create_time or QT_TRANSLATE_NOOP('IncidentTimeline', 'Unknown')))
    for destination in snapshot.destinations:
        context.append(QT_TRANSLATE_NOOP('IncidentTimeline', 'Destination context ({value1}): {value2}; port {value3}; protocol {value4}.').format(value1=destination.kind.value, value2=destination.value, value3=destination.port if destination.port is not None else QT_TRANSLATE_NOOP('IncidentTimeline', 'Unknown'), value4=destination.protocol.value if destination.protocol else QT_TRANSLATE_NOOP('IncidentTimeline', 'Unknown')))
    for scope in snapshot.scopes:
        context.append(QT_TRANSLATE_NOOP('IncidentTimeline', 'Scope: {value1}; network status {value2}; fingerprint {value3}.').format(value1=scope.kind.value, value2=scope.network_status.value if scope.network_status else QT_TRANSLATE_NOOP('IncidentTimeline', 'Unknown'), value3=scope.network_fingerprint or QT_TRANSLATE_NOOP('IncidentTimeline', 'Unavailable')))
    for source_ref in bundle.incident.references:
        if source_ref.status is not Source.AVAILABLE:
            context.append(QT_TRANSLATE_NOOP('IncidentTimeline', '{value1} reference {value2}: {value3}').format(value1=source_ref.link.kind, value2=source_ref.link.identity, value3=SOURCE_TEXT[source_ref.status]))
    # Canonical entries deduplicate retries, and ordering never depends on insertion order.
    return tuple(sorted({e.entry_id: e for e in entries}.values(), key=lambda e: e.sort_key)), limitations, tuple(context)


class IncidentTimelineQueryService:
    def __init__(self, repository: IncidentTimelineRepository) -> None:
        self._repository = repository

    def lookup(self, request: TimelineRequest) -> IncidentPage | TimelinePage:
        if type(request) is not TimelineRequest:
            raise TypeError("typed incident query required")
        try:
            if request.incident_id is None:
                return self._repository.list_summaries(limit=request.limit, after_id=request.after_id)
            bundle = self._repository.read_snapshot(request.incident_id)
            record = bundle.incident.record
            if bundle.incident.status is not IncidentStatus.FOUND or record is None:
                return TimelinePage(TimelineStatus.UNAVAILABLE, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident details unavailable: ') + bundle.incident.status.value)
            if record.incident_id != request.incident_id:
                return TimelinePage(TimelineStatus.UNAVAILABLE, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident identity unavailable.'))
            entries, limitations, context = map_snapshot(bundle)
            # The closed domain codec accepts exact machine types. Keep its
            # English cursor bytes identical; UI recipes never cross this boundary.
            canonical_entries = tuple(replace(e, time_semantics=str(e.time_semantics),
                title=str(e.title), explanation=str(e.explanation)) for e in entries)
            token = sha256(canonical_incident_json((canonical_entries,
                tuple(map(str, limitations)), tuple(map(str, context)))).encode("ascii")).hexdigest()
            cursor = request.cursor
            if cursor is not None:
                if not self._valid_cursor(cursor, request.incident_id):
                    return TimelinePage(TimelineStatus.INVALID_CURSOR, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Invalid timeline cursor. Refresh.'))
                if cursor.incident_revision != record.revision or cursor.token != token:
                    return TimelinePage(TimelineStatus.UPDATED, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident or source availability updated — refresh.'))
                if cursor.after not in {e.sort_key for e in entries}:
                    return TimelinePage(TimelineStatus.INVALID_CURSOR, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Invalid timeline cursor. Refresh.'))
                entries = tuple(e for e in entries if e.sort_key > cursor.after)
            page = entries[:request.limit]
            next_cursor = TimelineCursor(record.incident_id, record.revision, token, page[-1].sort_key) if len(entries) > request.limit else None
            return TimelinePage(TimelineStatus.FOUND, record, page, next_cursor, limitations, context)
        except Exception:
            if request.incident_id is None:
                return IncidentPage((IncidentResult(IncidentStatus.UNAVAILABLE),))
            return TimelinePage(TimelineStatus.UNAVAILABLE, message=QT_TRANSLATE_NOOP('IncidentTimeline', 'Incident timeline unavailable. Try Refresh.'))

    @staticmethod
    def _valid_cursor(cursor: TimelineCursor, incident_id: UUID) -> bool:
        if type(cursor) is not TimelineCursor or cursor.incident_id != incident_id:
            return False
        if type(cursor.incident_revision) is not int or not 1 <= cursor.incident_revision <= 2**63 - 1:
            return False
        if type(cursor.token) is not str or len(cursor.token) != 64 or any(c not in "0123456789abcdef" for c in cursor.token):
            return False
        key = cursor.after
        if type(key) is not tuple or len(key) != 6:
            return False
        try:
            incident_time(key[0])
        except (ValueError, TypeError, AttributeError):
            return False
        return type(key[1]) is int and key[1] in KIND_PRIORITY.values() and all(type(v) is str and len(v) <= 2048 for v in (key[2], key[3], key[5])) and type(key[4]) is int and 0 <= key[4] <= 2**63 - 1
