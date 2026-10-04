"""NS-090 additive durable contract; no SQL, source objects or alert lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
from uuid import UUID, uuid5

from netsentinel.domain.incidents import (
    CorrelatedIncident, IncidentConnectionRef, IncidentDestination, IncidentLimitation,
    IncidentPolicy, IncidentProcessRef, IncidentRelation, IncidentRelationReason, incident_time,
)
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceScope

INCIDENT_FORMAT_VERSION = 1
MAX_INCIDENT_BYTES = 131072
MAX_LINK_BYTES = 2048
MAX_REVISION_BYTES = 2048
INCIDENT_NAMESPACE = UUID("57b94390-7050-5ce8-a9a0-1cfd6d435cad")


class IncidentState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class IncidentAction(str, Enum):
    CREATED = "created"
    APPENDED = "appended"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class IncidentOrigin(str, Enum):
    MANUAL_USER = "manual_user"
    SYSTEM_CORRELATION = "system_correlation"


class IncidentStatus(str, Enum):
    FOUND = "found"
    CHANGED = "changed"
    NO_CHANGE = "no_change"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    IDENTITY_CONFLICT = "identity_conflict"
    INVALID_TRANSITION = "invalid_transition"
    NOT_CORRELATED = "not_correlated"
    HORIZON_EXCEEDED = "horizon_exceeded"
    CAPACITY_REACHED = "capacity_reached"
    CORRUPT = "corrupt"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNAVAILABLE = "unavailable"


class IncidentSourceStatus(str, Enum):
    AVAILABLE = "available"
    SOURCE_EXPIRED_OR_UNAVAILABLE = "source_expired_or_unavailable"
    UNRESOLVED = "unresolved"
    CORRUPT = "corrupt"
    UNSUPPORTED_VERSION = "unsupported_version"


@dataclass(frozen=True, slots=True)
class IncidentStoragePolicy:
    max_incidents: int = 1024
    max_revisions: int = 32
    max_links: int = 320
    max_query: int = 100
    max_hydration: int = 256
    cleanup_chunk: int = 16
    reopen_horizon: timedelta = timedelta(minutes=5)
    correlation: IncidentPolicy = IncidentPolicy()

    def __post_init__(self) -> None:
        for name, maximum in (("max_incidents", 1024), ("max_revisions", 32),
                              ("max_links", 320), ("max_query", 100),
                              ("max_hydration", 256), ("cleanup_chunk", 16)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("incident storage policy exceeds hard bound")
        if type(self.reopen_horizon) is not timedelta or not timedelta(0) < self.reopen_horizon <= timedelta(minutes=10):
            raise ValueError("invalid reopen horizon")
        if type(self.correlation) is not IncidentPolicy:
            raise TypeError("typed correlation policy required")


def canonical_incident_json(value: object) -> str:
    """Closed encoder; exact allowed types are checked by the codec on write/read."""
    def primitive(item: object) -> object:
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return incident_time(item).isoformat(timespec="microseconds")
        if isinstance(item, UUID):
            return str(item)
        if isinstance(item, timedelta):
            return item // timedelta(microseconds=1)
        if isinstance(item, tuple):
            return [primitive(v) for v in item]
        if is_dataclass(item) and not isinstance(item, type):
            return {f.name: primitive(getattr(item, f.name)) for f in fields(item) if f.init}
        if item is None or type(item) in (str, int, bool):
            return item
        raise TypeError("unsupported incident value")
    return json.dumps(primitive(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def validate_incident(snapshot: CorrelatedIncident, policy: IncidentPolicy) -> None:
    if type(snapshot) is not CorrelatedIncident or type(snapshot.incident_id) is not UUID:
        raise TypeError("typed incident snapshot required")
    first, last, cohort = (incident_time(snapshot.first_observed_at),
                           incident_time(snapshot.last_observed_at), incident_time(snapshot.cohort))
    if first > last or policy.cohort(first) != cohort or policy.cohort(last) != cohort:
        raise ValueError("incident lies outside fixed cohort")
    for name, maximum in (("processes", policy.max_processes), ("connections", policy.max_connections),
                          ("destinations", policy.max_destinations), ("evidence", policy.max_evidence),
                          ("alerts", policy.max_alerts), ("assessments", policy.max_assessments),
                          ("scopes", policy.max_scopes), ("relations", policy.max_relations),
                          ("limitations", 7)):
        values = getattr(snapshot, name)
        if type(values) is not tuple or len(values) > maximum or len(set(values)) != len(values):
            raise ValueError("incident aggregate exceeds bounds")
        expected = {"processes": IncidentProcessRef, "connections": IncidentConnectionRef,
                    "destinations": IncidentDestination, "evidence": EvidenceReference,
                    "alerts": UUID, "assessments": AlertAssessmentReference, "scopes": EvidenceScope,
                    "relations": IncidentRelation, "limitations": IncidentLimitation}[name]
        if any(type(v) is not expected for v in values):
            raise TypeError("incident aggregate contains an untyped value")
    if not snapshot.relations or sum(r.reason is IncidentRelationReason.FIRST_OBSERVATION for r in snapshot.relations) != 1:
        raise ValueError("incident requires exactly one canonical seed")
    observations = [r.observation for r in snapshot.relations]
    if len(set(observations)) != len(observations) or min(r.observed_at for r in observations) != first or max(r.observed_at for r in observations) != last:
        raise ValueError("incident observation range is inconsistent")
    for relation in snapshot.relations:
        ref = relation.observation.reference
        refs = (snapshot.connections if isinstance(ref, IncidentConnectionRef) else
                snapshot.evidence if isinstance(ref, EvidenceReference) else
                snapshot.assessments if isinstance(ref, AlertAssessmentReference) else snapshot.alerts)
        if ref not in refs:
            raise ValueError("observation source is missing")
        key = relation.matched_key
        if key is None:
            continue
        reason, identity = key.reason, key.identity
        if reason is IncidentRelationReason.SAME_CONNECTION_LIFECYCLE and identity not in snapshot.connections:
            raise ValueError("matched connection is missing")
        if reason is IncidentRelationReason.SAME_CANONICAL_EVIDENCE and identity not in snapshot.evidence:
            raise ValueError("matched evidence is missing")
        if reason is IncidentRelationReason.SAME_ASSESSMENT_LINEAGE and identity not in {a.assessment_id for a in snapshot.assessments}:
            raise ValueError("matched assessment lineage is missing")
        if reason is IncidentRelationReason.SAME_ALERT_OBSERVATION and identity not in snapshot.alerts:
            raise ValueError("matched alert is missing")
        if reason is IncidentRelationReason.SAME_PROCESS_AND_DESTINATION:
            from netsentinel.domain.incidents import IncidentProcessDestination
            from netsentinel.domain.risk_evidence import EvidenceScopeKind
            if not isinstance(identity, IncidentProcessDestination) or identity.process not in snapshot.processes or identity.destination not in snapshot.destinations or identity.scope not in snapshot.scopes:
                raise ValueError("matched process/destination is missing")
            if identity.process.identity.create_time is None or identity.destination.port is None or identity.destination.protocol is None or identity.scope.kind is not EvidenceScopeKind.NETWORK:
                raise ValueError("derived matching identity is incomplete")
    if len(canonical_incident_json(snapshot).encode("ascii")) > MAX_INCIDENT_BYTES:
        raise ValueError("incident snapshot exceeds byte bound")


def stable_incident_id(snapshot: CorrelatedIncident, policy: IncidentPolicy = IncidentPolicy()) -> UUID:
    seed = next(r.observation for r in snapshot.relations if r.reason is IncidentRelationReason.FIRST_OBSERVATION)
    context = f"v1:{policy.window // timedelta(microseconds=1)}:{snapshot.cohort.isoformat()}:"
    return uuid5(INCIDENT_NAMESPACE, context + canonical_incident_json(seed))


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    snapshot: CorrelatedIncident = field(repr=False)
    revision: int
    state: IncidentState
    created_at: datetime
    updated_at: datetime
    action: IncidentAction
    origin: IncidentOrigin
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    reopened_at: datetime | None = None
    correlation_policy: IncidentPolicy = IncidentPolicy()
    correlation_version: int = 1
    format_version: int = INCIDENT_FORMAT_VERSION

    def __post_init__(self) -> None:
        validate_incident(self.snapshot, self.correlation_policy)
        if type(self.revision) is not int or not 1 <= self.revision <= 2**63 - 1:
            raise ValueError("invalid incident revision")
        if self.format_version != 1 or type(self.format_version) is not int or self.correlation_version != 1 or type(self.correlation_version) is not int:
            raise ValueError("unsupported incident contract version")
        for value, expected in ((self.state, IncidentState), (self.action, IncidentAction), (self.origin, IncidentOrigin)):
            if type(value) is not expected:
                raise TypeError("typed lifecycle required")
        for name in ("created_at", "updated_at", "acknowledged_at", "resolved_at", "reopened_at"):
            stamp = getattr(self, name)
            if stamp is not None:
                incident_time(stamp)
                if name != "created_at" and not self.created_at <= stamp <= self.updated_at:
                    raise ValueError("invalid lifecycle timestamp ordering")
        if self.state is IncidentState.RESOLVED and self.resolved_at is None:
            raise ValueError("resolved incident requires time")
        if self.state is IncidentState.ACKNOWLEDGED and self.acknowledged_at is None:
            raise ValueError("acknowledged incident requires time")

    @property
    def incident_id(self) -> UUID:
        return self.snapshot.incident_id


@dataclass(frozen=True, slots=True)
class IncidentRevision:
    incident_id: UUID
    revision: int
    state: IncidentState
    action: IncidentAction
    origin: IncidentOrigin
    changed_at: datetime
    first_observed_at: datetime
    last_observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.incident_id) is not UUID or type(self.revision) is not int or not 1 <= self.revision <= 2**63 - 1:
            raise ValueError("invalid revision identity")
        for value, expected in ((self.state, IncidentState), (self.action, IncidentAction), (self.origin, IncidentOrigin)):
            if type(value) is not expected:
                raise TypeError("invalid revision lifecycle")
        for stamp in (self.changed_at, self.first_observed_at, self.last_observed_at):
            incident_time(stamp)
        if self.first_observed_at > self.last_observed_at:
            raise ValueError("invalid revision observation range")


@dataclass(frozen=True, slots=True)
class IncidentSourceLink:
    """Namespaced identity with minimum explanation; payload has a closed codec."""
    kind: str
    identity: str = field(repr=False)
    payload: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.kind not in ("process", "connection", "destination", "evidence", "assessment", "alert", "scope", "relation"):
            raise ValueError("unknown incident source kind")
        if type(self.identity) is not str or len(self.identity) != 64 or any(c not in "0123456789abcdef" for c in self.identity):
            raise ValueError("invalid source identity")
        if type(self.payload) is not str or len(self.payload.encode("utf-8")) > MAX_LINK_BYTES:
            raise ValueError("source explanation exceeds bound")
        if sha256(self.payload.encode("ascii")).hexdigest() != self.identity:
            raise ValueError("inconsistent source identity")


@dataclass(frozen=True, slots=True)
class IncidentReferenceState:
    link: IncidentSourceLink = field(repr=False)
    status: IncidentSourceStatus


@dataclass(frozen=True, slots=True)
class IncidentResult:
    status: IncidentStatus
    record: IncidentRecord | None = None
    references: tuple[IncidentReferenceState, ...] = ()


@dataclass(frozen=True, slots=True)
class IncidentPage:
    entries: tuple[IncidentResult, ...]
    has_more: bool = False
    after_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class IncidentHistory:
    status: IncidentStatus
    entries: tuple[IncidentRevision, ...] = ()
    truncated: bool = False


class IncidentCommandError(RuntimeError):
    def __init__(self, status: IncidentStatus) -> None:
        self.status = status
        super().__init__(status.value)
