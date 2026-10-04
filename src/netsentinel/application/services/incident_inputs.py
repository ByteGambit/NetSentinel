"""NS-089 explicit adapters for canonical events; no runtime subscriptions/I/O."""

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionLifecycleEvent, ConnectionOpened, ConnectionUpdated,
)
from netsentinel.domain.incidents import (
    INCIDENT_EVIDENCE_KINDS, IncidentConnectionRef, IncidentDestination,
    IncidentDestinationKind, IncidentInput, IncidentObservationKind as Kind,
    IncidentObservationRef, IncidentProcessRef,
)
from netsentinel.domain.risk_assessment import RiskAssessmentRevision
from netsentinel.domain.risk_evidence import (
    EvidenceQuality, EvidenceReference, EvidenceReferenceKind as RefKind,
    EvidenceScope, EvidenceSubject, RiskEvidence,
)
from uuid import UUID


def _connection(subject: EvidenceSubject, references: tuple[EvidenceReference, ...]) -> IncidentConnectionRef | None:
    sessions = {r.value for r in references if r.kind is RefKind.MONITORING_SESSION}
    lifecycles = {r.value for r in references if r.kind is RefKind.CONNECTION_LIFECYCLE}
    if subject.session_id is not None:
        sessions.add(subject.session_id)
    if subject.lifecycle_id is not None:
        lifecycles.add(subject.lifecycle_id)
    # Never guess which lifecycle/session a multi-reference evidence describes.
    if len(sessions) == len(lifecycles) == 1:
        session, lifecycle = next(iter(sessions)), next(iter(lifecycles))
        if isinstance(session, UUID) and isinstance(lifecycle, UUID):
            return IncidentConnectionRef(session, lifecycle)
    return None


def _process(subject: EvidenceSubject, connection: IncidentConnectionRef | None) -> IncidentProcessRef | None:
    session = subject.session_id or (connection.session_id if connection else None)
    if session is not None and subject.process is not None:
        return IncidentProcessRef(session, subject.process)
    return None


def _destination(subject: EvidenceSubject) -> IncidentDestination | None:
    if subject.ip_address is None:
        return None
    kind = IncidentDestinationKind.IPV6 if ":" in subject.ip_address else IncidentDestinationKind.IPV4
    # Evidence IP-only identity cannot invent a transport port or protocol.
    return IncidentDestination(kind, subject.ip_address)


def incident_input_from_connection(event: ConnectionLifecycleEvent,
                                   quality: EvidenceQuality = EvidenceQuality()) -> IncidentInput:
    if type(event) not in (ConnectionOpened, ConnectionUpdated, ConnectionClosed):
        raise TypeError("incident input requires an existing typed lifecycle event")
    if isinstance(event, ConnectionOpened):
        snapshot, kind = event.snapshot, Kind.CONNECTION_OBSERVED
    elif isinstance(event, ConnectionUpdated):
        snapshot, kind = event.current, Kind.CONNECTION_UPDATED
    else:
        snapshot, kind = event.last_snapshot, Kind.CONNECTION_NOT_OBSERVED
    connection = IncidentConnectionRef(event.session_id, event.lifecycle_id)
    process = IncidentProcessRef(event.session_id, snapshot.process.identity) if snapshot.process.identity else None
    destination = IncidentDestination.from_endpoint(snapshot.remote_endpoint, snapshot.protocol) if snapshot.remote_endpoint else None
    return IncidentInput(IncidentObservationRef(kind, connection, event.occurred_at),
        EvidenceScope.from_connection(snapshot.network_scope), process, connection, destination, quality=quality)


def incident_input_from_evidence(evidence: RiskEvidence) -> IncidentInput:
    if type(evidence) is not RiskEvidence:
        raise TypeError("incident input requires canonical RiskEvidence")
    ref = EvidenceReference(RefKind.EVIDENCE, evidence.evidence_id)
    refs = tuple(sorted({ref, *(r for r in evidence.references if r.kind in INCIDENT_EVIDENCE_KINDS)},
        key=lambda r: (r.kind.value, str(r.value))))
    connection = _connection(evidence.subject, evidence.references)
    return IncidentInput(IncidentObservationRef(Kind.EVIDENCE_OBSERVED, ref, evidence.observed_at),
        evidence.scope, _process(evidence.subject, connection), connection,
        _destination(evidence.subject), refs, quality=evidence.quality)


def incident_input_from_assessment(revision: RiskAssessmentRevision) -> IncidentInput:
    if type(revision) is not RiskAssessmentRevision:
        raise TypeError("incident input requires a historical assessment revision")
    key = revision.key
    ref = AlertAssessmentReference(key.assessment_id, revision.revision, key.scope.network_status)
    connection = _connection(key.subject, (key.observation_reference,))
    # Only pointers: do not retain/copy snapshot, provider context, scores or payload.
    evidence = {EvidenceReference(RefKind.EVIDENCE, e.evidence_id) for e in revision.snapshot.evidence}
    if key.observation_reference.kind in INCIDENT_EVIDENCE_KINDS:
        evidence.add(key.observation_reference)
    limitations = tuple(sorted({limitation for e in revision.snapshot.evidence
        for limitation in e.quality.limitations}, key=lambda limitation: limitation.value))
    quality = EvidenceQuality(revision.snapshot.measurement_quality, limitations)
    return IncidentInput(IncidentObservationRef(Kind.ASSESSMENT_PRODUCED, ref, key.original_observed_at),
        key.scope, _process(key.subject, connection), connection, _destination(key.subject),
        tuple(sorted(evidence, key=lambda r: (r.kind.value, str(r.value)))), ref, quality=quality)
