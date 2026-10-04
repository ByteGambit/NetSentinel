"""NS-089 memory-only incident pointers; correlation is not causality."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from ipaddress import ip_address
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import Endpoint, ProcessIdentity, TransportProtocol
from netsentinel.domain.dns import canonical_dns_name
from netsentinel.domain.risk_evidence import (
    EvidenceQuality, EvidenceReference, EvidenceReferenceKind, EvidenceScope,
    _digest,
)


def incident_time(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("incident time must be UTC-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class IncidentPolicy:
    window: timedelta = timedelta(minutes=10)
    max_lateness: timedelta = timedelta(minutes=10)
    max_incidents: int = 256
    max_processes: int = 16
    max_connections: int = 32
    max_destinations: int = 32
    max_evidence: int = 64
    max_alerts: int = 16
    max_assessments: int = 16
    max_scopes: int = 16
    max_relations: int = 128
    max_keys_per_incident: int = 256
    max_index_entries: int = 16_384
    max_gaps: int = 256

    def __post_init__(self) -> None:
        if type(self.window) is not timedelta or not timedelta(0) < self.window <= timedelta(minutes=10):
            raise ValueError("window must be positive and at most ten minutes")
        if type(self.max_lateness) is not timedelta or not timedelta(0) <= self.max_lateness <= timedelta(minutes=10):
            raise ValueError("lateness must be between zero and ten minutes")
        for name, maximum in (
            ("max_incidents", 256), ("max_processes", 16), ("max_connections", 32),
            ("max_destinations", 32), ("max_evidence", 64), ("max_alerts", 16),
            ("max_assessments", 16), ("max_scopes", 16), ("max_relations", 128),
            ("max_keys_per_incident", 256), ("max_index_entries", 16_384), ("max_gaps", 256),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("incident policy exceeds a hard bound")

    @property
    def retention_horizon(self) -> timedelta:
        return self.window + self.max_lateness

    def cohort(self, stamp: datetime) -> datetime:
        stamp = incident_time(stamp)
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        return epoch + ((stamp - epoch) // self.window) * self.window


@dataclass(frozen=True, slots=True)
class IncidentConnectionRef:
    session_id: UUID
    lifecycle_id: UUID

    def __post_init__(self) -> None:
        if type(self.session_id) is not UUID or type(self.lifecycle_id) is not UUID:
            raise TypeError("connection reference requires session and lifecycle UUIDs")


@dataclass(frozen=True, slots=True)
class IncidentProcessRef:
    session_id: UUID
    identity: ProcessIdentity

    def __post_init__(self) -> None:
        if type(self.session_id) is not UUID or type(self.identity) is not ProcessIdentity:
            raise TypeError("process reference requires canonical instance and session")
        if self.identity.pid > 2**32 - 1:
            raise ValueError("PID exceeds Windows identity bounds")


class IncidentDestinationKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"


@dataclass(frozen=True, slots=True)
class IncidentDestination:
    kind: IncidentDestinationKind
    value: str = field(repr=False)
    port: int | None = None
    protocol: TransportProtocol | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not IncidentDestinationKind or type(self.value) is not str:
            raise TypeError("destination requires typed kind and canonical text")
        if self.kind is IncidentDestinationKind.DOMAIN:
            value = canonical_dns_name(self.value)
        else:
            if len(self.value) > 45 or "%" in self.value:
                raise ValueError("IP must be bounded without an interface zone")
            address = ip_address(self.value)
            if (address.version == 4) != (self.kind is IncidentDestinationKind.IPV4):
                raise ValueError("destination kind and IP family disagree")
            value = str(address)
        object.__setattr__(self, "value", value)
        if self.port is not None and (type(self.port) is not int or not 0 <= self.port <= 65535):
            raise ValueError("destination port exceeds bounds")
        if self.protocol is not None and type(self.protocol) is not TransportProtocol:
            raise TypeError("destination protocol must be typed")

    @classmethod
    def from_endpoint(cls, endpoint: Endpoint, protocol: TransportProtocol) -> IncidentDestination:
        if type(endpoint) is not Endpoint:
            raise TypeError("destination requires a canonical endpoint")
        kind = IncidentDestinationKind.IPV4 if endpoint.ip_version == 4 else IncidentDestinationKind.IPV6
        return cls(kind, endpoint.address, endpoint.port, protocol)


class IncidentObservationKind(str, Enum):
    CONNECTION_OBSERVED = "connection_observed"
    CONNECTION_UPDATED = "connection_updated"
    CONNECTION_NOT_OBSERVED = "connection_not_observed"
    EVIDENCE_OBSERVED = "evidence_observed"
    ASSESSMENT_PRODUCED = "risk_assessment_produced"
    ALERT_OBSERVED = "alert_observed"


@dataclass(frozen=True, slots=True)
class IncidentObservationRef:
    kind: IncidentObservationKind
    reference: IncidentConnectionRef | EvidenceReference | AlertAssessmentReference | UUID
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.kind) is not IncidentObservationKind:
            raise TypeError("observation kind must be typed")
        expected = {
            IncidentObservationKind.CONNECTION_OBSERVED: IncidentConnectionRef,
            IncidentObservationKind.CONNECTION_UPDATED: IncidentConnectionRef,
            IncidentObservationKind.CONNECTION_NOT_OBSERVED: IncidentConnectionRef,
            IncidentObservationKind.EVIDENCE_OBSERVED: EvidenceReference,
            IncidentObservationKind.ASSESSMENT_PRODUCED: AlertAssessmentReference,
            IncidentObservationKind.ALERT_OBSERVED: UUID,
        }[self.kind]
        if type(self.reference) is not expected:
            raise TypeError("observation kind and reference disagree")
        if isinstance(self.reference, EvidenceReference) and self.reference.kind not in INCIDENT_EVIDENCE_KINDS:
            raise ValueError("session/lifecycle alone is not an evidence observation")
        object.__setattr__(self, "observed_at", incident_time(self.observed_at))


INCIDENT_EVIDENCE_KINDS = (
    EvidenceReferenceKind.EVIDENCE, EvidenceReferenceKind.DNS_EVIDENCE,
    EvidenceReferenceKind.LEGACY_ARP_EVENT,
)


@dataclass(frozen=True, slots=True)
class IncidentInput:
    observation: IncidentObservationRef
    scope: EvidenceScope
    process: IncidentProcessRef | None = None
    connection: IncidentConnectionRef | None = None
    destination: IncidentDestination | None = field(default=None, repr=False)
    evidence: tuple[EvidenceReference, ...] = ()
    assessment: AlertAssessmentReference | None = None
    alert_id: UUID | None = None
    quality: EvidenceQuality = EvidenceQuality()

    def __post_init__(self) -> None:
        if type(self.observation) is not IncidentObservationRef or type(self.scope) is not EvidenceScope or type(self.quality) is not EvidenceQuality:
            raise TypeError("incident input requires typed observation, scope and quality")
        for value, expected in ((self.process, IncidentProcessRef), (self.connection, IncidentConnectionRef),
                                (self.destination, IncidentDestination), (self.assessment, AlertAssessmentReference),
                                (self.alert_id, UUID)):
            if value is not None and type(value) is not expected:
                raise TypeError("incident references must use canonical types")
        if self.connection is not None and self.process is not None and self.connection.session_id != self.process.session_id:
            raise ValueError("process and connection sessions disagree")
        if self.assessment is not None and self.assessment.network_status != self.scope.network_status:
            raise ValueError("assessment reference and input scope disagree")
        ref = self.observation.reference
        if isinstance(ref, IncidentConnectionRef) and ref != self.connection:
            raise ValueError("observation must identify its supplied connection")
        if isinstance(ref, AlertAssessmentReference) and ref != self.assessment:
            raise ValueError("observation must identify its supplied assessment")
        if isinstance(ref, UUID) and ref != self.alert_id:
            raise ValueError("observation must identify its supplied alert")
        refs = self.evidence
        if type(refs) is not tuple or len(refs) > 64 or any(type(r) is not EvidenceReference or r.kind not in INCIDENT_EVIDENCE_KINDS for r in refs) or len(set(refs)) != len(refs):
            raise ValueError("incident evidence must be a bounded unique canonical tuple")
        if isinstance(ref, EvidenceReference) and ref not in refs:
            raise ValueError("evidence observation must retain its canonical reference")
        object.__setattr__(self, "evidence", tuple(sorted(refs, key=lambda r: (r.kind.value, str(r.value)))))

    @property
    def observed_at(self) -> datetime:
        return self.observation.observed_at


class IncidentRelationReason(str, Enum):
    FIRST_OBSERVATION = "first_observation"
    SAME_CONNECTION_LIFECYCLE = "same_connection_lifecycle"
    SAME_CANONICAL_EVIDENCE = "same_canonical_evidence_reference"
    SAME_ASSESSMENT_LINEAGE = "same_assessment_lineage"
    SAME_ALERT_OBSERVATION = "same_alert_observation"
    SAME_PROCESS_AND_DESTINATION = "same_process_instance_and_destination"


RELATION_PRIORITY = (
    IncidentRelationReason.SAME_CONNECTION_LIFECYCLE,
    IncidentRelationReason.SAME_CANONICAL_EVIDENCE,
    IncidentRelationReason.SAME_ASSESSMENT_LINEAGE,
    IncidentRelationReason.SAME_ALERT_OBSERVATION,
    IncidentRelationReason.SAME_PROCESS_AND_DESTINATION,
)


@dataclass(frozen=True, slots=True)
class IncidentProcessDestination:
    process: IncidentProcessRef
    destination: IncidentDestination
    scope: EvidenceScope

    def __post_init__(self) -> None:
        if type(self.process) is not IncidentProcessRef or type(self.destination) is not IncidentDestination or type(self.scope) is not EvidenceScope:
            raise TypeError("process/destination key requires typed identities")


@dataclass(frozen=True, slots=True)
class IncidentCorrelationKey:
    reason: IncidentRelationReason
    identity: IncidentConnectionRef | EvidenceReference | str | UUID | IncidentProcessDestination

    def __post_init__(self) -> None:
        expected = {
            IncidentRelationReason.SAME_CONNECTION_LIFECYCLE: IncidentConnectionRef,
            IncidentRelationReason.SAME_CANONICAL_EVIDENCE: EvidenceReference,
            IncidentRelationReason.SAME_ASSESSMENT_LINEAGE: str,
            IncidentRelationReason.SAME_ALERT_OBSERVATION: UUID,
            IncidentRelationReason.SAME_PROCESS_AND_DESTINATION: IncidentProcessDestination,
        }
        if type(self.reason) is not IncidentRelationReason or self.reason not in expected or type(self.identity) is not expected[self.reason]:
            raise TypeError("relation key requires a typed matching identity")
        if isinstance(self.identity, str):
            _digest(self.identity)
        if isinstance(self.identity, EvidenceReference) and self.identity.kind not in INCIDENT_EVIDENCE_KINDS:
            raise ValueError("non-evidence reference cannot be an evidence key")


class IncidentLimitation(str, Enum):
    QUALITY_LIMITED = "quality_limited"
    MONITORING_GAP = "monitoring_gap"
    CANONICAL_GAP_BRIDGE = "canonical_reference_across_gap"
    AMBIGUOUS_MATCH = "multiple_matching_incidents_not_unioned"
    CAPACITY_LIMITED = "capacity_limited"
    GAP_CAPACITY = "gap_marker_capacity_continuity_unknown"
    LATE = "outside_supported_lateness"


@dataclass(frozen=True, slots=True)
class IncidentRelation:
    observation: IncidentObservationRef
    reason: IncidentRelationReason
    matched_key: IncidentCorrelationKey | None = None

    def __post_init__(self) -> None:
        if type(self.observation) is not IncidentObservationRef or type(self.reason) is not IncidentRelationReason:
            raise TypeError("relation requires typed observation and reason")
        if self.reason is IncidentRelationReason.FIRST_OBSERVATION:
            if self.matched_key is not None:
                raise ValueError("seed cannot claim a matched key")
        elif type(self.matched_key) is not IncidentCorrelationKey or self.matched_key.reason is not self.reason:
            raise ValueError("attachment must explain its exact matching key")


@dataclass(frozen=True, slots=True)
class CorrelatedIncident:
    incident_id: UUID
    cohort: datetime
    first_observed_at: datetime
    last_observed_at: datetime
    processes: tuple[IncidentProcessRef, ...] = ()
    connections: tuple[IncidentConnectionRef, ...] = ()
    destinations: tuple[IncidentDestination, ...] = field(default=(), repr=False)
    evidence: tuple[EvidenceReference, ...] = ()
    assessments: tuple[AlertAssessmentReference, ...] = ()
    alerts: tuple[UUID, ...] = ()
    scopes: tuple[EvidenceScope, ...] = ()
    relations: tuple[IncidentRelation, ...] = ()
    limitations: tuple[IncidentLimitation, ...] = ()


class IncidentCorrelationStatus(str, Enum):
    NEW_INCIDENT = "new_incident"
    ATTACHED = "attached"
    DUPLICATE = "duplicate"
    LATE = "late"
    CAPACITY_LIMITED = "capacity_limited"


@dataclass(frozen=True, slots=True)
class IncidentCorrelationResult:
    status: IncidentCorrelationStatus
    incident: CorrelatedIncident | None = None
    reason: IncidentRelationReason | None = None
    limitations: tuple[IncidentLimitation, ...] = ()


@dataclass(frozen=True, slots=True)
class IncidentDiagnostics:
    active_incidents: int
    index_entries: int
    gap_markers: int
    new_incidents: int
    attachments: int
    duplicates: int
    out_of_order: int
    late: int
    gap_separated: int
    capacity_limited: int
    evictions: int
    expired: int
