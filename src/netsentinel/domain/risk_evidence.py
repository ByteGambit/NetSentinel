"""NS-076 portable evidence envelopes, without assessment or scoring policy."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import ip_address
import json
import ntpath
import re
from uuid import UUID

from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityEvidence, ArpIdentityRule,
    ArpRiskAssessment, ArpScoreComponent,
)
from netsentinel.domain.application_identity import (
    ApplicationIdentity, ApplicationIdentityQuality, ApplicationRevision,
)
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkScopeStatus, ObservationQuality, ProcessIdentity,
)
from netsentinel.domain.observations import MacAddress

EVIDENCE_CONTRACT_VERSION = 1
MAX_EVIDENCE_REFERENCES = 8
MAX_EVIDENCE_CONTRIBUTORS = 32
MAX_EVIDENCE_LIMITATIONS = 16
MAX_EVIDENCE_CODE_LENGTH = 64


def _code(value: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_EVIDENCE_CODE_LENGTH or re.fullmatch(r"[a-z][a-z0-9_]*", value) is None:
        raise ValueError("evidence code must be bounded lower-case symbolic ASCII")


def _digest(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("reference must be canonical SHA-256 hex")


class EvidenceSource(str, Enum):
    THREAT_INTELLIGENCE = "threat_intelligence"
    ARP_IDENTITY = "arp_identity"
    DESTINATION_NOVELTY = "destination_novelty"
    FREQUENCY_DIVERSITY = "frequency_diversity"
    PERIODICITY = "periodicity"


class EvidenceRole(str, Enum):
    OBSERVATION = "observation"
    FINDING = "finding"
    LIMITATION = "limitation"


class EvidenceScopeKind(str, Enum):
    HOST = "host"
    NETWORK = "network"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceScope:
    """ARP needs no invented interface attribution; unresolved has no fingerprint."""

    kind: EvidenceScopeKind
    network_status: NetworkScopeStatus | None = None
    network_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceScopeKind):
            raise TypeError("scope kind must be typed")
        if self.kind is EvidenceScopeKind.HOST:
            if self.network_status is not None or self.network_fingerprint is not None:
                raise ValueError("host scope cannot assert a network")
        elif self.kind is EvidenceScopeKind.NETWORK:
            if self.network_status is not NetworkScopeStatus.RESOLVED:
                raise ValueError("network scope requires resolved attribution")
            _digest(self.network_fingerprint)
        elif self.network_status not in (NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS) or not isinstance(self.network_status, NetworkScopeStatus) or self.network_fingerprint is not None:
            raise ValueError("unknown/ambiguous scope cannot assert a fingerprint")

    @classmethod
    def from_connection(cls, network: ConnectionNetworkScope) -> EvidenceScope:
        if not isinstance(network, ConnectionNetworkScope):
            raise TypeError("network must be ConnectionNetworkScope")
        kind = EvidenceScopeKind.NETWORK if network.status is NetworkScopeStatus.RESOLVED else EvidenceScopeKind.UNKNOWN
        return cls(kind, network.status, network.fingerprint)


class EvidenceSubjectKind(str, Enum):
    NETWORK = "network"
    APPLICATION = "application"
    PROCESS = "process"
    CONNECTION = "connection"
    DESTINATION = "destination"
    DEVICE = "device"
    GATEWAY = "gateway"


@dataclass(frozen=True, slots=True)
class EvidenceSubject:
    """Identity only: no process name, ProcessInfo, command line or free path."""

    kind: EvidenceSubjectKind
    application: ApplicationIdentity | None = field(default=None, repr=False)
    revision: ApplicationRevision | None = None
    process: ProcessIdentity | None = None
    session_id: UUID | None = None
    lifecycle_id: UUID | None = None
    ip_address: str | None = None
    mac: MacAddress | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceSubjectKind):
            raise TypeError("subject kind must be typed")
        for value, expected in ((self.application, ApplicationIdentity), (self.revision, ApplicationRevision),
                                (self.process, ProcessIdentity), (self.session_id, UUID),
                                (self.lifecycle_id, UUID), (self.mac, MacAddress)):
            if value is not None and not isinstance(value, expected):
                raise TypeError("subject fields must use canonical domain types")
        if self.revision is not None and self.application is None:
            raise ValueError("revision requires an application identity")
        if self.process is not None and self.process.create_time is None and self.session_id is None:
            raise ValueError("PID-only identity requires a monitoring session")
        if self.process is not None and self.process.pid > 2**32 - 1:
            raise ValueError("process PID exceeds the portable Windows identity bound")
        if self.application is not None:
            key = self.application.key
            if key is not None and (len(key.encode("utf-8")) > 4096 or any(ord(c) < 32 for c in key)):
                raise ValueError("application key exceeds controlled identity bounds")
            if self.application.quality is ApplicationIdentityQuality.STABLE:
                assert key is not None
                path = key[len("winpath:v1:"):]
                drive, tail = ntpath.splitdrive(path)
                if not drive or not tail.startswith("\\") or ntpath.normcase(ntpath.normpath(path)) != path:
                    raise ValueError("application key must be canonical")
            elif self.application.quality is ApplicationIdentityQuality.PROVISIONAL:
                if self.process is None or self.process.create_time is None:
                    raise ValueError("provisional application requires a known process instance")
                delta = self.process.create_time - datetime(1970, 1, 1, tzinfo=UTC)
                micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
                if key != f"instance:v1:{self.process.pid}:{micros}":
                    raise ValueError("provisional application must match its process instance")
        if self.ip_address is not None:
            if not isinstance(self.ip_address, str) or len(self.ip_address) > 45 or "%" in self.ip_address:
                raise ValueError("IP requires a bounded address without an interface zone")
            object.__setattr__(self, "ip_address", str(ip_address(self.ip_address)))
        required = {
            EvidenceSubjectKind.APPLICATION: self.application,
            EvidenceSubjectKind.PROCESS: self.process,
            EvidenceSubjectKind.CONNECTION: self.lifecycle_id,
            EvidenceSubjectKind.DESTINATION: self.ip_address,
            EvidenceSubjectKind.DEVICE: self.mac,
            EvidenceSubjectKind.GATEWAY: self.ip_address,
        }
        if self.kind in required and required[self.kind] is None:
            raise ValueError("subject is missing its defining identity")


class EvidenceLimitation(str, Enum):
    CAPACITY_LOSS = "capacity_loss"
    MONITORING_GAP = "monitoring_gap"
    REVISION_UNVERIFIED = "revision_unverified"
    IP_ONLY = "ip_only_service_not_inferred"
    REDUCED_OBSERVATION = "reduced_current_observation"
    RESOLUTION_LIMITED = "resolution_limited"
    POLLING_QUANTIZED = "polling_quantized_exact_timer_not_inferred"
    BENIGN_SCHEDULE_COMPATIBLE = "benign_updates_telemetry_sync_reconnects_compatible"
    BEHAVIORAL_ONLY = "behavioral_only_low_security_significance"
    MISSED_MULTIPLE_COMPATIBLE = "missed_multiple_compatible_not_proven"
    SEQUENCE_TRUNCATED = "recent_bounded_sequence_only"
    PRIOR_HISTORY_UNAVAILABLE = "prior_history_unavailable"


@dataclass(frozen=True, slots=True)
class EvidenceQuality:
    """None means unreported measurement quality, never COMPLETE by assumption."""

    measurement: ObservationQuality | None = None
    limitations: tuple[EvidenceLimitation, ...] = ()

    def __post_init__(self) -> None:
        if self.measurement is not None and not isinstance(self.measurement, ObservationQuality):
            raise TypeError("measurement must be ObservationQuality or None")
        if not isinstance(self.limitations, tuple) or len(self.limitations) > MAX_EVIDENCE_LIMITATIONS or any(not isinstance(x, EvidenceLimitation) for x in self.limitations):
            raise ValueError("limitations must be a bounded typed tuple")
        if len(set(self.limitations)) != len(self.limitations):
            raise ValueError("duplicate limitation")
        object.__setattr__(self, "limitations", tuple(sorted(self.limitations, key=lambda x: x.value)))


class EvidenceConfidence(str, Enum):
    PASSIVE_OBSERVATION = "passive_observation"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class EvidenceReferenceKind(str, Enum):
    CONNECTION_LIFECYCLE = "connection_lifecycle"
    MONITORING_SESSION = "monitoring_session"
    DNS_EVIDENCE = "dns_evidence"
    EVIDENCE = "evidence"
    LEGACY_ARP_EVENT = "legacy_arp_event"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    kind: EvidenceReferenceKind
    value: UUID | str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceReferenceKind):
            raise TypeError("reference kind must be typed")
        if self.kind in (EvidenceReferenceKind.EVIDENCE, EvidenceReferenceKind.LEGACY_ARP_EVENT):
            if not isinstance(self.value, str):
                raise TypeError("evidence reference requires a digest")
            _digest(self.value)
        elif not isinstance(self.value, UUID):
            raise TypeError("observation reference requires a canonical UUID")


@dataclass(frozen=True, slots=True)
class LegacyArpContext:
    """Original semantics, including legacy severity/score; no new weights."""

    source: ArpIdentityConflictDetected
    correlation: ArpRiskAssessment | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, ArpIdentityConflictDetected):
            raise TypeError("legacy context requires the original typed event")
        if self.correlation is not None:
            c = self.correlation
            if not isinstance(c, ArpRiskAssessment) or c.source != self.source:
                raise ValueError("correlation must reference the same original event")
            if not isinstance(c.breakdown, tuple) or len(c.breakdown) > MAX_EVIDENCE_REFERENCES or not 1 <= c.observation_count <= 1_000_000_000 or any(part.points > 1_000_000_000 for part in c.breakdown):
                raise ValueError("legacy correlation exceeds portable bounds")


def _primitive(value: object) -> object:
    """Internal canonical encoding of validated fields, never an input payload."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, tuple):
        return [_primitive(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        if type(value) not in (
            RiskEvidence, EvidenceScope, EvidenceSubject, EvidenceQuality,
            EvidenceReference, LegacyArpContext, ApplicationIdentity,
            ApplicationRevision, ProcessIdentity, MacAddress,
            ArpIdentityConflictDetected, ArpIdentityEvidence, ArpRiskAssessment, ArpScoreComponent,
        ):
            raise TypeError("extended dataclasses cannot add evidence payload fields")
        return {f.name: _primitive(getattr(value, f.name)) for f in fields(value) if f.name != "evidence_id"}
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError("unsupported evidence field")


@dataclass(frozen=True, slots=True)
class RiskEvidence:
    source: EvidenceSource
    rule_id: str
    reason_code: str
    observed_at: datetime
    scope: EvidenceScope
    subject: EvidenceSubject
    quality: EvidenceQuality
    role: EvidenceRole = EvidenceRole.OBSERVATION
    policy_version: int | None = None
    result_code: str | None = None
    confidence: EvidenceConfidence | None = None
    references: tuple[EvidenceReference, ...] = ()
    legacy_arp: LegacyArpContext | None = None
    contract_version: int = EVIDENCE_CONTRACT_VERSION
    evidence_id: str = field(init=False)

    def __post_init__(self) -> None:
        for value, expected in ((self.source, EvidenceSource), (self.scope, EvidenceScope),
                                (self.subject, EvidenceSubject), (self.quality, EvidenceQuality),
                                (self.role, EvidenceRole)):
            if not isinstance(value, expected):
                raise TypeError("evidence fields must be typed")
        _code(self.rule_id)
        _code(self.reason_code)
        if self.result_code is not None:
            _code(self.result_code)
        if type(self.contract_version) is not int or self.contract_version != EVIDENCE_CONTRACT_VERSION:
            raise ValueError("unsupported evidence contract version")
        if self.policy_version is not None and (type(self.policy_version) is not int or not 1 <= self.policy_version <= 1_000_000):
            raise ValueError("producer version must be bounded and positive")
        stamp = self.observed_at
        if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
            raise ValueError("evidence time must be UTC-aware")
        object.__setattr__(self, "observed_at", stamp.astimezone(UTC))
        if self.confidence is not None and not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("confidence must be typed or unreported")
        if self.quality.measurement is ObservationQuality.FAILED and self.role is not EvidenceRole.LIMITATION:
            raise ValueError("failed collection can only describe a limitation")
        refs = self.references
        if not isinstance(refs, tuple) or len(refs) > MAX_EVIDENCE_REFERENCES or any(not isinstance(r, EvidenceReference) for r in refs):
            raise ValueError("references must be a bounded typed tuple")
        if len(set(refs)) != len(refs):
            raise ValueError("duplicate evidence reference")
        object.__setattr__(self, "references", tuple(sorted(refs, key=lambda r: (r.kind.value, str(r.value)))))
        if self.legacy_arp is not None:
            if not isinstance(self.legacy_arp, LegacyArpContext) or self.source is not EvidenceSource.ARP_IDENTITY:
                raise TypeError("legacy context is only valid for ARP evidence")
            context = self.legacy_arp
            event = context.source
            subject_kind = EvidenceSubjectKind.GATEWAY if event.rule_id is ArpIdentityRule.GATEWAY_MAC_CHANGE else EvidenceSubjectKind.DEVICE
            at = context.correlation.last_observed_at if context.correlation else event.observed_at
            confidence = context.correlation.confidence if context.correlation else event.confidence
            if (self.rule_id != event.rule_id.value or self.reason_code != event.reason.value
                    or self.scope != EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, event.evidence.network_fingerprint)
                    or self.subject.kind is not subject_kind
                    or self.subject.ip_address != event.evidence.ip_address or self.subject.mac != event.evidence.observed_mac
                    or self.observed_at != at or self.confidence != EvidenceConfidence(confidence)
                    or self.role is not EvidenceRole.FINDING or self.result_code is not None
                    or self.policy_version is not None
                    or EvidenceReference(EvidenceReferenceKind.LEGACY_ARP_EVENT, event.event_fingerprint) not in refs):
                raise ValueError("legacy envelope must preserve the source semantics")
        encoded = json.dumps(_primitive(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        object.__setattr__(self, "evidence_id", sha256(encoded.encode("ascii")).hexdigest())


@dataclass(frozen=True, slots=True)
class RiskEvidenceBatch:
    """Flat evidence contributors, not scored contributors or a recursive graph."""

    evidence: tuple[RiskEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, tuple) or len(self.evidence) > MAX_EVIDENCE_CONTRIBUTORS or any(not isinstance(e, RiskEvidence) for e in self.evidence):
            raise ValueError("evidence contributors must be a bounded typed tuple")
        if len({e.evidence_id for e in self.evidence}) != len(self.evidence):
            raise ValueError("duplicate evidence contributor")
        object.__setattr__(self, "evidence", tuple(sorted(self.evidence, key=lambda e: e.evidence_id)))
