"""NS-078 immutable historical explanations, independent of alert lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
from uuid import UUID

from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationRevision
from netsentinel.domain.connections import ObservationQuality, ProcessIdentity
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceQuality, EvidenceReference, EvidenceRole,
    EvidenceScope, EvidenceSource, EvidenceSubject, _code, _digest,
    MAX_EVIDENCE_CONTRIBUTORS, MAX_EVIDENCE_REFERENCES,
)
from netsentinel.domain.risk_scoring import (
    AssessmentAvailability, ContributionDirection, ContributorFamily, CorrelationKey, CorrelationGroup,
    Freshness, RiskScoreResult, RiskScoringInput, RiskSeverity, ScoringAdjustment,
    ScoringReason, SeverityCapReason, MAX_SCORE_CONTRIBUTORS,
)

ASSESSMENT_FORMAT_VERSION = 1
MAX_ASSESSMENT_PAYLOAD_BYTES = 65_536
MAX_ASSESSMENT_KEY_BYTES = 8_192
MAX_ASSESSMENTS = 512
MAX_ASSESSMENT_REVISIONS = 8
MAX_ASSESSMENT_CLEANUP_ROWS = 128


def utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("assessment timestamp must be UTC-aware")
    return value.astimezone(UTC)


def positive_version(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 1_000_000:
        raise ValueError("historical version must be a bounded positive integer")


@dataclass(frozen=True, slots=True)
class AssessmentStoragePolicy:
    max_assessments: int = MAX_ASSESSMENTS
    max_revisions: int = MAX_ASSESSMENT_REVISIONS
    retention_days: int = 30
    cleanup_chunk_size: int = MAX_ASSESSMENT_CLEANUP_ROWS

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_assessments, MAX_ASSESSMENTS),
                               (self.max_revisions, MAX_ASSESSMENT_REVISIONS),
                               (self.retention_days, 365),
                               (self.cleanup_chunk_size, MAX_ASSESSMENT_CLEANUP_ROWS)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("assessment storage policy exceeds bounds")
        if self.cleanup_chunk_size < self.max_revisions:
            raise ValueError("cleanup must accommodate one complete assessment")


@dataclass(frozen=True, slots=True)
class RiskAssessmentKey:
    kind: str
    scope: EvidenceScope
    subject: EvidenceSubject = field(repr=False)
    observation_reference: EvidenceReference
    original_observed_at: datetime
    assessment_id: str = field(init=False)

    def __post_init__(self) -> None:
        _code(self.kind)
        if type(self.scope) is not EvidenceScope or type(self.subject) is not EvidenceSubject or type(self.observation_reference) is not EvidenceReference:
            raise TypeError("assessment identity requires canonical typed observation context")
        object.__setattr__(self, "original_observed_at", utc_time(self.original_observed_at))
        content = canonical_json(self)
        if len(content.encode("ascii")) > MAX_ASSESSMENT_KEY_BYTES:
            raise ValueError("assessment identity exceeds quota")
        object.__setattr__(self, "assessment_id", sha256(content.encode("ascii")).hexdigest())


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceSnapshot:
    evidence_id: str
    contract_version: int
    source: EvidenceSource
    rule_id: str
    reason_code: str
    producer_policy_version: int | None
    role: EvidenceRole
    result_code: str | None
    scope: EvidenceScope
    subject: EvidenceSubject = field(repr=False)
    quality: EvidenceQuality
    confidence: EvidenceConfidence | None
    observed_at: datetime
    freshness: Freshness
    references: tuple[EvidenceReference, ...]
    expected_mac: MacAddress | None = None

    def __post_init__(self) -> None:
        _digest(self.evidence_id)
        positive_version(self.contract_version)
        if self.producer_policy_version is not None:
            positive_version(self.producer_policy_version)
        for code in (self.rule_id, self.reason_code):
            _code(code)
        if self.result_code is not None:
            _code(self.result_code)
        for value, expected in ((self.source, EvidenceSource), (self.role, EvidenceRole),
                                (self.scope, EvidenceScope), (self.subject, EvidenceSubject),
                                (self.quality, EvidenceQuality), (self.freshness, Freshness)):
            if type(value) is not expected:
                raise TypeError("evidence snapshot fields must be typed")
        if self.confidence is not None and type(self.confidence) is not EvidenceConfidence:
            raise TypeError("confidence must be typed")
        if self.expected_mac is not None and type(self.expected_mac) is not MacAddress:
            raise TypeError("expected MAC must be typed")
        if self.quality.measurement is ObservationQuality.FAILED and self.role is not EvidenceRole.LIMITATION:
            raise ValueError("failed evidence must remain limitation-only")
        object.__setattr__(self, "observed_at", utc_time(self.observed_at))
        if type(self.references) is not tuple or len(self.references) > MAX_EVIDENCE_REFERENCES or any(type(r) is not EvidenceReference for r in self.references) or len(set(self.references)) != len(self.references):
            raise ValueError("references must be a bounded unique tuple")
        object.__setattr__(self, "references", tuple(sorted(self.references, key=lambda r: (r.kind.value, str(r.value)))))


@dataclass(frozen=True, slots=True)
class AssessmentContributorSnapshot:
    evidence_id: str
    policy_version: int
    family: ContributorFamily | None
    correlation_group: CorrelationGroup | None
    correlation_fingerprint: str | None
    direction: ContributionDirection
    raw_points: int
    applied_points: int
    eligible: bool
    reason: ScoringReason
    adjustments: tuple[ScoringAdjustment, ...]

    def __post_init__(self) -> None:
        _digest(self.evidence_id)
        positive_version(self.policy_version)
        if any(type(p) is not int or not -100 <= p <= 100 for p in (self.raw_points, self.applied_points)):
            raise ValueError("contributor points exceed bounds")
        if type(self.direction) is not ContributionDirection or type(self.reason) is not ScoringReason or type(self.eligible) is not bool:
            raise TypeError("contributor decisions must be typed")
        if self.family is not None and type(self.family) is not ContributorFamily:
            raise TypeError("family must be typed")
        if self.correlation_group is not None and type(self.correlation_group) is not CorrelationGroup:
            raise TypeError("correlation group must be typed")
        if (self.correlation_group is None) != (self.correlation_fingerprint is None):
            raise ValueError("correlation group and identity must be reported together")
        if self.correlation_fingerprint is not None:
            _digest(self.correlation_fingerprint)
        direction = ContributionDirection.POSITIVE if self.raw_points > 0 else ContributionDirection.NEGATIVE if self.raw_points < 0 else ContributionDirection.NEUTRAL
        if self.direction is not direction or abs(self.applied_points) > abs(self.raw_points) or self.applied_points * self.raw_points < 0 or (not self.eligible and self.applied_points):
            raise ValueError("contributor direction/eligibility is inconsistent")
        if type(self.adjustments) is not tuple or len(self.adjustments) > len(ScoringAdjustment) or any(type(a) is not ScoringAdjustment for a in self.adjustments) or len(set(self.adjustments)) != len(self.adjustments):
            raise ValueError("adjustments must be a bounded unique tuple")
        object.__setattr__(self, "adjustments", tuple(sorted(self.adjustments, key=lambda a: a.value)))


@dataclass(frozen=True, slots=True)
class AssessmentSnapshot:
    """Stored result values; accepts historical versions without invoking policy."""

    policy_version: int
    score: int
    positive_subtotal: int
    raw_mitigation: int
    applied_mitigation: int
    availability: AssessmentAvailability
    confidence: EvidenceConfidence | None
    measurement_quality: ObservationQuality | None
    score_severity: RiskSeverity | None
    severity: RiskSeverity | None
    severity_caps: tuple[SeverityCapReason, ...]
    evidence: tuple[AssessmentEvidenceSnapshot, ...] = field(repr=False)
    contributors: tuple[AssessmentContributorSnapshot, ...]

    def __post_init__(self) -> None:
        positive_version(self.policy_version)
        for items, maximum, item_type in ((self.evidence, MAX_EVIDENCE_CONTRIBUTORS, AssessmentEvidenceSnapshot),
                                         (self.contributors, MAX_SCORE_CONTRIBUTORS, AssessmentContributorSnapshot),
                                         (self.severity_caps, len(SeverityCapReason), SeverityCapReason)):
            if type(items) is not tuple or len(items) > maximum or any(type(i) is not item_type for i in items):
                raise ValueError("snapshot collection exceeds typed quota")
        ids = {e.evidence_id for e in self.evidence}
        if len(ids) != len(self.evidence) or len(set(self.severity_caps)) != len(self.severity_caps):
            raise ValueError("duplicate snapshot evidence or severity cap")
        if {c.evidence_id for c in self.contributors} != ids or any(c.policy_version != self.policy_version for c in self.contributors):
            raise ValueError("contributor evidence/version mismatch")
        if len({(c.evidence_id, c.direction) for c in self.contributors}) != len(self.contributors):
            raise ValueError("duplicate contributor")
        if any(type(n) is not int for n in (self.score, self.positive_subtotal, self.raw_mitigation, self.applied_mitigation)):
            raise ValueError("snapshot totals must be integers")
        if not 0 <= self.score <= self.positive_subtotal <= 100 or not 0 <= self.raw_mitigation <= 3 * MAX_EVIDENCE_CONTRIBUTORS or not 0 <= self.applied_mitigation <= min(5, self.positive_subtotal // 4, self.raw_mitigation):
            raise ValueError("snapshot totals exceed bounds")
        if self.score != sum(c.applied_points for c in self.contributors) or self.score != self.positive_subtotal - self.applied_mitigation or self.positive_subtotal != sum(max(0, c.applied_points) for c in self.contributors) or self.raw_mitigation != -sum(min(0, c.raw_points) for c in self.contributors):
            raise ValueError("stored score must reconcile with explanations")
        if type(self.availability) is not AssessmentAvailability:
            raise TypeError("availability must be typed")
        for value, expected in ((self.confidence, EvidenceConfidence), (self.measurement_quality, ObservationQuality), (self.score_severity, RiskSeverity), (self.severity, RiskSeverity)):
            if value is not None and type(value) is not expected:
                raise TypeError("result context must be typed")
        if (self.availability is AssessmentAvailability.UNKNOWN) != (self.severity is None and self.score_severity is None):
            raise ValueError("unknown availability must preserve unknown severity")
        object.__setattr__(self, "evidence", tuple(sorted(self.evidence, key=lambda e: e.evidence_id)))
        object.__setattr__(self, "contributors", tuple(sorted(self.contributors, key=lambda c: (c.evidence_id, c.direction.value))))
        object.__setattr__(self, "severity_caps", tuple(sorted(self.severity_caps, key=lambda s: s.value)))
        if len(canonical_json(self).encode("ascii")) > MAX_ASSESSMENT_PAYLOAD_BYTES:
            raise ValueError("assessment snapshot exceeds payload quota")

    @property
    def content_fingerprint(self) -> str:
        return sha256(canonical_json(self).encode("ascii")).hexdigest()


def snapshot_from_score(value: RiskScoringInput, result: RiskScoreResult) -> AssessmentSnapshot:
    """Copy only the bounded explanation; no raw source object graph is stored."""
    if type(value) is not RiskScoringInput or type(result) is not RiskScoreResult:
        raise TypeError("snapshot requires typed scoring input/result")
    evidence_by_id = {e.evidence_id: e for e in value.batch.evidence}
    if any(evidence_by_id.get(c.evidence.evidence_id) != c.evidence for c in result.contributors):
        raise ValueError("result does not describe the supplied evidence")
    freshness = {f.evidence_id: f.status for f in value.freshness}
    evidence = tuple(AssessmentEvidenceSnapshot(
        e.evidence_id, e.contract_version, e.source, e.rule_id, e.reason_code,
        e.policy_version, e.role, e.result_code, e.scope, e.subject, e.quality,
        e.confidence, e.observed_at, freshness.get(e.evidence_id, Freshness.UNKNOWN),
        e.references, e.legacy_arp.source.evidence.expected_mac if e.legacy_arp else None,
    ) for e in value.batch.evidence)
    contributors = tuple(AssessmentContributorSnapshot(
        c.evidence.evidence_id, c.policy_version, c.family,
        c.correlation_key.group if c.correlation_key else None,
        sha256(canonical_json(c.correlation_key).encode("ascii")).hexdigest() if c.correlation_key else None,
        c.direction, c.raw_points, c.applied_points, c.eligible, c.reason, c.adjustments,
    ) for c in result.contributors)
    return AssessmentSnapshot(result.policy_version, result.score, result.positive_subtotal,
                              result.raw_mitigation, result.applied_mitigation, result.availability,
                              result.confidence, result.measurement_quality, result.score_severity,
                              result.severity, result.severity_caps, evidence, contributors)


@dataclass(frozen=True, slots=True)
class RiskAssessmentRevision:
    key: RiskAssessmentKey
    revision: int
    assessed_at: datetime
    snapshot: AssessmentSnapshot
    format_version: int = ASSESSMENT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if type(self.key) is not RiskAssessmentKey or type(self.snapshot) is not AssessmentSnapshot:
            raise TypeError("revision requires immutable identity and snapshot")
        if type(self.revision) is not int or not 1 <= self.revision <= 2**63 - 1:
            raise ValueError("revision number must be a positive local integer")
        if type(self.format_version) is not int or self.format_version != ASSESSMENT_FORMAT_VERSION:
            raise ValueError("unsupported assessment format")
        object.__setattr__(self, "assessed_at", utc_time(self.assessed_at))


class AssessmentReadStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    CORRUPT = "corrupt"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNAVAILABLE = "unavailable"


class AssessmentSourceStatus(str, Enum):
    AVAILABLE = "available"
    SOURCE_EXPIRED_OR_UNAVAILABLE = "source_expired_or_unavailable"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class AssessmentReferenceState:
    reference: EvidenceReference
    status: AssessmentSourceStatus


@dataclass(frozen=True, slots=True)
class AssessmentRead:
    status: AssessmentReadStatus
    revision: RiskAssessmentRevision | None = None
    references: tuple[AssessmentReferenceState, ...] = ()


@dataclass(frozen=True, slots=True)
class AssessmentHistory:
    status: AssessmentReadStatus
    entries: tuple[AssessmentRead, ...] = ()
    truncated: bool = False


class AssessmentPersistenceError(RuntimeError):
    """Sanitized persistence failure; does not change the scoring result."""


class AssessmentIdentityConflict(AssessmentPersistenceError):
    """Persisted logical identity conflicts with the request."""


@dataclass(frozen=True, slots=True)
class AssessmentSave:
    revision: RiskAssessmentRevision
    created: bool


# Closed serializer vocabulary, shared by identity hashing and the SQL codec.
ASSESSMENT_VALUE_TYPES = (
    RiskAssessmentKey, AssessmentSnapshot, AssessmentEvidenceSnapshot,
    AssessmentContributorSnapshot, EvidenceScope, EvidenceSubject, EvidenceQuality,
    EvidenceReference, CorrelationKey, ApplicationIdentity, ApplicationRevision,
    ProcessIdentity, MacAddress,
)


def _primitive(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return utc_time(value).isoformat(timespec="microseconds")
    if isinstance(value, UUID):
        return str(value)
    if type(value) is tuple:
        return [_primitive(v) for v in value]
    if is_dataclass(value) and not isinstance(value, type):
        if type(value) not in ASSESSMENT_VALUE_TYPES:
            raise TypeError("extended values cannot add assessment payload fields")
        return {f.name: _primitive(getattr(value, f.name)) for f in fields(value) if f.init}
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError("unsupported snapshot value")


def canonical_json(value: object) -> str:
    return json.dumps(_primitive(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
