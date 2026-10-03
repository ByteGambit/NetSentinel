"""NS-077 pure, versioned review-priority policy; no security probability."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

from netsentinel.domain.alerts import ArpIdentityReason, ArpIdentityRule
from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationRevision
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.destination_novelty import DestinationNoveltyClassification as Novelty
from netsentinel.domain.frequency_diversity import BehaviorClassification as Behavior, BehaviorRule
from netsentinel.domain.periodicity import PeriodicityClassification as Periodicity, RULE_ID as PERIODICITY_RULE
from netsentinel.domain.risk_evidence import (
    MAX_EVIDENCE_CONTRIBUTORS, EvidenceConfidence, EvidenceLimitation,
    EvidenceRole, EvidenceScope, EvidenceSource, EvidenceSubject,
    RiskEvidence, RiskEvidenceBatch,
)
from netsentinel.domain.observations import MacAddress
from uuid import UUID

MAX_SCORE_CONTRIBUTORS = 2 * MAX_EVIDENCE_CONTRIBUTORS
NOVELTY_RULE = "destination_ip_novelty_rarity"


class Freshness(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceFreshness:
    evidence_id: str
    status: Freshness

    def __post_init__(self) -> None:
        if (not isinstance(self.evidence_id, str) or len(self.evidence_id) != 64
                or any(c not in "0123456789abcdef" for c in self.evidence_id)):
            raise ValueError("freshness requires a canonical evidence ID")
        if not isinstance(self.status, Freshness):
            raise TypeError("freshness must be typed")


@dataclass(frozen=True, slots=True)
class RiskScoringInput:
    batch: RiskEvidenceBatch
    freshness: tuple[EvidenceFreshness, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.batch, RiskEvidenceBatch):
            raise TypeError("scoring requires a bounded evidence batch")
        if (not isinstance(self.freshness, tuple) or len(self.freshness) > MAX_EVIDENCE_CONTRIBUTORS
                or any(not isinstance(item, EvidenceFreshness) for item in self.freshness)):
            raise ValueError("freshness must be a bounded typed tuple")
        ids = {item.evidence_id for item in self.freshness}
        if len(ids) != len(self.freshness) or not ids <= {e.evidence_id for e in self.batch.evidence}:
            raise ValueError("freshness IDs must be unique members of the batch")
        object.__setattr__(self, "freshness", tuple(sorted(self.freshness, key=lambda item: item.evidence_id)))


class ContributorFamily(str, Enum):
    NOVELTY = "novelty"
    FREQUENCY = "frequency"
    DIVERSITY = "diversity"
    PERIODICITY = "periodicity"
    IDENTITY = "identity"
    SCHEDULE_COMPATIBILITY = "schedule_compatibility"


class CorrelationGroup(str, Enum):
    ACTIVITY = "activity"
    PERIODICITY = "periodicity"
    IDENTITY = "identity"


class ContributionDirection(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class ScoringReason(str, Enum):
    RULE_APPLIED = "rule_applied"
    OBSERVATION_ONLY = "observation_only"
    SCHEDULE_COMPATIBLE = "schedule_compatible_not_verified_benign"
    UNKNOWN_FRESHNESS = "unknown_freshness"
    STALE = "stale"
    EXPIRED = "expired"
    UNSUPPORTED_RULE = "unsupported_rule"
    UNSUPPORTED_PRODUCER_VERSION = "unsupported_producer_version"
    LEGACY_CONTEXT_REQUIRED = "legacy_context_required"
    LIMITATION_ONLY = "limitation_only"
    INSUFFICIENT_DATA = "insufficient_data"
    INSUFFICIENT_QUALITY = "insufficient_quality"
    NOT_EVALUATED = "not_evaluated"
    RESOLUTION_LIMITED = "resolution_limited"
    ROLE_MISMATCH = "role_mismatch"
    CONFLICT = "conflicting_novelty"


class ScoringAdjustment(str, Enum):
    CORRELATED_SUPERSEDED = "correlated_superseded"
    FAMILY_CAP = "family_cap"
    SCORE_CAP = "score_cap"
    MITIGATION_CAP = "mitigation_cap"


class AssessmentAvailability(str, Enum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class RiskSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SeverityCapReason(str, Enum):
    REDUCED_MEASUREMENT = "reduced_measurement"
    UNAVAILABLE_MEASUREMENT = "unavailable_measurement"
    INSUFFICIENT_CONFIDENCE = "insufficient_confidence"


@dataclass(frozen=True, slots=True)
class ScoringRule:
    source: EvidenceSource
    rule_id: str
    result_code: str | None
    family: ContributorFamily
    group: CorrelationGroup
    points: int
    reason_code: str | None = None
    corroborated_points: int | None = None


# Exact namespace/result rows. Unknown rows never inherit a neighboring mapping.
SCORING_RULES_V1 = (
    ScoringRule(EvidenceSource.DESTINATION_NOVELTY, NOVELTY_RULE, Novelty.KNOWN.value, ContributorFamily.NOVELTY, CorrelationGroup.ACTIVITY, 0),
    ScoringRule(EvidenceSource.DESTINATION_NOVELTY, NOVELTY_RULE, Novelty.RARE.value, ContributorFamily.NOVELTY, CorrelationGroup.ACTIVITY, 10),
    ScoringRule(EvidenceSource.DESTINATION_NOVELTY, NOVELTY_RULE, Novelty.FIRST_SEEN.value, ContributorFamily.NOVELTY, CorrelationGroup.ACTIVITY, 20),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.APPEARANCE_FREQUENCY.value, Behavior.NORMAL.value, ContributorFamily.FREQUENCY, CorrelationGroup.ACTIVITY, 0),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.APPEARANCE_FREQUENCY.value, Behavior.ELEVATED_UNCONFIRMED.value, ContributorFamily.FREQUENCY, CorrelationGroup.ACTIVITY, 15),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.APPEARANCE_FREQUENCY.value, Behavior.ELEVATED_CONFIRMED.value, ContributorFamily.FREQUENCY, CorrelationGroup.ACTIVITY, 35),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.DESTINATION_DIVERSITY.value, Behavior.NORMAL.value, ContributorFamily.DIVERSITY, CorrelationGroup.ACTIVITY, 0),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.DESTINATION_DIVERSITY.value, Behavior.ELEVATED_UNCONFIRMED.value, ContributorFamily.DIVERSITY, CorrelationGroup.ACTIVITY, 10),
    ScoringRule(EvidenceSource.FREQUENCY_DIVERSITY, BehaviorRule.DESTINATION_DIVERSITY.value, Behavior.ELEVATED_CONFIRMED.value, ContributorFamily.DIVERSITY, CorrelationGroup.ACTIVITY, 25),
    ScoringRule(EvidenceSource.PERIODICITY, PERIODICITY_RULE, Periodicity.IRREGULAR.value, ContributorFamily.PERIODICITY, CorrelationGroup.PERIODICITY, 0),
    ScoringRule(EvidenceSource.PERIODICITY, PERIODICITY_RULE, Periodicity.PERIODIC_CANDIDATE.value, ContributorFamily.PERIODICITY, CorrelationGroup.PERIODICITY, 15),
    ScoringRule(EvidenceSource.ARP_IDENTITY, ArpIdentityRule.IP_MAC_CONFLICT.value, None, ContributorFamily.IDENTITY, CorrelationGroup.IDENTITY, 30, ArpIdentityReason.RECENT_SENDER_CONFLICT.value, 45),
    ScoringRule(EvidenceSource.ARP_IDENTITY, ArpIdentityRule.GATEWAY_MAC_CHANGE.value, None, ContributorFamily.IDENTITY, CorrelationGroup.IDENTITY, 35, ArpIdentityReason.LEARNED_GATEWAY_CONFLICT.value, 50),
    ScoringRule(EvidenceSource.ARP_IDENTITY, ArpIdentityRule.GATEWAY_MAC_CHANGE.value, None, ContributorFamily.IDENTITY, CorrelationGroup.IDENTITY, 45, ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT.value, 60),
)

SEVERITY_BANDS_V1 = ((0, RiskSeverity.INFO), (10, RiskSeverity.LOW),
                     (30, RiskSeverity.MEDIUM), (60, RiskSeverity.HIGH))
GROUP_CAPS_V1 = ((CorrelationGroup.ACTIVITY, 40), (CorrelationGroup.PERIODICITY, 30),
                 (CorrelationGroup.IDENTITY, 70))
CONFIDENCE_ORDER = (EvidenceConfidence.PASSIVE_OBSERVATION, EvidenceConfidence.LOW,
                    EvidenceConfidence.MODERATE, EvidenceConfidence.HIGH)
SEVERITY_ORDER = tuple(RiskSeverity)


@dataclass(frozen=True, slots=True)
class RiskScoringPolicy:
    """One frozen release policy; changing weights requires a new version."""

    version: int = 1
    minimum_score: int = field(default=0, init=False)
    maximum_score: int = field(default=100, init=False)
    maximum_mitigation: int = field(default=5, init=False)
    mitigation_divisor: int = field(default=4, init=False)
    schedule_reduction: int = field(default=3, init=False)
    rules: tuple[ScoringRule, ...] = field(default=SCORING_RULES_V1, init=False)
    group_caps: tuple[tuple[CorrelationGroup, int], ...] = field(default=GROUP_CAPS_V1, init=False)
    severity_bands: tuple[tuple[int, RiskSeverity], ...] = field(default=SEVERITY_BANDS_V1, init=False)

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported scoring policy version")


@dataclass(frozen=True, slots=True)
class CorrelationKey:
    group: CorrelationGroup
    scope: EvidenceScope
    application: ApplicationIdentity | None = field(default=None, repr=False)
    revision: ApplicationRevision | None = None
    session_id: UUID | None = None
    fallback_subject: EvidenceSubject | None = field(default=None, repr=False)
    destination_ip: str | None = None
    expected_mac: MacAddress | None = None
    observed_mac: MacAddress | None = None

    def __post_init__(self) -> None:
        for value, expected in ((self.group, CorrelationGroup), (self.scope, EvidenceScope)):
            if not isinstance(value, expected):
                raise TypeError("correlation identity must be typed")
        for optional_value, optional_type in ((self.application, ApplicationIdentity), (self.revision, ApplicationRevision),
                                (self.session_id, UUID), (self.fallback_subject, EvidenceSubject),
                                (self.expected_mac, MacAddress), (self.observed_mac, MacAddress)):
            if optional_value is not None and not isinstance(optional_value, optional_type):
                raise TypeError("correlation fields must be immutable domain identities")
        if self.destination_ip is not None and not isinstance(self.destination_ip, str):
            raise TypeError("correlation destination must be canonical evidence IP")


@dataclass(frozen=True, slots=True)
class RiskContributor:
    evidence: RiskEvidence = field(repr=False)
    policy_version: int
    family: ContributorFamily | None
    correlation_key: CorrelationKey | None
    direction: ContributionDirection
    raw_points: int
    applied_points: int
    eligible: bool
    reason: ScoringReason
    adjustments: tuple[ScoringAdjustment, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, RiskEvidence) or type(self.policy_version) is not int or self.policy_version != 1:
            raise ValueError("contributor requires evidence and supported scoring version")
        if any(type(p) is not int or not -100 <= p <= 100 for p in (self.raw_points, self.applied_points)):
            raise ValueError("contributor points must be bounded integers")
        if not isinstance(self.direction, ContributionDirection) or not isinstance(self.reason, ScoringReason) or type(self.eligible) is not bool:
            raise TypeError("contributor decisions must be typed")
        if self.family is not None and not isinstance(self.family, ContributorFamily):
            raise TypeError("contributor family must be typed")
        if self.correlation_key is not None and not isinstance(self.correlation_key, CorrelationKey):
            raise TypeError("correlation key must be typed")
        expected = (ContributionDirection.POSITIVE if self.raw_points > 0 else
                    ContributionDirection.NEGATIVE if self.raw_points < 0 else ContributionDirection.NEUTRAL)
        if self.direction is not expected or abs(self.applied_points) > abs(self.raw_points) or self.applied_points * self.raw_points < 0 or (not self.eligible and self.applied_points):
            raise ValueError("applied points must preserve eligibility and direction")
        if not isinstance(self.adjustments, tuple) or len(self.adjustments) > len(ScoringAdjustment) or any(not isinstance(a, ScoringAdjustment) for a in self.adjustments):
            raise ValueError("adjustments must be typed and immutable")
        if len(set(self.adjustments)) != len(self.adjustments):
            raise ValueError("duplicate contributor adjustment")


@dataclass(frozen=True, slots=True)
class RiskScoreResult:
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
    contributors: tuple[RiskContributor, ...]

    def __post_init__(self) -> None:
        if type(self.policy_version) is not int or self.policy_version != 1 or any(type(n) is not int for n in (
                self.score, self.positive_subtotal, self.raw_mitigation, self.applied_mitigation)):
            raise ValueError("result requires supported version and integer totals")
        if not 0 <= self.score <= self.positive_subtotal <= 100 or not 0 <= self.raw_mitigation <= 3 * MAX_EVIDENCE_CONTRIBUTORS or not 0 <= self.applied_mitigation <= min(5, self.positive_subtotal // 4, self.raw_mitigation):
            raise ValueError("result exceeds score or mitigation bounds")
        if not isinstance(self.contributors, tuple) or len(self.contributors) > MAX_SCORE_CONTRIBUTORS or any(not isinstance(c, RiskContributor) for c in self.contributors):
            raise ValueError("result contributors must be bounded and immutable")
        if self.score != sum(c.applied_points for c in self.contributors) or self.score != self.positive_subtotal - self.applied_mitigation:
            raise ValueError("result must reconcile with explanations")
        if self.positive_subtotal != sum(max(0, c.applied_points) for c in self.contributors) or self.raw_mitigation != -sum(min(0, c.raw_points) for c in self.contributors):
            raise ValueError("result subtotals must reconcile with contributors")
        if not isinstance(self.availability, AssessmentAvailability):
            raise TypeError("availability must be typed")
        for value, expected in ((self.confidence, EvidenceConfidence), (self.measurement_quality, ObservationQuality),
                                (self.score_severity, RiskSeverity), (self.severity, RiskSeverity)):
            if value is not None and not isinstance(value, expected):
                raise TypeError("assessment context must use immutable typed values")
        if (self.availability is AssessmentAvailability.UNKNOWN) != (self.severity is None and self.score_severity is None):
            raise ValueError("unknown availability must preserve unknown severity")
        if not isinstance(self.severity_caps, tuple) or len(self.severity_caps) > len(SeverityCapReason) or any(not isinstance(c, SeverityCapReason) for c in self.severity_caps):
            raise ValueError("severity caps must be typed and immutable")
        if len(set(self.severity_caps)) != len(self.severity_caps):
            raise ValueError("duplicate severity cap reason")


def severity_for_score(score: int, policy: RiskScoringPolicy) -> RiskSeverity:
    if type(score) is not int or not policy.minimum_score <= score <= policy.maximum_score:
        raise ValueError("score outside policy integer scale")
    return next(severity for minimum, severity in reversed(policy.severity_bands) if score >= minimum)


def _key(e: RiskEvidence, group: CorrelationGroup) -> CorrelationKey:
    s = e.subject
    if group is CorrelationGroup.IDENTITY:
        assert e.legacy_arp is not None
        return CorrelationKey(group, e.scope, destination_ip=s.ip_address,
                              expected_mac=e.legacy_arp.source.evidence.expected_mac, observed_mac=s.mac)
    identified_application = s.application is not None and s.application.key is not None
    return CorrelationKey(group, e.scope, s.application, s.revision, s.session_id,
                          None if identified_application else s,
                          s.ip_address if group is CorrelationGroup.PERIODICITY else None)


def _rule(e: RiskEvidence, policy: RiskScoringPolicy) -> ScoringRule | None:
    return next((row for row in policy.rules if (row.source, row.rule_id, row.result_code) ==
                 (e.source, e.rule_id, e.result_code) and (row.reason_code is None or row.reason_code == e.reason_code)), None)


_INSUFFICIENT_RESULTS = (
    ("insufficient_data", ScoringReason.INSUFFICIENT_DATA),
    ("insufficient_quality", ScoringReason.INSUFFICIENT_QUALITY),
    ("not_evaluated", ScoringReason.NOT_EVALUATED),
    ("resolution_limited", ScoringReason.RESOLUTION_LIMITED),
)


def _exclusion(e: RiskEvidence, freshness: Freshness, row: ScoringRule | None) -> ScoringReason | None:
    if freshness is not Freshness.CURRENT:
        return {Freshness.UNKNOWN: ScoringReason.UNKNOWN_FRESHNESS,
                Freshness.STALE: ScoringReason.STALE, Freshness.EXPIRED: ScoringReason.EXPIRED}[freshness]
    if e.policy_version != (None if e.source is EvidenceSource.ARP_IDENTITY else 1):
        return ScoringReason.UNSUPPORTED_PRODUCER_VERSION
    if e.source is EvidenceSource.ARP_IDENTITY and e.legacy_arp is None:
        return ScoringReason.LEGACY_CONTEXT_REQUIRED
    if e.role is EvidenceRole.LIMITATION:
        return ScoringReason.LIMITATION_ONLY
    if e.quality.measurement is ObservationQuality.FAILED:
        return ScoringReason.INSUFFICIENT_QUALITY
    if EvidenceLimitation.RESOLUTION_LIMITED in e.quality.limitations:
        return ScoringReason.RESOLUTION_LIMITED
    # Insufficient classifications are recognized only inside known namespaces.
    if (e.source, e.rule_id) in {(r.source, r.rule_id) for r in SCORING_RULES_V1}:
        for code, reason in _INSUFFICIENT_RESULTS:
            if e.result_code == code:
                return reason
    if row is None:
        return ScoringReason.UNSUPPORTED_RULE
    if e.role is not (EvidenceRole.FINDING if row.points else EvidenceRole.OBSERVATION):
        return ScoringReason.ROLE_MISMATCH
    return None


def _quality(evidence: tuple[RiskEvidence, ...]) -> ObservationQuality | None:
    values = tuple(e.quality.measurement for e in evidence)
    if ObservationQuality.FAILED in values:
        return ObservationQuality.FAILED
    if not values or None in values:
        return None
    if ObservationQuality.REDUCED in values:
        return ObservationQuality.REDUCED
    return ObservationQuality.COMPLETE


def score_risk(value: RiskScoringInput, policy: RiskScoringPolicy) -> RiskScoreResult:
    """Calculate solely from explicit values; keep every excluded input explained."""
    if not isinstance(value, RiskScoringInput) or type(policy) is not RiskScoringPolicy:
        raise TypeError("scoring requires typed input and explicit frozen policy")
    statuses = {item.evidence_id: item.status for item in value.freshness}
    contributions: list[RiskContributor] = []
    for e in value.batch.evidence:
        row = _rule(e, policy)
        excluded = _exclusion(e, statuses.get(e.evidence_id, Freshness.UNKNOWN), row)
        points = row.points if row else 0
        if row and row.corroborated_points is not None and e.legacy_arp is not None and e.legacy_arp.correlation is not None and e.confidence is EvidenceConfidence.MODERATE:
            points = row.corroborated_points
        if excluded is ScoringReason.UNSUPPORTED_PRODUCER_VERSION:
            points = 0
        contributions.append(RiskContributor(
            e, policy.version, row.family if row else None,
            _key(e, row.group) if row and (row.group is not CorrelationGroup.IDENTITY or e.legacy_arp is not None) else None,
            ContributionDirection.POSITIVE if points else ContributionDirection.NEUTRAL,
            points, 0, excluded is None,
            excluded or (ScoringReason.RULE_APPLIED if points else ScoringReason.OBSERVATION_ONLY),
        ))

    # A same-time contradictory novelty observation is not source arbitration.
    conflicts = {c.evidence.evidence_id for c in contributions if c.eligible and c.family is ContributorFamily.NOVELTY and any(
        o.eligible and o.family is ContributorFamily.NOVELTY
        and (o.evidence.scope, o.evidence.subject, o.evidence.observed_at) == (c.evidence.scope, c.evidence.subject, c.evidence.observed_at)
        and o.evidence.result_code != c.evidence.result_code for o in contributions)}
    contributions = [replace(c, eligible=False, reason=ScoringReason.CONFLICT) if c.evidence.evidence_id in conflicts else c for c in contributions]

    used_keys: set[CorrelationKey] = set()
    budgets = dict(policy.group_caps)
    remaining = policy.maximum_score
    # Highest points first is deterministic; totals are min(cap, sum(key maxima)).
    for i in sorted(range(len(contributions)), key=lambda n: (-contributions[n].raw_points, contributions[n].evidence.evidence_id)):
        c = contributions[i]
        if not c.eligible or c.raw_points == 0:
            continue
        assert c.correlation_key is not None
        if c.correlation_key in used_keys:
            contributions[i] = replace(c, adjustments=(ScoringAdjustment.CORRELATED_SUPERSEDED,))
            continue
        used_keys.add(c.correlation_key)
        group = c.correlation_key.group
        family_points = min(c.raw_points, budgets[group])
        applied = min(family_points, remaining)
        adjustments: tuple[ScoringAdjustment, ...] = ()
        if family_points < c.raw_points:
            adjustments += (ScoringAdjustment.FAMILY_CAP,)
        if applied < family_points:
            adjustments += (ScoringAdjustment.SCORE_CAP,)
        budgets[group] -= family_points
        remaining -= applied
        contributions[i] = replace(c, applied_points=applied, adjustments=adjustments)

    positive = sum(c.applied_points for c in contributions)
    mitigation_budget = min(policy.maximum_mitigation, positive // policy.mitigation_divisor)
    for c in tuple(contributions):
        if (c.eligible and c.family is ContributorFamily.PERIODICITY and c.raw_points > 0
                and ScoringAdjustment.CORRELATED_SUPERSEDED not in c.adjustments
                and EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE in c.evidence.quality.limitations):
            applied = min(policy.schedule_reduction, c.applied_points, mitigation_budget)
            mitigation_budget -= applied
            contributions.append(RiskContributor(
                c.evidence, policy.version, ContributorFamily.SCHEDULE_COMPATIBILITY,
                c.correlation_key, ContributionDirection.NEGATIVE, -policy.schedule_reduction,
                -applied, True, ScoringReason.SCHEDULE_COMPATIBLE,
                (ScoringAdjustment.MITIGATION_CAP,) if applied < policy.schedule_reduction else (),
            ))
    raw_mitigation = -sum(c.raw_points for c in contributions if c.direction is ContributionDirection.NEGATIVE)
    applied_mitigation = -sum(c.applied_points for c in contributions if c.direction is ContributionDirection.NEGATIVE)
    eligible = tuple(c for c in contributions if c.eligible and c.direction is not ContributionDirection.NEGATIVE)
    excluded_any = any(not c.eligible for c in contributions)
    availability = (AssessmentAvailability.UNKNOWN if not eligible else
                    AssessmentAvailability.PARTIAL if excluded_any else AssessmentAvailability.AVAILABLE)
    confidence = None
    if eligible and all(c.evidence.confidence is not None for c in eligible):
        confidence = min((c.evidence.confidence for c in eligible if c.evidence.confidence is not None), key=CONFIDENCE_ORDER.index)
        if excluded_any and CONFIDENCE_ORDER.index(confidence) > CONFIDENCE_ORDER.index(EvidenceConfidence.LOW):
            confidence = EvidenceConfidence.LOW
        if any(set(c.evidence.quality.limitations) & {
            EvidenceLimitation.CAPACITY_LOSS, EvidenceLimitation.MONITORING_GAP,
            EvidenceLimitation.REDUCED_OBSERVATION, EvidenceLimitation.PRIOR_HISTORY_UNAVAILABLE,
        } for c in eligible) and CONFIDENCE_ORDER.index(confidence) > CONFIDENCE_ORDER.index(EvidenceConfidence.LOW):
            confidence = EvidenceConfidence.LOW
    quality = _quality(value.batch.evidence)
    score = positive - applied_mitigation
    raw_severity = severity_for_score(score, policy) if eligible else None
    severity = raw_severity
    caps: list[SeverityCapReason] = []
    if severity is not None:
        cap = RiskSeverity.HIGH
        if quality in (None, ObservationQuality.FAILED):
            cap = RiskSeverity.LOW
            caps.append(SeverityCapReason.UNAVAILABLE_MEASUREMENT)
        elif quality is ObservationQuality.REDUCED:
            cap = RiskSeverity.MEDIUM
            caps.append(SeverityCapReason.REDUCED_MEASUREMENT)
        if confidence in (None, EvidenceConfidence.PASSIVE_OBSERVATION, EvidenceConfidence.LOW):
            cap = RiskSeverity.LOW
            caps.append(SeverityCapReason.INSUFFICIENT_CONFIDENCE)
        severity = min((severity, cap), key=SEVERITY_ORDER.index)
    return RiskScoreResult(policy.version, score, positive, raw_mitigation, applied_mitigation,
                           availability, confidence, quality, raw_severity, severity, tuple(caps),
                           tuple(sorted(contributions, key=lambda c: (c.evidence.evidence_id, c.direction.value))))
