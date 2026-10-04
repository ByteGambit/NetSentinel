"""NS-081 bounded current-policy explanations, separate from historical risk."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.preferences import (
    MAX_PREFERENCE_QUERY, PreferenceLifetime, PreferenceMatchContext, PreferenceOrigin,
    PreferenceSelector, ScopedPreference, preference_id, preference_reason, preference_time, revision_number,
    selector_matches,
)
from netsentinel.domain.risk_evidence import MAX_EVIDENCE_CONTRIBUTORS, _digest
from netsentinel.domain.risk_scoring import (
    AssessmentAvailability, ContributionDirection, CorrelationKey, RiskScoreResult, RiskSeverity,
)

MAX_SUPPRESSION_MATCHES = 8  # Per evidence; at most 32 * 8 references per result.
MAX_SUPPRESSION_CANDIDATES = MAX_PREFERENCE_QUERY


class SuppressionDisposition(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    NOT_SUPPRESSED = "not_suppressed"
    SUPPRESSED = "suppressed"
    PARTIALLY_SUPPRESSED = "partially_suppressed"
    INDETERMINATE = "indeterminate"
    UNAVAILABLE = "unavailable"


class SuppressionLimitation(str, Enum):
    CANDIDATES_TRUNCATED = "candidates_truncated"
    MATCHES_TRUNCATED = "matches_truncated"
    CORRUPT_PREFERENCE = "corrupt_preference"
    UNSUPPORTED_PREFERENCE_FORMAT = "unsupported_preference_format"
    LOOKUP_UNAVAILABLE = "lookup_unavailable"
    EVALUATION_UNAVAILABLE = "evaluation_unavailable"
    EVALUATOR_NOT_CONFIGURED = "evaluator_not_configured"


class SelectorDimension(str, Enum):
    APPLICATION = "application"
    REVISION = "revision"
    DESTINATION = "destination"
    NETWORK = "network"
    RULE = "rule"


def selector_dimensions(selector: PreferenceSelector) -> tuple[SelectorDimension, ...]:
    return tuple(d for d, value in (
        (SelectorDimension.APPLICATION, selector.application),
        (SelectorDimension.REVISION, selector.application_revision),
        (SelectorDimension.DESTINATION, selector.destination),
        (SelectorDimension.NETWORK, selector.network_fingerprint),
        (SelectorDimension.RULE, selector.rule_id),
    ) if value is not None)


def has_alert_driving_risk(result: RiskScoreResult) -> bool:
    """The unchanged NS-079 gate, without rescoring or user policy input."""
    return (result.availability is not AssessmentAvailability.UNKNOWN
            and result.severity in (RiskSeverity.LOW, RiskSeverity.MEDIUM, RiskSeverity.HIGH)
            and any(c.eligible and c.direction is ContributionDirection.POSITIVE and c.applied_points > 0
                    for c in result.contributors))


@dataclass(frozen=True, slots=True)
class MatchedPreference:
    preference_id: UUID
    revision: int
    selector: PreferenceSelector = field(repr=False)
    lifetime: PreferenceLifetime
    reason: str = field(repr=False)
    origin: PreferenceOrigin

    def __post_init__(self) -> None:
        preference_id(self.preference_id)
        revision_number(self.revision)
        preference_reason(self.reason)
        if type(self.selector) is not PreferenceSelector or type(self.lifetime) is not PreferenceLifetime or type(self.origin) is not PreferenceOrigin:
            raise TypeError("matched preference requires typed bounded policy context")

    @classmethod
    def from_preference(cls, value: ScopedPreference) -> "MatchedPreference":
        return cls(value.preference_id, value.revision, value.definition.selector,
                   value.definition.lifetime, value.definition.reason, value.created_origin)

    @property
    def dimensions(self) -> tuple[SelectorDimension, ...]:
        return selector_dimensions(self.selector)

    @property
    def explanation_order(self) -> tuple[int, str]:
        return (-len(self.dimensions), str(self.preference_id))


def _limitations(values: tuple[SuppressionLimitation, ...]) -> tuple[SuppressionLimitation, ...]:
    if type(values) is not tuple or len(values) > len(SuppressionLimitation) or any(type(v) is not SuppressionLimitation for v in values) or len(set(values)) != len(values):
        raise ValueError("suppression limitations must be a bounded unique typed tuple")
    return tuple(sorted(values, key=lambda v: v.value))


def _ids(values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple or len(values) > MAX_EVIDENCE_CONTRIBUTORS or len(set(values)) != len(values):
        raise ValueError("suppression evidence references exceed quota or repeat")
    for value in values:
        _digest(value)
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class EvidenceSuppression:
    evidence_id: str
    context: PreferenceMatchContext = field(repr=False)
    disposition: SuppressionDisposition
    matches: tuple[MatchedPreference, ...] = ()
    observed_match_count: int = 0
    expired_match_count: int = 0
    revoked_match_count: int = 0
    limitations: tuple[SuppressionLimitation, ...] = ()

    def __post_init__(self) -> None:
        _digest(self.evidence_id)
        if type(self.context) is not PreferenceMatchContext or type(self.disposition) is not SuppressionDisposition or self.disposition is SuppressionDisposition.PARTIALLY_SUPPRESSED:
            raise TypeError("evidence suppression requires typed context and disposition")
        if type(self.matches) is not tuple or len(self.matches) > MAX_SUPPRESSION_MATCHES or any(type(m) is not MatchedPreference for m in self.matches) or len({m.preference_id for m in self.matches}) != len(self.matches):
            raise ValueError("matched preference references exceed quota or repeat")
        if any(type(n) is not int or not 0 <= n <= MAX_SUPPRESSION_CANDIDATES for n in (self.observed_match_count, self.expired_match_count, self.revoked_match_count)):
            raise ValueError("suppression match counts exceed candidate quota")
        if self.observed_match_count < len(self.matches) or (self.disposition is SuppressionDisposition.SUPPRESSED) != bool(self.matches):
            raise ValueError("affirmative evidence suppression requires a policy reference")
        if any(not selector_matches(m.selector, self.context) for m in self.matches):
            raise ValueError("matched preference must constrain this exact evidence context")
        object.__setattr__(self, "matches", tuple(sorted(self.matches, key=lambda m: m.explanation_order)))
        object.__setattr__(self, "limitations", _limitations(self.limitations))

    @property
    def primary(self) -> MatchedPreference | None:
        return self.matches[0] if self.matches else None


@dataclass(frozen=True, slots=True)
class AlertDrivingGroup:
    correlation_key: CorrelationKey = field(repr=False)
    supporting_evidence_ids: tuple[str, ...]
    remaining_evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.correlation_key) is not CorrelationKey:
            raise TypeError("alert support requires the original typed correlation key")
        object.__setattr__(self, "supporting_evidence_ids", _ids(self.supporting_evidence_ids))
        object.__setattr__(self, "remaining_evidence_ids", _ids(self.remaining_evidence_ids))
        if not self.supporting_evidence_ids or not set(self.remaining_evidence_ids) <= set(self.supporting_evidence_ids):
            raise ValueError("remaining support must belong to the original positive group")


@dataclass(frozen=True, slots=True)
class SuppressionEvaluation:
    assessment: AlertAssessmentReference
    evaluated_at: datetime
    disposition: SuppressionDisposition
    evidence: tuple[EvidenceSuppression, ...]
    groups: tuple[AlertDrivingGroup, ...]
    limitations: tuple[SuppressionLimitation, ...] = ()

    def __post_init__(self) -> None:
        if type(self.assessment) is not AlertAssessmentReference or type(self.disposition) is not SuppressionDisposition:
            raise TypeError("suppression evaluation requires typed assessment and disposition")
        object.__setattr__(self, "evaluated_at", preference_time(self.evaluated_at))
        for items, expected in ((self.evidence, EvidenceSuppression), (self.groups, AlertDrivingGroup)):
            if type(items) is not tuple or len(items) > MAX_EVIDENCE_CONTRIBUTORS or any(type(i) is not expected for i in items):
                raise ValueError("suppression summary exceeds typed evidence/group quota")
        if len({e.evidence_id for e in self.evidence}) != len(self.evidence) or len({g.correlation_key for g in self.groups}) != len(self.groups):
            raise ValueError("suppression summary cannot duplicate evidence or groups")
        by_id = {e.evidence_id: e for e in self.evidence}
        for e in self.evidence:
            if any(m.lifetime.expires_at is not None and self.evaluated_at >= m.lifetime.expires_at for m in e.matches):
                raise ValueError("an expired policy cannot justify affirmative suppression")
        for g in self.groups:
            if not set(g.supporting_evidence_ids) <= by_id.keys():
                raise ValueError("group points to missing evidence")
            expected_ids = {i for i in g.supporting_evidence_ids if by_id[i].disposition is not SuppressionDisposition.SUPPRESSED}
            if set(g.remaining_evidence_ids) != expected_ids:
                raise ValueError("group support must preserve unsuppressed and uncertain evidence")
        fully_suppressed = bool(self.groups) and not any(g.remaining_evidence_ids for g in self.groups)
        if (self.disposition is SuppressionDisposition.SUPPRESSED) != fully_suppressed or (self.disposition is SuppressionDisposition.NOT_APPLICABLE) != (not self.groups):
            raise ValueError("aggregate suppression must agree with alert-driving support")
        object.__setattr__(self, "evidence", tuple(sorted(self.evidence, key=lambda e: e.evidence_id)))
        object.__setattr__(self, "groups", tuple(sorted(self.groups, key=lambda g: g.supporting_evidence_ids)))
        object.__setattr__(self, "limitations", _limitations(self.limitations))

    @property
    def alert_eligible(self) -> bool:
        return any(g.remaining_evidence_ids for g in self.groups)

    @property
    def suppressed_evidence_ids(self) -> tuple[str, ...]:
        return tuple(e.evidence_id for e in self.evidence if e.disposition is SuppressionDisposition.SUPPRESSED)

    @property
    def unsuppressed_evidence_ids(self) -> tuple[str, ...]:
        return tuple(sorted({i for g in self.groups for i in g.remaining_evidence_ids}))

    @property
    def reason_code(self) -> str:
        return {
            SuppressionDisposition.NOT_APPLICABLE: "no_alert_driving_evidence",
            SuppressionDisposition.NOT_SUPPRESSED: "no_effective_matching_policy",
            SuppressionDisposition.SUPPRESSED: "all_alert_driving_support_suppressed",
            SuppressionDisposition.PARTIALLY_SUPPRESSED: "unsuppressed_alert_driving_support_remains",
            SuppressionDisposition.INDETERMINATE: "policy_evaluation_incomplete_fail_open",
            SuppressionDisposition.UNAVAILABLE: "policy_evaluation_unavailable_fail_open",
        }[self.disposition]
