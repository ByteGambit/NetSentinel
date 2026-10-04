"""NS-081 explicit current preference evaluation, with fail-open alert support."""

from datetime import datetime

from netsentinel.application.ports import ScopedPreferenceRepository
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.preferences import (
    PreferenceMatchContext, PreferencePage, PreferenceResultStatus, PreferenceStatus,
    preference_time, selector_matches,
)
from netsentinel.domain.risk_evidence import RiskEvidence
from netsentinel.domain.risk_scoring import ContributionDirection, CorrelationKey, RiskScoreResult
from netsentinel.domain.suppression import (
    MAX_SUPPRESSION_CANDIDATES, MAX_SUPPRESSION_MATCHES, AlertDrivingGroup, EvidenceSuppression,
    MatchedPreference, SuppressionDisposition as Disposition, SuppressionEvaluation,
    SuppressionLimitation as Limitation, has_alert_driving_risk,
)


def match_context(evidence: RiskEvidence) -> PreferenceMatchContext:
    """One normalization boundary, without inferred application/destination/network."""
    return PreferenceMatchContext(evidence.rule_id, evidence.subject, evidence.scope)


def _supports(result: RiskScoreResult) -> dict[CorrelationKey, tuple[str, ...]]:
    if not has_alert_driving_risk(result):
        return {}
    positive = tuple(c for c in result.contributors if c.eligible and
                     c.direction is ContributionDirection.POSITIVE and c.raw_points > 0)
    keys = {c.correlation_key for c in positive if c.applied_points > 0 and c.correlation_key is not None}
    return {key: tuple(sorted({c.evidence.evidence_id for c in positive if c.correlation_key == key}))
            for key in keys}


def evaluate_suppression(result: RiskScoreResult, reference: AlertAssessmentReference,
                         evaluated_at: datetime, candidates: PreferencePage, *,
                         failure_limitation: Limitation = Limitation.LOOKUP_UNAVAILABLE) -> SuppressionEvaluation:
    """Pure deterministic policy evaluation; never mutates risk, sources or storage."""
    now = preference_time(evaluated_at)
    supports = _supports(result)
    driving = {i for ids in supports.values() for i in ids}
    evidence = {c.evidence.evidence_id: c.evidence for c in result.contributors}
    limitations: set[Limitation] = set()
    unavailable = candidates.status is not PreferenceResultStatus.FOUND
    if driving and unavailable:
        limitations.add(failure_limitation)
    if driving and candidates.truncated:
        limitations.add(Limitation.CANDIDATES_TRUNCATED)
    if type(candidates.entries) is not tuple or len(candidates.entries) > MAX_SUPPRESSION_CANDIDATES:
        raise ValueError("candidate reply exceeds bounded port contract")
    preferences = []
    seen = set()
    repeated = set()
    if driving and not unavailable:
        for entry in candidates.entries:
            if entry.status is PreferenceResultStatus.FOUND and entry.preference is not None:
                p = entry.preference
                if entry.preference_id is not None and entry.preference_id != p.preference_id:
                    limitations.add(Limitation.CORRUPT_PREFERENCE)
                    continue
                if p.preference_id in seen:
                    repeated.add(p.preference_id)
                    limitations.add(Limitation.CORRUPT_PREFERENCE)
                seen.add(p.preference_id)
                preferences.append(p)
            else:
                limitations.add(Limitation.UNSUPPORTED_PREFERENCE_FORMAT if entry.status is PreferenceResultStatus.UNSUPPORTED_VERSION else Limitation.CORRUPT_PREFERENCE)
        preferences = [p for p in preferences if p.preference_id not in repeated]
    summaries = []
    for identity, item in sorted(evidence.items()):
        context = match_context(item)
        if identity not in driving:
            summaries.append(EvidenceSuppression(identity, context, Disposition.NOT_APPLICABLE))
            continue
        active, expired, revoked = [], 0, 0
        for p in preferences:
            if not selector_matches(p.definition.selector, context):
                continue
            status = p.status_at(now)
            if status is PreferenceStatus.REVOKED:
                revoked += 1
            elif status is PreferenceStatus.EXPIRED:
                expired += 1
            else:
                active.append(MatchedPreference.from_preference(p))
        active.sort(key=lambda p: p.explanation_order)
        entry_limits = set(limitations)
        if len(active) > MAX_SUPPRESSION_MATCHES:
            entry_limits.add(Limitation.MATCHES_TRUNCATED)
        disposition = (Disposition.SUPPRESSED if active else Disposition.UNAVAILABLE if unavailable else
                       Disposition.INDETERMINATE if limitations else Disposition.NOT_SUPPRESSED)
        summaries.append(EvidenceSuppression(identity, context, disposition,
                         tuple(active[:MAX_SUPPRESSION_MATCHES]), len(active), expired, revoked,
                         tuple(sorted(entry_limits, key=lambda v: v.value))))
    suppressed = {e.evidence_id for e in summaries if e.disposition is Disposition.SUPPRESSED}
    groups = tuple(AlertDrivingGroup(key, ids, tuple(i for i in ids if i not in suppressed))
                   for key, ids in supports.items())
    if not groups:
        disposition = Disposition.NOT_APPLICABLE
    elif not any(g.remaining_evidence_ids for g in groups):
        disposition = Disposition.SUPPRESSED
    elif suppressed:
        disposition = Disposition.PARTIALLY_SUPPRESSED
    elif unavailable:
        disposition = Disposition.UNAVAILABLE
    elif limitations:
        disposition = Disposition.INDETERMINATE
    else:
        disposition = Disposition.NOT_SUPPRESSED
    all_limits = set(limitations)
    all_limits.update(v for e in summaries for v in e.limitations)
    return SuppressionEvaluation(reference, now, disposition, tuple(summaries), groups,
                                 tuple(sorted(all_limits, key=lambda v: v.value)))


def unavailable_evaluation(result: RiskScoreResult, reference: AlertAssessmentReference,
                           evaluated_at: datetime, limitation: Limitation) -> SuppressionEvaluation:
    return evaluate_suppression(result, reference, evaluated_at,
                                PreferencePage(PreferenceResultStatus.UNAVAILABLE), failure_limitation=limitation)


class SuppressionEvaluationService:
    """Blocking read-only operation owned by the existing bounded risk worker."""

    def __init__(self, repository: ScopedPreferenceRepository) -> None:
        self._repository = repository

    def evaluate(self, result: RiskScoreResult, reference: AlertAssessmentReference, *,
                 evaluated_at: datetime) -> SuppressionEvaluation:
        now = preference_time(evaluated_at)
        driving = {i for ids in _supports(result).values() for i in ids}
        contexts = tuple(dict.fromkeys(match_context(c.evidence) for c in result.contributors
                                       if c.evidence.evidence_id in driving))
        if not contexts:
            return evaluate_suppression(result, reference, now, PreferencePage(PreferenceResultStatus.FOUND))
        try:
            candidates = self._repository.find_candidates(contexts, evaluated_at=now, limit=MAX_SUPPRESSION_CANDIDATES)
            if type(candidates) is not PreferencePage:
                raise TypeError("invalid preference page")
            return evaluate_suppression(result, reference, now, candidates)
        except Exception:
            return unavailable_evaluation(result, reference, now, Limitation.EVALUATION_UNAVAILABLE)
