"""NS-083 read-only, bounded explanations of stored results; never rescore."""

from netsentinel.shared.source_text import QT_TRANSLATE_NOOP, join_text


from collections.abc import Callable
from enum import Enum
from netsentinel.shared.enum_sources import enum_source
from netsentinel.shared.source_text import SourceText
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from netsentinel.application.ports import ScopedPreferenceRepository
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.alerts import Alert
from netsentinel.domain.preferences import (
    PreferenceMatchContext, PreferenceResultStatus, PreferenceSelector, selector_matches,
)
from netsentinel.domain.risk_assessment import (
    AssessmentEvidenceSnapshot, AssessmentRead, AssessmentReadStatus, AssessmentSourceStatus, utc_time,
)
from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceSubject
from netsentinel.domain.risk_scoring import AssessmentAvailability, ScoringAdjustment
from netsentinel.domain.suppression import SuppressionEvaluation
from netsentinel.application.services.threat_intel_evidence import context_lines

MAX_DISPLAY_TEXT = 700
MAX_DISPLAY_PREFERENCES = 32
SCORE_SEMANTICS = QT_TRANSLATE_NOOP('RiskExplanation', 'Deterministic review-priority score; not a malware probability.')


class RiskExplanationRepository(Protocol):
    def revision(self, assessment_id: str, revision: int) -> AssessmentRead: ...
    def for_connection(self, lifecycle_id: UUID) -> AssessmentRead: ...


@dataclass(frozen=True, slots=True)
class RiskExplanationRequest:
    reference: AlertAssessmentReference | None = None
    lifecycle_id: UUID | None = None

    def __post_init__(self) -> None:
        if (self.reference is None) == (self.lifecycle_id is None):
            raise ValueError("select exactly one assessment reference or connection lifecycle")
        if self.reference is not None and type(self.reference) is not AlertAssessmentReference:
            raise TypeError("typed assessment reference required")
        if self.lifecycle_id is not None and type(self.lifecycle_id) is not UUID:
            raise TypeError("canonical connection lifecycle required")

    @classmethod
    def for_alert(cls, alert: Alert) -> QT_TRANSLATE_NOOP('RiskExplanation', 'RiskExplanationRequest | None'):
        # The last attached pointer is the alert's current linked revision. Never latest().
        reference = next((e.assessment for e in reversed(alert.evidence) if e.assessment), None)
        return cls(reference=reference) if reference else None


@dataclass(frozen=True, slots=True)
class ExplanationSection:
    title: str
    lines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RiskExplanationViewModel:
    status: AssessmentReadStatus
    message: str
    assessment_id: str | None = None
    revision: int | None = None
    summary: tuple[tuple[str, str], ...] = ()
    sections: tuple[ExplanationSection, ...] = ()


def bounded(value: str, maximum: int = MAX_DISPLAY_TEXT) -> str:
    if isinstance(value, SourceText):
        return value.bounded(maximum)
    return value if len(value) <= maximum else value[:maximum] + QT_TRANSLATE_NOOP('RiskExplanation', '… [display truncated]')


def human(value: object | None) -> str:
    if value is None:
        return QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown / not reported')
    if isinstance(value, Enum):
        return enum_source(value, 'human')
    return bounded(str(value).replace("_", " ").capitalize())


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds") + " (UTC)"


def scope_text(scope: EvidenceScope) -> str:
    if scope.network_status is None:
        return QT_TRANSLATE_NOOP('RiskExplanation', 'Host scope; network not constrained')
    return human(scope.network_status) + (QT_TRANSLATE_NOOP('RiskExplanation', '; scope {value1}').format(value1=scope.network_fingerprint[:12]) if scope.network_fingerprint else QT_TRANSLATE_NOOP('RiskExplanation', '; no resolved fingerprint'))


def subject_text(subject: EvidenceSubject) -> str:
    app = subject.application
    identity = QT_TRANSLATE_NOOP('RiskExplanation', '{quality}: {identity}').format(quality=human(app.quality), identity=bounded(app.key or QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown'), 256)) if app else QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown')
    revision = subject.revision.digest if subject.revision else None
    return (QT_TRANSLATE_NOOP('RiskExplanation', 'Application identity: {value1}; artifact revision: {value2} (file identity, not reputation); destination: {value3}; observed MAC: {value4}').format(value1=identity, value2=revision[:16] if revision else QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown'), value3=subject.ip_address or QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown'), value4=subject.mac or QT_TRANSLATE_NOOP('RiskExplanation', 'Not reported')))


def selector_text(selector: PreferenceSelector) -> str:
    return bounded(join_text('; ', (QT_TRANSLATE_NOOP('RiskExplanation', 'Rule: {value1}').format(value1=selector.rule_id or QT_TRANSLATE_NOOP('RiskExplanation', 'Any / not constrained')), QT_TRANSLATE_NOOP('RiskExplanation', 'Application: {value1}').format(value1=bounded(selector.application.key or QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown'), 256) if selector.application else QT_TRANSLATE_NOOP('RiskExplanation', 'Any / not constrained')), QT_TRANSLATE_NOOP('RiskExplanation', 'Revision: {value1}').format(value1=selector.application_revision.digest if selector.application_revision else QT_TRANSLATE_NOOP('RiskExplanation', 'Any / not constrained')), QT_TRANSLATE_NOOP('RiskExplanation', 'Destination: {value1}').format(value1=selector.destination.value if selector.destination else QT_TRANSLATE_NOOP('RiskExplanation', 'Any / not constrained')), QT_TRANSLATE_NOOP('RiskExplanation', 'Network: {value1}').format(value1=selector.network_fingerprint or QT_TRANSLATE_NOOP('RiskExplanation', 'Any / not constrained')))))


RULE_NAMES = {
    "destination_ip_novelty_rarity": QT_TRANSLATE_NOOP('RiskExplanation', 'Destination novelty / rarity'),
    "observed_appearance_frequency": QT_TRANSLATE_NOOP('RiskExplanation', 'Observed appearance frequency'),
    "destination_window_diversity": QT_TRANSLATE_NOOP('RiskExplanation', 'Retained destination diversity'),
    "observed_appearance_periodicity": QT_TRANSLATE_NOOP('RiskExplanation', 'Regular observed appearance timing'),
    "ip_mac_conflict": QT_TRANSLATE_NOOP('RiskExplanation', 'ARP IP–MAC identity conflict'),
    "gateway_mac_change": QT_TRANSLATE_NOOP('RiskExplanation', 'ARP gateway identity change'),
}
SOURCE_NAMES = {
    "destination_novelty": QT_TRANSLATE_NOOP('RiskExplanation', 'Behavioral baseline: destination novelty'),
    "frequency_diversity": QT_TRANSLATE_NOOP('RiskExplanation', 'Behavioral baseline: frequency / diversity'),
    "periodicity": QT_TRANSLATE_NOOP('RiskExplanation', 'Polling observations: timing'),
    "arp_identity": QT_TRANSLATE_NOOP('RiskExplanation', 'ARP identity observation'),
}
REASONS = {
    "rule_applied": QT_TRANSLATE_NOOP('RiskExplanation', 'Stored policy rule applied.'),
    "observation_only": QT_TRANSLATE_NOOP('RiskExplanation', 'Observation context only; no positive concern contribution.'),
    "schedule_compatible_not_verified_benign": QT_TRANSLATE_NOOP('RiskExplanation', 'Mitigating context: compatible with scheduled workloads; cause is not verified.'),
    "unknown_freshness": QT_TRANSLATE_NOOP('RiskExplanation', 'Freshness was unknown.'),
    "stale": QT_TRANSLATE_NOOP('RiskExplanation', 'Old evidence was not used in the score.'),
    "expired": QT_TRANSLATE_NOOP('RiskExplanation', 'Evidence was expired at assessment time.'),
    "unsupported_rule": QT_TRANSLATE_NOOP('RiskExplanation', 'No supported scoring rule for this evidence.'),
    "unsupported_producer_version": QT_TRANSLATE_NOOP('RiskExplanation', 'Producer policy version was unsupported.'),
    "legacy_context_required": QT_TRANSLATE_NOOP('RiskExplanation', 'Required legacy ARP context was missing.'),
    "limitation_only": QT_TRANSLATE_NOOP('RiskExplanation', 'Limitation context, not an alert-driving finding.'),
    "insufficient_data": QT_TRANSLATE_NOOP('RiskExplanation', 'Insufficient retained baseline data.'),
    "insufficient_quality": QT_TRANSLATE_NOOP('RiskExplanation', 'Insufficient measurement quality.'),
    "not_evaluated": QT_TRANSLATE_NOOP('RiskExplanation', 'This evidence was not evaluated.'),
    "resolution_limited": QT_TRANSLATE_NOOP('RiskExplanation', 'Polling resolution limits timing inference.'),
    "role_mismatch": QT_TRANSLATE_NOOP('RiskExplanation', 'Evidence role did not meet the scoring rule.'),
    "conflicting_novelty": QT_TRANSLATE_NOOP('RiskExplanation', 'Conflicting novelty evidence was excluded.'),
}
ADJUSTMENTS = {
    ScoringAdjustment.CORRELATED_SUPERSEDED: QT_TRANSLATE_NOOP('RiskExplanation', 'Related evidence was grouped to avoid double-counting.'),
    ScoringAdjustment.FAMILY_CAP: QT_TRANSLATE_NOOP('RiskExplanation', 'Contribution limited by the activity/identity/timing family cap.'),
    ScoringAdjustment.SCORE_CAP: QT_TRANSLATE_NOOP('RiskExplanation', 'Contribution limited by the global score cap.'),
    ScoringAdjustment.MITIGATION_CAP: QT_TRANSLATE_NOOP('RiskExplanation', 'Mitigation limited so supporting concern evidence is retained.'),
}
CAPS = {
    "reduced_measurement": QT_TRANSLATE_NOOP('RiskExplanation', 'Severity limited because telemetry quality was reduced.'),
    "unavailable_measurement": QT_TRANSLATE_NOOP('RiskExplanation', 'Severity limited because measurement quality was unavailable or failed.'),
    "insufficient_confidence": QT_TRANSLATE_NOOP('RiskExplanation', 'Severity limited because inference support was insufficient or unreported.'),
}
LIMITATIONS = {
    "polling_quantized_exact_timer_not_inferred": QT_TRANSLATE_NOOP('RiskExplanation', 'Timing is based on polling observations and does not prove an exact timer.'),
    "resolution_limited": QT_TRANSLATE_NOOP('RiskExplanation', 'Polling resolution limits timing inference.'),
    "capacity_loss": QT_TRANSLATE_NOOP('RiskExplanation', 'Retained data was limited by capacity; exact totals cannot be inferred.'),
    "monitoring_gap": QT_TRANSLATE_NOOP('RiskExplanation', 'Monitoring gaps limit coverage.'),
    "ip_only_service_not_inferred": QT_TRANSLATE_NOOP('RiskExplanation', 'IP-only context does not identify a domain or service.'),
    "revision_unverified": QT_TRANSLATE_NOOP('RiskExplanation', 'Artifact revision was unverified.'),
    "reduced_current_observation": QT_TRANSLATE_NOOP('RiskExplanation', 'Reduced observation coverage.'),
    "missed_multiple_compatible_not_proven": QT_TRANSLATE_NOOP('RiskExplanation', 'Missed observations may be compatible with this timing pattern.'),
    "benign_updates_telemetry_sync_reconnects_compatible": QT_TRANSLATE_NOOP('RiskExplanation', 'Timing is compatible with scheduled workloads; cause is unverified.'),
    "prior_history_unavailable": QT_TRANSLATE_NOOP('RiskExplanation', 'Prior retained history was unavailable.'),
    "behavioral_only_low_security_significance": QT_TRANSLATE_NOOP('RiskExplanation', 'Behavioral timing alone has limited security significance.'),
    "recent_bounded_sequence_only": QT_TRANSLATE_NOOP('RiskExplanation', 'Only the recent bounded observation sequence is retained.'),
}
SUPPRESSION_TEXT = {
    "not_applicable": QT_TRANSLATE_NOOP('RiskExplanation', 'No alert-driving evidence in this evaluation.'),
    "not_suppressed": QT_TRANSLATE_NOOP('RiskExplanation', 'Alerting was not suppressed by an effective matching preference.'),
    "suppressed": QT_TRANSLATE_NOOP('RiskExplanation', 'Alerting suppressed for all alert-driving evidence.'),
    "partially_suppressed": QT_TRANSLATE_NOOP('RiskExplanation', 'Some evidence was suppressed for alerting; independent or correlated supporting evidence remained.'),
    "indeterminate": QT_TRANSLATE_NOOP('RiskExplanation', 'Preference evaluation was incomplete; uncertain support remained eligible (fail-open).'),
    "unavailable": QT_TRANSLATE_NOOP('RiskExplanation', 'Preference evaluation was unavailable; alerting was not suppressed (fail-open).'),
}


class RiskExplanationQueryService:
    """All repository reads execute on the query owner, with an explicit clock."""

    def __init__(self, repository: RiskExplanationRepository, *,
                 preferences: ScopedPreferenceRepository | None = None,
                 suppression_lookup: Callable[[str, int], SuppressionEvaluation | None] | None = None) -> None:
        self._repository = repository
        self._preferences = preferences
        self._suppression_lookup = suppression_lookup

    def lookup(self, request: RiskExplanationRequest, *, now: datetime) -> RiskExplanationViewModel:
        utc_time(now)
        try:
            if request.reference is not None:
                read = self._repository.revision(request.reference.assessment_id, request.reference.revision)
            else:
                assert request.lifecycle_id is not None
                read = self._repository.for_connection(request.lifecycle_id)
            if read.status is AssessmentReadStatus.FOUND and read.revision is not None:
                revision = read.revision
                if request.reference is not None and (revision.key.assessment_id != request.reference.assessment_id or revision.revision != request.reference.revision or revision.key.scope.network_status != request.reference.network_status):
                    return self._missing(AssessmentReadStatus.CORRUPT)
                if request.lifecycle_id is not None and revision.key.observation_reference.value != request.lifecycle_id:
                    return self._missing(AssessmentReadStatus.CORRUPT)
                return self._map(read, request, now)
            return self._missing(read.status if read.status is not AssessmentReadStatus.FOUND else AssessmentReadStatus.CORRUPT)
        except Exception:
            return self._missing(AssessmentReadStatus.UNAVAILABLE)

    @staticmethod
    def _missing(status: AssessmentReadStatus) -> RiskExplanationViewModel:
        return RiskExplanationViewModel(status, {
            AssessmentReadStatus.NOT_FOUND: QT_TRANSLATE_NOOP('RiskExplanation', 'No retained risk assessment available for this selection.'),
            AssessmentReadStatus.CORRUPT: QT_TRANSLATE_NOOP('RiskExplanation', 'Stored assessment is unavailable / corrupt.'),
            AssessmentReadStatus.UNSUPPORTED_VERSION: QT_TRANSLATE_NOOP('RiskExplanation', 'Unsupported assessment version.'),
        }.get(status, QT_TRANSLATE_NOOP('RiskExplanation', 'Risk details unavailable. Try Refresh.')))

    def _map(self, read: AssessmentRead, request: RiskExplanationRequest, now: datetime) -> RiskExplanationViewModel:
        revision = read.revision
        assert revision is not None
        key, snapshot = revision.key, revision.snapshot
        by_id = {e.evidence_id: e for e in snapshot.evidence[:32]}
        applied: list[str] = []
        excluded: list[str] = []
        evidence_lines: list[str] = []
        baseline: list[str] = []
        for contributor in snapshot.contributors[:64]:
            evidence = by_id[contributor.evidence_id]
            name = RULE_NAMES.get(evidence.rule_id, QT_TRANSLATE_NOOP('RiskExplanation', '{value1} (no display mapping available)').format(value1=evidence.rule_id))
            line = (QT_TRANSLATE_NOOP('RiskExplanation', '{value1} [{value2}] — raw {value3:+d}; applied {value4:+d} policy points; {value5}').format(value1=name, value2=evidence.evidence_id[:12], value3=contributor.raw_points, value4=contributor.applied_points, value5=REASONS.get(contributor.reason.value, human(contributor.reason))))
            if contributor.raw_points < 0:
                line = QT_TRANSLATE_NOOP('RiskExplanation', 'Mitigating context — ') + line
            line += " " + join_text(' ', (ADJUSTMENTS.get(a, human(a)) for a in contributor.adjustments))
            (applied if contributor.eligible and contributor.applied_points != 0 else excluded).append(bounded(line))
        states = {s.reference: s.status for s in read.references[:257]}
        for evidence in snapshot.evidence[:32]:
            name = RULE_NAMES.get(evidence.rule_id, QT_TRANSLATE_NOOP('RiskExplanation', '{value1} (no display mapping available)').format(value1=evidence.rule_id))
            evidence_lines.extend((
                QT_TRANSLATE_NOOP('RiskExplanation', '{value1} [{value2}]; source: {value3}').format(value1=name, value2=evidence.evidence_id[:12], value3=SOURCE_NAMES.get(evidence.source.value, human(evidence.source))),
                QT_TRANSLATE_NOOP('RiskExplanation', 'Result: {value1}; reason: {value2}; role: {value3}').format(value1=human(evidence.result_code), value2=human(evidence.reason_code), value3=human(evidence.role)),
                QT_TRANSLATE_NOOP('RiskExplanation', 'Rule ID: {value1}; evidence contract v{value2}; producer policy: {value3}').format(value1=evidence.rule_id, value2=evidence.contract_version, value3=f'v{evidence.producer_policy_version}' if evidence.producer_policy_version is not None else QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown / not reported')),
                QT_TRANSLATE_NOOP('RiskExplanation', 'Observed: {value1}; confidence: {value2}; measurement quality: {value3}').format(value1=timestamp(evidence.observed_at), value2=human(evidence.confidence), value3=human(evidence.quality.measurement)),
                QT_TRANSLATE_NOOP('RiskExplanation', 'Freshness at assessment: {value1}; network: {value2}').format(value1=human(evidence.freshness), value2=scope_text(evidence.scope)),
                subject_text(evidence.subject),
            ))
            if evidence.expected_mac:
                evidence_lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Expected MAC: {value1}').format(value1=evidence.expected_mac))
            for limitation in evidence.quality.limitations[:16]:
                evidence_lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Limitation: ') + LIMITATIONS.get(limitation.value, human(limitation)))
            for reference in evidence.references[:8]:
                status = states.get(reference, AssessmentSourceStatus.UNRESOLVED)
                evidence_lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Source record now — {value1} {value2}: {value3}').format(value1=human(reference.kind), value2=str(reference.value)[:16], value3=human(status)))
                if status is AssessmentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE:
                    evidence_lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Original source is no longer retained or was unavailable; minimum assessment snapshot remains available.'))
                elif status is AssessmentSourceStatus.UNRESOLVED:
                    evidence_lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Source pointer has no resolver; this does not establish expiry.'))
            if evidence.source.value != "arp_identity":
                context = {
                    "first_seen": QT_TRANSLATE_NOOP('RiskExplanation', 'Not previously observed in the retained scoped baseline.'),
                    "rare": QT_TRANSLATE_NOOP('RiskExplanation', 'Rare within the retained scoped baseline.'),
                    "known": QT_TRANSLATE_NOOP('RiskExplanation', 'Previously observed in the retained scoped baseline; no safety verdict.'),
                }.get(evidence.result_code or "", human(evidence.result_code))
                baseline.append(QT_TRANSLATE_NOOP('RiskExplanation', '{name}: {context}').format(name=name, context=context))
                baseline += [QT_TRANSLATE_NOOP('RiskExplanation', 'Baseline limitation: ') + LIMITATIONS.get(v.value, human(v)) for v in evidence.quality.limitations[:16]]
                if evidence.source.value == "periodicity":
                    baseline.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Regular observed appearance timing is not proof of a security cause. Timing is based on polling observations and does not prove an exact timer.'))
        baseline.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Only stored classification/limitations are available. Counts, rates, sample coverage, reference ranges and intervals were not persisted in format v1. Current learned baseline is shown separately in Behavior baseline.'))
        suppression, suppression_summary = self._suppression(key.assessment_id, revision.revision, snapshot.evidence, now)
        score = (QT_TRANSLATE_NOOP('RiskExplanation', 'Unavailable / insufficient evidence') if snapshot.availability is AssessmentAvailability.UNKNOWN
                 else f"{snapshot.score} / 100")
        summary = (
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Concern score'), score), (QT_TRANSLATE_NOOP('RiskExplanation', 'Score meaning'), SCORE_SEMANTICS),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Effective severity'), human(snapshot.severity)), (QT_TRANSLATE_NOOP('RiskExplanation', 'Raw score severity'), human(snapshot.score_severity)),
            ("Availability", human(snapshot.availability)), (QT_TRANSLATE_NOOP('RiskExplanation', 'Confidence'), human(snapshot.confidence)),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Measurement quality'), human(snapshot.measurement_quality)),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Assessment revision'), str(revision.revision)), (QT_TRANSLATE_NOOP('RiskExplanation', 'Scoring policy'), f"v{snapshot.policy_version}"),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Observed at'), timestamp(key.original_observed_at)), (QT_TRANSLATE_NOOP('RiskExplanation', 'Assessed at'), timestamp(revision.assessed_at)),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Suppression'), suppression_summary),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Contributor context'), bounded(join_text(' ', applied[:2])) if applied else QT_TRANSLATE_NOOP('RiskExplanation', 'No applied contributions; review excluded evidence and limitations.')),
        )
        limitations = [CAPS.get(cap.value, human(cap)) for cap in snapshot.severity_caps]
        limitations += [QT_TRANSLATE_NOOP('RiskExplanation', 'Confidence describes evidence/inference support; measurement quality describes telemetry coverage/loss. Complete quality does not imply full visibility.'),
                        QT_TRANSLATE_NOOP('RiskExplanation', 'Unknown, stale or excluded evidence is not a safety verdict.')]
        technical = [QT_TRANSLATE_NOOP('RiskExplanation', 'Assessment ID: {value1}; format v{value2}').format(value1=key.assessment_id, value2=revision.format_version),
                     QT_TRANSLATE_NOOP('RiskExplanation', 'Alert-linked revision (exact stored result).') if request.reference else QT_TRANSLATE_NOOP('RiskExplanation', 'Latest retained revision for this exact connection lifecycle.'),
                     QT_TRANSLATE_NOOP('RiskExplanation', 'A revision re-evaluates the same observation; it does not mean the event happened again.'),
                     QT_TRANSLATE_NOOP('RiskExplanation', 'Network: {value1}').format(value1=scope_text(key.scope)), subject_text(key.subject),
                     QT_TRANSLATE_NOOP('RiskExplanation', 'Stored positive subtotal: {value1}; raw mitigation: {value2}; applied mitigation: {value3}').format(value1=snapshot.positive_subtotal, value2=snapshot.raw_mitigation, value3=snapshot.applied_mitigation)]
        sections = tuple(ExplanationSection(title, tuple(bounded(line) for line in lines)) for title, lines in (
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Why this result'), applied or [QT_TRANSLATE_NOOP('RiskExplanation', 'No applied policy contributions.')]),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Not used in score'), excluded or [QT_TRANSLATE_NOOP('RiskExplanation', 'No excluded or zero-point contributors.')]),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Quality and limitations'), limitations), (QT_TRANSLATE_NOOP('RiskExplanation', 'Evidence and source freshness'), evidence_lines),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Baseline context at assessment time'), baseline), (QT_TRANSLATE_NOOP('RiskExplanation', 'Suppression and preferences'), suppression),
            (QT_TRANSLATE_NOOP('RiskExplanation', 'Technical details'), technical),
        ))
        if snapshot.threat_intelligence:
            sections += (ExplanationSection(QT_TRANSLATE_NOOP('RiskExplanation', 'External reputation context'), tuple(
                line for context in snapshot.threat_intelligence for line in context_lines(context, historical=True))),)
        return RiskExplanationViewModel(AssessmentReadStatus.FOUND, QT_TRANSLATE_NOOP('RiskExplanation', 'Stored risk explanation'), key.assessment_id, revision.revision, summary, sections)

    def _suppression(self, assessment_id: str, revision: int,
                     evidence: tuple[AssessmentEvidenceSnapshot, ...], now: datetime) -> tuple[list[str], str]:
        lines = [QT_TRANSLATE_NOOP('RiskExplanation', 'Risk evidence and score are retained; preferences affect alert/notification eligibility.')]
        evaluation = None
        try:
            if self._suppression_lookup:
                evaluation = self._suppression_lookup(assessment_id, revision)
        except Exception:
            pass
        if (evaluation is not None and (type(evaluation) is not SuppressionEvaluation or evaluation.assessment.assessment_id != assessment_id or evaluation.assessment.revision != revision)):
            evaluation = None
        summary = QT_TRANSLATE_NOOP('RiskExplanation', 'Historical suppression not recorded')
        if evaluation is not None:
            summary = human(evaluation.disposition) + QT_TRANSLATE_NOOP('RiskExplanation', ' (last runtime evaluation)')
            lines += [QT_TRANSLATE_NOOP('RiskExplanation', 'Last runtime evaluation in this session: {value1}; not a persisted assessment-time snapshot.').format(value1=timestamp(evaluation.evaluated_at)),
                      SUPPRESSION_TEXT[evaluation.disposition.value],
                      QT_TRANSLATE_NOOP('RiskExplanation', 'Alert eligibility at that evaluation: {value1}; eligibility does not prove delivery.').format(value1='eligible' if evaluation.alert_eligible else QT_TRANSLATE_NOOP('RiskExplanation', 'not eligible'))]
            seen = set()
            for item in evaluation.evidence[:32]:
                lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Evidence {value1}: {value2}; examined expired matches {value3}, revoked matches {value4}').format(value1=item.evidence_id[:12], value2=human(item.disposition), value3=item.expired_match_count, value4=item.revoked_match_count))
                for match in item.matches[:8]:
                    marker = (match.preference_id, match.revision)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    if len(seen) > MAX_DISPLAY_PREFERENCES:
                        continue
                    lines += [QT_TRANSLATE_NOOP('RiskExplanation', 'Applied preference {value1}; revision {value2}; {value3}').format(value1=match.preference_id, value2=match.revision, value3=selector_text(match.selector)),
                              QT_TRANSLATE_NOOP('RiskExplanation', 'Lifetime: {value1}; reason: {value2}').format(value1=timestamp(match.lifetime.expires_at) if match.lifetime.expires_at else QT_TRANSLATE_NOOP('RiskExplanation', 'Permanent'), value2=bounded(match.reason))]
            if len(seen) > MAX_DISPLAY_PREFERENCES:
                lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Applied preference display truncated at 32 distinct references.'))
            lines += [QT_TRANSLATE_NOOP('RiskExplanation', 'Evaluation limitation: ') + human(v) for v in evaluation.limitations]
        else:
            lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Historical suppression was not persisted and no runtime evaluation is retained for this revision. Past alert eligibility cannot be reconstructed from current preferences.'))
        lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Current matching preferences as of {value1} (read only; no alert re-evaluation):').format(value1=timestamp(now)))
        if self._preferences is None:
            lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Current preference lookup unavailable; no no-match claim can be made.'))
            return lines, summary
        try:
            contexts = tuple(dict.fromkeys(PreferenceMatchContext(e.rule_id, e.subject, e.scope) for e in evidence[:32]))
            if not contexts:
                lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'No evidence context to query.'))
                return lines, summary
            page = self._preferences.find_candidates(contexts, evaluated_at=now, limit=100)
            if page.status is not PreferenceResultStatus.FOUND:
                raise RuntimeError("unavailable")
            shown = 0
            incomplete = page.truncated
            for entry in page.entries[:100]:
                p = entry.preference
                if entry.status is not PreferenceResultStatus.FOUND or p is None:
                    incomplete = True
                    lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Current preference record: ') + human(entry.status))
                    continue
                if not any(selector_matches(p.definition.selector, c) for c in contexts):
                    continue
                shown += 1
                if shown > MAX_DISPLAY_PREFERENCES:
                    continue
                lines += [QT_TRANSLATE_NOOP('RiskExplanation', 'Current preference {value1}; revision {value2}; status {value3}').format(value1=p.preference_id, value2=p.revision, value3=human(p.status_at(now))),
                          selector_text(p.definition.selector),
                          QT_TRANSLATE_NOOP('RiskExplanation', 'Lifetime: {value1}; reason: {value2}').format(value1=timestamp(p.definition.lifetime.expires_at) if p.definition.lifetime.expires_at else QT_TRANSLATE_NOOP('RiskExplanation', 'Permanent'), value2=bounded(p.definition.reason))]
            if incomplete or shown > MAX_DISPLAY_PREFERENCES:
                lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Current preference lookup/display incomplete or truncated; absence is not a complete no-match result.'))
            elif shown == 0:
                lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'No current matching preference found in the complete query.'))
        except Exception:
            lines.append(QT_TRANSLATE_NOOP('RiskExplanation', 'Current preference lookup unavailable; no no-match claim can be made.'))
        return lines, summary
