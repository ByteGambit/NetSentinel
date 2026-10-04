"""NS-083 read-only, bounded explanations of stored results; never rescore."""

from collections.abc import Callable
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
SCORE_SEMANTICS = "Deterministic review-priority score; not a malware probability."


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
    def for_alert(cls, alert: Alert) -> "RiskExplanationRequest | None":
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
    return value if len(value) <= maximum else value[:maximum] + "… [display truncated]"


def human(value: object | None) -> str:
    if value is None:
        return "Unknown / not reported"
    return bounded(str(getattr(value, "value", value)).replace("_", " ").capitalize())


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds") + " (UTC)"


def scope_text(scope: EvidenceScope) -> str:
    if scope.network_status is None:
        return "Host scope; network not constrained"
    return f"{human(scope.network_status)}" + (f"; scope {scope.network_fingerprint[:12]}" if scope.network_fingerprint else "; no resolved fingerprint")


def subject_text(subject: EvidenceSubject) -> str:
    app = subject.application
    identity = f"{human(app.quality)}: {bounded(app.key or 'Unknown', 256)}" if app else "Unknown"
    revision = subject.revision.digest if subject.revision else None
    return (f"Application identity: {identity}; artifact revision: {revision[:16] if revision else 'Unknown'} "
            f"(file identity, not reputation); destination: {subject.ip_address or 'Unknown'}; "
            f"observed MAC: {subject.mac or 'Not reported'}")


def selector_text(selector: PreferenceSelector) -> str:
    return bounded("; ".join((
        f"Rule: {selector.rule_id or 'Any / not constrained'}",
        f"Application: {bounded(selector.application.key or 'Unknown', 256) if selector.application else 'Any / not constrained'}",
        f"Revision: {selector.application_revision.digest if selector.application_revision else 'Any / not constrained'}",
        f"Destination: {selector.destination.value if selector.destination else 'Any / not constrained'}",
        f"Network: {selector.network_fingerprint or 'Any / not constrained'}",
    )))


RULE_NAMES = {
    "destination_ip_novelty_rarity": "Destination novelty / rarity",
    "observed_appearance_frequency": "Observed appearance frequency",
    "destination_window_diversity": "Retained destination diversity",
    "observed_appearance_periodicity": "Regular observed appearance timing",
    "ip_mac_conflict": "ARP IP–MAC identity conflict",
    "gateway_mac_change": "ARP gateway identity change",
}
SOURCE_NAMES = {
    "destination_novelty": "Behavioral baseline: destination novelty",
    "frequency_diversity": "Behavioral baseline: frequency / diversity",
    "periodicity": "Polling observations: timing",
    "arp_identity": "ARP identity observation",
}
REASONS = {
    "rule_applied": "Stored policy rule applied.",
    "observation_only": "Observation context only; no positive concern contribution.",
    "schedule_compatible_not_verified_benign": "Mitigating context: compatible with scheduled workloads; cause is not verified.",
    "unknown_freshness": "Freshness was unknown.",
    "stale": "Old evidence was not used in the score.",
    "expired": "Evidence was expired at assessment time.",
    "unsupported_rule": "No supported scoring rule for this evidence.",
    "unsupported_producer_version": "Producer policy version was unsupported.",
    "legacy_context_required": "Required legacy ARP context was missing.",
    "limitation_only": "Limitation context, not an alert-driving finding.",
    "insufficient_data": "Insufficient retained baseline data.",
    "insufficient_quality": "Insufficient measurement quality.",
    "not_evaluated": "This evidence was not evaluated.",
    "resolution_limited": "Polling resolution limits timing inference.",
    "role_mismatch": "Evidence role did not meet the scoring rule.",
    "conflicting_novelty": "Conflicting novelty evidence was excluded.",
}
ADJUSTMENTS = {
    ScoringAdjustment.CORRELATED_SUPERSEDED: "Related evidence was grouped to avoid double-counting.",
    ScoringAdjustment.FAMILY_CAP: "Contribution limited by the activity/identity/timing family cap.",
    ScoringAdjustment.SCORE_CAP: "Contribution limited by the global score cap.",
    ScoringAdjustment.MITIGATION_CAP: "Mitigation limited so supporting concern evidence is retained.",
}
CAPS = {
    "reduced_measurement": "Severity limited because telemetry quality was reduced.",
    "unavailable_measurement": "Severity limited because measurement quality was unavailable or failed.",
    "insufficient_confidence": "Severity limited because inference support was insufficient or unreported.",
}
LIMITATIONS = {
    "polling_quantized_exact_timer_not_inferred": "Timing is based on polling observations and does not prove an exact timer.",
    "resolution_limited": "Polling resolution limits timing inference.",
    "capacity_loss": "Retained data was limited by capacity; exact totals cannot be inferred.",
    "monitoring_gap": "Monitoring gaps limit coverage.",
    "ip_only_service_not_inferred": "IP-only context does not identify a domain or service.",
    "revision_unverified": "Artifact revision was unverified.",
    "reduced_current_observation": "Reduced observation coverage.",
    "missed_multiple_compatible_not_proven": "Missed observations may be compatible with this timing pattern.",
    "benign_updates_telemetry_sync_reconnects_compatible": "Timing is compatible with scheduled workloads; cause is unverified.",
    "prior_history_unavailable": "Prior retained history was unavailable.",
    "behavioral_only_low_security_significance": "Behavioral timing alone has limited security significance.",
    "recent_bounded_sequence_only": "Only the recent bounded observation sequence is retained.",
}
SUPPRESSION_TEXT = {
    "not_applicable": "No alert-driving evidence in this evaluation.",
    "not_suppressed": "Alerting was not suppressed by an effective matching preference.",
    "suppressed": "Alerting suppressed for all alert-driving evidence.",
    "partially_suppressed": "Some evidence was suppressed for alerting; independent or correlated supporting evidence remained.",
    "indeterminate": "Preference evaluation was incomplete; uncertain support remained eligible (fail-open).",
    "unavailable": "Preference evaluation was unavailable; alerting was not suppressed (fail-open).",
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
            AssessmentReadStatus.NOT_FOUND: "No retained risk assessment available for this selection.",
            AssessmentReadStatus.CORRUPT: "Stored assessment is unavailable / corrupt.",
            AssessmentReadStatus.UNSUPPORTED_VERSION: "Unsupported assessment version.",
        }.get(status, "Risk details unavailable. Try Refresh."))

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
            name = RULE_NAMES.get(evidence.rule_id, f"{evidence.rule_id} (no display mapping available)")
            line = (f"{name} [{evidence.evidence_id[:12]}] — raw {contributor.raw_points:+d}; "
                    f"applied {contributor.applied_points:+d} policy points; "
                    f"{REASONS.get(contributor.reason.value, human(contributor.reason))}")
            if contributor.raw_points < 0:
                line = "Mitigating context — " + line
            line += " " + " ".join(ADJUSTMENTS.get(a, human(a)) for a in contributor.adjustments)
            (applied if contributor.eligible and contributor.applied_points != 0 else excluded).append(bounded(line))
        states = {s.reference: s.status for s in read.references[:257]}
        for evidence in snapshot.evidence[:32]:
            name = RULE_NAMES.get(evidence.rule_id, f"{evidence.rule_id} (no display mapping available)")
            evidence_lines.extend((
                f"{name} [{evidence.evidence_id[:12]}]; source: {SOURCE_NAMES.get(evidence.source.value, human(evidence.source))}",
                f"Result: {human(evidence.result_code)}; reason: {human(evidence.reason_code)}; role: {human(evidence.role)}",
                f"Rule ID: {evidence.rule_id}; evidence contract v{evidence.contract_version}; producer policy: {f'v{evidence.producer_policy_version}' if evidence.producer_policy_version is not None else 'Unknown / not reported'}",
                f"Observed: {timestamp(evidence.observed_at)}; confidence: {human(evidence.confidence)}; measurement quality: {human(evidence.quality.measurement)}",
                f"Freshness at assessment: {human(evidence.freshness)}; network: {scope_text(evidence.scope)}",
                subject_text(evidence.subject),
            ))
            if evidence.expected_mac:
                evidence_lines.append(f"Expected MAC: {evidence.expected_mac}")
            for limitation in evidence.quality.limitations[:16]:
                evidence_lines.append("Limitation: " + LIMITATIONS.get(limitation.value, human(limitation)))
            for reference in evidence.references[:8]:
                status = states.get(reference, AssessmentSourceStatus.UNRESOLVED)
                evidence_lines.append(f"Source record now — {human(reference.kind)} {str(reference.value)[:16]}: {human(status)}")
                if status is AssessmentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE:
                    evidence_lines.append("Original source is no longer retained or was unavailable; minimum assessment snapshot remains available.")
                elif status is AssessmentSourceStatus.UNRESOLVED:
                    evidence_lines.append("Source pointer has no resolver; this does not establish expiry.")
            if evidence.source.value != "arp_identity":
                context = {
                    "first_seen": "Not previously observed in the retained scoped baseline.",
                    "rare": "Rare within the retained scoped baseline.",
                    "known": "Previously observed in the retained scoped baseline; no safety verdict.",
                }.get(evidence.result_code or "", human(evidence.result_code))
                baseline.append(f"{name}: {context}")
                baseline += ["Baseline limitation: " + LIMITATIONS.get(v.value, human(v)) for v in evidence.quality.limitations[:16]]
                if evidence.source.value == "periodicity":
                    baseline.append("Regular observed appearance timing is not proof of a security cause. Timing is based on polling observations and does not prove an exact timer.")
        baseline.append("Only stored classification/limitations are available. Counts, rates, sample coverage, reference ranges and intervals were not persisted in format v1. Current learned baseline is shown separately in Behavior baseline.")
        suppression, suppression_summary = self._suppression(key.assessment_id, revision.revision, snapshot.evidence, now)
        score = ("Unavailable / insufficient evidence" if snapshot.availability is AssessmentAvailability.UNKNOWN
                 else f"{snapshot.score} / 100")
        summary = (
            ("Concern score", score), ("Score meaning", SCORE_SEMANTICS),
            ("Effective severity", human(snapshot.severity)), ("Raw score severity", human(snapshot.score_severity)),
            ("Availability", human(snapshot.availability)), ("Confidence", human(snapshot.confidence)),
            ("Measurement quality", human(snapshot.measurement_quality)),
            ("Assessment revision", str(revision.revision)), ("Scoring policy", f"v{snapshot.policy_version}"),
            ("Observed at", timestamp(key.original_observed_at)), ("Assessed at", timestamp(revision.assessed_at)),
            ("Suppression", suppression_summary),
            ("Contributor context", bounded(" ".join(applied[:2])) if applied else "No applied contributions; review excluded evidence and limitations."),
        )
        limitations = [CAPS.get(cap.value, human(cap)) for cap in snapshot.severity_caps]
        limitations += ["Confidence describes evidence/inference support; measurement quality describes telemetry coverage/loss. Complete quality does not imply full visibility.",
                        "Unknown, stale or excluded evidence is not a safety verdict."]
        technical = [f"Assessment ID: {key.assessment_id}; format v{revision.format_version}",
                     "Alert-linked revision (exact stored result)." if request.reference else "Latest retained revision for this exact connection lifecycle.",
                     "A revision re-evaluates the same observation; it does not mean the event happened again.",
                     f"Network: {scope_text(key.scope)}", subject_text(key.subject),
                     f"Stored positive subtotal: {snapshot.positive_subtotal}; raw mitigation: {snapshot.raw_mitigation}; applied mitigation: {snapshot.applied_mitigation}"]
        sections = tuple(ExplanationSection(title, tuple(bounded(line) for line in lines)) for title, lines in (
            ("Why this result", applied or ["No applied policy contributions."]),
            ("Not used in score", excluded or ["No excluded or zero-point contributors."]),
            ("Quality and limitations", limitations), ("Evidence and source freshness", evidence_lines),
            ("Baseline context at assessment time", baseline), ("Suppression and preferences", suppression),
            ("Technical details", technical),
        ))
        if snapshot.threat_intelligence:
            sections += (ExplanationSection("External reputation context", tuple(
                line for context in snapshot.threat_intelligence for line in context_lines(context, historical=True))),)
        return RiskExplanationViewModel(AssessmentReadStatus.FOUND, "Stored risk explanation", key.assessment_id, revision.revision, summary, sections)

    def _suppression(self, assessment_id: str, revision: int,
                     evidence: tuple[AssessmentEvidenceSnapshot, ...], now: datetime) -> tuple[list[str], str]:
        lines = ["Risk evidence and score are retained; preferences affect alert/notification eligibility."]
        evaluation = None
        try:
            if self._suppression_lookup:
                evaluation = self._suppression_lookup(assessment_id, revision)
        except Exception:
            pass
        if (evaluation is not None and (type(evaluation) is not SuppressionEvaluation or evaluation.assessment.assessment_id != assessment_id or evaluation.assessment.revision != revision)):
            evaluation = None
        summary = "Historical suppression not recorded"
        if evaluation is not None:
            summary = human(evaluation.disposition) + " (last runtime evaluation)"
            lines += [f"Last runtime evaluation in this session: {timestamp(evaluation.evaluated_at)}; not a persisted assessment-time snapshot.",
                      SUPPRESSION_TEXT[evaluation.disposition.value],
                      f"Alert eligibility at that evaluation: {'eligible' if evaluation.alert_eligible else 'not eligible'}; eligibility does not prove delivery."]
            seen = set()
            for item in evaluation.evidence[:32]:
                lines.append(f"Evidence {item.evidence_id[:12]}: {human(item.disposition)}; examined expired matches {item.expired_match_count}, revoked matches {item.revoked_match_count}")
                for match in item.matches[:8]:
                    marker = (match.preference_id, match.revision)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    if len(seen) > MAX_DISPLAY_PREFERENCES:
                        continue
                    lines += [f"Applied preference {match.preference_id}; revision {match.revision}; {selector_text(match.selector)}",
                              f"Lifetime: {timestamp(match.lifetime.expires_at) if match.lifetime.expires_at else 'Permanent'}; reason: {bounded(match.reason)}"]
            if len(seen) > MAX_DISPLAY_PREFERENCES:
                lines.append("Applied preference display truncated at 32 distinct references.")
            lines += ["Evaluation limitation: " + human(v) for v in evaluation.limitations]
        else:
            lines.append("Historical suppression was not persisted and no runtime evaluation is retained for this revision. Past alert eligibility cannot be reconstructed from current preferences.")
        lines.append(f"Current matching preferences as of {timestamp(now)} (read only; no alert re-evaluation):")
        if self._preferences is None:
            lines.append("Current preference lookup unavailable; no no-match claim can be made.")
            return lines, summary
        try:
            contexts = tuple(dict.fromkeys(PreferenceMatchContext(e.rule_id, e.subject, e.scope) for e in evidence[:32]))
            if not contexts:
                lines.append("No evidence context to query.")
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
                    lines.append("Current preference record: " + human(entry.status))
                    continue
                if not any(selector_matches(p.definition.selector, c) for c in contexts):
                    continue
                shown += 1
                if shown > MAX_DISPLAY_PREFERENCES:
                    continue
                lines += [f"Current preference {p.preference_id}; revision {p.revision}; status {human(p.status_at(now))}",
                          selector_text(p.definition.selector),
                          f"Lifetime: {timestamp(p.definition.lifetime.expires_at) if p.definition.lifetime.expires_at else 'Permanent'}; reason: {bounded(p.definition.reason)}"]
            if incomplete or shown > MAX_DISPLAY_PREFERENCES:
                lines.append("Current preference lookup/display incomplete or truncated; absence is not a complete no-match result.")
            elif shown == 0:
                lines.append("No current matching preference found in the complete query.")
        except Exception:
            lines.append("Current preference lookup unavailable; no no-match claim can be made.")
        return lines, summary
