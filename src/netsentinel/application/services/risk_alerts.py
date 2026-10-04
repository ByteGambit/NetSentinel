"""NS-079 owning-worker orchestration: evidence -> assessment -> AlertService."""

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json

from netsentinel.application.events import AlertNotificationIntent, EventDispatcher, PublishReport
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.risk_assessments import RiskAssessmentService
from netsentinel.application.services.risk_evidence import BehaviorEvidence, evidence_from_behavior
from netsentinel.application.services.suppression import SuppressionEvaluationService, unavailable_evaluation
from netsentinel.domain.alert_risk import AlertAssessmentReference, AlertWriteIntent
from netsentinel.domain.alerts import Alert, AlertCandidate, AlertEvidence, alert_id
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.risk_assessment import (
    AssessmentSave, AssessmentReadStatus, AssessmentEvidenceSnapshot, AssessmentContributorSnapshot,
    RiskAssessmentKey, canonical_json, utc_time,
)
from netsentinel.domain.risk_evidence import (
    EvidenceReference, EvidenceReferenceKind, RiskEvidenceBatch,
    EvidenceSource,
)
from netsentinel.domain.risk_scoring import (
    EvidenceFreshness, Freshness,
    RiskScoreResult, RiskScoringInput, RiskScoringPolicy, score_risk,
    ContributionDirection, ScoringReason,
)
from netsentinel.domain.threat_intel_evidence import ThreatIntelAssessmentSignal
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness
from netsentinel.application.services.threat_intel_evidence import evidence_for_context
from netsentinel.domain.suppression import (
    SuppressionDisposition, SuppressionEvaluation, SuppressionLimitation, has_alert_driving_risk,
)


class RiskAlertStatus(str, Enum):
    SUCCESS = "success"
    NO_ALERT = "no_alert"
    NORMALIZATION_FAILED = "normalization_failed"
    SCORING_FAILED = "scoring_failed"
    ASSESSMENT_PERSISTENCE_FAILED = "assessment_persistence_failed"
    ASSESSMENT_PERSISTED_ALERT_FAILED = "assessment_persisted_alert_failed"
    SATURATED = "saturated"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class BehaviorRiskSignal:
    key: RiskAssessmentKey
    evidence: tuple[BehaviorEvidence, ...]
    assessed_at: datetime
    intent: AlertWriteIntent = AlertWriteIntent.OCCURRENCE
    freshness: Freshness = Freshness.CURRENT

    def __post_init__(self) -> None:
        if type(self.key) is not RiskAssessmentKey:
            raise TypeError("signal requires the original assessment identity")
        if (self.key.kind != "connection_behavior" or
                self.key.observation_reference.kind is not EvidenceReferenceKind.CONNECTION_LIFECYCLE):
            raise ValueError("behavior signals require a canonical lifecycle reference")
        if not isinstance(self.evidence, tuple) or not 1 <= len(self.evidence) <= 4:
            raise ValueError("signal must contain at most four M13 results")
        if not isinstance(self.intent, AlertWriteIntent) or not isinstance(self.freshness, Freshness):
            raise TypeError("signal intent/freshness must be typed")
        if (self.key.scope.network_status in (NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS)
                and self.key.subject.session_id is None):
            raise ValueError("unresolved occurrence requires a monitoring session")
        utc_time(self.assessed_at)


@dataclass(frozen=True, slots=True)
class RiskAlertResult:
    status: RiskAlertStatus
    assessment: AssessmentSave | None = None
    alert: Alert | None = None
    dispatch: PublishReport | None = None
    suppression: SuppressionEvaluation | None = None


def risk_alert_fingerprint(key: RiskAssessmentKey) -> str:
    """Semantic identity independent of occurrence, score, policy and revision.

    Stable executable identity + artifact revision + destination + typed network.
    Unresolved networks/provisional applications also retain their session.
    Unknown applications use exact process/session rather than a PID/name key.
    """
    subject = key.subject
    application = subject.application
    stable = application is not None and application.quality is ApplicationIdentityQuality.STABLE
    content = {
        "family": "connection_behavior", "scope": canonical_json(key.scope),
        "application": application.key if application is not None else None,
        "revision": subject.revision.digest if subject.revision is not None else None,
        "destination": subject.ip_address,
        "process": None if stable else canonical_json(subject.process),
        "session": str(subject.session_id) if not stable or key.scope.network_fingerprint is None else None,
        "fallback_occurrence": str(key.observation_reference.value) if not stable and
            (subject.process is None or subject.process.create_time is None) else None,
    }
    return sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def alert_eligible(result: RiskScoreResult) -> bool:
    """No new alert for UNKNOWN/INFO, zero or exclusively excluded evidence."""
    return has_alert_driving_risk(result)


class RiskToAlertService:
    """Blocking service used only by the risk worker; no concrete DB adapter."""

    def __init__(self, assessments: RiskAssessmentService, alerts: AlertService,
                 dispatcher: EventDispatcher, *, policy: RiskScoringPolicy = RiskScoringPolicy(),
                 suppression: SuppressionEvaluationService | None = None) -> None:
        self._assessments, self._alerts, self._dispatcher = assessments, alerts, dispatcher
        self._policy = policy
        self._suppression = suppression

    def enrich(self, signal: ThreatIntelAssessmentSignal) -> RiskAlertResult:
        """Explicit TI revision on the same risk owner; no scoring or occurrence."""
        try:
            read = self._assessments.for_connection(signal.lifecycle_id)
            if read.status is AssessmentReadStatus.NOT_FOUND:
                return RiskAlertResult(RiskAlertStatus.NO_ALERT)
            if read.status is not AssessmentReadStatus.FOUND or read.revision is None:
                return RiskAlertResult(RiskAlertStatus.UNAVAILABLE)
            current = read.revision
            context = signal.context
            if current.key.subject.ip_address != context.key.subject.value:
                return RiskAlertResult(RiskAlertStatus.NORMALIZATION_FAILED)
            evidence = evidence_for_context(context)
            if evidence.evidence_id != context.evidence_id:
                return RiskAlertResult(RiskAlertStatus.NORMALIZATION_FAILED)
            old_context = next((c for c in current.snapshot.threat_intelligence if c.key.provider == context.key.provider), None)
            # A delayed old fetch cannot replace newer provenance from this provider.
            if old_context and old_context.result.received_at > context.result.received_at:
                return RiskAlertResult(RiskAlertStatus.NO_ALERT)
            removed = {old_context.evidence_id} if old_context else set()
            snapshot = current.snapshot
            addition = AssessmentEvidenceSnapshot(evidence.evidence_id, evidence.contract_version,
                EvidenceSource.THREAT_INTELLIGENCE, evidence.rule_id, evidence.reason_code,
                evidence.policy_version, evidence.role, evidence.result_code, evidence.scope,
                evidence.subject, evidence.quality, evidence.confidence, evidence.observed_at,
                Freshness.CURRENT if context.freshness is ThreatIntelCacheFreshness.FRESH else Freshness.STALE,
                evidence.references)
            contributor = AssessmentContributorSnapshot(evidence.evidence_id, snapshot.policy_version,
                None, None, None, ContributionDirection.NEUTRAL, 0, 0, False,
                ScoringReason.OBSERVATION_ONLY, ())
            updated = replace(snapshot,
                evidence=tuple(e for e in snapshot.evidence if e.evidence_id not in removed) + (addition,),
                contributors=tuple(c for c in snapshot.contributors if c.evidence_id not in removed) + (contributor,),
                threat_intelligence=tuple(c for c in snapshot.threat_intelligence if c.key.provider != context.key.provider) + (context,))
        except (ValueError, TypeError, AttributeError):
            return RiskAlertResult(RiskAlertStatus.NORMALIZATION_FAILED)
        except Exception:
            return RiskAlertResult(RiskAlertStatus.UNAVAILABLE)
        try:
            saved = self._assessments.persist_snapshot(current.key, updated, assessed_at=signal.assessed_at)
        except Exception:
            return RiskAlertResult(RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED)
        # Never initialize an alert solely to attach external information.
        fingerprint = risk_alert_fingerprint(current.key)
        try:
            existing = self._alerts.get(alert_id(fingerprint))
            if existing is None:
                return RiskAlertResult(RiskAlertStatus.NO_ALERT, saved)
            reference = AlertAssessmentReference(current.key.assessment_id, saved.revision.revision, current.key.scope.network_status)
            candidate = AlertCandidate(fingerprint, "connection_behavior", current.key.scope.network_fingerprint,
                fingerprint, existing.severity, existing.confidence,
                AlertEvidence(current.key.original_observed_at, assessment=reference), AlertWriteIntent.REASSESSMENT)
            alert, _ = self._alerts.update_assessment(candidate)
            return RiskAlertResult(RiskAlertStatus.SUCCESS, saved, alert)
        except Exception:
            return RiskAlertResult(RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED, saved)

    def process(self, signal: BehaviorRiskSignal) -> RiskAlertResult:
        try:
            key = signal.key
            references: tuple[EvidenceReference, ...] = (key.observation_reference,)
            if key.subject.session_id is not None:
                references += (EvidenceReference(EvidenceReferenceKind.MONITORING_SESSION, key.subject.session_id),)
            batch = RiskEvidenceBatch(tuple(evidence_from_behavior(e, subject=key.subject,
                scope=key.scope, references=references) for e in signal.evidence))
            value = RiskScoringInput(batch, tuple(EvidenceFreshness(e.evidence_id, signal.freshness)
                                                 for e in batch.evidence))
        except (ValueError, TypeError, AttributeError):
            return RiskAlertResult(RiskAlertStatus.NORMALIZATION_FAILED)
        try:
            result = score_risk(value, self._policy)
        except (ValueError, TypeError):
            return RiskAlertResult(RiskAlertStatus.SCORING_FAILED)
        try:
            saved = self._assessments.persist(key, value, result, assessed_at=signal.assessed_at)
        except Exception:
            # Operational boundary: no adapter exception text enters the result.
            return RiskAlertResult(RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED)
        reference = AlertAssessmentReference(key.assessment_id, saved.revision.revision, key.scope.network_status)
        # User policy is a current decision, never part of the historical scoring snapshot.
        try:
            suppression = (self._suppression.evaluate(result, reference, evaluated_at=signal.assessed_at)
                           if self._suppression is not None else unavailable_evaluation(result, reference,
                               signal.assessed_at, SuppressionLimitation.EVALUATOR_NOT_CONFIGURED))
            if type(suppression) is not SuppressionEvaluation or suppression.assessment != reference or suppression.evaluated_at != signal.assessed_at:
                raise ValueError("suppression result context mismatch")
        except Exception:
            suppression = unavailable_evaluation(result, reference, signal.assessed_at,
                                                SuppressionLimitation.EVALUATION_UNAVAILABLE)
        if suppression.disposition is SuppressionDisposition.SUPPRESSED:
            return RiskAlertResult(RiskAlertStatus.NO_ALERT, saved, suppression=suppression)
        # A replay of a retained older revision must never rewind current state.
        fingerprint = risk_alert_fingerprint(key)
        candidate = AlertCandidate(fingerprint, "connection_behavior", key.scope.network_fingerprint,
            fingerprint, result.severity.value if result.severity is not None else "info",
            result.confidence.value if result.confidence is not None else "low",
            AlertEvidence(key.original_observed_at, assessment=reference), signal.intent)
        try:
            eligible = alert_eligible(result) and suppression.alert_eligible
            if not eligible:
                if self._alerts.get(alert_id(fingerprint)) is None:
                    return RiskAlertResult(RiskAlertStatus.NO_ALERT, saved, suppression=suppression)
                alert, notify = self._alerts.update_assessment(candidate)
            elif signal.intent is AlertWriteIntent.REASSESSMENT:
                alert, notify = self._alerts.update_assessment(candidate)
            else:
                alert, notify = self._alerts.record(candidate)
        except Exception:
            return RiskAlertResult(RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED, saved, suppression=suppression)
        report = None
        if notify:
            report = self._dispatcher.publish(AlertNotificationIntent(
                alert.id, alert.fingerprint, reference, alert.severity, signal.intent, alert.updated_at))
        return RiskAlertResult(RiskAlertStatus.SUCCESS if eligible else RiskAlertStatus.NO_ALERT,
                               saved, alert, report, suppression)
