"""Synthetic NS-078 examples, with no runtime detector integration."""

from datetime import UTC, datetime
from uuid import UUID

from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationIdentityQuality, ApplicationIdentityEvidence
from netsentinel.domain.connections import ObservationQuality, ProcessInfoStatus
from netsentinel.domain.risk_assessment import RiskAssessmentKey, snapshot_from_score
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceQuality, EvidenceReference, EvidenceReferenceKind,
    EvidenceRole, EvidenceScope, EvidenceScopeKind, EvidenceSource, EvidenceSubject,
    EvidenceSubjectKind, RiskEvidence, RiskEvidenceBatch,
)
from netsentinel.domain.risk_scoring import EvidenceFreshness, Freshness, RiskScoringInput, RiskScoringPolicy, score_risk

NOW = datetime(2026, 10, 3, tzinfo=UTC)
SCOPE = EvidenceScope(EvidenceScopeKind.HOST)
APP = ApplicationIdentity(ApplicationIdentityQuality.STABLE, r"winpath:v1:c:\apps\example.exe", ApplicationIdentityEvidence.EXECUTABLE_PATH, ProcessInfoStatus.AVAILABLE)


def evidence(index=1, **changes):
    values = dict(source=EvidenceSource.DESTINATION_NOVELTY, rule_id="destination_ip_novelty_rarity",
                  reason_code="test_observation", result_code="first_seen", policy_version=1,
                  observed_at=NOW, scope=SCOPE, subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION,
                  application=APP, ip_address=f"192.0.2.{index}"), quality=EvidenceQuality(ObservationQuality.COMPLETE),
                  role=EvidenceRole.FINDING, confidence=EvidenceConfidence.MODERATE)
    values.update(changes)
    return RiskEvidence(**values)


def scoring(*items, freshness=Freshness.CURRENT):
    items = items or (evidence(),)
    value = RiskScoringInput(RiskEvidenceBatch(tuple(items)), tuple(EvidenceFreshness(e.evidence_id, freshness) for e in items))
    return value, score_risk(value, RiskScoringPolicy())


def snapshot(*items, freshness=Freshness.CURRENT):
    return snapshot_from_score(*scoring(*items, freshness=freshness))


def key(index=1, **changes):
    values = dict(kind="connection_behavior", scope=SCOPE, subject=evidence(index).subject,
                  observation_reference=EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=index)),
                  original_observed_at=NOW)
    values.update(changes)
    return RiskAssessmentKey(**values)
