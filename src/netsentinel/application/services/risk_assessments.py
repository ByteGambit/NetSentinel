"""Explicit blocking assessment operations, for use on an owning worker."""

from datetime import datetime
from dataclasses import replace
from uuid import UUID

from netsentinel.application.ports import RiskAssessmentRepository
from netsentinel.domain.risk_assessment import (
    AssessmentHistory, AssessmentRead, AssessmentReadStatus, AssessmentSave, AssessmentSnapshot, RiskAssessmentKey,
    snapshot_from_score,
)
from netsentinel.domain.risk_scoring import RiskScoreResult, RiskScoringInput
from netsentinel.domain.risk_evidence import MAX_EVIDENCE_CONTRIBUTORS


class RiskAssessmentService:
    def __init__(self, repository: RiskAssessmentRepository) -> None:
        self._repository = repository

    def persist(self, key: RiskAssessmentKey, value: RiskScoringInput,
                result: RiskScoreResult, *, assessed_at: datetime) -> AssessmentSave:
        snapshot = snapshot_from_score(value, result)
        # A later local reassessment of the same observation keeps independent
        # provider snapshots. Optional context never prevents local persistence.
        try:
            read = self._repository.latest(key.assessment_id)
            if read.status is AssessmentReadStatus.FOUND and read.revision is not None and read.revision.key == key:
                previous = read.revision.snapshot
                ids = {c.evidence_id for c in previous.threat_intelligence}
                if ids and len(snapshot.evidence) + len(ids) <= MAX_EVIDENCE_CONTRIBUTORS:
                    snapshot = replace(snapshot,
                        evidence=snapshot.evidence + tuple(e for e in previous.evidence if e.evidence_id in ids),
                        contributors=snapshot.contributors + tuple(replace(c, policy_version=snapshot.policy_version) for c in previous.contributors if c.evidence_id in ids),
                        threat_intelligence=previous.threat_intelligence)
        except Exception:
            pass
        return self._repository.save(key, snapshot, assessed_at)

    def latest(self, assessment_id: str) -> AssessmentRead:
        return self._repository.latest(assessment_id)

    def for_connection(self, lifecycle_id: UUID) -> AssessmentRead:
        return self._repository.for_connection(lifecycle_id)

    def persist_snapshot(self, key: RiskAssessmentKey, snapshot: AssessmentSnapshot,
                         *, assessed_at: datetime) -> AssessmentSave:
        return self._repository.save(key, snapshot, assessed_at)

    def history(self, assessment_id: str, *, limit: int = 8) -> AssessmentHistory:
        return self._repository.history(assessment_id, limit=limit)

    def cleanup(self, now: datetime) -> int:
        return self._repository.cleanup(now)
