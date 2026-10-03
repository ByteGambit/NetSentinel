"""Explicit blocking assessment operations, for use on an owning worker."""

from datetime import datetime

from netsentinel.application.ports import RiskAssessmentRepository
from netsentinel.domain.risk_assessment import (
    AssessmentHistory, AssessmentRead, AssessmentSave, RiskAssessmentKey,
    snapshot_from_score,
)
from netsentinel.domain.risk_scoring import RiskScoreResult, RiskScoringInput


class RiskAssessmentService:
    def __init__(self, repository: RiskAssessmentRepository) -> None:
        self._repository = repository

    def persist(self, key: RiskAssessmentKey, value: RiskScoringInput,
                result: RiskScoreResult, *, assessed_at: datetime) -> AssessmentSave:
        return self._repository.save(key, snapshot_from_score(value, result), assessed_at)

    def latest(self, assessment_id: str) -> AssessmentRead:
        return self._repository.latest(assessment_id)

    def history(self, assessment_id: str, *, limit: int = 8) -> AssessmentHistory:
        return self._repository.history(assessment_id, limit=limit)

    def cleanup(self, now: datetime) -> int:
        return self._repository.cleanup(now)
