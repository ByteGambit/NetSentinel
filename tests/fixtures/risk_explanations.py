"""Synthetic stored explanations and bounded read-only ports for NS-083."""

from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.risk_assessment import AssessmentRead, AssessmentReadStatus, RiskAssessmentRevision
from tests.fixtures.risk_assessments import NOW, key, snapshot


class ExplanationRepository:
    def __init__(self, read=None):
        self.read = read or AssessmentRead(AssessmentReadStatus.FOUND, RiskAssessmentRevision(key(), 3, NOW, snapshot()))
        self.calls = []

    def revision(self, assessment_id, revision):
        self.calls.append((assessment_id, revision))
        return self.read

    def for_connection(self, lifecycle_id):
        self.calls.append(lifecycle_id)
        return self.read


def model(stored=None, *, references=(), suppression=None, preferences=None):
    revision = RiskAssessmentRevision(key(), 3, NOW, stored or snapshot())
    read = AssessmentRead(AssessmentReadStatus.FOUND, revision, references)
    service = RiskExplanationQueryService(ExplanationRepository(read), preferences=preferences,
        suppression_lookup=(lambda *args: suppression) if suppression else None)
    return service.lookup(RiskExplanationRequest(reference=AlertAssessmentReference(key().assessment_id, 3, None)), now=NOW)


def all_text(value):
    return "\n".join([value.message, *(f"{k}: {v}" for k, v in value.summary),
                      *("\n".join(s.lines) for s in value.sections)])
