"""Real SQLite TI → existing revision → alert/query, fully offline."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from netsentinel.application.services.risk_alerts import BehaviorRiskSignal, RiskAlertStatus
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.risk_assessment import AssessmentReadStatus
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness as F
from netsentinel.domain.threat_intel_evidence import ThreatIntelAssessmentSignal
from netsentinel.domain.threat_intelligence import ThreatIntelResultStatus as S
from tests.fixtures.behavior_risk import key, novelty, NOW as OBSERVED
from tests.fixtures.threat_intel_evidence import mapping, NOW
from tests.integration.test_risk_alert_pipeline import Harness


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path / "ti.sqlite3")


def initial(harness, *, index=1, stamp=OBSERVED):
    return harness.process(novelty(address="8.8.8.8", stamp=stamp), occurrence=key(index=index, address="8.8.8.8", stamp=stamp))


def enrich(harness, *, index=1, **kwargs):
    return harness.service.enrich(ThreatIntelAssessmentSignal(UUID(int=index), mapping(**kwargs).context, NOW))


@pytest.mark.parametrize("status", list(AlertStatus))
@pytest.mark.parametrize("ti_status", [S.HIT, S.NO_HIT])
def test_revision_keeps_occurrence_lifecycle_and_score(harness, status, ti_status):
    first = initial(harness)
    harness.alerts.set_status(first.alert.id, status, OBSERVED)
    before = harness.alerts.get(first.alert.id)
    result = enrich(harness, status=ti_status)
    assert result.status is RiskAlertStatus.SUCCESS
    original, revised = first.assessment.revision, result.assessment.revision
    assert revised.key == original.key and revised.revision == 2 and revised.format_version == 2
    for field in ("score", "positive_subtotal", "applied_mitigation", "severity", "score_severity", "confidence", "measurement_quality", "availability", "policy_version"):
        assert getattr(revised.snapshot, field) == getattr(original.snapshot, field)
    for field in ("occurrence_count", "first_seen", "last_seen", "status", "fingerprint", "severity", "confidence"):
        assert getattr(result.alert, field) == getattr(before, field)
    assert len(harness.intents) == 1  # only the original local occurrence
    assert result.alert.evidence[-1].assessment.revision == 2
    assert harness.assessments.revision(original.key.assessment_id, 1).revision == original


def test_transitions_duplicate_new_fetch_metrics_and_restart(harness):
    original = initial(harness)
    first = enrich(harness, status=S.NO_HIT)
    assert first.assessment.revision.revision == 2
    assert not enrich(harness, status=S.NO_HIT, cached=True).assessment.created
    hit = enrich(harness)
    assert hit.assessment.revision.revision == 3
    changed = enrich(harness, score=80)
    assert changed.assessment.revision.revision == 4
    refreshed = enrich(harness, score=80, stamp=NOW + timedelta(hours=1))
    assert refreshed.assessment.revision.revision == 5
    no_hit = enrich(harness, status=S.NO_HIT, stamp=NOW + timedelta(hours=2))
    assert no_hit.assessment.revision.revision == 6
    # Late older provider observations never rewind current provenance.
    assert enrich(harness).assessment is None
    restored = Harness(harness.database.path)
    latest = restored.assessments.latest(original.assessment.revision.key.assessment_id).revision
    assert latest == no_hit.assessment.revision
    assert restored.assessments.revision(latest.key.assessment_id, 3).revision.snapshot.threat_intelligence[0].result.status is S.HIT


def test_independent_conflicting_providers_and_freshness(harness):
    first = initial(harness)
    enrich(harness, provider="fake_provider_a", freshness=F.STALE)
    result = enrich(harness, provider="fake_provider_b", status=S.NO_HIT)
    contexts = result.assessment.revision.snapshot.threat_intelligence
    assert [(c.key.provider.value, c.result.status, c.freshness) for c in contexts] == [
        ("fake_provider_a", S.HIT, F.STALE), ("fake_provider_b", S.NO_HIT, F.FRESH)]
    assert result.assessment.revision.snapshot.score == first.assessment.revision.snapshot.score
    model = RiskExplanationQueryService(harness.assessments).lookup(RiskExplanationRequest.for_alert(result.alert), now=NOW)
    text = "\n".join(model.sections[-1].lines)
    assert "fake_provider_a" in text and "fake_provider_b" in text and "STALE" in text
    assert "50%" not in text and "safe" in text


def test_no_assessment_or_mismatched_subject_never_fabricates_occurrence(harness):
    assert enrich(harness).status is RiskAlertStatus.NO_ALERT
    assert harness.assessments.for_connection(UUID(int=1)).status is AssessmentReadStatus.NOT_FOUND
    original = initial(harness)
    assert enrich(harness, address="1.1.1.1").status is RiskAlertStatus.NORMALIZATION_FAILED
    assert harness.assessments.latest(original.assessment.revision.key.assessment_id).revision.revision == 1


def test_old_occurrence_does_not_rewind_current_alert(harness):
    first = initial(harness)
    later = initial(harness, index=2, stamp=OBSERVED + timedelta(seconds=1))
    result = enrich(harness)
    assert result.assessment.revision.key == first.assessment.revision.key
    assert result.alert == later.alert and result.alert.occurrence_count == 2


def test_persistence_failure_keeps_lookup_and_local_pipeline(harness, monkeypatch):
    first = initial(harness)
    with monkeypatch.context() as patch:
        patch.setattr(harness.assessments, "save", lambda *args: (_ for _ in ()).throw(RuntimeError("secret exception")))
        failed = enrich(harness)
        assert failed.status is RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED
        assert failed.alert is None and failed.assessment is None
    assert harness.assessments.latest(first.assessment.revision.key.assessment_id).revision.revision == 1
    assert enrich(harness).assessment.created
    assert initial(harness, index=2, stamp=OBSERVED + timedelta(seconds=1)).alert.occurrence_count == 2


def test_partial_alert_failure_retry_is_idempotent(harness, monkeypatch):
    initial(harness)
    with monkeypatch.context() as patch:
        patch.setattr(harness.alert_service, "update_assessment", lambda *args: (_ for _ in ()).throw(RuntimeError("secret")))
        failed = enrich(harness)
    assert failed.status is RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED
    assert failed.assessment.revision.revision == 2
    retry = enrich(harness)
    assert not retry.assessment.created and retry.alert.occurrence_count == 1
    assert retry.alert.evidence[-1].assessment.revision == 2 and len(harness.intents) == 1


def test_real_worker_owns_enrichment_and_shutdown_receipt(harness):
    worker = RiskAlertWorker(harness.service, harness.dispatcher)
    signal = BehaviorRiskSignal(key(address="8.8.8.8"), (novelty(address="8.8.8.8"),), NOW, AlertWriteIntent.OCCURRENCE)
    assert worker.start()
    try:
        assert worker.submit(signal) is RiskAlertStatus.SUCCESS
        receipt = worker.submit_threat_intelligence(ThreatIntelAssessmentSignal(UUID(int=1), mapping().context, NOW))
        result = receipt.result(timeout=3)
        assert result.assessment.revision.revision == 2 and result.alert.occurrence_count == 1
    finally:
        assert worker.stop()
    receipt = worker.submit_threat_intelligence(ThreatIntelAssessmentSignal(UUID(int=1), mapping().context, NOW))
    assert receipt.result().status is RiskAlertStatus.UNAVAILABLE


def test_v1_integrity_and_v2_corruption_are_distinct(harness):
    first = initial(harness)
    result = enrich(harness)
    with harness.database.connection() as connection:
        rows = connection.execute("SELECT format_version, snapshot FROM risk_assessment_revisions ORDER BY revision").fetchall()
        assert rows[0][0] == 1 and "threat_intelligence" not in rows[0][1]
        assert rows[1][0] == 2 and "threat_intelligence" in rows[1][1]
        connection.execute("UPDATE risk_assessment_revisions SET format_version = 1 WHERE revision = 2")
    assert harness.assessments.latest(result.assessment.revision.key.assessment_id).status is AssessmentReadStatus.CORRUPT
    assert harness.assessments.revision(first.assessment.revision.key.assessment_id, 1).status is AssessmentReadStatus.FOUND


def test_local_reassessment_keeps_external_snapshot(harness):
    from netsentinel.domain.destination_novelty import DestinationNoveltyClassification
    original = initial(harness)
    ti = enrich(harness)
    revised = harness.process(replace(novelty(address="8.8.8.8"), classification=DestinationNoveltyClassification.RARE),
        occurrence=original.assessment.revision.key, intent=AlertWriteIntent.REASSESSMENT)
    assert revised.assessment.revision.snapshot.threat_intelligence == ti.assessment.revision.snapshot.threat_intelligence
    assert revised.assessment.revision.snapshot.score == 10 and revised.alert.occurrence_count == 1


def test_provider_context_hard_cap_does_not_disable_local_detection(harness):
    initial(harness)
    for index in range(16):
        result = enrich(harness, provider=f"fake_provider_{index}")
        assert result.assessment is not None
    assert len(result.assessment.revision.snapshot.threat_intelligence) == 16
    assert enrich(harness, provider="fake_provider_overflow").status is RiskAlertStatus.NORMALIZATION_FAILED
    assert initial(harness, index=2, stamp=OBSERVED + timedelta(seconds=1)).alert.occurrence_count == 2
