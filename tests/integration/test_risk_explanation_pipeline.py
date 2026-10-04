"""Real risk worker result -> UI query, without recalculation or policy writes."""

from threading import Event
from uuid import UUID

from netsentinel.application.services.risk_alerts import BehaviorRiskSignal, RiskAlertResult
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.bootstrap import create_desktop_engine, create_risk_explanation_service_factory
from tests.fixtures.behavior_risk import NOW, key, novelty, periodic
from tests.fixtures.risk_explanations import all_text
from tests.integration.test_suppression_pipeline import PolicyHarness


def test_suppressed_assessment_query_uses_exact_runtime_evaluation_without_writes(tmp_path):
    harness = PolicyHarness(tmp_path / "runtime.db")
    p = harness.create()
    worker = RiskAlertWorker(harness.service, harness.dispatcher)
    done = Event()
    harness.dispatcher.subscribe(RiskAlertResult, lambda _: done.set())
    worker.start()
    try:
        worker.submit(BehaviorRiskSignal(key(), (novelty(),), NOW))
        assert done.wait(2)
        assert worker.stop()
        query = RiskExplanationQueryService(harness.assessments, preferences=harness.preferences,
                                           suppression_lookup=worker.suppression_for)
        request = RiskExplanationRequest(lifecycle_id=key().observation_reference.value)
        displayed = query.lookup(request, now=NOW)
        assert "all alert-driving evidence" in all_text(displayed)
        assert dict(displayed.summary)["Concern score"] == "20 / 100"
        assert not harness.intents
        # Revoke does not rewrite the cached historical runtime result or score.
        harness.revoke(p)
        before = harness.preferences.get_history(p.preference_id)
        changed = query.lookup(request, now=NOW)
        assert "all alert-driving evidence" in all_text(changed)
        assert "status Revoked" in all_text(changed)
        assert harness.preferences.get_history(p.preference_id) == before
        assert worker.start()  # New session cache explicitly starts empty.
        assert worker.suppression_for(key().assessment_id, 1) is None
        restarted = query.lookup(request, now=NOW)
        assert "Historical suppression not recorded" in all_text(restarted)
    finally:
        assert worker.stop()


def test_runtime_cache_has_hard_bound_and_preserves_references(tmp_path):
    harness = PolicyHarness(tmp_path / "bounds.db")
    worker = RiskAlertWorker(harness.service, harness.dispatcher)
    worker.start()
    for i in range(1, 35):
        worker.submit(BehaviorRiskSignal(key(index=i), (novelty(), periodic()), NOW))
    assert worker.stop(timeout=5)
    assert len(worker._explanations) == 32
    assert worker.suppression_for(key(index=1).assessment_id, 1) is None
    retained = worker.suppression_for(key(index=34).assessment_id, 1)
    assert retained is not None and retained.assessment.assessment_id == key(index=34).assessment_id


def test_bootstrap_factory_is_dormant_and_shares_production_worker_cache(tmp_path):
    path = tmp_path / "dormant.db"
    engine = create_desktop_engine(database_path=path)
    factory = create_risk_explanation_service_factory(engine, database_path=path)
    query = factory()
    assert not path.exists()
    assert query._suppression_lookup.__self__ is engine.behavior_risk.worker
    assert engine.stop(1)
    # A fresh/restarted reader does not invent a connection assessment.
    result = query.lookup(RiskExplanationRequest(lifecycle_id=UUID(int=99)), now=NOW)
    assert "No retained risk assessment" in result.message
