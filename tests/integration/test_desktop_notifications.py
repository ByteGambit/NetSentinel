"""Actual schema 020 persistence, restart, legacy and risk notification sources."""

from datetime import timedelta
from dataclasses import replace

import pytest

from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.notifications import (
    NotificationDeliveryService, PersistedNotificationIntent, NotificationDeliveryOutcome as Outcome,
)
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import builtin_migrations
from tests.fixtures.notifications import NOW, Clock, FakeNotificationSink, candidate
from tests.integration.test_risk_alert_pipeline import Harness
from tests.fixtures.behavior_risk import deviations, novelty
from netsentinel.domain.frequency_diversity import BehaviorClassification


def compose(path, *, enabled=True):
    repo = SQLiteAlertRepository(SQLiteDatabase(path))
    dispatcher, sink, clock = EventDispatcher(), FakeNotificationSink(), Clock()
    delivery = NotificationDeliveryService(sink, enabled=enabled, clock=clock)
    events = []

    def accept(event):
        # Event is emitted only after repository commit and a separate read sees it.
        assert repo.get(event.alert_id) is not None
        events.append(event)
        delivery.enqueue(event)

    dispatcher.subscribe(PersistedNotificationIntent, accept)
    service = AlertService(repo, clock=lambda: NOW + timedelta(seconds=clock.value), dispatcher=dispatcher)
    return repo, sink, clock, delivery, events, service


def test_committed_legacy_then_restart_no_replay_same_alert_and_genuine_future(tmp_path):
    path = tmp_path / "notifications.sqlite3"
    repo, sink, clock, delivery, events, service = compose(path)
    first, eligible = service.record(candidate())
    assert eligible and len(events) == 1
    def verify_commit(request):
        assert repo.get(request.alert_id).occurrence_count == 1
    sink.on_submit = verify_commit
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    delivery.close()
    repo2, sink2, clock2, delivery2, events2, service2 = compose(path)
    assert sink2.attempts == 0 and repo2.get(first.id) == first
    assert not service2.record(candidate())[1]
    assert events2 == [] and delivery2.drain_one() is None
    clock2.value = 121
    later, eligible = service2.record(candidate(seconds=121))
    assert eligible and later.occurrence_count == 2 and later.id == first.id
    assert delivery2.drain_one() is Outcome.SUBMITTED_TO_SINK and sink2.attempts == 1
    assert max(m.version for m in builtin_migrations()) == 20


def test_persistence_failure_produces_zero_intents(tmp_path, monkeypatch):
    repo, sink, _, delivery, events, service = compose(tmp_path / "failure.db")
    def fail(*args):
        raise RuntimeError("private sqlite path")
    monkeypatch.setattr(repo, "record", fail)
    with pytest.raises(RuntimeError):
        service.record(candidate())
    assert events == [] and delivery.drain_one() is None and sink.attempts == 0


@pytest.mark.parametrize("status", [AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED])
def test_lifecycle_commit_cancels_pending_and_reopen_only_new_occurrence(tmp_path, status):
    repo, sink, clock, delivery, _, service = compose(tmp_path / "lifecycle.db")
    first, _ = service.record(candidate())
    (service.acknowledge if status is AlertStatus.ACKNOWLEDGED else service.resolve)(first.id)
    assert repo.get(first.id).status is status
    assert delivery.drain_one() is None
    clock.value = 1
    later, _ = service.record(candidate(seconds=1, severity="high"))
    if status is AlertStatus.RESOLVED:
        assert later.status is AlertStatus.OPEN
        assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    else:
        assert later.status is AlertStatus.ACKNOWLEDGED
        assert delivery.drain_one() is None
    assert sink.attempts == (status is AlertStatus.RESOLVED)


def test_disabled_events_not_replayed_on_enable(tmp_path):
    _, sink, clock, delivery, _, service = compose(tmp_path / "disabled.db", enabled=False)
    for index in range(20):
        service.record(candidate(index))
    delivery.set_enabled(True)
    assert delivery.drain_one() is None and sink.attempts == 0
    clock.value = 121
    service.record(candidate(seconds=121))
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK


def test_duplicate_1000_actual_repository_writes_one_intent(tmp_path):
    repo, sink, _, delivery, events, service = compose(tmp_path / "storm.db")
    for _ in range(1000):
        record, _ = service.record(candidate())
    assert repo.get(record.id).occurrence_count == 1 and len(events) == 1
    delivery.drain_one()
    assert sink.attempts == 1


def test_risk_commits_and_suppression_pipeline_intent_boundary(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    sink = FakeNotificationSink()
    delivery = NotificationDeliveryService(sink, enabled=True)
    events = []
    def accept(event):
        assert harness.alerts.get(event.alert_id) is not None
        events.append(event)
        delivery.enqueue(event)
    harness.dispatcher.subscribe(PersistedNotificationIntent, accept)
    first = harness.process()
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    assert events[0].alert_id == first.alert.id
    harness.process()
    assert delivery.drain_one() is None and sink.attempts == 1
    harness.process(replace(novelty(), gap_seen=True), intent=AlertWriteIntent.REASSESSMENT)
    assert delivery.drain_one() is None and sink.attempts == 1
    raised = harness.process(replace(deviations()[0], classification=BehaviorClassification.ELEVATED_CONFIRMED), intent=AlertWriteIntent.REASSESSMENT)
    if raised.alert.severity != first.alert.severity:
        assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK
    assert first.alert.occurrence_count == raised.alert.occurrence_count == 1


def test_restart_reassessment_escalation_can_submit_without_backlog(tmp_path):
    path = tmp_path / "risk-restart.db"
    first = Harness(path).process()
    harness = Harness(path)
    sink, events = FakeNotificationSink(), []
    delivery = NotificationDeliveryService(sink, enabled=True)
    def accept(event):
        events.append(event)
        delivery.enqueue(event)
    harness.dispatcher.subscribe(PersistedNotificationIntent, accept)
    assert delivery.drain_one() is None
    raised = harness.process(replace(deviations()[0], classification=BehaviorClassification.ELEVATED_CONFIRMED), intent=AlertWriteIntent.REASSESSMENT)
    assert raised.alert.id == first.alert.id and raised.alert.severity == "medium"
    assert delivery.drain_one() is Outcome.SUBMITTED_TO_SINK


def test_actual_suppression_cancels_pending_preserves_alert_and_assessment(tmp_path):
    from tests.integration.test_suppression_pipeline import PolicyHarness
    harness = PolicyHarness(tmp_path / "suppression.db")
    sink = FakeNotificationSink()
    delivery = NotificationDeliveryService(sink, enabled=True)
    def accept(event):
        delivery.enqueue(event)
    harness.dispatcher.subscribe(PersistedNotificationIntent, accept)
    first = harness.process()
    assert delivery.sizes[0] == 1
    harness.create()
    suppressed = harness.process()
    assert suppressed.suppression.disposition.value == "suppressed"
    assert delivery.drain_one() is None and sink.attempts == 0
    assert harness.alerts.get(first.alert.id) == first.alert
    assert suppressed.assessment.revision.snapshot.score == first.assessment.revision.snapshot.score


def test_assessment_failure_no_desktop_intent(tmp_path, monkeypatch):
    harness = Harness(tmp_path / "assessment-failure.db")
    events = []
    harness.dispatcher.subscribe(PersistedNotificationIntent, events.append)
    def fail(*args, **kwargs):
        raise RuntimeError("private database path")
    monkeypatch.setattr(harness.service._assessments, "persist", fail)
    harness.process()
    assert events == []
