"""Frozen NS-094 policy matrix, storm bounds and failure semantics."""

from dataclasses import asdict, replace
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

import pytest

from netsentinel.application.services.notifications import (
    DesktopNotificationRequest, NotificationDeliveryPolicy, NotificationDeliveryService,
    NotificationDeliveryOutcome as Outcome,
)
from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.risk_scoring import RiskSeverity
from tests.fixtures.notifications import Clock, FakeNotificationSink, alert, intent


def setup(enabled=True):
    sink, clock = FakeNotificationSink(), Clock()
    return sink, clock, NotificationDeliveryService(sink, enabled=enabled, clock=clock)


def deliver(service, event):
    service.enqueue(event)
    return service.drain_one()


def test_new_eligible_then_identical_even_after_cooldown():
    sink, clock, service = setup()
    assert deliver(service, intent()) is Outcome.SUBMITTED_TO_SINK
    clock.value = 121
    assert deliver(service, intent()) is Outcome.POLICY_SKIPPED
    assert sink.attempts == 1 and service.diagnostics().duplicate_skipped == 1


@pytest.mark.parametrize("elapsed,expected", [(0, False), (119.999, False), (120, True), (121, True)])
def test_new_same_severity_occurrence_cooldown(elapsed, expected):
    sink, clock, service = setup()
    deliver(service, intent())
    clock.value = elapsed
    outcome = deliver(service, intent(seconds=1, count=2, previous=alert()))
    assert (outcome is Outcome.SUBMITTED_TO_SINK) is expected
    assert sink.attempts == 1 + expected


@pytest.mark.parametrize("previous,current", [("low", "medium"), ("low", "high"), ("medium", "high")])
@pytest.mark.parametrize("elapsed", [0, 121])
def test_escalations_bypass_cooldown(previous, current, elapsed):
    sink, clock, service = setup()
    deliver(service, intent(severity=previous))
    clock.value = elapsed
    assert deliver(service, intent(severity=current, seconds=1, count=2,
                                  previous=alert(severity=previous))) is Outcome.SUBMITTED_TO_SINK
    assert sink.attempts == 2 and service.diagnostics().escalation_notifications == 1


@pytest.mark.parametrize("previous,current", [("high", "medium"), ("high", "low"), ("medium", "low")])
def test_decrease_never_notifies(previous, current):
    sink, clock, service = setup()
    deliver(service, intent(severity=previous))
    clock.value = 1000
    assert deliver(service, intent(severity=current, seconds=1, count=2,
                                  previous=alert(severity=previous))) is Outcome.POLICY_SKIPPED
    assert sink.attempts == 1


def test_high_low_high_reassessment_hysteresis():
    sink, clock, service = setup()
    deliver(service, intent(severity="high"))
    deliver(service, intent(severity="medium", seconds=1, count=2, previous=alert(severity="high")))
    clock.value = 1000
    event = replace(intent(severity="high", seconds=2, count=3, previous=alert(severity="medium")),
                    write_intent=AlertWriteIntent.REASSESSMENT)
    assert deliver(service, event) is Outcome.POLICY_SKIPPED
    assert sink.attempts == 1


@pytest.mark.parametrize("severity", ["low", "medium", "high"])
def test_numeric_confidence_only_reassessment_without_runtime_state_skips(severity):
    sink, clock, service = setup()
    clock.value = 1000
    event = replace(intent(severity=severity, previous=alert(severity=severity)),
                    write_intent=AlertWriteIntent.REASSESSMENT)
    assert deliver(service, event) is Outcome.POLICY_SKIPPED
    assert sink.attempts == 0


@pytest.mark.parametrize("status", [AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED])
def test_lifecycle_skips_and_cancels_pending(status):
    sink, _, service = setup()
    service.enqueue(intent())
    event = intent(status=status, severity="high")
    assert service.enqueue(event) is Outcome.POLICY_SKIPPED
    assert service.drain_one() is None and sink.attempts == 0


def test_genuine_reopen_bypasses_previous_high_and_cooldown():
    sink, _, service = setup()
    deliver(service, intent(severity="high"))
    event = intent(severity="low", seconds=1, count=2,
                   previous=alert(severity="high", status=AlertStatus.RESOLVED))
    assert deliver(service, event) is Outcome.SUBMITTED_TO_SINK
    assert sink.attempts == 2


@pytest.mark.parametrize("field", ["suppressed", "eligible"])
def test_suppression_ineligibility_cancels_pending(field):
    sink, _, service = setup()
    service.enqueue(intent())
    service.enqueue(replace(intent(), **{field: field == "suppressed"}))
    assert service.drain_one() is None and sink.attempts == 0


def test_disable_enable_no_backlog_and_future_event_works():
    sink, _, service = setup(False)
    for index in range(100):
        assert service.enqueue(intent(index)) is Outcome.POLICY_SKIPPED
    service.set_enabled(True)
    assert service.drain_one() is None
    deliver(service, intent(101))
    service.enqueue(intent(102))
    service.set_enabled(False)
    service.set_enabled(True)
    assert service.drain_one() is None and sink.attempts == 1


def test_1000_identical_concurrent_intents_coalesce_and_dedup():
    sink, _, service = setup()
    event = intent()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(service.enqueue, [event] * 1000))
    assert service.sizes == (1, 0)
    service.drain_one()
    for _ in range(1000):
        deliver(service, event)
    assert sink.attempts == 1 and service.sizes == (0, 1)
    assert service.diagnostics().queue_coalesced == 999


def test_distinct_storm_and_state_hard_bounds():
    sink, _, service = setup()
    for index in range(1000):
        service.enqueue(intent(index))
    assert service.sizes == (32, 0)
    assert service.diagnostics().queue_dropped == 968
    while service.drain_one() is not None:
        pass
    for index in range(32, 1000):
        deliver(service, intent(index))
    assert service.sizes == (0, 512) and sink.attempts == 512
    assert service.diagnostics().capacity_skipped == 488


@pytest.mark.parametrize("outcome,exception", [(Outcome.SINK_UNAVAILABLE, False), (Outcome.SINK_FAILED, False),
                                             (Outcome.SUBMITTED_TO_SINK, True)])
def test_failed_attempt_not_successful_no_tight_retry(outcome, exception):
    sink, _, service = setup()
    sink.outcome, sink.exception = outcome, exception
    expected = Outcome.SINK_FAILED if exception else outcome
    assert deliver(service, intent()) is expected
    assert service.diagnostics().submitted_to_sink == 0
    sink.outcome, sink.exception = Outcome.SUBMITTED_TO_SINK, False
    assert deliver(service, intent()) is Outcome.POLICY_SKIPPED
    assert deliver(service, intent(seconds=1, count=2, previous=alert())) is Outcome.SUBMITTED_TO_SINK
    assert sink.attempts == 2


def test_shutdown_clears_rejects_late_and_is_idempotent():
    sink, _, service = setup()
    service.enqueue(intent())
    service.close()
    service.close()
    assert service.sizes == (0, 0) and sink.closed
    assert service.enqueue(intent()) is Outcome.POLICY_SKIPPED
    assert service.drain_one() is None and sink.attempts == 0


@pytest.mark.parametrize("severity", ["low", "medium", "high"])
def test_preview_fixed_plain_bounded_and_diagnostics_aggregate(severity):
    sink, _, service = setup()
    deliver(service, intent(severity=severity))
    request = sink.requests[0]
    assert len(request.body) <= service.policy.body_max
    assert request.title == "NetSentinel security alert"
    for forbidden in ("192.0.2", "private", "C:/", "<", ">", "MAC", "hash", "path", "evidence"):
        assert forbidden not in request.body
    from netsentinel.application.services.notifications import NotificationPlatformState
    aggregate = asdict(service.diagnostics())
    assert aggregate.pop("platform_state") is NotificationPlatformState.DELIVERY_UNKNOWN
    assert aggregate.pop("last_submission_outcome") is Outcome.SUBMITTED_TO_SINK
    assert aggregate.pop("visible_delivery_confirmed") is None
    assert all(type(value) is int for value in aggregate.values())
    with pytest.raises(ValueError):
        replace(request, body="<b>192.0.2.1</b>")


def test_info_no_popup_distinct_subjects_independent_policy_frozen():
    sink, _, service = setup()
    assert deliver(service, intent(severity="info")) is Outcome.POLICY_SKIPPED
    for index in range(1, 5):
        assert deliver(service, intent(index)) is Outcome.SUBMITTED_TO_SINK
    assert sink.attempts == 4
    with pytest.raises(ValueError):
        NotificationDeliveryPolicy(cooldown_seconds=10)
    with pytest.raises(ValueError):
        DesktopNotificationRequest(alert().id, RiskSeverity.LOW, "raw", "raw")


def test_coalesced_pending_escalation_preserves_reopen_and_latest_severity():
    sink, _, service = setup()
    service.enqueue(intent(previous=alert(status=AlertStatus.RESOLVED)))
    service.enqueue(intent(severity="high", seconds=1, count=2, previous=alert()))
    assert service.drain_one() is Outcome.SUBMITTED_TO_SINK
    assert sink.requests[0].severity is RiskSeverity.HIGH


def test_stale_pending_occurrence_cannot_rewind_latest():
    sink, _, service = setup()
    service.enqueue(intent(seconds=10, count=2, severity="high"))
    service.enqueue(intent())
    service.drain_one()
    assert sink.requests[0].severity is RiskSeverity.HIGH


def test_identity_does_not_use_random_uuid_or_numeric_score():
    event = intent()
    assert event.alert_id == alert().id and event.identity[1] == 1
    assert replace(event, observed_at=event.observed_at + timedelta(seconds=1)).identity != event.identity


def test_delayed_old_intent_after_cooldown_cannot_replay():
    sink, clock, service = setup()
    deliver(service, intent(seconds=10, count=2))
    clock.value = 1000
    assert deliver(service, intent()) is Outcome.POLICY_SKIPPED
    assert sink.attempts == 1


@pytest.mark.parametrize("fields", [{"alert_id": "raw"}, {"severity": "critical"},
    {"occurrence_count": 0}, {"eligible": 1}, {"previous_status": "open"}])
def test_malformed_intent_rejected(fields):
    with pytest.raises(ValueError):
        replace(intent(), **fields)
