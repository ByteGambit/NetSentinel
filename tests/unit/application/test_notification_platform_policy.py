"""Platform gating consumes intents, never retries or changes alert policy."""
import pytest

from netsentinel.application.services.notifications import (
    NotificationDeliveryOutcome as Outcome, NotificationDeliveryService,
    NotificationPlatformState as State,
)
from tests.fixtures.notifications import FakeNotificationSink, intent


@pytest.mark.parametrize("state,outcome,counter", [
    (State.DISABLED_BY_OS, Outcome.PLATFORM_RESTRICTED, "os_policy_skipped"),
    (State.SESSION_RESTRICTED, Outcome.PLATFORM_RESTRICTED, "os_policy_skipped"),
    (State.UNAVAILABLE, Outcome.SINK_UNAVAILABLE, "sink_unavailable"),
    (State.FAILED, Outcome.SINK_FAILED, "sink_failure"),
])
def test_restriction_no_submission_no_reenable_replay(state, outcome, counter):
    sink = FakeNotificationSink()
    sink.platform_state = state
    service = NotificationDeliveryService(sink, enabled=True)
    event = intent()
    service.enqueue(event)
    assert service.drain_one() is outcome
    snapshot = service.diagnostics()
    assert getattr(snapshot, counter) == 1
    assert snapshot.eligible_for_delivery == 1
    assert snapshot.submission_attempts == snapshot.submitted_to_sink == sink.attempts == 0
    assert snapshot.visible_delivery_confirmed is None
    sink.platform_state = State.DELIVERY_UNKNOWN
    service.refresh_policy()
    assert service.drain_one() is None
    service.enqueue(event)
    assert service.drain_one() is Outcome.POLICY_SKIPPED
    assert sink.attempts == 0
    service.enqueue(intent(seconds=1, count=2))
    assert service.drain_one() is Outcome.SUBMITTED_TO_SINK
    assert sink.attempts == 1


def test_default_off_does_not_query_platform_or_submit():
    sink = FakeNotificationSink()
    def forbidden():
        raise AssertionError("disabled application queried Windows")
    sink.policy_state = forbidden
    service = NotificationDeliveryService(sink)
    assert service.refresh_policy() is State.DISABLED_BY_APP
    assert service.enqueue(intent()) is Outcome.POLICY_SKIPPED
    assert service.drain_one() is None and sink.attempts == 0


def test_unknown_submission_failure_and_visibility_are_separate():
    sink = FakeNotificationSink()
    service = NotificationDeliveryService(sink, enabled=True)
    service.enqueue(intent())
    assert service.drain_one() is Outcome.SUBMITTED_TO_SINK
    snapshot = service.diagnostics()
    assert snapshot.submission_attempts == snapshot.submitted_to_sink == snapshot.delivery_unknown == 1
    assert snapshot.visible_delivery_confirmed is None
    assert snapshot.platform_state is State.DELIVERY_UNKNOWN
    sink.exception = True
    service.enqueue(intent(index=2))
    assert service.drain_one() is Outcome.SINK_FAILED
    assert service.diagnostics().last_submission_outcome is Outcome.SINK_FAILED
    assert service.diagnostics().submitted_to_sink == 1
    assert service.diagnostics().visible_delivery_confirmed is None


def test_adapter_policy_race_is_restriction_not_failure():
    sink = FakeNotificationSink()
    sink.outcome = Outcome.PLATFORM_RESTRICTED
    service = NotificationDeliveryService(sink, enabled=True)
    service.enqueue(intent())
    assert service.drain_one() is Outcome.PLATFORM_RESTRICTED
    assert service.diagnostics().os_policy_skipped == 1
    assert service.diagnostics().sink_failure == service.diagnostics().submitted_to_sink == 0


def test_known_restriction_discards_pending_backlog_before_reenable():
    sink = FakeNotificationSink()
    service = NotificationDeliveryService(sink, enabled=True)
    for index in range(1, 10):
        service.enqueue(intent(index))
    sink.platform_state = State.DISABLED_BY_OS
    assert service.refresh_policy() is State.DISABLED_BY_OS
    assert service.sizes[0] == 0 and service.diagnostics().queue_dropped == 9
    sink.platform_state = State.DELIVERY_UNKNOWN
    service.refresh_policy()
    assert service.drain_one() is None and sink.attempts == 0


@pytest.mark.parametrize("outcome", [None, "private provider details", Outcome.QUEUED])
def test_invalid_adapter_results_are_sanitized_failures(outcome):
    sink = FakeNotificationSink()
    sink.outcome = outcome
    service = NotificationDeliveryService(sink, enabled=True)
    service.enqueue(intent())
    assert service.drain_one() is Outcome.SINK_FAILED
    assert service.diagnostics().last_submission_outcome is Outcome.SINK_FAILED
    assert service.diagnostics().sink_failure == 1
