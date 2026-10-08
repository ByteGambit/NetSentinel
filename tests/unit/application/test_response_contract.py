"""NS-100 fake privilege review; no OS adapter or executor can be called."""

from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.services.response_contract import ResponseContractReview, UnavailableResponsePrivilege
from netsentinel.domain.response import (
    ResponseAction, ResponseConfirmation, ResponseOutcome, ResponsePrivilegeAssessment,
    ResponsePrivilegeStatus, ResponseReason, ResponseSourceStatus,
)
from netsentinel.domain.connections import ObservationQuality
from tests.unit.domain.test_response import NOW, UNDO_ID, command


class FakePrivilege:
    def __init__(self, status=ResponsePrivilegeStatus.PRIVILEGE_REQUIRED):
        self.status = status
        self.calls = []

    def assess(self, request):
        self.calls.append(request)
        return ResponsePrivilegeAssessment(self.status)


@pytest.mark.parametrize("status", list(ResponsePrivilegeStatus))
@pytest.mark.parametrize("action", list(ResponseAction))
def test_one_fake_assessment_returns_typed_not_attempted_receipt(status, action):
    c = command() if action is ResponseAction.CREATE else replace(command(), command_id=UNDO_ID, action=action)
    fake = FakePrivilege(status)
    result = ResponseContractReview(fake).review(c, ResponseConfirmation(c.fingerprint, NOW), NOW)
    assert fake.calls == [c]
    assert result.command_id == c.command_id
    assert result.action is action
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert result.reason is ResponseReason(status.value)
    assert not hasattr(fake, "create")
    assert not hasattr(fake, "remove")


def test_cancel_or_unconfirmed_review_performs_no_port_call():
    c = command()
    fake = FakePrivilege()
    result = ResponseContractReview(fake).review(c, None, NOW)
    assert result.reason is ResponseReason.CONFIRMATION_REQUIRED
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert fake.calls == []


def test_changed_selection_or_timeout_never_reaches_probe():
    c = command()
    confirmation = ResponseConfirmation(c.fingerprint, NOW)
    fake = FakePrivilege()
    review = ResponseContractReview(fake)
    changed = review.review(replace(c, selection_generation=3), confirmation, NOW)
    stale = review.review(c, confirmation, NOW + timedelta(minutes=6))
    assert changed.reason is stale.reason is ResponseReason.STALE_CONFIRMATION
    assert fake.calls == []


def test_default_boundary_cannot_be_enabled_by_forged_local_confirmation():
    c = command()
    result = ResponseContractReview(UnavailableResponsePrivilege()).review(c, ResponseConfirmation(c.fingerprint, NOW), NOW)
    assert result.reason is ResponseReason.BOUNDARY_UNAVAILABLE
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED


def test_probe_exception_never_exposes_raw_secret_or_becomes_permission():
    class BrokenPrivilege:
        def assess(self, request):
            raise RuntimeError("hidden_secret; C:\\private\\user.exe 192.168.1.2")

    c = command()
    result = ResponseContractReview(BrokenPrivilege()).review(c, ResponseConfirmation(c.fingerprint, NOW), NOW)
    assert result.reason is ResponseReason.BOUNDARY_UNAVAILABLE
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert "hidden_secret" not in repr(result)


def test_untyped_probe_result_is_fail_closed():
    class MalformedPrivilege:
        def assess(self, request):
            return True

    c = command()
    result = ResponseContractReview(MalformedPrivilege()).review(c, ResponseConfirmation(c.fingerprint, NOW), NOW)
    assert result.reason is ResponseReason.BOUNDARY_UNAVAILABLE
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED


@pytest.mark.parametrize("source_change", [
    {"status": ResponseSourceStatus.UNAVAILABLE}, {"status": ResponseSourceStatus.EXPIRED},
    {"quality": ObservationQuality.FAILED},
])
def test_unavailable_creation_source_denied_but_undo_keeps_provenance(source_change):
    c = replace(command(), source=replace(command().source, **source_change))
    fake = FakePrivilege()
    review = ResponseContractReview(fake)
    result = review.review(c, ResponseConfirmation(c.fingerprint, NOW), NOW)
    assert result.reason is ResponseReason.TARGET_UNAVAILABLE
    assert fake.calls == []
    undo = replace(c, command_id=UNDO_ID, action=ResponseAction.REMOVE)
    result = review.review(undo, ResponseConfirmation(undo.fingerprint, NOW), NOW)
    assert result.reason is ResponseReason.PRIVILEGE_REQUIRED
    assert fake.calls == [undo]
