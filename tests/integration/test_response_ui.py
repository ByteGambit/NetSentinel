"""Application/UI boundary acceptance with real SQLite and fake firewall."""

from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.services.response_ui import ResponseUiService, result_text
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import FirewallReadStatus, ResponseOutcome, ResponseProfile, ResponseSourceStatus
from netsentinel.domain.response_lifecycle import ResponseAuditEvent
from tests.fixtures.response_ui import selection, ui_service, setup as lifecycle_setup
from tests.integration.test_response_lifecycle import ops, restart
from tests.unit.infrastructure.test_windows_response_firewall import FirewallApiError, raises

setup = lifecycle_setup


def preview(service, generation=1):
    return service.preview(selection(), ResponseProfile.PRIVATE, generation).preview


def test_exact_preview_create_confirm_owned_read_restart_and_undo(setup):
    service = ui_service(setup)
    p = preview(service)
    text = p.text
    for expected in (r"C:\Example\app.exe", "8.8.8.8", "IPv4", "TCP", "443", "Private", "outbound", "block",
                     "until manually removed", "expiry: none", "Source: connection", "session", "lifecycle",
                     "complete", "malware verdict", "Shared/cloud/CDN", "administrator", "unrestricted"):
        assert expected in text
    assert ops(setup[2], "add") == 0 and setup[1].page() == ()
    reply = service.confirm(p, 1, setup[3]())
    assert reply.result.outcome is ResponseOutcome.VERIFIED
    row = service.history().rows[0]
    assert row.undo_available and "SUCCESS" in row.text
    witness = setup[1].page()[0].claim.witness
    assert witness not in repr(service.history()) and witness not in row.text
    repo, lifecycle = restart(setup)
    restarted = ResponseUiService(repo, lifecycle=lifecycle, clock=setup[3])
    assert restarted.history().rows == service.history().rows
    undo = restarted.preview(None, None, 2, row.operation_id).preview
    assert "REMOVE" in undo.text and p.command.rule_name in undo.text
    reply = restarted.confirm(undo, 2, setup[3]())
    assert reply.result.outcome is ResponseOutcome.VERIFIED and "absence verified" in reply.message
    assert ops(setup[2], "remove") == 1
    assert not service.history().rows[0].undo_available
    assert ResponseAuditEvent.ROLLBACK_SUCCESS in [r.event for r in repo.audit()]


@pytest.mark.parametrize("field,value", [
    ("program_path", None), ("program_path", r"C:\Windows\..\x.exe"),
    ("remote_ip", None), ("remote_ip", "example.org"), ("remote_ip", "192.168.1.10"),
    ("remote_port", None), ("remote_port", 0), ("protocol", "icmp"), ("source", None),
])
def test_unavailable_target_explicit_no_scope_widening(setup, field, value):
    service = ui_service(setup)
    reply = service.preview(replace(selection(), **{field: value}), ResponseProfile.PRIVATE, 1)
    assert reply.preview is None and "Unavailable" in reply.message
    assert setup[2].calls == [] and setup[1].audit() == ()


@pytest.mark.parametrize("status,quality", [(ResponseSourceStatus.EXPIRED, None),
    (ResponseSourceStatus.UNAVAILABLE, None), (ResponseSourceStatus.AVAILABLE, ObservationQuality.FAILED)])
def test_source_ambiguity_and_quality_not_fabricated(setup, status, quality):
    s = selection()
    reply = ui_service(setup).preview(replace(s, source=replace(s.source, status=status, quality=quality)), ResponseProfile.PUBLIC, 1)
    assert reply.preview is None and setup[2].calls == []


@pytest.mark.parametrize("profile", list(ResponseProfile))
def test_no_hidden_profile_or_expiry_defaults(setup, profile):
    service = ui_service(setup)
    assert service.preview(selection(), None, 1).preview is None
    p = service.preview(selection(), profile, 2).preview
    assert p.command.spec.profile is profile and p.command.spec.lifetime.expires_at is None


@pytest.mark.parametrize("stale", ["generation", "deadline", "changed_preview", "repeat"])
def test_stale_confirmation_consumed_without_attempt(setup, stale):
    service = ui_service(setup)
    p = preview(service)
    generation = 1
    if stale == "generation":
        generation = 3  # A -> B -> A
    elif stale == "deadline":
        setup[3].now += timedelta(minutes=5, microseconds=1)
    elif stale == "changed_preview":
        service.preview(selection(), ResponseProfile.PUBLIC, 1)
    else:
        # First call has no writer authority; second cannot reuse its approval.
        service.lifecycle = None
        service.confirm(p, 1, setup[3]())
    reply = service.confirm(p, generation, setup[3]())
    assert reply.result.outcome is ResponseOutcome.NOT_ATTEMPTED and "stale_confirmation" in reply.message
    assert setup[2].calls == [] and setup[1].audit() == ()


def test_default_trusted_boundary_unavailable_even_with_complete_preview(setup):
    service = ResponseUiService(setup[1], file_identity=lambda _: preview(ui_service(setup)).command.file_identity,
                                clock=setup[3])
    p = preview(service)
    reply = service.confirm(p, 1, setup[3]())
    assert reply.result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert "boundary_unavailable" in reply.message
    assert setup[2].calls == [] and setup[1].audit() == ()


@pytest.mark.parametrize("mode,expected", [("denied", "DENIED"), ("failure", "FAILURE"), ("partial", "UNKNOWN / PARTIAL")])
def test_denied_failure_partial_no_false_ownership(setup, mode, expected):
    if mode in {"denied", "failure"}:
        setup[2].hooks["add"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED if mode == "denied"
            else FirewallReadStatus.INVALID_REQUEST, definite_failure=True))
    else:
        save = setup[1].save
        def fail_final(operation, event):
            if event is ResponseAuditEvent.VERIFIED_SUCCESS:
                from netsentinel.domain.response_lifecycle import ResponseStorageError
                raise ResponseStorageError("synthetic finalization failure")
            return save(operation, event)
        setup[1].save = fail_final
    service = ui_service(setup)
    reply = service.confirm(preview(service), 1, setup[3]())
    assert expected in reply.message and not service.history().rows[0].undo_available


def test_external_drift_after_preview_refuses_remove(setup):
    service = ui_service(setup)
    service.confirm(preview(service), 1, setup[3]())
    row = service.history().rows[0]
    undo = service.preview(None, None, 2, row.operation_id).preview
    setup[2].rows = (replace(setup[2].rows[0], enabled=False),)
    reply = service.confirm(undo, 2, setup[3]())
    assert reply.result.outcome is not ResponseOutcome.VERIFIED
    assert ops(setup[2], "remove") == 0
    setup[4].reconcile()
    assert not service.history().rows[0].undo_available
    assert "externally_disabled" in service.history().rows[0].text


def test_audit_bounded_and_no_witness_or_confirmation_digest(setup):
    service = ui_service(setup)
    service.confirm(preview(service), 1, setup[3]())
    operation = setup[1].page()[0]
    history = service.history()
    assert len(history.audit) == 3 and "attempt" in history.audit[1]
    assert operation.claim.witness not in str(history)
    assert operation.command.fingerprint not in str(history)
    assert result_text(operation.result).startswith("SUCCESS")


def test_undo_invalidated_by_new_custody_revision_without_remove(setup):
    service = ui_service(setup)
    service.confirm(preview(service), 1, setup[3]())
    undo = service.preview(None, None, 2, service.history().rows[0].operation_id).preview
    setup[4].reconcile()  # a newer recorded observation needs a new review
    reply = service.confirm(undo, 2, setup[3]())
    assert "ownership_conflict" in reply.message and ops(setup[2], "remove") == 0


def test_partial_prepared_has_no_undo_and_expired_source_does_not_disable_owned_undo(setup):
    service = ui_service(setup)
    service.confirm(preview(service), 1, setup[3]())
    setup[3].now += timedelta(days=30)
    row = service.history().rows[0]
    undo = service.preview(None, None, 2, row.operation_id).preview
    assert undo is not None
    reply = service.confirm(undo, 2, setup[3]())
    assert reply.result.outcome is ResponseOutcome.VERIFIED
