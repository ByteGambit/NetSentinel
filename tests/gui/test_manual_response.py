"""NS-103 offscreen human action, accessibility and thread-affinity acceptance."""

from dataclasses import replace
from datetime import timedelta
from threading import Event, get_ident

import pytest
from PyQt6.QtCore import Qt, QTimer

from netsentinel.application.services.response_ui import ResponseUiService
from netsentinel.domain.response import FirewallReadStatus, ResponseProfile
from netsentinel.domain.response_lifecycle import ResponseAuditEvent, ResponseStorageError
from netsentinel.presentation.response_commands import ResponseCommandCoordinator
from netsentinel.presentation.widgets.manual_response import ManualResponseWidget
from tests.fixtures.response_ui import selection, ui_service, setup as lifecycle_setup
from tests.integration.test_response_lifecycle import ops
from tests.unit.infrastructure.test_windows_response_firewall import FirewallApiError, raises

setup = lifecycle_setup


@pytest.fixture
def panel(qtbot, setup):
    service = ui_service(setup)
    coordinator = ResponseCommandCoordinator(lambda: service)
    coordinator.start()
    widget = ManualResponseWidget(coordinator, clock=setup[3])
    qtbot.addWidget(widget)
    widget.show()
    widget.select(selection())
    yield widget, coordinator, service, setup
    coordinator.stop()


def review(panel, qtbot):
    w = panel[0]
    w.profile.setCurrentIndex(2)
    w.review.click()
    qtbot.waitUntil(lambda: w.dialog is not None)
    return w.dialog


def confirm(panel, qtbot):
    d = review(panel, qtbot)
    d.confirm.click()
    qtbot.waitUntil(lambda: not panel[0]._pending)


def read(panel, qtbot):
    panel[0].refresh.click()
    qtbot.waitUntil(lambda: not panel[0]._pending)


def test_profile_explicit_preview_plain_full_fields_no_automatic_response(panel, qtbot):
    w, _, _, env = panel
    assert w.profile.currentData() is None and not w.review.isEnabled()
    assert env[2].calls == [] and env[1].audit() == ()
    d = review(panel, qtbot)
    assert "Windows Firewall profile: Private" in d.text.toPlainText()
    for text in ("Executable:", "Remote IP:", "Protocol:", "Remote port:", "Direction:", "Rule action:",
                 "Lifetime:", "Observed UTC:", "Measurement quality:", "Undo", "Shared/cloud/CDN", "malware verdict"):
        assert text in d.text.toPlainText()
    assert d.cancel.isDefault() and not d.confirm.autoDefault()
    assert env[2].calls == [] and env[1].audit() == ()


@pytest.mark.parametrize("cancel", ["button", "escape", "close", "selection", "profile", "evidence"])
def test_cancel_zero_firewall_writes_and_zero_intent_attempt(panel, qtbot, cancel):
    w, _, _, env = panel
    d = review(panel, qtbot)
    if cancel == "button":
        d.cancel.click()
    elif cancel == "escape":
        qtbot.keyClick(d, Qt.Key.Key_Escape)
    elif cancel == "close":
        d.close()
    elif cancel == "selection":
        w.select(replace(selection(), remote_ip="1.1.1.1"))
    elif cancel == "profile":
        w.profile.setCurrentIndex(3)
    else:
        w.invalidate_evidence()
    qtbot.waitUntil(lambda: w.dialog is None)
    assert ops(env[2], "add") == ops(env[2], "remove") == 0
    assert env[1].page() == () and env[1].audit() == ()


@pytest.mark.parametrize("mode,expected", [("success", "SUCCESS"), ("denied", "DENIED"),
    ("failure", "FAILURE"), ("unknown", "UNKNOWN / PARTIAL"), ("partial", "UNKNOWN / PARTIAL")])
def test_typed_completion_and_no_witness(panel, qtbot, mode, expected):
    w, _, _, env = panel
    if mode in {"denied", "failure"}:
        env[2].hooks["add"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED if mode == "denied"
            else FirewallReadStatus.INVALID_REQUEST, definite_failure=True))
    if mode == "unknown":
        env[2].hooks["add"] = raises(RuntimeError("raw COM secret exception must not escape"))
    if mode == "partial":
        save = env[1].save
        def fail(operation, event):
            if event is ResponseAuditEvent.VERIFIED_SUCCESS:
                raise ResponseStorageError("synthetic final failure")
            return save(operation, event)
        env[1].save = fail
    confirm(panel, qtbot)
    assert expected in w.status.text()
    assert "raw COM secret" not in w.status.text()
    read(panel, qtbot)
    w.records.setCurrentRow(0)
    assert expected in w.record_text.toPlainText()
    assert w.undo.isEnabled() == (mode == "success")
    op = env[1].page()[0]
    all_text = w.record_text.toPlainText() + w.audit.toPlainText() + w.status.text()
    assert op.claim.witness not in all_text and op.command.fingerprint not in all_text


@pytest.mark.parametrize("mode,expected", [("success", "ROLLED BACK / REMOVED"), ("denied", "DENIED"),
    ("unknown", "UNKNOWN / PARTIAL"), ("partial", "UNKNOWN / PARTIAL"), ("drift", "FAILURE")])
def test_owned_undo_confirmation_strict_rollback_results(panel, qtbot, mode, expected):
    w, _, _, env = panel
    confirm(panel, qtbot)
    read(panel, qtbot)
    w.records.setCurrentRow(0)
    assert w.undo.isEnabled()
    w.undo.click()
    qtbot.waitUntil(lambda: w.dialog is not None)
    d = w.dialog
    assert "REMOVE" in d.text.toPlainText() and "8.8.8.8" in d.text.toPlainText()
    assert "Undo" in d.confirm.text()
    if mode == "denied":
        env[2].hooks["remove"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True))
    if mode == "unknown":
        env[2].hooks["remove"] = raises(RuntimeError("uncertain removal"))
    if mode == "partial":
        save = env[1].save
        def fail(operation, event):
            if event is ResponseAuditEvent.ROLLBACK_SUCCESS:
                raise ResponseStorageError("synthetic removal finalization failure")
            return save(operation, event)
        env[1].save = fail
    if mode == "drift":
        env[2].rows = (replace(env[2].rows[0], enabled=False),)
    d.confirm.click()
    qtbot.waitUntil(lambda: not w._pending)
    assert expected in w.status.text()
    if mode == "success":
        assert not env[2].rows
        read(panel, qtbot)
        w.records.setCurrentRow(0)
        assert not w.undo.isEnabled()
    if mode == "drift":
        assert ops(env[2], "remove") == 0


def test_undo_cancel_and_missing_ownership_inaccessible(panel, qtbot):
    w, _, _, env = panel
    read(panel, qtbot)
    assert not w.undo.isEnabled()
    confirm(panel, qtbot)
    read(panel, qtbot)
    w.records.setCurrentRow(0)
    w.undo.click()
    qtbot.waitUntil(lambda: w.dialog is not None)
    w.dialog.cancel.click()
    assert ops(env[2], "remove") == 0 and len(env[1].page()) == 1


def test_duplicate_prevented_responsive_worker_and_selection_change(panel, qtbot):
    w, coordinator, _, env = panel
    entered, release = Event(), Event()
    threads = []
    def slow_add(rule):
        threads.append(get_ident())
        entered.set()
        assert release.wait(3)
        env[2].rows += (rule,)
    env[2].hooks["add"] = slow_add
    d = review(panel, qtbot)
    preview = w._preview
    d.confirm.click()
    qtbot.waitUntil(entered.is_set)
    assert not w.review.isEnabled() and coordinator.confirm(preview, env[3]()) is None
    heartbeat = []
    QTimer.singleShot(0, lambda: heartbeat.append(True))
    qtbot.waitUntil(lambda: bool(heartbeat))
    w.select(replace(selection(), remote_ip="1.1.1.1"))
    release.set()
    qtbot.waitUntil(lambda: not w._pending)
    assert threads[0] != get_ident() and ops(env[2], "add") == 1
    assert "Earlier operation" in w.status.text() and "1.1.1.1" in w.context.text()
    assert "SUCCESS" not in w.status.text()


def test_stale_deadline_requires_new_preview(panel, qtbot):
    w, _, _, env = panel
    d = review(panel, qtbot)
    env[3].now += timedelta(minutes=6)
    d.confirm.click()
    qtbot.waitUntil(lambda: not w._pending)
    assert "stale_confirmation" in w.status.text()
    assert env[2].calls == [] and env[1].audit() == ()


def test_keyboard_tab_order_accessible_names_and_safe_default(panel, qtbot):
    w = panel[0]
    for control in (w.profile, w.review, w.refresh, w.records, w.record_text, w.undo, w.audit, w.status):
        assert control.accessibleName()
    w.profile.setCurrentIndex(2)
    w.profile.setFocus()
    qtbot.keyClick(w.profile, Qt.Key.Key_Tab)
    assert w.review.hasFocus()
    d = review(panel, qtbot)
    qtbot.waitUntil(d.cancel.hasFocus)
    assert d.text.accessibleName() and d.confirm.accessibleName() and d.cancel.accessibleName()
    qtbot.keyClick(d.cancel, Qt.Key.Key_Tab)
    assert d.confirm.hasFocus()
    qtbot.keyClick(d, Qt.Key.Key_Escape)
    assert panel[3][2].calls == []


def test_default_boundary_read_mode_does_not_disable_local_feedback(qtbot, tmp_path, monkeypatch):
    from netsentinel.presentation.app import create_application
    from netsentinel.presentation.views.main_window import PageId
    from tests.gui.test_connections_view import FakeEngine
    from tests.fixtures.mark_normal import request
    from tests.gui.test_mark_normal import service, prepare_dialog, counts
    from tests.gui.test_connections_view import _snapshot
    from netsentinel.domain.connections import ConnectionOpened
    path = tmp_path / "feedback.db"
    shell = create_application(FakeEngine(), preference_service_factory=lambda: service(path),
                               response_service_factory=ResponseUiService)
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    try:
        view = shell.window.page_widget(PageId.CONNECTIONS)
        shell.window.connections_model.handle_connection_opened(ConnectionOpened(_snapshot()))
        assert shell.window.connections_model.rowCount() == 1
        response = view.details.response
        assert response.refresh.isEnabled()
        response.select(selection())
        response.profile.setCurrentIndex(2)
        response.review.click()
        qtbot.waitUntil(lambda: not response._pending)
        assert "BOUNDARY_UNAVAILABLE" in response.status.text()
        feedback = view.details.baseline.preferences
        feedback.select(request())
        feedback.rule.setCurrentIndex(1)
        qtbot.waitUntil(lambda: feedback._generation is None)
        prepare_dialog(monkeypatch)
        feedback.action.click()
        qtbot.waitUntil(lambda: feedback._pending is None)
        assert counts(path) == (1, 1)
    finally:
        assert shell.lifecycle.shutdown()


def test_shutdown_bounded_active_completion_not_cancellation(panel, qtbot):
    w, coordinator, _, env = panel
    entered, release = Event(), Event()
    def slow(rule):
        entered.set()
        assert release.wait(3)
        env[2].rows += (rule,)
    env[2].hooks["add"] = slow
    d = review(panel, qtbot)
    d.confirm.click()
    qtbot.waitUntil(entered.is_set)
    assert not coordinator.stop(timeout=0.01)
    assert not w.review.isEnabled()
    release.set()
    assert coordinator.stop(timeout=2)
    assert ops(env[2], "add") == 1 and env[1].page()[0].manifest is not None


def test_restart_read_and_external_drift_without_unsafe_undo(panel, qtbot):
    w, _, _, env = panel
    confirm(panel, qtbot)
    env[2].rows = (replace(env[2].rows[0], enabled=False),)
    env[4].reconcile()
    read(panel, qtbot)
    w.records.setCurrentRow(0)
    assert "externally_disabled" in w.record_text.toPlainText() and not w.undo.isEnabled()
    from tests.integration.test_response_lifecycle import restart
    repo, _ = restart(env)
    coordinator = ResponseCommandCoordinator(lambda: ResponseUiService(repo))
    coordinator.start()
    restored = ManualResponseWidget(coordinator)
    qtbot.addWidget(restored)
    try:
        restored.refresh.click()
        qtbot.waitUntil(lambda: not restored._pending)
        restored.records.setCurrentRow(0)
        assert "externally_disabled" in restored.record_text.toPlainText()
        assert not restored.undo.isEnabled() and ops(env[2], "remove") == 0
    finally:
        coordinator.stop()


def test_worker_factory_failure_is_sanitized_and_read_mode_still_usable(qtbot):
    def fail():
        raise RuntimeError("secret raw exception")
    coordinator = ResponseCommandCoordinator(fail)
    coordinator.start()
    widget = ManualResponseWidget(coordinator)
    qtbot.addWidget(widget)
    widget.select(selection())
    widget.profile.setCurrentIndex(1)
    try:
        widget.review.click()
        qtbot.waitUntil(lambda: not widget._pending)
        assert "Unavailable" in widget.status.text() and "secret" not in widget.status.text()
        assert widget.refresh.isEnabled() and widget.dialog is None
    finally:
        coordinator.stop()


def test_invalidation_of_queued_confirm_completes_without_mutation(qtbot, setup):
    # Hold factory construction so a confirmed job is still queued at Cancel.
    entered, release = Event(), Event()
    service = ui_service(setup)
    p = service.preview(selection(), ResponseProfile.PRIVATE, 1).preview
    def factory():
        entered.set()
        assert release.wait(3)
        return service
    coordinator = ResponseCommandCoordinator(factory)
    completions = []
    coordinator.completed.connect(lambda *args: completions.append(args))
    coordinator.start()
    try:
        assert entered.wait(1)
        coordinator.invalidate()
        assert coordinator.confirm(p, setup[3]()) is not None
        coordinator.invalidate()
        assert len(completions) == 1 and "Cancelled before dispatch" in completions[0][3].message
        release.set()
    finally:
        release.set()
        assert coordinator.stop()
    assert setup[2].calls == [] and setup[1].audit() == ()
