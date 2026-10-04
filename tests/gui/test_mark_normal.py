"""NS-082 offscreen preview/save/cancel/revoke and bounded worker lifecycle."""

from concurrent.futures import Future
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event, get_ident

import pytest
from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QDialog, QMessageBox

from netsentinel.application.services.mark_normal import MarkNormalCommandService
from netsentinel.application.services.preferences import ScopedPreferenceService
from netsentinel.domain.connections import ConnectionNetworkScope
from netsentinel.domain.preferences import (
    PreferenceLifetime, PreferenceLifetimeKind, PreferencePage, PreferenceResult, PreferenceResultStatus as Status,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator
from netsentinel.presentation.widgets.mark_normal import MarkNormalDialog, MarkNormalWidget
from netsentinel.presentation.app import create_application
from tests.fixtures.mark_normal import context, preview, request
from tests.fixtures.preferences import NOW, application
from tests.gui.test_connections_view import FakeEngine
from tests.integration.test_mark_normal_commands import service, counts


@pytest.fixture
def panel(qtbot, tmp_path):
    path = tmp_path / "feedback.db"
    coordinator = PreferenceCommandCoordinator(lambda: service(path), clock=lambda: NOW)
    coordinator.start()
    widget = MarkNormalWidget(coordinator)
    qtbot.addWidget(widget)
    widget.show()
    widget.select(request())
    widget.rule.setCurrentIndex(1)
    qtbot.waitUntil(lambda: widget._generation is None)
    yield widget, coordinator, path
    coordinator.stop()


def prepare_dialog(monkeypatch, *, confirm=True):
    captured = []

    def message(box):
        captured.append(box.text())
        assert box.textFormat() is Qt.TextFormat.PlainText
        return QMessageBox.StandardButton.Save if confirm else QMessageBox.StandardButton.Cancel

    def options(dialog):
        dialog.reason.setText("<b>Expected behavior</b>")
        dialog.lifetime.setCurrentIndex(2)
        dialog._preview()
        return dialog.result()

    monkeypatch.setattr(QMessageBox, "exec", message)
    monkeypatch.setattr(MarkNormalDialog, "exec", options)
    return captured


def test_action_requires_selected_behavior_and_stable_application(panel, qtbot):
    widget, _, _ = panel
    assert widget.action.isEnabled() and widget.action.accessibleName()
    widget.rule.setCurrentIndex(0)
    assert not widget.action.isEnabled()
    widget.rule.setCurrentIndex(1)
    widget.clear()
    assert not widget.action.isEnabled()
    from netsentinel.application.services.baseline_detail import baseline_detail_request
    from netsentinel.domain.connections import ProcessInfo, ProcessIdentity, ProcessInfoStatus
    for known in (None, NOW):
        r = baseline_detail_request(ProcessInfo(identity=ProcessIdentity(12, known), name="browser",
                                               status=ProcessInfoStatus.AVAILABLE), request().network, "203.0.113.10")
        widget.select(r)
        assert not widget.action.isEnabled() and "cannot persist" in widget.status.text()


def test_lifetime_required_narrow_default_accessibility_and_plain_text(qtbot):
    dialog = MarkNormalDialog(context(name="<b>browser</b>"))
    qtbot.addWidget(dialog)
    assert dialog.scope.currentIndex() == 0
    assert dialog.lifetime.currentData() is None
    assert not dialog.preview_button.isEnabled()
    dialog.reason.setText("Expected")
    assert not dialog.preview_button.isEnabled()
    dialog.lifetime.setCurrentIndex(1)
    assert dialog.preview_button.isEnabled()
    for control in (dialog.scope, dialog.lifetime, dialog.reason, dialog.preview_button):
        assert control.accessibleName()
    assert dialog.summary.textFormat() is Qt.TextFormat.PlainText
    assert "Rule:" in dialog.summary.text() and "Current network scope:" in dialog.summary.text()
    assert dialog.reason.maxLength() == 512
    dialog.reason.setText("\u2028bad")
    dialog._preview()
    assert "Invalid" in dialog.error.text() and dialog.preview is None


@pytest.mark.parametrize("network", [ConnectionNetworkScope.unknown(), ConnectionNetworkScope.ambiguous()])
def test_unresolved_scope_visible_and_broadening_warning(qtbot, monkeypatch, network):
    dialog = MarkNormalDialog(context(network=network))
    qtbot.addWidget(dialog)
    assert network.status.value in dialog.summary.text() and "Any network" in dialog.summary.text()
    assert all("this network" not in dialog.scope.itemText(i) for i in range(dialog.scope.count()))
    dialog.scope.setCurrentIndex(1)
    dialog.reason.setText("Expected")
    dialog.lifetime.setCurrentIndex(1)
    captured = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: captured.append(box.text()) or QMessageBox.StandardButton.Cancel)
    dialog._preview()
    assert "Broader scope" in captured[0] and "Expires:" in captured[0]


@pytest.mark.parametrize("cancel_at", ["options", "preview"])
def test_cancel_creates_no_preference_or_audit_even_after_restart(panel, qtbot, monkeypatch, cancel_at):
    widget, _, path = panel
    if cancel_at == "options":
        monkeypatch.setattr(MarkNormalDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    else:
        captured = prepare_dialog(monkeypatch, confirm=False)
    widget.action.click()
    assert widget._pending is None and counts(path) == (0, 0)
    assert service(path).relevant(context(), now=NOW).entries == ()
    if cancel_at == "preview":
        assert "future matching" in captured[0] and "current alert remains unchanged" in captured[0]


def test_save_refresh_revoke_cancel_then_confirm_and_restart(panel, qtbot, monkeypatch):
    widget, _, path = panel
    captured = prepare_dialog(monkeypatch)
    widget.action.click()
    assert not widget.action.isEnabled()
    qtbot.waitUntil(lambda: widget._pending is None and widget.list.count() == 1)
    assert counts(path) == (1, 1)
    assert "ACTIVE" in widget.list.item(0).text() and "permanent" in widget.list.item(0).text()
    assert "<b>Expected behavior</b>" in widget.detail.text()
    assert widget.detail.textFormat() is Qt.TextFormat.PlainText
    assert "Rule:" in captured[0] and "Network:" in captured[0]
    assert widget.revoke.isEnabled()
    monkeypatch.setattr(QMessageBox, "exec", lambda box: QMessageBox.StandardButton.Cancel)
    widget.revoke.click()
    assert counts(path) == (1, 1)
    revoke_text = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: revoke_text.append(box.text()) or QMessageBox.StandardButton.Yes)
    widget.revoke.click()
    qtbot.waitUntil(lambda: widget._pending is None and "REVOKED" in widget.list.item(0).text())
    assert "does not recreate past alerts" in revoke_text[0]
    assert not widget.revoke.isEnabled() and counts(path) == (1, 2)
    assert service(path).relevant(context(), now=NOW).entries[0].preference.revision == 2


def test_preview_a_selection_b_saves_immutable_a(panel, qtbot, monkeypatch):
    widget, _, path = panel
    other = request(app=application(r"c:\other\browser.exe"))

    def options(dialog):
        dialog.reason.setText("Expected")
        dialog.lifetime.setCurrentIndex(2)
        dialog._preview()
        return dialog.result()

    def confirmation(box):
        assert application().key in box.text()
        widget.select(other)
        return QMessageBox.StandardButton.Save

    monkeypatch.setattr(MarkNormalDialog, "exec", options)
    monkeypatch.setattr(QMessageBox, "exec", confirmation)
    widget.action.click()
    qtbot.waitUntil(lambda: widget._pending is None and widget._generation is None)
    assert service(path).relevant(context(), now=NOW).entries[0].preference.definition.selector.application == application()
    assert service(path).relevant(context(app=other.application.identity), now=NOW).entries == ()
    assert widget.list.count() == 0


class Queries(QObject):
    result_ready = pyqtSignal(int, object)
    stopped = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.generation = 0
        self.requests = []
        self.future = Future()
        self.submitted = []

    def request(self, c):
        self.generation += 1
        self.requests.append((self.generation, c))
        return self.generation

    def invalidate(self):
        self.generation += 1

    def submit(self, command):
        self.submitted.append(command)
        return self.future


def test_stale_a_b_a_query_and_pending_command_cannot_overwrite(panel, qtbot):
    widget, real, _ = panel
    real.stop()
    q = Queries()
    w = MarkNormalWidget(q)
    qtbot.addWidget(w)
    w.select(request())
    w.rule.setCurrentIndex(1)
    old = q.requests[-1][0]
    w.select(request(app=application(r"c:\other\browser.exe")))
    w.select(request())
    current = q.requests[-1][0]
    q.result_ready.emit(old, None)
    assert w._generation == current
    q.result_ready.emit(current, PreferencePage(Status.FOUND))
    assert w._generation is None
    w._submit(preview(), w._epoch)
    w.select(request(app=application(r"c:\other\browser.exe")))
    w.select(request())
    message = w.status.text()
    w._submit(preview(), w._epoch)
    assert len(q.submitted) == 1
    q.future.set_result(PreferenceResult(Status.CAPACITY_REACHED))
    w._poll()
    assert w.status.text() == message


@pytest.mark.parametrize("status", [Status.CONFLICT, Status.CAPACITY_REACHED, Status.UNAVAILABLE, Status.INVALID, Status.NO_CHANGE])
def test_safe_failure_messages_refresh_without_raw_exception(qtbot, status):
    q = Queries()
    widget = MarkNormalWidget(q)
    qtbot.addWidget(widget)
    widget.select(request())
    widget.rule.setCurrentIndex(1)
    previous = len(q.requests)
    widget._submit(preview(), widget._epoch)
    q.future.set_result(PreferenceResult(status))
    widget._poll()
    assert len(q.requests) == previous + 1
    assert widget.status.text() and widget.status.textFormat() is Qt.TextFormat.PlainText
    if status is Status.CONFLICT:
        assert "Nothing was overwritten" in widget.status.text()
    q.result_ready.emit(widget._generation, None)
    assert "query unavailable" in widget.status.text()


def test_worker_io_off_gui_and_factory_failure_sanitized(qtbot, tmp_path):
    main = get_ident()
    threads = []
    path = tmp_path / "worker.db"

    class Storage(SQLiteScopedPreferenceRepository):
        def create(self, *args, **kwargs):
            threads.append(get_ident())
            return super().create(*args, **kwargs)

        def find_candidates(self, *args, **kwargs):
            threads.append(get_ident())
            return super().find_candidates(*args, **kwargs)

        def revoke(self, *args, **kwargs):
            threads.append(get_ident())
            return super().revoke(*args, **kwargs)

    def factory():
        threads.append(get_ident())
        return MarkNormalCommandService(ScopedPreferenceService(Storage(SQLiteDatabase(path))))

    q = PreferenceCommandCoordinator(factory, clock=lambda: NOW)
    q.start()
    try:
        f = q.submit(preview())
        qtbot.waitUntil(f.done)
        with qtbot.waitSignal(q.result_ready):
            q.request(context())
        revoke = q.submit(f.result().preference)
        qtbot.waitUntil(revoke.done)
        assert revoke.result().status is Status.REVOKED
        assert threads and all(t != main for t in threads)
    finally:
        q.stop()
    broken = PreferenceCommandCoordinator(lambda: (_ for _ in ()).throw(PermissionError("secret")))
    broken.start()
    try:
        f = broken.submit(preview())
        qtbot.waitUntil(f.done)
        assert f.result().status is Status.UNAVAILABLE
    finally:
        broken.stop()


@pytest.mark.parametrize("operation", ["save", "revoke"])
def test_pending_command_bounded_shutdown_queue_and_closed_widget(qtbot, tmp_path, operation):
    entered, release = Event(), Event()
    original = service(tmp_path / "blocked.db").save(preview(), now=NOW).preference

    class Blocked:
        def save(self, *args, **kwargs):
            entered.set()
            release.wait(timeout=5)
            return PreferenceResult(Status.CREATED)

        revoke = save

    q = PreferenceCommandCoordinator(lambda: Blocked())
    q.start()
    first = q.submit(preview() if operation == "save" else original)
    qtbot.waitUntil(entered.is_set)
    widget = MarkNormalWidget(q)
    qtbot.addWidget(widget)
    widget.close()
    pending = [q.submit(preview()) for _ in range(9)]
    assert pending[-1].result().status is Status.UNAVAILABLE
    try:
        assert not q.stop(timeout=0.01)
        assert all(f.done() for f in pending)
        assert all(f.result().status is Status.UNAVAILABLE for f in pending)
    finally:
        release.set()
        qtbot.waitUntil(first.done)
        assert q.stop()


def test_real_worker_query_coalescing_generation(qtbot):
    entered, release = Event(), Event()
    calls = []

    class Slow:
        def relevant(self, c, **kwargs):
            calls.append(c)
            if len(calls) == 1:
                entered.set()
                release.wait(timeout=5)
            return PreferencePage(Status.FOUND)

    q = PreferenceCommandCoordinator(lambda: Slow())
    received = []
    q.result_ready.connect(lambda generation, page: received.append(generation))
    q.start()
    try:
        q.request(context())
        qtbot.waitUntil(entered.is_set)
        q.request(context(app=application(r"c:\other\browser.exe")))
        latest = q.request(context())
        release.set()
        qtbot.waitUntil(lambda: received == [latest])
        assert len(calls) == 2
    finally:
        release.set()
        q.stop()


def test_keyboard_cancel_and_preview_has_no_write(qtbot, panel):
    _, _, path = panel
    dialog = MarkNormalDialog(context())
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.reason.setFocus()
    qtbot.keyClicks(dialog.reason, "Expected")
    dialog.lifetime.setCurrentIndex(1)

    def cancel_preview():
        modal = dialog.findChild(QMessageBox)
        assert modal is not None and "Expires:" in modal.text()
        assert counts(path) == (0, 0)
        modal.button(QMessageBox.StandardButton.Cancel).click()

    QTimer.singleShot(0, cancel_preview)
    qtbot.mouseClick(dialog.preview_button, Qt.MouseButton.LeftButton)
    assert dialog.preview is None and counts(path) == (0, 0)
    qtbot.keyClick(dialog, Qt.Key.Key_Escape)
    assert dialog.result() == QDialog.DialogCode.Rejected


def test_expired_state_no_reactivation_and_relevant_list_bound(qtbot, tmp_path):
    path = tmp_path / "expired.db"
    repo = SQLiteScopedPreferenceRepository(SQLiteDatabase(path))
    from tests.fixtures.preferences import ORIGIN
    from uuid import uuid4
    expiry = datetime.now(UTC) - timedelta(hours=1)
    p = preview(lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, NOW + timedelta(hours=1)))
    # Keep test time independent from host time: historical valid create, now expired read.
    definition = replace(p.definition, lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expiry))
    for index in range(34):
        repo.create(uuid4(), replace(definition, reason=f"Decision {index}"), ORIGIN, expiry - timedelta(hours=1))
    q = PreferenceCommandCoordinator(lambda: service(path))
    q.start()
    try:
        widget = MarkNormalWidget(q)
        qtbot.addWidget(widget)
        widget.select(request())
        widget.rule.setCurrentIndex(1)
        qtbot.waitUntil(lambda: widget.list.count() == 32)
        assert "EXPIRED" in widget.list.item(0).text() and "additional entries" in widget.status.text()
        assert counts(path) == (34, 34)
    finally:
        q.stop()


def test_desktop_composition_and_shutdown_owns_preference_worker(qtbot, tmp_path):
    shell = create_application(FakeEngine(), argv=[], preference_service_factory=lambda: service(tmp_path / "shell.db"))
    qtbot.addWidget(shell.window)
    assert shell.preference_commands is not None
    shell.lifecycle.start()
    assert shell.preference_commands._thread.is_alive()
    from netsentinel.presentation.views.main_window import PageId
    page = shell.window._pages[PageId.CONNECTIONS]
    assert page.details.baseline.preferences._coordinator is shell.preference_commands
    assert shell.lifecycle.shutdown()
    assert not shell.preference_commands._thread.is_alive()


@pytest.mark.parametrize("state", ["permanent", "timed", "expired", "revoked"])
def test_restarted_ui_reads_persisted_status_and_exact_expiry(qtbot, tmp_path, state):
    path = tmp_path / "restart.db"
    now = datetime.now(UTC)
    expires = now + timedelta(hours=24) if state == "timed" else now - timedelta(minutes=1)
    lifetime = (PreferenceLifetime(PreferenceLifetimeKind.PERMANENT) if state in ("permanent", "revoked") else
                PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expires))
    p = preview()
    definition = replace(p.definition, lifetime=lifetime)
    old = SQLiteScopedPreferenceRepository(SQLiteDatabase(path))
    from tests.fixtures.preferences import ORIGIN
    saved = old.create(p.preference_id, definition, ORIGIN, now - timedelta(hours=2)).preference
    if state == "revoked":
        old.revoke(saved.preference_id, saved.revision, "Undo", ORIGIN, now)
    q = PreferenceCommandCoordinator(lambda: service(path))
    q.start()
    try:
        w = MarkNormalWidget(q)
        qtbot.addWidget(w)
        w.select(request())
        w.rule.setCurrentIndex(1)
        qtbot.waitUntil(lambda: w.list.count() == 1)
        item = w.list.item(0)
        pref = item.data(Qt.ItemDataRole.UserRole)
        assert pref.definition.lifetime.expires_at == lifetime.expires_at
        assert (state.upper() if state in ("expired", "revoked") else "ACTIVE") in item.text()
        assert counts(path) == (1, 2 if state == "revoked" else 1)
    finally:
        q.stop()
