"""Offscreen NS-094 exact navigation, threading, settings and Qt adapter seam."""

from datetime import timedelta
from threading import Thread, current_thread
from uuid import UUID

import pytest
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QSystemTrayIcon

from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.notifications import (
    DesktopNotificationRequest, PersistedNotificationIntent, NotificationDeliveryOutcome as Outcome,
    preview_body,
)
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.risk_scoring import RiskSeverity
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.presentation.app import create_application
from netsentinel.presentation.notifications import QtDesktopNotificationSink
from netsentinel.presentation.views.main_window import PageId
from netsentinel.shared.config import AppConfig, WindowCloseBehavior, load_config_file, save_config_file
from tests.fixtures.notifications import FakeNotificationSink, NOW, candidate
from tests.gui._ns013_support import FakeEngine
from tests.gui.test_tray_lifecycle import FakeTray


def compose(qtbot, tmp_path, *, tray_available=True, enabled=True):
    engine, sink, tray = FakeEngine(), FakeNotificationSink(), FakeTray(tray_available)
    db = SQLiteDatabase(tmp_path / "notifications.db")
    repo = SQLiteAlertRepository(db)
    service = AlertService(repo, clock=lambda: NOW + timedelta(days=1), dispatcher=engine.dispatcher)
    path = tmp_path / "config.json"
    config = AppConfig(desktop_notifications_enabled=enabled, window_close_behavior=WindowCloseBehavior.HIDE_TO_TRAY)
    save_config_file(path, config)
    shell = create_application(engine, argv=[], notification_sink=sink, tray_adapter=tray,
        config=config, config_path=path,
        alert_service_factory=lambda: AlertQueryService(AlertService(SQLiteAlertRepository(db), dispatcher=engine.dispatcher)))
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    shell.window.show()
    return shell, engine, sink, tray, db, repo, service, path


@pytest.mark.parametrize("visibility", ["visible", "hidden", "minimized"])
def test_click_restores_exact_alert_and_never_mutates(qtbot, tmp_path, visibility):
    shell, engine, sink, tray, db, repo, service, _ = compose(qtbot, tmp_path)
    try:
        first, _ = service.record(candidate())
        shell.notifications.drain()
        assert len(sink.requests) == 1
        if visibility == "hidden":
            tray.hide()
            assert not shell.window.isVisible()
        elif visibility == "minimized":
            shell.window.showMinimized()
            assert shell.window.isMinimized()
        before = repo.get(first.id)
        sink.click()
        view = shell.window.page_widget(PageId.ALERTS)
        qtbot.waitUntil(lambda: view.selected_alert_id == first.id)
        assert shell.window.isVisible() and not shell.window.isMinimized()
        assert shell.window.current_page is PageId.ALERTS
        assert view.details.values["severity"].text() == "low"
        assert repo.get(first.id) == before  # No ACK/resolve/count/reassessment.
        assert engine.start_calls == 1 and engine.stop_calls == 0
        assert shell.notifications.service.diagnostics().navigation_success == 1
        with db.connection() as connection:
            assert connection.execute("SELECT count(*) FROM risk_assessments").fetchone()[0] == 0
    finally:
        shell.controller.shutdown()


def test_A_then_B_then_delayed_A_click_selects_A_after_B(qtbot, tmp_path):
    shell, _, sink, _, _, _, service, _ = compose(qtbot, tmp_path)
    try:
        a, _ = service.record(candidate(1))
        shell.notifications.drain()
        b, _ = service.record(candidate(2, severity="high"))
        shell.notifications.drain()
        sink.click(1)
        view = shell.window.page_widget(PageId.ALERTS)
        qtbot.waitUntil(lambda: view.selected_alert_id == b.id)
        sink.click(0)
        qtbot.waitUntil(lambda: view.selected_alert_id == a.id)
        assert view.model.alerts == (a,) and view.details.values["severity"].text() == "low"
    finally:
        shell.controller.shutdown()


def test_other_page_and_all_filters_revealed_by_exact_ID(qtbot, tmp_path):
    shell, _, sink, _, _, repo, service, _ = compose(qtbot, tmp_path, enabled=False)
    try:
        old, _ = service.record(candidate(1))
        for index in range(2, 122):
            service.record(candidate(index, seconds=index, severity="high"))
        view = shell.window.page_widget(PageId.ALERTS)
        shell.window.navigate_to(PageId.ALERTS)
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() == 50)
        assert view.model.row_for_id(old.id) is None
        view.severity_filter.setCurrentIndex(view.severity_filter.findData("high"))
        view.status_filter.setCurrentIndex(view.status_filter.findData(AlertStatus.RESOLVED))
        qtbot.waitUntil(lambda: not view._loading)
        shell.notifications.save_enabled(True)
        # Synthetic test event represents a fresh committed eligible intent.
        shell.notifications.service.enqueue(PersistedNotificationIntent.from_alert(old, None, eligible=True))
        shell.notifications.drain()
        sink.click()
        qtbot.waitUntil(lambda: view.selected_alert_id == old.id)
        assert view.model.rowCount() == 1 and not view._filters_active()
        assert repo.get(old.id) == old
        assert not view.next_button.isEnabled()
    finally:
        shell.controller.shutdown()


def test_deleted_target_safe_and_no_wrong_selection(qtbot, tmp_path):
    shell, _, sink, _, db, _, service, _ = compose(qtbot, tmp_path)
    try:
        a, _ = service.record(candidate(1))
        shell.notifications.drain()
        service.record(candidate(2))
        with db.connection() as connection:
            connection.execute("DELETE FROM alerts WHERE id = ?", (str(a.id),))
            connection.commit()
        sink.click()
        view = shell.window.page_widget(PageId.ALERTS)
        qtbot.waitUntil(lambda: not view._loading)
        assert view.selected_alert_id is None and view.model.rowCount() == 0
        assert view.state_label.text() == "Alert is no longer available."
        assert shell.notifications.service.diagnostics().navigation_failure == 1
    finally:
        shell.controller.shutdown()


def test_producer_thread_never_calls_sink_and_shutdown_cancels(qtbot, tmp_path):
    shell, _, sink, _, _, _, service, _ = compose(qtbot, tmp_path)
    threads = []
    sink.on_submit = lambda request: threads.append(current_thread())
    worker = Thread(target=lambda: service.record(candidate()))
    worker.start()
    worker.join(2)
    assert not worker.is_alive() and sink.attempts == 0
    shell.notifications.drain()
    assert threads == [current_thread()]
    service.record(candidate(2))
    callback = sink.handler
    shell.controller.shutdown()
    callback(sink.requests[0].alert_id)  # Late callback must remain harmless.
    shell.notifications.drain()
    assert sink.attempts == 1 and shell.notifications.service.sizes == (0, 0)


def test_unavailable_tray_independent_fake_sink_and_hide_show_no_duplicates(qtbot, tmp_path):
    shell, engine, sink, _, _, _, service, _ = compose(qtbot, tmp_path, tray_available=False)
    try:
        assert not shell.controller.tray_available
        service.record(candidate())
        shell.notifications.drain()
        for _ in range(10):
            shell.controller.show_window()
            shell.notifications.drain()
        assert sink.attempts == 1 and engine.start_calls == 1
    finally:
        shell.controller.shutdown()


def test_settings_cancel_save_atomic_and_other_preference_preserved(qtbot, tmp_path):
    shell, _, sink, _, _, _, _, path = compose(qtbot, tmp_path, enabled=False)
    try:
        shell.window.notification_settings_action.trigger()
        dialog = shell.notifications.settings_dialog
        dialog.enabled.setChecked(True)
        dialog.reject()
        assert not load_config_file(path).config.desktop_notifications_enabled
        assert not shell.notifications.service.enabled
        shell.notifications.show_settings()
        dialog = shell.notifications.settings_dialog
        dialog.enabled.setChecked(True)
        dialog._save()
        saved = load_config_file(path).config
        assert saved.desktop_notifications_enabled and shell.notifications.service.enabled
        assert saved.window_close_behavior is WindowCloseBehavior.HIDE_TO_TRAY
        assert sink.attempts == 0
    finally:
        shell.controller.shutdown()


def test_settings_save_failure_no_runtime_write(qtbot, tmp_path):
    shell, _, _, _, _, _, _, _ = compose(qtbot, tmp_path, enabled=False)
    try:
        def fail(enabled):
            raise OSError("private config path")
        shell.notifications._save_preference = fail
        shell.notifications.show_settings()
        dialog = shell.notifications.settings_dialog
        dialog.enabled.setChecked(True)
        dialog._save()
        assert not shell.notifications.service.enabled and dialog.isVisible()
        assert "private" not in dialog.error.text()
    finally:
        shell.controller.shutdown()


class FakeIcon(QObject):
    messageClicked = pyqtSignal()
    MessageIcon = QSystemTrayIcon.MessageIcon
    available = True
    messages = True
    failure = False
    instances = []

    def __init__(self, icon, parent):
        super().__init__(parent)
        self.visible = False
        self.requests = []
        type(self).instances.append(self)

    @staticmethod
    def isSystemTrayAvailable():
        return FakeIcon.available

    @staticmethod
    def supportsMessages():
        return FakeIcon.messages

    def setToolTip(self, text):
        self.tooltip = text

    def show(self):
        self.visible = True

    def hide(self):
        self.visible = False

    def showMessage(self, *args):
        if self.failure:
            raise RuntimeError("private platform error")
        self.requests.append(args)


@pytest.fixture
def adapter(qtbot, qapp, monkeypatch):
    from netsentinel.presentation import notifications
    from PyQt6.QtWidgets import QMainWindow
    FakeIcon.instances = []
    FakeIcon.available = FakeIcon.messages = True
    FakeIcon.failure = False
    monkeypatch.setattr(notifications, "QSystemTrayIcon", FakeIcon)
    window = QMainWindow()
    qtbot.addWidget(window)
    sink = QtDesktopNotificationSink(qapp, window)
    yield sink
    sink.close()


def request(index=1, severity=RiskSeverity.HIGH):
    return DesktopNotificationRequest(UUID(int=index), severity, "NetSentinel security alert", preview_body(severity))


def test_Qt_zero_startup_mapping_AB_stable_callbacks_expiry_and_quit(adapter, monkeypatch):
    assert FakeIcon.instances == [] and not adapter._timer.isActive()
    clicked = []
    adapter.set_click_handler(clicked.append)
    assert adapter.submit(request(1)) is Outcome.SUBMITTED_TO_SINK
    assert adapter.submit(request(2, RiskSeverity.LOW)) is Outcome.SUBMITTED_TO_SINK
    a, b = FakeIcon.instances
    assert a.requests[0] == (request(1).title, request(1).body, QSystemTrayIcon.MessageIcon.Critical, 10000)
    assert b.requests[0][2] == QSystemTrayIcon.MessageIcon.Warning
    b.messageClicked.emit()
    a.messageClicked.emit()
    assert clicked == [UUID(int=2), UUID(int=1)]
    from netsentinel.presentation import notifications
    monkeypatch.setattr(notifications, "monotonic", lambda: 10**20)
    adapter._expire()
    adapter._click(a)
    assert len(clicked) == 2 and not adapter._handles
    adapter.close()
    adapter._click(b)
    assert len(clicked) == 2


@pytest.mark.parametrize("unavailable", ["tray", "messages", "exception"])
def test_Qt_unavailable_and_failure_typed(adapter, unavailable):
    if unavailable == "tray":
        FakeIcon.available = False
    elif unavailable == "messages":
        FakeIcon.messages = False
    else:
        FakeIcon.failure = True
    result = adapter.submit(request())
    assert result is (Outcome.SINK_FAILED if unavailable == "exception" else Outcome.SINK_UNAVAILABLE)
    assert not adapter._handles


def test_Qt_handle_hard_bound_and_no_ID_reuse(adapter):
    for index in range(8):
        assert adapter.submit(request(index + 1)) is Outcome.SUBMITTED_TO_SINK
    assert adapter.submit(request(99)) is Outcome.SINK_UNAVAILABLE
    assert len(adapter._handles) == 8 and len(FakeIcon.instances) == 8


def test_Qt_rejects_producer_thread(adapter):
    failures = []
    def attempt():
        try:
            adapter.submit(request())
        except RuntimeError:
            failures.append(True)
    thread = Thread(target=attempt)
    thread.start()
    thread.join(2)
    assert failures == [True] and not FakeIcon.instances


def test_startup_existing_records_zero_notifications_and_future_only(qtbot, tmp_path):
    db = SQLiteDatabase(tmp_path / "notifications.db")
    service = AlertService(SQLiteAlertRepository(db), clock=lambda: NOW)
    for index in range(10):
        service.record(candidate(index))
    shell, _, sink, _, _, _, future, _ = compose(qtbot, tmp_path)
    try:
        shell.notifications.drain()
        assert sink.attempts == 0
        future.record(candidate(99))
        shell.notifications.drain()
        assert sink.attempts == 1
    finally:
        shell.controller.shutdown()


def test_rapid_AB_queries_only_latest_target_survives(qtbot, tmp_path):
    shell, _, sink, _, _, _, service, _ = compose(qtbot, tmp_path)
    try:
        a, _ = service.record(candidate(1))
        shell.notifications.drain()
        b, _ = service.record(candidate(2))
        shell.notifications.drain()
        sink.click(0)
        sink.click(1)
        view = shell.window.page_widget(PageId.ALERTS)
        qtbot.waitUntil(lambda: view.selected_alert_id == b.id)
        assert view.model.row_for_id(a.id) is None
    finally:
        shell.controller.shutdown()


def test_risk_alert_notification_click_reads_exact_assessment_no_TI_or_mutation(qtbot, tmp_path):
    from tests.integration.test_risk_alert_pipeline import Harness
    shell, engine, sink, tray, _, repo, _, _ = compose(qtbot, tmp_path)
    try:
        harness = Harness(tmp_path / "notifications.db")
        harness.service._dispatcher = engine.dispatcher
        result = harness.process()
        before = repo.get(result.alert.id)
        shell.notifications.drain()
        tray.hide()
        sink.click()
        view = shell.window.page_widget(PageId.ALERTS)
        qtbot.waitUntil(lambda: view.selected_alert_id == result.alert.id)
        assert view.details.tabs.isTabVisible(1)
        assert repo.get(result.alert.id) == before
        assert harness.assessments.latest(result.assessment.revision.key.assessment_id).revision == result.assessment.revision
        assert engine.start_calls == 1
    finally:
        shell.controller.shutdown()
