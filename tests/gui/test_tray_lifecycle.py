"""NS-093 fake tray, offscreen shell, real hidden pipeline and Qt quit tests."""

from pathlib import Path
from dataclasses import replace
from datetime import UTC, datetime
from subprocess import run
import sys
from threading import Event
from time import monotonic

import pytest
from PyQt6 import sip
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QDialog, QSystemTrayIcon

from netsentinel.presentation.app import create_application
from netsentinel.presentation.history_query import HistoryQueryCoordinator
from netsentinel.presentation.tray import QtTrayAdapter
from netsentinel.presentation.views.main_window import PageId
from netsentinel.shared.config import (
    AppConfig, WindowCloseBehavior as Close, load_config_file, save_config_file,
)
from tests.gui._ns013_support import FakeEngine
from tests.fixtures.incident_acceptance import Story, deny_network


class FakeTray:
    def __init__(self, available=True, fail=False):
        self.capability = available
        self.fail = fail
        self.visible = False
        self.start_calls = 0
        self.cleanup_calls = 0

    def available(self):
        return self.capability

    def start(self, show, hide, quit_application):
        self.start_calls += 1
        self.show, self.hide, self.quit = show, hide, quit_application
        self.visible = self.capability
        if self.fail:
            raise RuntimeError("sensitive initialization detail")
        return self.capability

    def cleanup(self):
        self.cleanup_calls += 1
        self.visible = False

    def activate(self):
        self.show()


def compose(qtbot, *, available=True, fail=False, behavior=Close.HIDE_TO_TRAY, path=None, **kwargs):
    engine, tray = FakeEngine(), FakeTray(available, fail)
    shell = create_application(engine, argv=[], tray_adapter=tray,
        config=AppConfig(window_close_behavior=behavior), config_path=path, **kwargs)
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    shell.window.show()
    return shell, engine, tray


def test_hide_show_and_close_restore_100_cycles_preserve_objects_and_monitoring(qtbot):
    shell, engine, tray = compose(qtbot)
    controller = shell.controller
    pages = tuple(shell.window.page_widget(page) for page in PageId)
    try:
        assert not shell.application.quitOnLastWindowClosed()
        for _ in range(100):
            tray.hide()
            assert not shell.window.isVisible() and tray.visible
            tray.show()
            assert shell.window.isVisible()
            shell.window.close()
            assert not shell.window.isVisible() and not sip.isdeleted(shell.window)
            assert not shell.window._close_notified
            tray.activate()
            assert shell.window.isVisible()
        assert engine.running and engine.start_calls == 1 and engine.stop_calls == 0
        assert shell.bridge.attached and not shell.lifecycle.shutdown_requested
        assert tray.start_calls == 1 and tray.cleanup_calls == 0
        assert pages == tuple(shell.window.page_widget(page) for page in PageId)
        for page in (PageId.CONNECTIONS, PageId.ALERTS, PageId.INCIDENTS):
            shell.window.navigate_to(page)
            assert shell.window.current_page is page
    finally:
        controller.shutdown()
    assert tray.cleanup_calls == 1 and not tray.visible and engine.stop_calls == 1


@pytest.mark.parametrize("available,fail", [(False, False), (True, True)])
def test_unavailable_or_partial_init_failure_never_hides_and_x_quits(qtbot, available, fail):
    shell, engine, tray = compose(qtbot, available=available, fail=fail)
    assert shell.controller.effective_close_behavior is Close.QUIT_APPLICATION
    assert shell.controller.behavior is Close.HIDE_TO_TRAY
    assert shell.application.quitOnLastWindowClosed()
    tray.hide()
    assert shell.window.isVisible() and engine.running
    assert shell.controller.tray_status == ("initialization_failed" if fail else "unavailable")
    shell.window.close()
    assert shell.controller.quitting and not shell.window.isVisible()
    assert engine.stop_calls == 1 and not tray.visible
    shell.application.aboutToQuit.emit()
    assert engine.stop_calls == 1


@pytest.mark.parametrize("source", ["tray", "file", "about_to_quit", "window"])
def test_all_quit_paths_stop_once_and_reentry_cannot_hide_or_show(qtbot, monkeypatch, source):
    quit_calls = []
    monkeypatch.setattr(QApplication, "quit", lambda self: quit_calls.append(True))
    shell, engine, tray = compose(qtbot, behavior=Close.QUIT_APPLICATION if source == "window" else Close.HIDE_TO_TRAY)
    if source == "tray":
        tray.quit()
    elif source == "file":
        shell.window.quit_action.trigger()
    elif source == "about_to_quit":
        shell.application.aboutToQuit.emit()
    else:
        shell.window.close()
    assert shell.controller.quitting and engine.stop_calls == 1
    tray.quit()
    shell.window.close()
    tray.show()
    tray.hide()
    shell.application.aboutToQuit.emit()
    shell.controller.shutdown()
    assert not shell.window.isVisible()
    assert engine.stop_calls == 1 and engine.start_calls == 1
    assert tray.cleanup_calls == 1
    assert shell.lifecycle.start() is False  # shutdown is terminal for this shell
    if source in ("tray", "file"):
        assert quit_calls == [True]


def test_capability_loss_restores_hidden_window_and_keeps_saved_choice(qtbot):
    shell, engine, tray = compose(qtbot)
    tray.hide()
    tray.capability = False
    qtbot.waitUntil(shell.window.isVisible, timeout=2500)
    assert shell.controller.behavior is Close.HIDE_TO_TRAY
    assert shell.controller.effective_close_behavior is Close.QUIT_APPLICATION
    assert shell.application.quitOnLastWindowClosed()
    assert engine.stop_calls == 0
    shell.window.close()
    assert engine.stop_calls == 1


def test_show_restores_minimized_maximized_state_without_geometry_reset(qtbot):
    shell, engine, tray = compose(qtbot)
    try:
        shell.window.setWindowState(Qt.WindowState.WindowMaximized | Qt.WindowState.WindowMinimized)
        tray.hide()
        tray.show()
        assert not shell.window.isMinimized() and shell.window.isMaximized()
        assert engine.start_calls == 1
    finally:
        shell.controller.shutdown()


def test_settings_cancel_save_restart_and_preserve_other_preferences(qtbot, tmp_path):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig())
    shell, engine, tray = compose(qtbot, behavior=Close.QUIT_APPLICATION, path=path)
    try:
        original = path.read_bytes()
        shell.window.application_behavior_action.trigger()
        dialog = shell.controller.settings_dialog
        assert dialog.close_behavior.accessibleName()
        dialog.close_behavior.setCurrentIndex(1)
        dialog.reject()
        assert path.read_bytes() == original and shell.controller.behavior is Close.QUIT_APPLICATION
        # Another settings surface/onboarding Save between opening and saving.
        save_config_file(path, AppConfig(onboarding_completed=True, polling_interval=2))
        shell.controller.show_settings()
        dialog = shell.controller.settings_dialog
        dialog.close_behavior.setCurrentIndex(1)
        dialog._save()
        assert dialog.result() == QDialog.DialogCode.Accepted
        assert shell.controller.behavior is Close.HIDE_TO_TRAY
        config = load_config_file(path).config
        assert config.window_close_behavior is Close.HIDE_TO_TRAY
        assert config.onboarding_completed and config.polling_interval == 2
        shell.window.close()
        assert engine.stop_calls == 0
    finally:
        shell.controller.shutdown()
    restarted = create_application(FakeEngine(), argv=[], tray_adapter=FakeTray(), config=load_config_file(path).config)
    qtbot.addWidget(restarted.window)
    assert restarted.controller.behavior is Close.HIDE_TO_TRAY
    assert not restarted.window.isVisible()  # composition has no startup side effects
    restarted.controller.shutdown()


def test_settings_unavailable_disables_hide_without_rewriting_stored_choice(qtbot, tmp_path):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(window_close_behavior=Close.HIDE_TO_TRAY))
    shell, _, _ = compose(qtbot, available=False, path=path)
    try:
        before = path.read_bytes()
        shell.controller.show_settings()
        dialog = shell.controller.settings_dialog
        assert not dialog.close_behavior.model().item(1).isEnabled()
        assert "System tray unavailable" in dialog.explanation.text()
        assert dialog.close_behavior.currentData() is Close.HIDE_TO_TRAY
        dialog.reject()
        assert path.read_bytes() == before
    finally:
        shell.controller.shutdown()


def test_settings_failed_save_does_not_apply_runtime_preference(qtbot, monkeypatch, tmp_path):
    shell, _, _ = compose(qtbot, behavior=Close.QUIT_APPLICATION, path=tmp_path / "config.json")
    def fail(*args):
        raise OSError("sensitive path")
    monkeypatch.setattr("netsentinel.presentation.app.save_window_close_behavior", fail)
    try:
        shell.controller.show_settings()
        dialog = shell.controller.settings_dialog
        dialog.close_behavior.setCurrentIndex(1)
        dialog._save()
        assert dialog.isVisible() and "could not be saved" in dialog.error.text()
        assert "sensitive" not in dialog.error.text()
        assert shell.controller.behavior is Close.QUIT_APPLICATION
    finally:
        shell.controller.shutdown()


def test_real_connection_risk_alert_incident_pipeline_processes_while_hidden(qtbot, tmp_path, monkeypatch):
    deny_network(monkeypatch)
    story = Story(tmp_path / "hidden.db")
    shell, engine, tray = compose(qtbot, incident_service_factory=lambda: story.query)
    try:
        tray.hide()
        # Existing real baseline/risk workers, AlertService, incident persistence,
        # and SQLite adapters produce their full story while MainWindow is hidden.
        story.build()
        engine.dispatcher.publish(story.event)
        qtbot.waitUntil(lambda: shell.window.connections_model.rowCount() == 1)
        assert not shell.window.isVisible() and engine.stop_calls == 0
        assert story.result.alert is not None and story.record is not None
        shell.window.navigate_to(PageId.INCIDENTS)
        view = shell.window.page_widget(PageId.INCIDENTS)
        view.refresh()
        qtbot.waitUntil(lambda: view.model.rowCount() == 2)
        view.select_incident(story.record.incident_id)
        qtbot.waitUntil(lambda: not view._detail_loading)
        assert view.timeline_model.rowCount() > 0
        tray.show()
        assert shell.window.connections_model.rowCount() == 1
        assert engine.start_calls == 1
    finally:
        shell.controller.shutdown()


def test_startup_policy_visible_and_engine_starts_once_before_first_frame(qapp, monkeypatch):
    from netsentinel.presentation.app import run_application
    engine = FakeEngine()
    seen = []
    def inspect(application):
        from netsentinel.presentation.views.main_window import MainWindow
        windows = [w for w in application.topLevelWidgets() if isinstance(w, MainWindow) and w.isVisible()]
        assert len(windows) == 1
        assert not windows[0].isMinimized()
        assert engine.running and engine.start_calls == 1
        seen.append(True)
        windows[0].close()
        return 0
    monkeypatch.setattr(QApplication, "exec", inspect)
    assert run_application(argv=[], engine=engine) == 0
    assert seen == [True] and engine.stop_calls == 1


def test_shutdown_preserves_component_order_and_attempts_all_after_timeout(qtbot):
    shell, engine, tray = compose(qtbot)
    order = []
    class Stop:
        def __init__(self, name): self.name = name
        def stop(self):
            order.append(self.name)
            return self.name != "incident-list"  # degraded, still stop every owner
    lifecycle = shell.lifecycle
    attributes = (
        ("_threat_intel_lookup", "ti-lookup"), ("_threat_intel", "ti"),
        ("_incident_risk_queries", "incident-risk"), ("_preference_commands", "preferences"),
        ("_baseline_queries", "baseline"), ("_history_queries", "history"),
        ("_signer_service", "signer"), ("_alert_queries", "alerts"),
        ("_dns_queries", "dns"), ("_device_inventory", "devices"),
        ("_device_profiles", "profiles"), ("_capability_queries", "capabilities"),
    )
    for attribute, name in attributes:
        setattr(lifecycle, attribute, Stop(name))
    lifecycle._incident_queries = (Stop("incident-list"), Stop("incident-detail"))
    lifecycle._risk_queries = (Stop("risk-connection"), Stop("risk-alert"))
    lifecycle._destination_queries = (Stop("destination-connection"), Stop("destination-history"))
    lifecycle._bridge = Stop("bridge")
    original_stop = engine.stop
    def stop_engine():
        order.append("engine")
        return original_stop()
    engine.stop = stop_engine
    tray.quit()
    shell.application.aboutToQuit.emit()
    assert lifecycle.shutdown() is False
    assert order == ["ti-lookup", "ti", "incident-list", "incident-detail", "incident-risk",
        "risk-connection", "risk-alert", "preferences", "baseline", "history",
        "destination-connection", "destination-history", "signer", "alerts", "dns",
        "devices", "profiles", "capabilities", "bridge", "engine"]
    assert engine.stop_calls == 1
    # The real bridge was attached before replacing the lifecycle spy.
    shell.bridge.stop()


def test_quit_with_blocked_query_is_bounded_and_result_remains_degraded(qtbot):
    entered, release = Event(), Event()
    class Blocked:
        def query(self, *args, **kwargs):
            entered.set()
            release.wait(5)
    shell, engine, tray = compose(qtbot)
    from netsentinel.application.services.history_query import ConnectionHistoryQueryService
    query = HistoryQueryCoordinator(lambda: ConnectionHistoryQueryService(Blocked()), shutdown_timeout=.05)
    shell.lifecycle._history_queries = query
    from netsentinel.application.ports import ConnectionHistoryQuery
    query.start()
    query.request(ConnectionHistoryQuery(limit=25))
    assert entered.wait(2)
    try:
        begin = monotonic()
        tray.quit()
        assert monotonic() - begin < 1
        assert shell.lifecycle.shutdown() is False
        assert engine.stop_calls == 1 and not tray.visible
    finally:
        release.set()
        assert query.stop(2)


def test_real_polling_and_sqlite_writer_continue_after_hide(qtbot, tmp_path, monkeypatch):
    import netsentinel.bootstrap as bootstrap
    from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
    from netsentinel.infrastructure.sqlite.repositories import SQLiteConnectionHistoryRepository
    from netsentinel.application.ports import ConnectionHistoryQuery
    from tests.gui._ns013_support import snapshot
    from tests.unit.application.test_engine import PassthroughEnricher
    deny_network(monkeypatch)
    admitted, polled = Event(), Event()
    class Collector:
        def collect(self):
            if admitted.is_set():
                polled.set()
                return (replace(snapshot(), observed_at=datetime.now(UTC)),)
            return ()
    class Contexts:
        def get_contexts(self): return ()
    monkeypatch.setattr(bootstrap, "PsutilConnectionCollector", Collector)
    monkeypatch.setattr(bootstrap, "ProcessMetadataEnricher", lambda _: PassthroughEnricher())
    monkeypatch.setattr(bootstrap, "create_network_context_provider", Contexts)
    path = tmp_path / "poll.db"
    engine = bootstrap.create_desktop_engine(database_path=path, config=AppConfig(polling_interval=.05))
    tray = FakeTray()
    shell = create_application(engine, argv=[], tray_adapter=tray,
        config=AppConfig(window_close_behavior=Close.HIDE_TO_TRAY))
    qtbot.addWidget(shell.window)
    try:
        shell.lifecycle.start()
        shell.window.show()
        tray.hide()
        admitted.set()
        assert polled.wait(3)
        qtbot.waitUntil(lambda: engine.persistence_health_snapshot().counters.persisted_events >= 1, timeout=5000)
        qtbot.waitUntil(lambda: shell.window.connections_model.rowCount() == 1)
        assert not shell.window.isVisible() and shell.bridge.attached
        rows = SQLiteConnectionHistoryRepository(SQLiteDatabase(path)).query(ConnectionHistoryQuery(limit=10))
        assert len(rows) == 1 and rows[0].snapshot.local_endpoint == snapshot().local_endpoint
        tray.show()
        assert shell.window.connections_model.rowCount() == 1
        with SQLiteDatabase(path).connection() as conn:
            assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
    finally:
        assert shell.controller.shutdown()


def test_fatal_engine_start_uses_one_rollback_then_final_cleanup(qtbot):
    engine, tray = FakeEngine(), FakeTray()
    shell = create_application(engine, argv=[], tray_adapter=tray)
    qtbot.addWidget(shell.window)
    calls = []
    class Query:
        def start(self): calls.append("start")
        def stop(self):
            calls.append("stop")
            return True
    shell.lifecycle._history_queries = Query()
    def fail(): raise RuntimeError("startup failed")
    engine.start = fail
    with pytest.raises(RuntimeError):
        shell.lifecycle.start()
    shell.controller.shutdown()
    assert calls == ["start", "stop"] and engine.stop_calls == 1
    assert not tray.visible and not shell.bridge.attached


def test_hide_show_never_requests_optional_reputation(qtbot, monkeypatch):
    from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupScheduler
    from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
    from tests.fixtures.threat_intelligence import DESCRIPTORS, grant
    from tests.unit.application.test_threat_intel_scheduler import Provider, Cache
    deny_network(monkeypatch)
    consent = grant()
    service = ThreatIntelConsentService(DESCRIPTORS, lambda: (consent,), lambda _: None)
    service.current()
    provider = Provider()
    scheduler = ThreatIntelLookupScheduler((provider,), service.snapshot, lambda: Cache())
    shell, engine, tray = compose(qtbot, threat_intel_scheduler=scheduler, threat_intel_consent_service=service)
    try:
        for _ in range(100):
            tray.hide()
            shell.window.close()
            tray.show()
        assert provider.calls == [] and engine.stop_calls == 0
    finally:
        shell.controller.shutdown()


def test_real_slow_engine_quit_retains_timeout_diagnostic(qtbot):
    from netsentinel.application.engine import MonitoringEngine
    from netsentinel.application.services.connections import ConnectionTrackingService
    from netsentinel.shared.diagnostics import DiagnosticCode
    from tests.unit.application.test_engine import PassthroughEnricher
    entered, release = Event(), Event()
    class Collector:
        def collect(self):
            entered.set()
            release.wait(5)
            return ()
    engine = MonitoringEngine(collector=Collector(), enricher=PassthroughEnricher(),
        tracker=ConnectionTrackingService(), shutdown_timeout=.05)
    tray = FakeTray()
    shell = create_application(engine, argv=[], tray_adapter=tray)
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    assert entered.wait(2)
    try:
        begin = monotonic()
        tray.quit()
        assert monotonic() - begin < 1
        assert shell.lifecycle.shutdown() is False
        assert engine.health_snapshot().last_error.code is DiagnosticCode.SHUTDOWN_TIMEOUT
        assert not tray.visible
    finally:
        release.set()
        qtbot.waitUntil(lambda: not engine.health_snapshot().worker_alive)


def test_missing_packaged_icon_uses_small_qt_fallback(qtbot, monkeypatch, tmp_path):
    monkeypatch.setattr("netsentinel.presentation.app.resources.files", lambda _: tmp_path)
    shell = create_application(FakeEngine(), argv=[], tray_adapter=FakeTray(False))
    qtbot.addWidget(shell.window)
    assert not shell.application.windowIcon().isNull()
    shell.controller.shutdown()


def test_tray_scope_has_no_notification_autostart_service_or_elevation_integration():
    import ast
    root = Path(__file__).resolve().parents[2] / "src/netsentinel/presentation"
    for filename in ("tray.py", "widgets/application_behavior.py"):
        tree = ast.parse((root / filename).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"showMessage", "ShellExecuteW", "CreateServiceW", "OpenSCManagerW"}
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] not in {"winreg", "subprocess", "socket", "scapy"}
                           for alias in node.names)


def test_qt_adapter_actions_activation_tooltip_cleanup_without_native_shell(qtbot, qapp, monkeypatch):
    monkeypatch.setattr(QSystemTrayIcon, "isSystemTrayAvailable", lambda: True)
    from netsentinel.presentation.views.main_window import MainWindow
    window = MainWindow()
    qtbot.addWidget(window)
    # Use the packaged icon via normal shell composition.
    shell = create_application(FakeEngine(), argv=[], tray_adapter=FakeTray(False))
    qtbot.addWidget(shell.window)
    adapter = QtTrayAdapter(qapp, window)
    monkeypatch.setattr(QSystemTrayIcon, "show", lambda self: self.setProperty("fakeVisible", True))
    monkeypatch.setattr(QSystemTrayIcon, "isVisible", lambda self: bool(self.property("fakeVisible")))
    calls = []
    try:
        assert adapter.start(lambda: calls.append("show"), lambda: calls.append("hide"), lambda: calls.append("quit"))
        icon, menu = adapter.icon, adapter.menu
        assert icon.toolTip() == "NetSentinel" and not icon.icon().isNull()
        assert [a.text() for a in menu.actions()] == ["Show NetSentinel", "Hide NetSentinel", "Quit"]
        for action in menu.actions():
            action.trigger()
        for reason in QSystemTrayIcon.ActivationReason:
            icon.activated.emit(reason)
        assert calls == ["show", "hide", "quit", "show", "show"]
        assert adapter.start(lambda: None, lambda: None, lambda: None)
        assert adapter.icon is icon and adapter.menu is menu
        adapter.cleanup()
        qtbot.waitUntil(lambda: sip.isdeleted(icon))
        assert sip.isdeleted(menu) and adapter.icon is None and adapter.menu is None
    finally:
        adapter.cleanup()
        shell.controller.shutdown()


@pytest.mark.parametrize("source", ["external", "tray", "window", "file"])
def test_real_qt_event_loop_quit_exits_with_hide_policy_and_once(source):
    # Separate process: quitting the session-wide pytest QApplication prevents
    # later Qt tests from pumping queued events. This also verifies process exit.
    code = '''
from PyQt6.QtCore import QTimer
from netsentinel.presentation.app import create_application
from netsentinel.shared.config import AppConfig, WindowCloseBehavior as Close
from tests.gui._ns013_support import FakeEngine
from tests.gui.test_tray_lifecycle import FakeTray
engine, tray = FakeEngine(), FakeTray()
shell = create_application(engine, argv=[], tray_adapter=tray,
    config=AppConfig(window_close_behavior=Close.HIDE_TO_TRAY))
shell.lifecycle.start()
shell.window.show()
assert shell.window.isVisible()
def action():
    tray.hide()
    assert not shell.window.isVisible() and engine.running
    tray.show()
    assert shell.window.isVisible() and engine.start_calls == 1
    if SOURCE == "external": shell.application.quit()
    elif SOURCE == "tray": tray.quit()
    elif SOURCE == "file": shell.window.quit_action.trigger()
    else:
        shell.controller.save_behavior(Close.QUIT_APPLICATION)
        shell.window.close()
QTimer.singleShot(0, action)
QTimer.singleShot(3000, lambda: shell.application.exit(99))
assert shell.application.exec() == 0
assert shell.controller.quitting and engine.stop_calls == 1
assert not tray.visible and tray.cleanup_calls == 1
assert not shell.window.isVisible()
shell.controller.shutdown()
assert engine.stop_calls == 1
'''.replace("SOURCE", repr(source))
    result = run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[2],
                 capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
