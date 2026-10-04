"""NS-008 offscreen application shell, navigation, and lifecycle tests."""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Event, Thread

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.application.events import EventDispatcher
from netsentinel.presentation.app import (
    ApplicationLifecycle,
    create_application,
    run_application,
)
from netsentinel.presentation.bridge import QtEngineBridge
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.incidents import IncidentsView
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.dns import DnsView
from netsentinel.presentation.views.history import HistoryView
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.presentation.views.main_window import (
    PAGE_ORDER,
    MainWindow,
    PageId,
)
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


class FakeEngine:
    def __init__(self, *, running: bool = False) -> None:
        self.running = running
        self.start_calls = 0
        self.stop_calls = 0
        self.dispatcher = EventDispatcher()

    def health_snapshot(self) -> EngineHealthSnapshot:
        return EngineHealthSnapshot(
            state=EngineState.RUNNING if self.running else EngineState.STOPPED,
            capabilities=CapabilitySnapshot(),
            counters=EngineCounters(),
            worker_alive=self.running,
        )

    def start(self) -> bool:
        self.start_calls += 1
        if self.running:
            return False
        self.running = True
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.stop_calls += 1
        self.running = False
        return True


class ThreadedFakeEngine(FakeEngine):
    def __init__(self) -> None:
        super().__init__()
        self._cancel = Event()
        self.worker = Thread(
            target=self._cancel.wait,
            name="netsentinel-ns008-test-worker",
            daemon=True,
        )

    def start(self) -> bool:
        started = super().start()
        if started:
            self.worker.start()
        return started

    def stop(self, timeout: float | None = None) -> bool:
        result = super().stop(timeout)
        self._cancel.set()
        self.worker.join(0.5 if timeout is None else timeout)
        return result and not self.worker.is_alive()


@pytest.fixture
def window(qtbot: QtBot) -> MainWindow:
    created = MainWindow()
    qtbot.addWidget(created)
    created.show()
    yield created
    created.close()


def test_application_shell_can_be_created_offscreen(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)

    assert shell.application is qapp
    assert shell.application.applicationName() == "NetSentinel"
    assert isinstance(shell.window, MainWindow)
    assert isinstance(shell.bridge, QtEngineBridge)
    assert shell.bridge.parent() is shell.window
    assert shell.bridge.attached is False
    assert engine.start_calls == 0

    shell.window.close()
    assert engine.stop_calls == 1


def test_main_window_owns_one_instance_of_each_planned_view(
    window: MainWindow,
) -> None:
    expected_types = {
        PageId.DASHBOARD: DashboardView,
        PageId.CONNECTIONS: ConnectionsView,
        PageId.HISTORY: HistoryView,
        PageId.DEVICES: DevicesView,
        PageId.DNS: DnsView,
        PageId.ALERTS: AlertsView,
        PageId.INCIDENTS: IncidentsView,
        PageId.DIAGNOSTICS: DiagnosticsView,
    }

    assert window.content.count() == len(expected_types)
    assert window.navigation.count() == len(expected_types)
    for page_id, view_type in expected_types.items():
        assert isinstance(window.page_widget(page_id), view_type)


def test_dashboard_is_the_deterministic_initial_page(window: MainWindow) -> None:
    assert window.current_page is PageId.DASHBOARD
    assert window.navigation.currentRow() == 0
    assert window.content.currentWidget() is window.page_widget(PageId.DASHBOARD)


def test_navigation_style_keeps_inactive_active_and_hover_text_readable(
    window: MainWindow,
) -> None:
    style = "".join(window.navigation.styleSheet().split())

    assert "QListWidget::item{border-radius:5px;color:#243b53;" in style
    assert "QListWidget::item:hover:!selected{background:#e7edf3;color:#102a43;}" in style
    assert "QListWidget::item:selected{background:#dce8f7;color:#163a5f;}" in style


@pytest.mark.parametrize("page_id", PAGE_ORDER)
def test_each_navigation_item_selects_its_page(
    qtbot: QtBot,
    window: MainWindow,
    page_id: PageId,
) -> None:
    item = window.navigation_item(page_id)
    position = window.navigation.visualItemRect(item).center()

    qtbot.mouseClick(
        window.navigation.viewport(),
        Qt.MouseButton.LeftButton,
        pos=position,
    )

    assert window.current_page is page_id
    assert window.content.currentWidget() is window.page_widget(page_id)


def test_pages_can_be_selected_consecutively(window: MainWindow) -> None:
    sequence = (
        PageId.CONNECTIONS,
        PageId.DEVICES,
        PageId.DNS,
        PageId.ALERTS,
        PageId.DASHBOARD,
    )

    for page_id in sequence:
        window.navigate_to(page_id)
        assert window.current_page is page_id
        assert window.content.currentWidget() is window.page_widget(page_id)


def test_selecting_the_current_page_again_is_idempotent(
    qtbot: QtBot,
    window: MainWindow,
) -> None:
    window.navigate_to(PageId.CONNECTIONS)
    selected = window.page_widget(PageId.CONNECTIONS)
    item = window.navigation_item(PageId.CONNECTIONS)

    qtbot.mouseClick(
        window.navigation.viewport(),
        Qt.MouseButton.LeftButton,
        pos=window.navigation.visualItemRect(item).center(),
    )
    window.navigate_to(PageId.CONNECTIONS)

    assert window.current_page is PageId.CONNECTIONS
    assert window.content.currentWidget() is selected


def test_window_close_uses_one_stop_request_and_leaves_no_worker(
    qtbot: QtBot,
) -> None:
    engine = ThreadedFakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    assert shell.lifecycle.start() is True
    assert shell.bridge.attached is True
    shell.window.show()
    assert engine.worker.is_alive()

    shell.window.close()
    shell.lifecycle.shutdown()

    assert shell.lifecycle.shutdown_requested is True
    assert engine.stop_calls == 1
    assert engine.worker.is_alive() is False
    assert shell.bridge.attached is False
    assert shell.window.isVisible() is False


def test_window_can_close_when_engine_is_already_stopped(qtbot: QtBot) -> None:
    engine = FakeEngine(running=False)
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    shell.window.show()

    shell.window.close()

    assert engine.stop_calls == 1
    assert engine.running is False
    assert shell.window.isVisible() is False


def test_application_lifecycle_starts_and_stops_only_once(
    qapp: QApplication,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    lifecycle = ApplicationLifecycle(engine, bridge)

    assert lifecycle.start() is True
    assert lifecycle.start() is False
    assert bridge.attached is True
    assert lifecycle.shutdown() is True
    assert lifecycle.shutdown() is True
    assert engine.start_calls == 1
    assert engine.stop_calls == 1
    assert bridge.attached is False


def test_run_application_starts_engine_and_stops_it_when_qt_quits(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = FakeEngine()
    # QApplication.exec() leaves the session-wide pytest-qt QApplication in a
    # quit state, preventing later queued-signal tests from pumping events.
    # The event loop itself is Qt-owned; this test needs only the composition
    # around its return value and therefore replaces that one blocking call.
    monkeypatch.setattr(QApplication, "exec", lambda _self: 0)

    exit_code = run_application(argv=[], engine=engine)

    assert exit_code == 0
    assert engine.start_calls == 1
    assert engine.stop_calls == 1
    assert engine.running is False


def test_view_modules_do_not_import_infrastructure_dependencies() -> None:
    views_directory = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "netsentinel"
        / "presentation"
        / "views"
    )
    forbidden_roots = {"psutil", "scapy", "sqlite3"}

    for path in views_directory.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        roots = {name.split(".", 1)[0].lower() for name in imported}
        assert roots.isdisjoint(forbidden_roots), path.name
        assert not any(
            name == "netsentinel.infrastructure"
            or name.startswith("netsentinel.infrastructure.")
            for name in imported
        ), path.name


def test_invalid_page_identity_is_rejected(window: MainWindow) -> None:
    with pytest.raises(TypeError):
        window.navigate_to("dashboard")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        window.page_widget("dashboard")  # type: ignore[arg-type]


def test_no_unowned_visible_widgets_remain_after_close(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    window.close()
    QApplication.processEvents()

    assert window.isVisible() is False
    assert all(
        not widget.isVisible()
        for widget in QApplication.topLevelWidgets()
        if widget is window or widget.parent() is window
    )
