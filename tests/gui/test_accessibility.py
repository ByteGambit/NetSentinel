"""NS-013 accessibility, keyboard, DPI, and state regression tests."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QWidget
from pytestqt.qtbot import QtBot

from netsentinel.domain.connections import ConnectionOpened
from netsentinel.presentation.bridge import BridgeHealthSnapshot
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.main_window import PAGE_ORDER, MainWindow, PageId
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    CapabilityStatus,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)
from tests.gui._ns013_support import snapshot


@pytest.fixture
def window(qtbot: QtBot) -> MainWindow:
    created = MainWindow()
    qtbot.addWidget(created)
    created.show()
    yield created
    created.close()


def _assert_accessible(widget: QWidget) -> None:
    name = widget.accessibleName().strip()
    assert name
    assert name.casefold() != type(widget).__name__.casefold()
    assert name.casefold() != widget.metaObject().className().casefold()


def _health(
    state: EngineState,
    *,
    connection: CapabilityStatus = CapabilityStatus.AVAILABLE,
    process: CapabilityStatus = CapabilityStatus.AVAILABLE,
) -> BridgeHealthSnapshot:
    return BridgeHealthSnapshot(
        engine=EngineHealthSnapshot(
            state=state,
            capabilities=CapabilitySnapshot(
                connection_monitoring=connection,
                process_metadata=process,
            ),
            counters=EngineCounters(),
            worker_alive=state is not EngineState.STOPPED,
        ),
        queued_events=0,
        dropped_events=0,
        queue_capacity=64,
    )


def test_critical_controls_have_meaningful_accessible_names(
    window: MainWindow,
) -> None:
    dashboard = window.page_widget(PageId.DASHBOARD)
    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(dashboard, DashboardView)
    assert isinstance(connections, ConnectionsView)

    critical = (
        window,
        window.navigation,
        dashboard,
        dashboard.status_label,
        dashboard.health_detail_label,
        dashboard.capability_label,
        dashboard.diagnostic_label,
        dashboard.last_poll_label,
        dashboard.dropped_events_label,
        dashboard.total_value,
        dashboard.tcp_value,
        dashboard.udp_value,
        dashboard.listening_value,
        dashboard.remote_hosts_value,
        dashboard.opened_value,
        dashboard.closed_value,
        connections,
        connections.health_label,
        connections.search_edit,
        connections.protocol_filter,
        connections.state_filter,
        connections.pause_button,
        connections.table,
        connections.details,
    )
    for widget in critical:
        _assert_accessible(widget)

    for page_id in PAGE_ORDER:
        accessible_text = window.navigation_item(page_id).data(
            Qt.ItemDataRole.AccessibleTextRole
        )
        assert isinstance(accessible_text, str)
        assert accessible_text.strip()
        assert page_id.value.casefold() in accessible_text.casefold()


def test_tab_and_shift_tab_follow_the_critical_connections_path(
    qtbot: QtBot,
    window: MainWindow,
) -> None:
    window.navigate_to(PageId.CONNECTIONS)
    window.navigation.setFocus()
    assert QApplication.focusWidget() is window.navigation

    expected_forward = (
        window.page_widget(PageId.CONNECTIONS).search_edit,
        window.page_widget(PageId.CONNECTIONS).protocol_filter,
        window.page_widget(PageId.CONNECTIONS).state_filter,
        window.page_widget(PageId.CONNECTIONS).pause_button,
        window.page_widget(PageId.CONNECTIONS).table,
    )
    for expected in expected_forward:
        focused = QApplication.focusWidget()
        assert focused is not None
        qtbot.keyClick(focused, Qt.Key.Key_Tab)
        assert QApplication.focusWidget() is expected

    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(connections, ConnectionsView)
    connections.search_edit.setFocus()
    qtbot.keyClick(
        connections.search_edit,
        Qt.Key.Key_Tab,
        modifier=Qt.KeyboardModifier.ShiftModifier,
    )
    assert QApplication.focusWidget() is window.navigation


def test_navigation_and_table_are_keyboard_operable(
    qtbot: QtBot,
    window: MainWindow,
) -> None:
    window.navigation.setFocus()
    window.navigation.setCurrentRow(0)
    qtbot.keyClick(window.navigation, Qt.Key.Key_Down)

    assert window.current_page is PageId.CONNECTIONS
    assert QApplication.focusWidget() is window.navigation

    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(connections, ConnectionsView)
    connections.source_model.handle_connection_opened(ConnectionOpened(snapshot(0)))
    connections.source_model.handle_connection_opened(ConnectionOpened(snapshot(1)))
    connections.table.setFocus()
    connections.table.setCurrentIndex(connections.proxy_model.index(0, 0))
    qtbot.keyClick(connections.table, Qt.Key.Key_Down)

    assert QApplication.focusWidget() is connections.table
    assert connections.table.currentIndex().row() == 1
    assert connections.selected_row_id is not None


def test_page_change_moves_focus_out_of_hidden_content(window: MainWindow) -> None:
    window.navigate_to(PageId.CONNECTIONS)
    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(connections, ConnectionsView)
    connections.search_edit.setFocus()
    assert QApplication.focusWidget() is connections.search_edit

    window.navigate_to(PageId.DASHBOARD)

    assert QApplication.focusWidget() is window.navigation
    assert window.current_page is PageId.DASHBOARD


def test_critical_layout_uses_scalable_heights_and_a_flexible_sidebar(
    window: MainWindow,
) -> None:
    window.resize(window.minimumSize())
    QApplication.processEvents()
    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(connections, ConnectionsView)

    assert window.navigation.minimumWidth() < window.navigation.maximumWidth()
    item_height = window.navigation_item(PageId.CONNECTIONS).sizeHint().height()
    assert item_height >= window.navigation.fontMetrics().height() + 18
    assert (
        connections.table.verticalHeader().defaultSectionSize()
        >= connections.table.fontMetrics().height() + 10
    )
    for control in (
        connections.search_edit,
        connections.protocol_filter,
        connections.state_filter,
        connections.pause_button,
    ):
        assert control.height() >= control.minimumSizeHint().height()


def test_high_dpi_offscreen_application_smoke() -> None:
    script = textwrap.dedent(
        """
        from PyQt6.QtWidgets import QApplication
        from netsentinel.presentation.views.main_window import MainWindow, PageId

        application = QApplication([])
        window = MainWindow()
        window.show()
        application.processEvents()
        window.navigate_to(PageId.CONNECTIONS)
        application.processEvents()
        view = window.page_widget(PageId.CONNECTIONS)
        assert window.isVisible()
        assert window.navigation.minimumWidth() < window.navigation.maximumWidth()
        assert view.search_edit.height() >= view.search_edit.minimumSizeHint().height()
        assert view.protocol_filter.height() >= view.protocol_filter.minimumSizeHint().height()
        assert view.state_filter.height() >= view.state_filter.minimumSizeHint().height()
        window.close()
        application.processEvents()
        """
    )
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_SCALE_FACTOR"] = "2"

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("health", "expected"),
    [
        (_health(EngineState.STOPPING), "stopping"),
        (_health(EngineState.STOPPED), "stopped"),
        (
            _health(
                EngineState.RUNNING,
                connection=CapabilityStatus.UNAVAILABLE,
            ),
            "unavailable",
        ),
        (
            _health(
                EngineState.RUNNING,
                connection=CapabilityStatus.DEGRADED,
            ),
            "degraded",
        ),
        (
            _health(
                EngineState.RUNNING,
                process=CapabilityStatus.DEGRADED,
            ),
            "process metadata is limited",
        ),
    ],
)
def test_connections_health_states_are_safe_and_user_facing(
    qtbot: QtBot,
    health: BridgeHealthSnapshot,
    expected: str,
) -> None:
    view = ConnectionsView()
    qtbot.addWidget(view)
    view.set_health(health)

    text = view.health_label.text()
    assert expected in text.casefold()
    assert "Traceback" not in text
    assert "Exception(" not in text
    assert "EngineState." not in text


def test_empty_and_initial_states_do_not_leak_python_values(
    window: MainWindow,
) -> None:
    dashboard = window.page_widget(PageId.DASHBOARD)
    connections = window.page_widget(PageId.CONNECTIONS)
    assert isinstance(dashboard, DashboardView)
    assert isinstance(connections, ConnectionsView)

    texts = (
        dashboard.status_label.text(),
        dashboard.health_detail_label.text(),
        dashboard.capability_label.text(),
        dashboard.diagnostic_label.text(),
        connections.health_label.text(),
        connections.empty_label.text(),
        connections.details.status_label.text(),
        *(connections.state_filter.itemText(index) for index in range(connections.state_filter.count())),
    )
    combined = " ".join(texts)
    assert dashboard.total_value.text() == "0"
    assert connections.proxy_model.rowCount() == 0
    assert "None" not in combined
    assert "Traceback" not in combined
    assert "Exception(" not in combined
    assert "ConnectionSnapshot(" not in combined

