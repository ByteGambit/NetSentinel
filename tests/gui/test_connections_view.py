"""NS-011 offscreen Connections page and composition tests."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread

import pytest
from PyQt6.QtCore import QItemSelectionModel, QThread, Qt
from PyQt6.QtWidgets import QAbstractItemView, QTableView
from pytestqt.qtbot import QtBot

from netsentinel.application.events import EventDispatcher
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.presentation.app import create_application
from netsentinel.presentation.models.connection_filter import (
    ConnectionsFilterProxyModel,
)
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
    ConnectionsTableModel,
)
from netsentinel.presentation.viewmodels import MISSING_VALUE
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.main_window import PageId
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    CapabilityStatus,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


BASE_TIME = datetime(2026, 9, 19, 10, 0, tzinfo=UTC)
CREATE_TIME = BASE_TIME - timedelta(minutes=10)


class FakeEngine:
    def __init__(self) -> None:
        self.dispatcher = EventDispatcher()
        self.running = False
        self.stop_calls = 0

    def start(self) -> bool:
        self.running = True
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.stop_calls += 1
        self.running = False
        return True

    def health_snapshot(self) -> EngineHealthSnapshot:
        return _health(
            EngineState.RUNNING if self.running else EngineState.STOPPED
        )


def _health(
    state: EngineState = EngineState.RUNNING,
    *,
    connection_monitoring: CapabilityStatus = CapabilityStatus.AVAILABLE,
    process_metadata: CapabilityStatus = CapabilityStatus.AVAILABLE,
) -> EngineHealthSnapshot:
    return EngineHealthSnapshot(
        state=state,
        capabilities=CapabilitySnapshot(
            connection_monitoring=connection_monitoring,
            process_metadata=process_metadata,
        ),
        counters=EngineCounters(),
        worker_alive=state is EngineState.RUNNING,
    )


def _process(pid: int, name: str) -> ProcessInfo:
    return ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(pid, CREATE_TIME + timedelta(seconds=pid)),
        name=name,
    )


def _snapshot(
    *,
    protocol: TransportProtocol = TransportProtocol.TCP,
    local_address: str = "192.168.1.10",
    local_port: int = 5002,
    remote_address: str | None = "93.184.216.34",
    remote_port: int | None = 443,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    process: ProcessInfo | None = None,
    observed_at: datetime = BASE_TIME,
) -> ConnectionSnapshot:
    remote = (
        None
        if remote_address is None
        else Endpoint(remote_address, remote_port if remote_port is not None else 0)
    )
    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local_address, local_port),
        remote_endpoint=remote,
        state=state,
        process=process or _process(9, "browser.exe"),
        observed_at=observed_at,
    )


def _rows() -> tuple[ConnectionSnapshot, ConnectionSnapshot, ConnectionSnapshot]:
    return (
        _snapshot(),
        _snapshot(
            protocol=TransportProtocol.UDP,
            local_address="0.0.0.0",
            local_port=5353,
            remote_address="8.8.8.8",
            remote_port=53,
            state=ConnectionState.NONE,
            process=_process(100, "dns-agent.exe"),
        ),
        _snapshot(
            local_address="2001:db8::1",
            local_port=8080,
            remote_address=None,
            remote_port=None,
            state=ConnectionState.LISTEN,
            process=_process(20, "service.exe"),
        ),
    )


@pytest.fixture
def view(qtbot: QtBot) -> ConnectionsView:
    created = ConnectionsView()
    qtbot.addWidget(created)
    created.resize(900, 650)
    created.show()
    yield created
    created.close()


def _open(view: ConnectionsView, *snapshots: ConnectionSnapshot) -> None:
    for snapshot in snapshots:
        view.source_model.handle_connection_opened(ConnectionOpened(snapshot))


def _select(view: ConnectionsView, row: int) -> None:
    index = view.proxy_model.index(row, 0)
    view.table.selectionModel().setCurrentIndex(
        index,
        QItemSelectionModel.SelectionFlag.ClearAndSelect
        | QItemSelectionModel.SelectionFlag.Rows,
    )


def _proxy_raw(view: ConnectionsView, row: int, role: ConnectionRole) -> object:
    return view.proxy_model.data(view.proxy_model.index(row, 0), int(role))


def test_view_builds_real_table_proxy_controls_and_empty_state(
    view: ConnectionsView,
) -> None:
    assert isinstance(view.table, QTableView)
    assert isinstance(view.source_model, ConnectionsTableModel)
    assert isinstance(view.proxy_model, ConnectionsFilterProxyModel)
    assert view.table.model() is view.proxy_model
    assert view.proxy_model.sourceModel() is view.source_model
    assert view.table.selectionBehavior() is QAbstractItemView.SelectionBehavior.SelectRows
    assert view.table.isSortingEnabled()
    assert view.empty_label.isVisible()
    assert view.details.status_label.text() == "No connection selected."


def test_open_update_close_and_two_rows_are_incremental(view: ConnectionsView) -> None:
    first, second, _third = _rows()
    resets: list[bool] = []
    view.source_model.modelReset.connect(lambda: resets.append(True))

    _open(view, first, second)
    assert view.proxy_model.rowCount() == 2

    updated = _snapshot(
        state=ConnectionState.CLOSE_WAIT,
        process=_process(9, "browser-renamed.exe"),
        observed_at=BASE_TIME + timedelta(seconds=12),
    )
    view.source_model.handle_connection_updated(ConnectionUpdated(first, updated))
    names = {
        _proxy_raw(view, row, ConnectionRole.RAW_PROCESS)
        for row in range(view.proxy_model.rowCount())
    }
    assert "browser-renamed.exe" in names

    view.source_model.handle_connection_closed(
        ConnectionClosed(second, BASE_TIME + timedelta(seconds=13))
    )
    assert view.proxy_model.rowCount() == 1
    assert resets == []


@pytest.mark.parametrize(
    ("query", "expected_process"),
    [
        ("browser", "browser.exe"),
        ("100", "dns-agent.exe"),
        ("192.168.1.10:5002", "browser.exe"),
        ("8.8.8.8:53", "dns-agent.exe"),
    ],
)
def test_search_uses_process_pid_and_raw_endpoints(
    view: ConnectionsView,
    query: str,
    expected_process: str,
) -> None:
    _open(view, *_rows())

    view.search_edit.setText(query)

    assert view.proxy_model.rowCount() == 1
    assert _proxy_raw(view, 0, ConnectionRole.RAW_PROCESS) == expected_process


@pytest.mark.parametrize(
    ("combo_name", "value", "expected_process"),
    [
        ("protocol_filter", TransportProtocol.TCP.value, {"browser.exe", "service.exe"}),
        ("protocol_filter", TransportProtocol.UDP.value, {"dns-agent.exe"}),
        ("state_filter", ConnectionState.ESTABLISHED.value, {"browser.exe"}),
    ],
)
def test_protocol_and_state_filters_use_raw_values(
    view: ConnectionsView,
    combo_name: str,
    value: str,
    expected_process: set[str],
) -> None:
    _open(view, *_rows())
    combo = getattr(view, combo_name)
    combo.setCurrentIndex(combo.findData(value))

    assert {
        _proxy_raw(view, row, ConnectionRole.RAW_PROCESS)
        for row in range(view.proxy_model.rowCount())
    } == expected_process


def test_filters_combine_and_clear_without_source_reset(view: ConnectionsView) -> None:
    _open(view, *_rows())
    resets: list[bool] = []
    view.source_model.modelReset.connect(lambda: resets.append(True))

    view.protocol_filter.setCurrentIndex(
        view.protocol_filter.findData(TransportProtocol.TCP.value)
    )
    view.state_filter.setCurrentIndex(
        view.state_filter.findData(ConnectionState.LISTEN.value)
    )
    view.search_edit.setText("2001:db8")
    assert view.proxy_model.rowCount() == 1
    assert _proxy_raw(view, 0, ConnectionRole.RAW_PROCESS) == "service.exe"

    view.clear_filters()
    assert view.proxy_model.rowCount() == 3
    assert resets == []


def test_sorting_is_semantic_for_pid_and_duration(view: ConnectionsView) -> None:
    first, second, third = _rows()
    _open(view, first, second, third)

    view.proxy_model.sort(int(ConnectionColumn.PID), Qt.SortOrder.AscendingOrder)
    assert [
        _proxy_raw(view, row, ConnectionRole.RAW_PID)
        for row in range(view.proxy_model.rowCount())
    ] == [9, 20, 100]

    first_updated = _snapshot(observed_at=BASE_TIME + timedelta(seconds=100))
    second_updated = _snapshot(
        protocol=TransportProtocol.UDP,
        local_address="0.0.0.0",
        local_port=5353,
        remote_address="8.8.8.8",
        remote_port=53,
        state=ConnectionState.NONE,
        process=_process(100, "dns-agent.exe"),
        observed_at=BASE_TIME + timedelta(seconds=2),
    )
    view.source_model.handle_connection_updated(
        ConnectionUpdated(first, first_updated)
    )
    view.source_model.handle_connection_updated(
        ConnectionUpdated(second, second_updated)
    )
    view.proxy_model.sort(
        int(ConnectionColumn.DURATION), Qt.SortOrder.AscendingOrder
    )
    durations = [
        _proxy_raw(view, row, ConnectionRole.DURATION)
        for row in range(view.proxy_model.rowCount())
    ]
    assert durations == [0.0, 2.0, 100.0]


def test_selection_detail_changes_and_selected_update_uses_stable_id(
    view: ConnectionsView,
) -> None:
    first, second, _third = _rows()
    _open(view, first, second)

    _select(view, 0)
    first_id = view.selected_row_id
    assert view.details.value_text("process") == "browser.exe"
    assert view.details.value_text("local_address") == "192.168.1.10"
    assert view.details.value_text("remote_port") == "443"

    _select(view, 1)
    assert view.details.value_text("process") == "dns-agent.exe"
    assert view.details.value_text("protocol") == "UDP"

    _select(view, 0)
    updated = _snapshot(
        process=_process(9, "browser-renamed.exe"),
        state=ConnectionState.TIME_WAIT,
        observed_at=BASE_TIME + timedelta(seconds=65),
    )
    view.source_model.handle_connection_updated(ConnectionUpdated(first, updated))
    assert view.selected_row_id == first_id
    assert view.details.value_text("process") == "browser-renamed.exe"
    assert view.details.value_text("state") == "Time Wait"
    assert view.details.value_text("duration") == "00:01:05"


def test_selected_close_and_filter_hide_clear_stale_details(
    view: ConnectionsView,
) -> None:
    first, second, _third = _rows()
    _open(view, first, second)
    _select(view, 0)

    view.search_edit.setText("dns-agent")
    assert view.selected_row_id is None
    assert view.details.status_label.text() == "No connection selected."
    assert view.details.value_text("process") == MISSING_VALUE

    view.search_edit.clear()
    browser_row = next(
        row
        for row in range(view.proxy_model.rowCount())
        if _proxy_raw(view, row, ConnectionRole.RAW_PROCESS) == "browser.exe"
    )
    _select(view, browser_row)
    view.source_model.handle_connection_closed(
        ConnectionClosed(first, BASE_TIME + timedelta(seconds=1))
    )
    assert view.selected_row_id is None
    assert view.details.status_label.text() == "No connection selected."
    assert view.details.value_text("remote_address") == MISSING_VALUE


def test_ipv4_ipv6_missing_remote_and_process_metadata_are_safe(
    view: ConnectionsView,
) -> None:
    ipv4, _udp, ipv6 = _rows()
    unavailable = _snapshot(
        local_port=9000,
        remote_address=None,
        remote_port=None,
        state=ConnectionState.LISTEN,
        process=ProcessInfo.unavailable(),
    )
    _open(view, ipv4, ipv6, unavailable)

    local_displays = {
        view.proxy_model.data(
            view.proxy_model.index(row, int(ConnectionColumn.LOCAL_ENDPOINT))
        )
        for row in range(view.proxy_model.rowCount())
    }
    assert "192.168.1.10:5002" in local_displays
    assert "[2001:db8::1]:8080" in local_displays

    unavailable_row = next(
        row
        for row in range(view.proxy_model.rowCount())
        if _proxy_raw(view, row, ConnectionRole.RAW_LOCAL_PORT) == 9000
    )
    _select(view, unavailable_row)
    assert view.details.value_text("process") == "Not available"
    assert view.details.value_text("pid") == "Not available"
    assert view.details.value_text("remote_address") == MISSING_VALUE
    assert view.details.value_text("remote_port") == MISSING_VALUE


def test_pause_freezes_painting_but_does_not_drop_model_events(
    view: ConnectionsView,
) -> None:
    view.set_paused(True)
    assert view.paused
    assert not view.table.viewport().updatesEnabled()

    _open(view, _rows()[0])
    assert view.source_model.rowCount() == 1

    view.set_paused(False)
    assert not view.paused
    assert view.table.viewport().updatesEnabled()
    assert view.proxy_model.rowCount() == 1


def test_degraded_and_unavailable_health_are_explained(view: ConnectionsView) -> None:
    from netsentinel.presentation.bridge import BridgeHealthSnapshot

    view.set_health(
        BridgeHealthSnapshot(
            engine=_health(process_metadata=CapabilityStatus.DEGRADED),
            queued_events=0,
            dropped_events=0,
            queue_capacity=10,
        )
    )
    assert "Process metadata is limited" in view.health_label.text()

    view.set_health(
        BridgeHealthSnapshot(
            engine=_health(
                connection_monitoring=CapabilityStatus.UNAVAILABLE
            ),
            queued_events=0,
            dropped_events=0,
            queue_capacity=10,
        )
    )
    assert "unavailable" in view.health_label.text().lower()
    assert "unavailable" in view.empty_label.text().lower()


def test_application_wires_each_bridge_signal_once_and_updates_main_thread(
    qapp,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    view = shell.window.page_widget(PageId.CONNECTIONS)
    assert isinstance(view, ConnectionsView)
    assert shell.window.connections_model is view.source_model
    assert shell.window.bind_engine_bridge(shell.bridge) is False
    assert shell.bridge.receivers(shell.bridge.connection_opened) == 1
    assert shell.bridge.receivers(shell.bridge.connection_updated) == 1
    assert shell.bridge.receivers(shell.bridge.connection_closed) == 1

    mutation_threads: list[QThread] = []
    shell.window.connections_model.rowsInserted.connect(
        lambda *_args: mutation_threads.append(QThread.currentThread())
    )
    shell.lifecycle.start()
    publisher = Thread(
        target=lambda: engine.dispatcher.publish(ConnectionOpened(_rows()[0])),
        name="netsentinel-ns011-test-publisher",
    )
    publisher.start()
    publisher.join(timeout=2)
    qtbot.waitUntil(lambda: shell.window.connections_model.rowCount() == 1)

    assert not publisher.is_alive()
    assert mutation_threads == [shell.window.connections_model.thread()]
    shell.window.close()
    assert engine.stop_calls == 1
    assert not shell.bridge.attached


def test_view_and_model_keep_infrastructure_out_and_qt_out_of_core_layers() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    presentation_paths = (
        repository_root / "src/netsentinel/presentation/views/connections.py",
        repository_root / "src/netsentinel/presentation/widgets/connection_details.py",
        repository_root / "src/netsentinel/presentation/models/connection_filter.py",
        repository_root / "src/netsentinel/presentation/models/connections.py",
    )
    blocked = {"psutil", "scapy", "sqlite3"}
    for path in presentation_paths:
        imports = _imports(path)
        assert not any(name.split(".", 1)[0].lower() in blocked for name in imports)
        assert not any(
            name == "netsentinel.infrastructure"
            or name.startswith("netsentinel.infrastructure.")
            for name in imports
        )

    source_root = repository_root / "src/netsentinel"
    for layer in ("application", "domain"):
        for path in (source_root / layer).rglob("*.py"):
            assert not any(
                name == "PyQt6" or name.startswith("PyQt6.")
                for name in _imports(path)
            )


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    return imported
