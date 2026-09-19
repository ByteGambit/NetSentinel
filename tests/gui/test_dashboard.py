"""NS-012 offscreen Dashboard metrics, health, and composition tests."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread

import pytest
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.statistics import StatisticsService
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessInfo,
    TransportProtocol,
)
from netsentinel.presentation.app import create_application
from netsentinel.presentation.bridge import BridgeHealthSnapshot, ConnectionEventBatch
from netsentinel.presentation.models.connections import ConnectionsTableModel
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.main_window import PageId
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    CapabilityStatus,
    Diagnostic,
    DiagnosticCode,
    DiagnosticComponent,
    DiagnosticSeverity,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


BASE_TIME = datetime(2026, 9, 19, 9, 41, 32, tzinfo=UTC)


@dataclass
class FakeClock:
    now: datetime = BASE_TIME

    def __call__(self) -> datetime:
        return self.now


class FakeEngine:
    def __init__(self) -> None:
        self.dispatcher = EventDispatcher()
        self.running = False

    def start(self) -> bool:
        self.running = True
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.running = False
        return True

    def health_snapshot(self) -> EngineHealthSnapshot:
        return _health(
            EngineState.RUNNING if self.running else EngineState.STOPPED
        )


def _snapshot(
    *,
    protocol: TransportProtocol = TransportProtocol.TCP,
    local_address: str = "192.0.2.10",
    local_port: int = 50_000,
    remote_address: str | None = "198.51.100.7",
    remote_port: int | None = 443,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    observed_at: datetime = BASE_TIME,
) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local_address, local_port),
        remote_endpoint=(
            None
            if remote_address is None
            else Endpoint(remote_address, 0 if remote_port is None else remote_port)
        ),
        state=state,
        process=ProcessInfo.unavailable(),
        observed_at=observed_at,
    )


def _health(
    state: EngineState = EngineState.RUNNING,
    *,
    connection: CapabilityStatus = CapabilityStatus.AVAILABLE,
    process: CapabilityStatus = CapabilityStatus.AVAILABLE,
    last_successful_poll_at: datetime | None = None,
    diagnostic: Diagnostic | None = None,
) -> EngineHealthSnapshot:
    return EngineHealthSnapshot(
        state=state,
        capabilities=CapabilitySnapshot(
            connection_monitoring=connection,
            process_metadata=process,
        ),
        counters=EngineCounters(),
        last_successful_poll_at=last_successful_poll_at,
        last_error=diagnostic,
        worker_alive=state is EngineState.RUNNING,
    )


def _bridge_health(
    engine: EngineHealthSnapshot,
    *,
    dropped: int = 0,
) -> BridgeHealthSnapshot:
    return BridgeHealthSnapshot(
        engine=engine,
        queued_events=0,
        dropped_events=dropped,
        queue_capacity=32,
    )


@pytest.fixture
def dashboard(qtbot: QtBot) -> DashboardView:
    model = ConnectionsTableModel()
    created = DashboardView(
        model=model,
        statistics=StatisticsService(clock=FakeClock()),
    )
    qtbot.addWidget(created)
    created.resize(900, 650)
    created.show()
    yield created
    created.close()


def _deliver(view: DashboardView, event: object) -> None:
    assert isinstance(event, (ConnectionOpened, ConnectionUpdated, ConnectionClosed))
    view.view_model.handle_events(ConnectionEventBatch((event,)))
    if isinstance(event, ConnectionOpened):
        view.connections_model.handle_connection_opened(event)
    elif isinstance(event, ConnectionUpdated):
        view.connections_model.handle_connection_updated(event)
    else:
        view.connections_model.handle_connection_closed(event)


def test_dashboard_builds_with_zero_empty_state(dashboard: DashboardView) -> None:
    assert dashboard.total_value.text() == "0"
    assert dashboard.tcp_value.text() == "0"
    assert dashboard.udp_value.text() == "0"
    assert dashboard.status_label.text() == "● Waiting"
    assert dashboard.last_poll_label.text() == "—"


def test_tcp_udp_multiple_and_closed_metrics_update(dashboard: DashboardView) -> None:
    tcp = _snapshot()
    udp = _snapshot(
        protocol=TransportProtocol.UDP,
        local_port=53_535,
        remote_address="203.0.113.8",
        remote_port=53,
        state=ConnectionState.NONE,
    )
    _deliver(dashboard, ConnectionOpened(tcp))
    assert dashboard.total_value.text() == "1"
    assert dashboard.tcp_value.text() == "1"
    _deliver(dashboard, ConnectionOpened(udp))
    assert dashboard.total_value.text() == "2"
    assert dashboard.udp_value.text() == "1"
    assert dashboard.opened_value.text() == "2"

    _deliver(dashboard, ConnectionClosed(tcp, BASE_TIME + timedelta(seconds=2)))
    assert dashboard.total_value.text() == "1"
    assert dashboard.tcp_value.text() == "0"
    assert dashboard.closed_value.text() == "1"


def test_listening_changes_after_update_and_close_without_stale_count(
    dashboard: DashboardView,
) -> None:
    initial = _snapshot(remote_address=None, remote_port=None)
    listening = _snapshot(
        remote_address=None,
        remote_port=None,
        state=ConnectionState.LISTEN,
        observed_at=BASE_TIME + timedelta(seconds=1),
    )
    _deliver(dashboard, ConnectionOpened(initial))
    _deliver(dashboard, ConnectionUpdated(initial, listening))
    assert dashboard.listening_value.text() == "1"

    _deliver(
        dashboard,
        ConnectionClosed(listening, BASE_TIME + timedelta(seconds=2)),
    )
    assert dashboard.listening_value.text() == "0"
    assert dashboard.total_value.text() == "0"


def test_remote_hosts_use_canonical_ipv4_ipv6_and_ignore_missing(
    dashboard: DashboardView,
) -> None:
    snapshots = (
        _snapshot(remote_address="198.51.100.7", local_port=50_001),
        _snapshot(remote_address="198.51.100.7", local_port=50_002),
        _snapshot(
            local_address="2001:db8::1",
            local_port=50_003,
            remote_address="2001:0db8:0:0:0:0:0:2",
        ),
        _snapshot(
            local_port=50_004,
            remote_address=None,
            remote_port=None,
            state=ConnectionState.LISTEN,
        ),
    )
    for snapshot in snapshots:
        _deliver(dashboard, ConnectionOpened(snapshot))

    assert dashboard.total_value.text() == "4"
    assert dashboard.remote_hosts_value.text() == "2"
    rows = dashboard.connections_model.rows_snapshot()
    assert any(row.remote_address == "2001:db8::2" for row in rows)


@pytest.mark.parametrize(
    ("health", "expected"),
    [
        (_health(), "Healthy"),
        (_health(connection=CapabilityStatus.DEGRADED), "Degraded"),
        (_health(process=CapabilityStatus.DEGRADED), "Degraded"),
        (_health(connection=CapabilityStatus.UNAVAILABLE), "Unavailable"),
        (_health(EngineState.STOPPING), "Stopping"),
        (_health(EngineState.STOPPED), "Stopped"),
    ],
)
def test_health_states_are_mapped_for_people(
    dashboard: DashboardView,
    health: EngineHealthSnapshot,
    expected: str,
) -> None:
    dashboard.view_model.set_health(_bridge_health(health))
    assert expected in dashboard.status_label.text()


def test_poll_time_diagnostic_and_bridge_drop_are_safe(
    dashboard: DashboardView,
) -> None:
    diagnostic = Diagnostic(
        code=DiagnosticCode.COLLECTOR_PERMISSION_DENIED,
        component=DiagnosticComponent.COLLECTOR,
        severity=DiagnosticSeverity.WARNING,
        occurred_at=BASE_TIME,
    )
    dashboard.view_model.set_health(
        _bridge_health(
            _health(
                last_successful_poll_at=BASE_TIME,
                diagnostic=diagnostic,
            ),
            dropped=3,
        )
    )

    assert dashboard.last_poll_label.text() == BASE_TIME.astimezone().strftime(
        "%H:%M:%S"
    )
    assert dashboard.dropped_events_label.text() == "3"
    visible = " ".join(
        (
            dashboard.health_detail_label.text(),
            dashboard.capability_label.text(),
            dashboard.diagnostic_label.text(),
        )
    )
    assert "dropped" in visible.lower()
    assert "collector_permission_denied" not in visible
    assert "Traceback" not in visible
    assert "Exception" not in visible


def test_typed_diagnostic_is_user_friendly_without_poll_time(
    dashboard: DashboardView,
) -> None:
    diagnostic = Diagnostic(
        code=DiagnosticCode.TRACKER_ERROR,
        component=DiagnosticComponent.TRACKER,
        severity=DiagnosticSeverity.ERROR,
        occurred_at=BASE_TIME,
    )
    dashboard.view_model.set_health(
        _bridge_health(_health(diagnostic=diagnostic))
    )
    assert dashboard.diagnostic_label.text() == (
        "Connection state could not be updated."
    )
    assert dashboard.last_poll_label.text() == "—"


def test_application_uses_shared_model_and_one_dashboard_batch_consumer(
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    dashboard = shell.window.page_widget(PageId.DASHBOARD)
    assert isinstance(dashboard, DashboardView)
    assert dashboard.connections_model is shell.window.connections_model
    assert shell.bridge.receivers(shell.bridge.events_ready) == 1
    assert shell.window.bind_engine_bridge(shell.bridge) is False

    shell.lifecycle.start()
    event = ConnectionOpened(_snapshot())
    mutation_threads: list[QThread] = []
    dashboard.view_model.metrics_changed.connect(
        lambda _metrics: mutation_threads.append(QThread.currentThread())
    )
    publisher = Thread(target=lambda: engine.dispatcher.publish(event))
    publisher.start()
    publisher.join(timeout=2)
    qtbot.waitUntil(lambda: dashboard.total_value.text() == "1")

    assert dashboard.opened_value.text() == "1"
    assert mutation_threads
    assert all(thread is dashboard.thread() for thread in mutation_threads)
    shell.window.close()


def test_duplicate_open_does_not_duplicate_active_rows(dashboard: DashboardView) -> None:
    event = ConnectionOpened(_snapshot())
    dashboard.connections_model.handle_connection_opened(event)
    dashboard.connections_model.handle_connection_opened(event)
    assert dashboard.total_value.text() == "1"
    assert dashboard.connections_model.rowCount() == 1


def test_dashboard_dependencies_respect_layer_boundaries() -> None:
    root = Path(__file__).resolve().parents[2]
    dashboard_paths = (
        root / "src/netsentinel/presentation/models/dashboard.py",
        root / "src/netsentinel/presentation/views/dashboard.py",
    )
    for path in dashboard_paths:
        imports = _imports(path)
        assert not any(
            name.split(".", 1)[0].lower() in {"psutil", "scapy", "sqlite3"}
            for name in imports
        )
        assert not any(name.startswith("netsentinel.infrastructure") for name in imports)

    for layer in ("application", "domain"):
        for path in (root / "src/netsentinel" / layer).rglob("*.py"):
            assert not any(
                name == "PyQt6" or name.startswith("PyQt6.")
                for name in _imports(path)
            )


def test_dashboard_close_leaves_no_visible_widget_or_thread(
    dashboard: DashboardView,
) -> None:
    dashboard.close()
    QApplication.processEvents()
    assert not dashboard.isVisible()
    assert dashboard.view_model.thread() is dashboard.thread()


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
