"""Presentation state for the live Dashboard page."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from math import ceil

from PyQt6.QtCore import QObject, QTimer, pyqtSignal, pyqtSlot

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.domain.connections import ConnectionState, TransportProtocol
from netsentinel.presentation.bridge import BridgeHealthSnapshot, ConnectionEventBatch
from netsentinel.presentation.models.connections import ConnectionsTableModel
from netsentinel.shared.diagnostics import (
    CapabilityStatus,
    DiagnosticCode,
    EngineState,
)


@dataclass(frozen=True, slots=True)
class DashboardMetrics:
    """Connection counts derived from the shared presentation model."""

    total_connections: int = 0
    tcp_connections: int = 0
    udp_connections: int = 0
    listening_connections: int = 0
    remote_hosts: int = 0
    opened_events: int = 0
    closed_events: int = 0
    rolling_window_seconds: int = 60


@dataclass(frozen=True, slots=True)
class DashboardHealthState:
    """User-facing health text with no raw diagnostic payload."""

    status: str = "Waiting"
    detail: str = "Waiting for monitoring status."
    capability: str = "Capability status is not available yet."
    diagnostic: str = "No monitoring status has been received."
    last_successful_poll: str = "—"
    dropped_bridge_events: int = 0
    tone: str = "neutral"


_DIAGNOSTIC_TEXT: dict[DiagnosticCode, str] = {
    DiagnosticCode.COLLECTOR_PERMISSION_DENIED: (
        "Connection access is restricted by Windows permissions."
    ),
    DiagnosticCode.COLLECTOR_TRANSIENT_ERROR: (
        "Connection monitoring is temporarily unavailable."
    ),
    DiagnosticCode.COLLECTOR_UNEXPECTED_ERROR: (
        "Connection monitoring encountered an unexpected problem."
    ),
    DiagnosticCode.PROCESS_ENRICHMENT_ERROR: (
        "Process details could not be refreshed."
    ),
    DiagnosticCode.PROCESS_METADATA_DEGRADED: (
        "Some process details are unavailable."
    ),
    DiagnosticCode.TRACKER_ERROR: "Connection state could not be updated.",
    DiagnosticCode.DISPATCHER_ERROR: "Monitoring updates could not be delivered.",
    DiagnosticCode.SUBSCRIBER_ERROR: (
        "One monitoring consumer could not process an update."
    ),
    DiagnosticCode.POLLING_OVERRUN: (
        "A monitoring refresh took longer than expected."
    ),
    DiagnosticCode.SHUTDOWN_TIMEOUT: "Monitoring is taking longer to stop.",
    DiagnosticCode.WORKER_ERROR: "The monitoring worker encountered a problem.",
}


class DashboardViewModel(QObject):
    """Combine shared connection rows, rolling counters, and bridge health."""

    metrics_changed = pyqtSignal(DashboardMetrics)
    health_changed = pyqtSignal(DashboardHealthState)

    def __init__(
        self,
        connections: ConnectionsTableModel,
        statistics: StatisticsService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._connections = connections
        self._statistics = statistics
        self._metrics = DashboardMetrics(
            rolling_window_seconds=max(1, int(statistics.window.total_seconds()))
        )
        self._health = DashboardHealthState()
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setSingleShot(True)
        self._expiry_timer.timeout.connect(self.refresh_statistics)

        connections.rowsInserted.connect(self._refresh_connection_metrics)
        connections.rowsRemoved.connect(self._refresh_connection_metrics)
        connections.dataChanged.connect(self._refresh_connection_metrics)
        connections.modelReset.connect(self._refresh_connection_metrics)
        self._refresh_connection_metrics()

    @property
    def metrics(self) -> DashboardMetrics:
        return self._metrics

    @property
    def health(self) -> DashboardHealthState:
        return self._health

    @property
    def statistics(self) -> StatisticsService:
        return self._statistics

    @pyqtSlot(ConnectionEventBatch)
    def handle_events(self, batch: ConnectionEventBatch) -> None:
        """Update rolling counters once for each bridge batch."""

        if not isinstance(batch, ConnectionEventBatch):
            raise TypeError("batch must be a ConnectionEventBatch")
        self._statistics.record_many(batch.events)
        self.refresh_statistics()

    @pyqtSlot()
    def refresh_statistics(self) -> None:
        snapshot = self._statistics.snapshot()
        self._set_metrics(
            replace(
                self._metrics,
                opened_events=snapshot.opened_events,
                closed_events=snapshot.closed_events,
            )
        )
        self._expiry_timer.stop()
        delay = snapshot.next_expiry_in_seconds
        if delay is not None:
            self._expiry_timer.start(max(1, ceil(delay * 1_000) + 1))

    @pyqtSlot(BridgeHealthSnapshot)
    def set_health(self, snapshot: BridgeHealthSnapshot) -> None:
        if not isinstance(snapshot, BridgeHealthSnapshot):
            raise TypeError("snapshot must be a BridgeHealthSnapshot")
        state = _health_state(snapshot)
        if state != self._health:
            self._health = state
            self.health_changed.emit(state)
        # Health already arrives through the bridge's existing timer. This also
        # prunes rolling counters without introducing dashboard polling.
        self.refresh_statistics()

    def _refresh_connection_metrics(self, *_args: object) -> None:
        tcp = 0
        udp = 0
        listening = 0
        remote_hosts: set[str] = set()
        rows = self._connections.rows_snapshot()
        for row in rows:
            if row.protocol == TransportProtocol.TCP.value:
                tcp += 1
            elif row.protocol == TransportProtocol.UDP.value:
                udp += 1
            if (
                row.protocol == TransportProtocol.TCP.value
                and row.state == ConnectionState.LISTEN.value
            ):
                listening += 1
            if row.remote_address is not None:
                remote_hosts.add(row.remote_address)

        self._set_metrics(
            replace(
                self._metrics,
                total_connections=len(rows),
                tcp_connections=tcp,
                udp_connections=udp,
                listening_connections=listening,
                remote_hosts=len(remote_hosts),
            )
        )

    def _set_metrics(self, metrics: DashboardMetrics) -> None:
        if metrics != self._metrics:
            self._metrics = metrics
            self.metrics_changed.emit(metrics)


def _health_state(snapshot: BridgeHealthSnapshot) -> DashboardHealthState:
    engine = snapshot.engine
    connection = engine.capabilities.connection_monitoring
    process = engine.capabilities.process_metadata

    if engine.state is EngineState.STOPPING:
        status = "Stopping"
        detail = "Monitoring is stopping."
        tone = "warning"
    elif engine.state is EngineState.STOPPED:
        status = "Stopped"
        detail = "Monitoring is stopped."
        tone = "neutral"
    elif connection is CapabilityStatus.UNAVAILABLE:
        status = "Unavailable"
        detail = "Connection monitoring is unavailable."
        tone = "error"
    elif (
        connection is CapabilityStatus.DEGRADED
        or process is not CapabilityStatus.AVAILABLE
        or engine.last_error is not None
        or snapshot.dropped_events > 0
    ):
        status = "Degraded"
        detail = "Connection monitoring is degraded."
        tone = "warning"
    else:
        status = "Healthy"
        detail = "Monitoring healthy."
        tone = "healthy"

    if connection is CapabilityStatus.UNAVAILABLE:
        capability = "Active connection visibility is unavailable."
    elif connection is CapabilityStatus.DEGRADED:
        capability = "Active connection visibility may be incomplete."
    elif process is CapabilityStatus.UNAVAILABLE:
        capability = "Connections are available; process details are unavailable."
    elif process is CapabilityStatus.DEGRADED:
        capability = "Connections are available; some process details are limited."
    else:
        capability = "Connection and process monitoring are available."

    diagnostic = (
        "No monitoring issues reported."
        if engine.last_error is None
        else _DIAGNOSTIC_TEXT.get(
            engine.last_error.code,
            "Monitoring reported an issue.",
        )
    )
    if snapshot.dropped_events:
        diagnostic = (
            f"{snapshot.dropped_events} UI update event(s) were dropped; "
            "displayed connection data may be incomplete."
        )

    return DashboardHealthState(
        status=status,
        detail=detail,
        capability=capability,
        diagnostic=diagnostic,
        last_successful_poll=_format_poll_time(engine.last_successful_poll_at),
        dropped_bridge_events=snapshot.dropped_events,
        tone=tone,
    )


def _format_poll_time(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.astimezone().strftime("%H:%M:%S")


__all__ = (
    "DashboardHealthState",
    "DashboardMetrics",
    "DashboardViewModel",
)
