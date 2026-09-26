"""Presentation state for the live Dashboard page."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from math import ceil, isfinite

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal, pyqtSlot

from netsentinel.application.services.device_inventory import DeviceInventorySnapshot
from netsentinel.application.services.traffic_metrics import BaselineState, MeasurementConfidence
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


@dataclass(frozen=True, slots=True)
class DashboardTrafficState:
    """One presentation snapshot derived from the current network read model."""

    broadcast_rate: str = "—"
    arp_rate: str = "—"
    broadcast_baseline: str = "—"
    arp_baseline: str = "—"
    window: str = "—"
    threshold: str = "—"
    measurement: str = "Unknown"
    capture: str = "Capture off — rates are unavailable."
    dropped: str = "—"


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
    traffic_changed = pyqtSignal(DashboardTrafficState)

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
        self._traffic = DashboardTrafficState()
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

    @property
    def traffic(self) -> DashboardTrafficState:
        return self._traffic

    @pyqtSlot(object)
    def set_traffic_snapshot(self, inventory: object) -> None:
        if QThread.currentThread() is not self.thread():
            raise RuntimeError("Dashboard traffic mutations must run in its Qt thread")
        if not isinstance(inventory, DeviceInventorySnapshot):
            raise TypeError("inventory must be a DeviceInventorySnapshot")
        metric = inventory.traffic_metrics
        capture_running = bool(inventory.capture and inventory.capture.running)
        if (metric is None or inventory.selected_fingerprint != metric.network_fingerprint
                or not any(context.fingerprint == metric.network_fingerprint
                           and context.interface_id.casefold() == metric.interface_id.casefold()
                           and context.interface_index == metric.interface_index
                           for context in inventory.contexts)):
            state = DashboardTrafficState()
        else:
            quality = metric.confidence
            measurement = {
                MeasurementConfidence.UNKNOWN: "Unknown — capture quality not established",
                MeasurementConfidence.COMPLETE: "Complete",
                MeasurementConfidence.REDUCED: "Reduced — capture queue dropped observations",
            }.get(quality, "Unknown — capture quality not established")
            policy = inventory.traffic_policy
            threshold = "—" if policy is None else (
                f"Broadcast >{_format_number(policy.broadcast_floor_pps)} pkt/s; "
                f"ARP >{_format_number(policy.arp_floor_pps)} pkt/s, and "
                f">{_format_number(policy.baseline_multiplier)}× learned baseline; "
                f"{policy.minimum_samples} high samples across the window."
            )
            state = DashboardTrafficState(
                broadcast_rate=_format_rate(metric.broadcast.packets_per_second),
                arp_rate=_format_rate(metric.arp.packets_per_second),
                broadcast_baseline=_format_baseline(metric.broadcast.baseline),
                arp_baseline=_format_baseline(metric.arp.baseline),
                window=f"Last {metric.window_seconds} s rolling window",
                threshold=threshold,
                measurement=measurement,
                capture=("Passive capture running — observed packets only." if capture_running
                         else "Capture off — last rates may be stale."),
                dropped=str(metric.dropped_observations),
            )
        if state != self._traffic:
            self._traffic = state
            self.traffic_changed.emit(state)

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


def _format_number(value: float) -> str:
    if not isfinite(value) or value < 0:
        return "—"
    return f"{value:g}"


def _format_rate(value: float) -> str:
    if not isfinite(value) or value < 0:
        return "—"
    if value == 0:
        return "0 pkt/s"
    return f"{value:.2f} pkt/s" if value < 0.1 else f"{value:.1f} pkt/s"


def _format_baseline(baseline: object) -> str:
    if getattr(baseline, "state", None) is not BaselineState.LEARNED:
        return "Learning baseline"
    value = getattr(baseline, "packets_per_second", None)
    return _format_rate(value) if isinstance(value, (int, float)) else "—"


__all__ = (
    "DashboardHealthState",
    "DashboardMetrics",
    "DashboardTrafficState",
    "DashboardViewModel",
)
