"""Live Dashboard backed by shared presentation state."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.presentation.models.connections import ConnectionsTableModel
from netsentinel.presentation.models.dashboard import (
    DashboardHealthState,
    DashboardMetrics,
    DashboardTrafficState,
    DashboardViewModel,
)
from netsentinel.presentation.models.vlan import VlanDashboardState, vlan_dashboard_state
from netsentinel.application.services.device_inventory import DeviceInventorySnapshot


class DashboardView(QWidget):
    """Compact live summary of connections and monitoring health."""

    def __init__(
        self,
        model: ConnectionsTableModel | None = None,
        statistics: StatisticsService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("dashboardPage")
        self.setAccessibleName("Dashboard")
        self.setStyleSheet(
            "QWidget#dashboardPage { background: #ffffff; color: #243b53; }"
        )

        self.connections_model = (
            ConnectionsTableModel(self) if model is None else model
        )
        self.view_model = DashboardViewModel(
            self.connections_model,
            StatisticsService() if statistics is None else statistics,
            self,
        )

        self.title_label = QLabel("Dashboard", self)
        self.title_label.setObjectName("pageTitle")
        self.title_label.setStyleSheet(
            "font-size: 24px; font-weight: 700; color: #102a43;"
        )
        self.subtitle_label = QLabel(
            "Live connection counts and monitoring health.", self
        )
        self.subtitle_label.setObjectName("pageDescription")
        self.subtitle_label.setStyleSheet("color: #627d98;")

        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(10)
        metrics_grid.setVerticalSpacing(10)
        self.total_value = self._add_metric_card(
            metrics_grid, 0, 0, "Active Connections", "activeConnectionsMetric"
        )
        self.tcp_value = self._add_metric_card(
            metrics_grid, 0, 1, "TCP", "tcpConnectionsMetric"
        )
        self.udp_value = self._add_metric_card(
            metrics_grid, 0, 2, "UDP", "udpConnectionsMetric"
        )
        self.listening_value = self._add_metric_card(
            metrics_grid, 1, 0, "Listening TCP", "listeningConnectionsMetric"
        )
        self.remote_hosts_value = self._add_metric_card(
            metrics_grid, 1, 1, "Remote Hosts", "remoteHostsMetric"
        )
        self.opened_value = self._add_metric_card(
            metrics_grid, 1, 2, "Opened (last 60s)", "openedEventsMetric"
        )
        self.closed_value = self._add_metric_card(
            metrics_grid, 2, 2, "Closed (last 60s)", "closedEventsMetric"
        )

        traffic_frame = QFrame(self)
        traffic_frame.setObjectName("dashboardTrafficCard")
        traffic_frame.setAccessibleName("Broadcast and ARP monitoring summary")
        traffic_frame.setStyleSheet(
            "QFrame#dashboardTrafficCard { background: #f8fafc; "
            "border: 1px solid #d9e2ec; border-radius: 6px; }"
        )
        traffic_layout = QGridLayout(traffic_frame)
        traffic_layout.setContentsMargins(16, 12, 16, 12)
        traffic_title = QLabel("Broadcast and ARP", traffic_frame)
        traffic_title.setStyleSheet("font-size: 16px; font-weight: 600; color: #102a43;")
        traffic_layout.addWidget(traffic_title, 0, 0, 1, 2)
        self.broadcast_rate_label = self._add_traffic_row(traffic_layout, 1, "Broadcast rate", "dashboardBroadcastRate")
        self.arp_rate_label = self._add_traffic_row(traffic_layout, 2, "ARP rate", "dashboardArpRate")
        self.broadcast_baseline_label = self._add_traffic_row(traffic_layout, 3, "Broadcast baseline", "dashboardBroadcastBaseline")
        self.arp_baseline_label = self._add_traffic_row(traffic_layout, 4, "ARP baseline", "dashboardArpBaseline")
        self.traffic_window_label = self._add_traffic_row(traffic_layout, 5, "Measurement window", "dashboardTrafficWindow")
        self.traffic_threshold_label = self._add_traffic_row(traffic_layout, 6, "Alert threshold", "dashboardTrafficThreshold")
        self.traffic_quality_label = self._add_traffic_row(traffic_layout, 7, "Measurement quality", "dashboardTrafficQuality")
        self.capture_drop_label = self._add_traffic_row(traffic_layout, 8, "Dropped observations in window", "dashboardCaptureDrops")
        self.traffic_capture_label = QLabel(traffic_frame)
        self.traffic_capture_label.setObjectName("dashboardTrafficCapture")
        self.traffic_capture_label.setAccessibleName("Traffic capture status")
        traffic_layout.addWidget(self.traffic_capture_label, 9, 0, 1, 2)

        vlan_frame = QFrame(self)
        vlan_frame.setObjectName("dashboardVlanCard")
        vlan_frame.setAccessibleName("Selected network VLAN observations")
        vlan_frame.setStyleSheet(
            "QFrame#dashboardVlanCard { background: #f8fafc; "
            "border: 1px solid #d9e2ec; border-radius: 6px; }"
        )
        vlan_layout = QVBoxLayout(vlan_frame)
        vlan_layout.setContentsMargins(16, 12, 16, 12)
        vlan_title = QLabel("VLAN observations", vlan_frame)
        vlan_title.setStyleSheet("font-size: 16px; font-weight: 600; color: #102a43;")
        vlan_layout.addWidget(vlan_title)
        self.vlan_labels = {}
        for key, name in (("scope", "VLAN scope"), ("status", "VLAN observation status"),
                          ("baseline", "VLAN baseline state"), ("observed", "Observed VLAN IDs"),
                          ("reference", "Learned or verified reference IDs"),
                          ("counts", "VLAN category counts"), ("times", "VLAN first and last seen"),
                          ("visibility", "VLAN capture visibility limitation")):
            label = QLabel(vlan_frame)
            label.setObjectName(f"dashboardVlan_{key}")
            label.setAccessibleName(name)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            vlan_layout.addWidget(label)
            self.vlan_labels[key] = label
        self.vlan_rows = QPlainTextEdit(vlan_frame)
        self.vlan_rows.setObjectName("dashboardVlanRows")
        self.vlan_rows.setAccessibleName("Observed VLAN ID counts and first and last seen")
        self.vlan_rows.setReadOnly(True)
        self.vlan_rows.setMaximumHeight(150)
        vlan_layout.insertWidget(7, self.vlan_rows)
        self.set_vlan_state(VlanDashboardState())

        health_frame = QFrame(self)
        health_frame.setObjectName("dashboardHealthCard")
        health_frame.setAccessibleName("Monitoring health summary")
        health_frame.setFrameShape(QFrame.Shape.StyledPanel)
        health_frame.setStyleSheet(
            "QFrame#dashboardHealthCard { background: #f8fafc; "
            "border: 1px solid #d9e2ec; border-radius: 6px; }"
        )
        health_title = QLabel("Monitoring Status", health_frame)
        health_title.setStyleSheet(
            "font-size: 16px; font-weight: 600; color: #102a43;"
        )
        self.status_label = QLabel("● Waiting", health_frame)
        self.status_label.setObjectName("dashboardMonitoringStatus")
        self.status_label.setAccessibleName("Monitoring status")
        self.status_label.setStyleSheet("font-weight: 600; color: #627d98;")
        self.health_detail_label = QLabel(
            "Waiting for monitoring status.", health_frame
        )
        self.health_detail_label.setObjectName("dashboardHealthDetail")
        self.health_detail_label.setAccessibleName("Monitoring health detail")
        self.health_detail_label.setStyleSheet("color: #243b53;")
        self.capability_label = QLabel(
            "Capability status is not available yet.", health_frame
        )
        self.capability_label.setObjectName("dashboardCapability")
        self.capability_label.setAccessibleName("Monitoring capability")
        self.capability_label.setStyleSheet("color: #334e68;")
        self.diagnostic_label = QLabel(
            "No monitoring status has been received.", health_frame
        )
        self.diagnostic_label.setObjectName("dashboardDiagnostic")
        self.diagnostic_label.setAccessibleName("Monitoring diagnostic")
        self.diagnostic_label.setWordWrap(True)
        self.diagnostic_label.setStyleSheet("color: #334e68;")

        poll_caption = QLabel("Last successful poll", health_frame)
        poll_caption.setStyleSheet("color: #627d98;")
        self.last_poll_label = QLabel("—", health_frame)
        self.last_poll_label.setObjectName("dashboardLastSuccessfulPoll")
        self.last_poll_label.setAccessibleName("Last successful poll")
        self.last_poll_label.setStyleSheet("color: #243b53;")
        dropped_caption = QLabel("Dropped UI events", health_frame)
        dropped_caption.setStyleSheet("color: #627d98;")
        self.dropped_events_label = QLabel("0", health_frame)
        self.dropped_events_label.setObjectName("dashboardDroppedEvents")
        self.dropped_events_label.setAccessibleName("Dropped UI events")
        self.dropped_events_label.setStyleSheet("color: #243b53;")

        facts = QGridLayout()
        facts.addWidget(poll_caption, 0, 0)
        facts.addWidget(self.last_poll_label, 0, 1)
        facts.addWidget(dropped_caption, 1, 0)
        facts.addWidget(self.dropped_events_label, 1, 1)
        facts.setColumnStretch(2, 1)

        health_layout = QVBoxLayout(health_frame)
        health_layout.setContentsMargins(16, 14, 16, 14)
        health_layout.setSpacing(6)
        health_layout.addWidget(health_title)
        health_layout.addWidget(self.status_label)
        health_layout.addWidget(self.health_detail_label)
        health_layout.addWidget(self.capability_label)
        health_layout.addWidget(self.diagnostic_label)
        health_layout.addLayout(facts)

        content = QWidget(self)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addLayout(metrics_grid)
        layout.addWidget(traffic_frame)
        layout.addWidget(vlan_frame)
        layout.addWidget(health_frame)
        layout.addStretch(1)

        scroll = QScrollArea(self)
        scroll.setObjectName("dashboardScrollArea")
        scroll.setAccessibleName("Dashboard content")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self.view_model.metrics_changed.connect(self.set_metrics)
        self.view_model.health_changed.connect(self.set_health)
        self.view_model.traffic_changed.connect(self.set_traffic)
        self.set_metrics(self.view_model.metrics)
        self.set_health(self.view_model.health)
        self.set_traffic(self.view_model.traffic)

    @pyqtSlot(DashboardTrafficState)
    def set_traffic(self, traffic: DashboardTrafficState) -> None:
        self.broadcast_rate_label.setText(traffic.broadcast_rate)
        self.arp_rate_label.setText(traffic.arp_rate)
        self.broadcast_baseline_label.setText(traffic.broadcast_baseline)
        self.arp_baseline_label.setText(traffic.arp_baseline)
        self.traffic_window_label.setText(traffic.window)
        self.traffic_threshold_label.setText(traffic.threshold)
        self.traffic_quality_label.setText(traffic.measurement)
        self.capture_drop_label.setText(traffic.dropped)
        self.traffic_capture_label.setText(traffic.capture)

    def set_vlan_snapshot(self, inventory: DeviceInventorySnapshot) -> None:
        self.set_vlan_state(vlan_dashboard_state(inventory))

    def set_vlan_state(self, state: VlanDashboardState) -> None:
        for key, label in self.vlan_labels.items():
            label.setText(getattr(state, key))
        if self.vlan_rows.toPlainText() != state.rows:
            self.vlan_rows.setPlainText(state.rows)

    def _add_traffic_row(self, grid: QGridLayout, row: int, title: str, name: str) -> QLabel:
        caption = QLabel(title, self)
        value = QLabel("—", self)
        value.setObjectName(name)
        value.setAccessibleName(title)
        value.setTextFormat(Qt.TextFormat.PlainText)
        value.setWordWrap(True)
        grid.addWidget(caption, row, 0)
        grid.addWidget(value, row, 1)
        return value

    @pyqtSlot(DashboardMetrics)
    def set_metrics(self, metrics: DashboardMetrics) -> None:
        self.total_value.setText(str(metrics.total_connections))
        self.tcp_value.setText(str(metrics.tcp_connections))
        self.udp_value.setText(str(metrics.udp_connections))
        self.listening_value.setText(str(metrics.listening_connections))
        self.remote_hosts_value.setText(str(metrics.remote_hosts))
        self.opened_value.setText(str(metrics.opened_events))
        self.closed_value.setText(str(metrics.closed_events))

    @pyqtSlot(DashboardHealthState)
    def set_health(self, health: DashboardHealthState) -> None:
        colors = {
            "healthy": "#276749",
            "warning": "#8d5b00",
            "error": "#9b2c2c",
            "neutral": "#627d98",
        }
        self.status_label.setText(f"● {health.status}")
        self.status_label.setStyleSheet(
            f"font-weight: 600; color: {colors[health.tone]};"
        )
        self.health_detail_label.setText(health.detail)
        self.capability_label.setText(health.capability)
        self.diagnostic_label.setText(health.diagnostic)
        self.last_poll_label.setText(health.last_successful_poll)
        self.dropped_events_label.setText(str(health.dropped_bridge_events))

    def _add_metric_card(
        self,
        grid: QGridLayout,
        row: int,
        column: int,
        title: str,
        object_name: str,
    ) -> QLabel:
        card = QFrame(self)
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.setStyleSheet(
            "QFrame { background: white; border: 1px solid #d9e2ec; "
            "border-radius: 6px; } QLabel { border: 0; }"
        )
        caption = QLabel(title, card)
        caption.setStyleSheet("color: #627d98;")
        value = QLabel("0", card)
        value.setObjectName(object_name)
        value.setAccessibleName(title)
        value.setAlignment(Qt.AlignmentFlag.AlignRight)
        value.setStyleSheet(
            "font-size: 25px; font-weight: 700; color: #102a43;"
        )
        card_layout = QHBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.addWidget(caption)
        card_layout.addStretch(1)
        card_layout.addWidget(value)
        grid.addWidget(card, row, column)
        return value


__all__ = ("DashboardView",)
