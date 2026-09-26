"""Main desktop window and deterministic page navigation."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.presentation.bridge import QtEngineBridge
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator
from netsentinel.presentation.history_query import HistoryQueryCoordinator
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.dns_query import DnsQueryCoordinator
from netsentinel.presentation.models.connections import ConnectionsTableModel
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.dns import DnsView
from netsentinel.presentation.views.history import HistoryView


class PageId(str, Enum):
    """Stable identities for pages in the desktop shell."""

    DASHBOARD = "dashboard"
    CONNECTIONS = "connections"
    HISTORY = "history"
    DEVICES = "devices"
    DNS = "dns"
    ALERTS = "alerts"


PAGE_ORDER: tuple[PageId, ...] = (
    PageId.DASHBOARD,
    PageId.CONNECTIONS,
    PageId.HISTORY,
    PageId.DEVICES,
    PageId.DNS,
    PageId.ALERTS,
)

PAGE_LABELS: dict[PageId, str] = {
    PageId.DASHBOARD: "Dashboard",
    PageId.CONNECTIONS: "Connections",
    PageId.HISTORY: "History",
    PageId.DEVICES: "Devices",
    PageId.DNS: "DNS",
    PageId.ALERTS: "Alerts",
}


class MainWindow(QMainWindow):
    """Own all top-level views and switch one content page at a time."""

    def __init__(
        self,
        *,
        on_close: Callable[[], object] | None = None,
        connections_model: ConnectionsTableModel | None = None,
        statistics: StatisticsService | None = None,
        history_queries: HistoryQueryCoordinator | None = None,
        device_inventory: DeviceInventoryCoordinator | None = None,
        alert_queries: AlertQueryCoordinator | None = None,
        dns_queries: DnsQueryCoordinator | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_close = on_close
        self._close_notified = False
        self._current_page = PageId.DASHBOARD
        self._engine_bridge: QtEngineBridge | None = None
        self._device_inventory = device_inventory
        self._dns_persisted_count = 0
        self.connections_model = (
            ConnectionsTableModel(self)
            if connections_model is None
            else connections_model
        )
        self.statistics = StatisticsService() if statistics is None else statistics

        self.setObjectName("mainWindow")
        self.setAccessibleName("NetSentinel main window")
        self.setWindowTitle("NetSentinel")
        self.resize(1080, 680)
        self.setMinimumSize(760, 480)

        self.navigation = QListWidget(self)
        self.navigation.setObjectName("navigation")
        self.navigation.setAccessibleName("Primary navigation")
        # Keep the sidebar bounded without forcing one device-pixel geometry.
        # Qt can therefore expand it when a larger logical font/DPI needs room.
        self.navigation.setMinimumWidth(180)
        self.navigation.setMaximumWidth(300)
        self.navigation.setSpacing(4)
        self.navigation.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.navigation.setStyleSheet(
            "QListWidget { border: 0; background: #f4f6f8; color: #243b53; "
            "padding: 8px; }"
            "QListWidget::item { border-radius: 5px; color: #243b53; "
            "padding-left: 12px; }"
            "QListWidget::item:hover:!selected { background: #e7edf3; "
            "color: #102a43; }"
            "QListWidget::item:selected { background: #dce8f7; color: #163a5f; }"
        )

        self.content = QStackedWidget(self)
        self.content.setObjectName("content")
        self.content.setAccessibleName("Page content")

        self._pages: dict[PageId, QWidget] = {
            PageId.DASHBOARD: DashboardView(
                model=self.connections_model,
                statistics=self.statistics,
                parent=self.content,
            ),
            PageId.CONNECTIONS: ConnectionsView(
                model=self.connections_model,
                parent=self.content,
            ),
            PageId.HISTORY: HistoryView(history_queries, parent=self.content),
            PageId.DEVICES: DevicesView(self.content, coordinator=device_inventory),
            PageId.DNS: DnsView(self.content, coordinator=dns_queries),
            PageId.ALERTS: AlertsView(self.content, coordinator=alert_queries),
        }

        for page_id in PAGE_ORDER:
            item = QListWidgetItem(PAGE_LABELS[page_id])
            item.setData(Qt.ItemDataRole.UserRole, page_id.value)
            item.setData(
                Qt.ItemDataRole.AccessibleTextRole,
                f"{PAGE_LABELS[page_id]} page",
            )
            item.setSizeHint(
                QSize(0, max(42, self.navigation.fontMetrics().height() + 18))
            )
            self.navigation.addItem(item)
            self.content.addWidget(self._pages[page_id])

        self.navigation.currentRowChanged.connect(self._on_navigation_changed)
        self.setCentralWidget(self._build_shell())
        self._configure_tab_order()
        self.navigate_to(PageId.DASHBOARD)
        if device_inventory is not None:
            device_inventory.snapshot_ready.connect(self._on_device_snapshot_for_alerts)
        dns = self.page_widget(PageId.DNS)
        assert isinstance(dns, DnsView)
        dns.config_alert_requested.connect(self._show_dns_config_alerts)

    def _show_dns_config_alerts(self) -> None:
        alerts = self.page_widget(PageId.ALERTS)
        assert isinstance(alerts, AlertsView)
        index = alerts.rule_filter.findData("dns_server_set_change")
        alerts.rule_filter.setCurrentIndex(index if index >= 0 else 0)
        self.navigate_to(PageId.ALERTS)
        alerts.refresh()

    def _on_device_snapshot_for_alerts(self, snapshot: object) -> None:
        if self._close_notified or (self._device_inventory is not None
                                   and not self._device_inventory.accepting):
            return
        dashboard = self.page_widget(PageId.DASHBOARD)
        assert isinstance(dashboard, DashboardView)
        dashboard.view_model.set_traffic_snapshot(snapshot)
        alerts = self.page_widget(PageId.ALERTS)
        assert isinstance(alerts, AlertsView)
        alerts.set_network_contexts(snapshot.contexts)
        dns = self.page_widget(PageId.DNS)
        assert isinstance(dns, DnsView)
        dns.set_network_contexts(snapshot.contexts)
        dns.set_capture_running(bool(snapshot.capture and snapshot.capture.running))
        dns.set_writer_available(snapshot.dns_writer_available)
        if snapshot.dns_persisted_count > self._dns_persisted_count:
            self._dns_persisted_count = snapshot.dns_persisted_count
            dns.refresh()
        if snapshot.new_devices or snapshot.arp_assessments or snapshot.traffic_alert_changed:
            alerts.refresh()

    def bind_engine_bridge(self, bridge: QtEngineBridge) -> bool:
        """Wire one bridge to the connection model and health view exactly once."""

        if not isinstance(bridge, QtEngineBridge):
            raise TypeError("bridge must be a QtEngineBridge")
        if self._engine_bridge is bridge:
            return False
        if self._engine_bridge is not None:
            raise RuntimeError("MainWindow is already bound to an engine bridge")

        bridge.connection_opened.connect(
            self.connections_model.handle_connection_opened
        )
        bridge.connection_updated.connect(
            self.connections_model.handle_connection_updated
        )
        bridge.connection_closed.connect(
            self.connections_model.handle_connection_closed
        )
        connections_view = self.page_widget(PageId.CONNECTIONS)
        assert isinstance(connections_view, ConnectionsView)
        bridge.health_changed.connect(connections_view.set_health)
        dashboard_view = self.page_widget(PageId.DASHBOARD)
        assert isinstance(dashboard_view, DashboardView)
        bridge.events_ready.connect(dashboard_view.view_model.handle_events)
        bridge.health_changed.connect(dashboard_view.view_model.set_health)
        self._engine_bridge = bridge
        return True

    @property
    def current_page(self) -> PageId:
        """Return the stable identity of the page currently being displayed."""

        return self._current_page

    def page_widget(self, page_id: PageId) -> QWidget:
        """Return the single view instance owned by this window."""

        if not isinstance(page_id, PageId):
            raise TypeError("page_id must be a PageId")
        return self._pages[page_id]

    def navigation_item(self, page_id: PageId) -> QListWidgetItem:
        """Return a page's navigation item for tests and accessibility helpers."""

        if not isinstance(page_id, PageId):
            raise TypeError("page_id must be a PageId")
        return self.navigation.item(PAGE_ORDER.index(page_id))

    def navigate_to(self, page_id: PageId) -> None:
        """Select a page; selecting the current page is an idempotent operation."""

        if not isinstance(page_id, PageId):
            raise TypeError("page_id must be a PageId")
        row = PAGE_ORDER.index(page_id)
        self.navigation.setCurrentRow(row)
        # QListWidget does not emit currentRowChanged when the row is already
        # selected. Keep programmatic repeated selection explicit and harmless.
        self._show_page(page_id)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        """Request application shutdown exactly once before accepting close."""

        if not self._close_notified:
            self._close_notified = True
            if self._on_close is not None:
                self._on_close()
        super().closeEvent(event)

    def _build_shell(self) -> QWidget:
        shell = QWidget(self)
        shell.setObjectName("applicationShell")

        sidebar = QFrame(shell)
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet("QFrame#sidebar { background: #f4f6f8; }")

        brand = QLabel("NetSentinel", sidebar)
        brand.setObjectName("brand")
        brand.setStyleSheet(
            "font-size: 20px; font-weight: 700; color: #102a43; padding: 8px;"
        )

        tagline = QLabel("Network Security Monitor", sidebar)
        tagline.setObjectName("tagline")
        tagline.setStyleSheet("color: #627d98; padding: 0 8px 8px 8px;")

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(4)
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(tagline)
        sidebar_layout.addSpacing(14)
        sidebar_layout.addWidget(self.navigation, 1)

        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(sidebar)
        shell_layout.addWidget(self.content, 1)
        return shell

    def _on_navigation_changed(self, row: int) -> None:
        if row < 0 or row >= len(PAGE_ORDER):
            return
        self._show_page(PAGE_ORDER[row])

    def _show_page(self, page_id: PageId) -> None:
        previous_page = self.content.currentWidget()
        focused = QApplication.focusWidget()
        self.content.setCurrentWidget(self._pages[page_id])
        self._current_page = page_id
        if (
            previous_page is not self._pages[page_id]
            and focused is not None
            and (
                focused is previous_page
                or previous_page.isAncestorOf(focused)
            )
        ):
            # Programmatic page changes must not leave focus on a now-hidden
            # child. Keyboard navigation changes already keep focus here.
            self.navigation.setFocus(Qt.FocusReason.OtherFocusReason)

    def _configure_tab_order(self) -> None:
        """Define the one critical keyboard path while retaining Qt defaults."""

        connections = self.page_widget(PageId.CONNECTIONS)
        assert isinstance(connections, ConnectionsView)
        QWidget.setTabOrder(self.navigation, connections.search_edit)
        QWidget.setTabOrder(connections.search_edit, connections.protocol_filter)
        QWidget.setTabOrder(connections.protocol_filter, connections.state_filter)
        QWidget.setTabOrder(connections.state_filter, connections.pause_button)
        QWidget.setTabOrder(connections.pause_button, connections.table)
        history = self.page_widget(PageId.HISTORY)
        assert isinstance(history, HistoryView)
        QWidget.setTabOrder(self.navigation, history.process_filter)
        QWidget.setTabOrder(history.process_filter, history.pid_filter)
        QWidget.setTabOrder(history.pid_filter, history.endpoint_filter)
        QWidget.setTabOrder(history.endpoint_filter, history.protocol_filter)
        QWidget.setTabOrder(history.protocol_filter, history.from_enabled)
        QWidget.setTabOrder(history.from_enabled, history.from_time)
        QWidget.setTabOrder(history.from_time, history.to_enabled)
        QWidget.setTabOrder(history.to_enabled, history.to_time)
        QWidget.setTabOrder(history.to_time, history.refresh_button)
        QWidget.setTabOrder(history.refresh_button, history.table)
        QWidget.setTabOrder(history.table, history.previous_button)
        QWidget.setTabOrder(history.previous_button, history.next_button)
        dns = self.page_widget(PageId.DNS)
        assert isinstance(dns, DnsView)
        QWidget.setTabOrder(self.navigation, dns.qname_filter)
        QWidget.setTabOrder(dns.qname_filter, dns.type_filter)
        QWidget.setTabOrder(dns.type_filter, dns.server_filter)
        QWidget.setTabOrder(dns.server_filter, dns.status_filter)
        QWidget.setTabOrder(dns.status_filter, dns.from_enabled)
        QWidget.setTabOrder(dns.from_enabled, dns.from_time)
        QWidget.setTabOrder(dns.from_time, dns.to_enabled)
        QWidget.setTabOrder(dns.to_enabled, dns.to_time)
        QWidget.setTabOrder(dns.to_time, dns.refresh_button)
        QWidget.setTabOrder(dns.refresh_button, dns.alert_button)
        QWidget.setTabOrder(dns.alert_button, dns.table)
        QWidget.setTabOrder(dns.table, dns.previous_button)
        QWidget.setTabOrder(dns.previous_button, dns.next_button)
        devices = self.page_widget(PageId.DEVICES)
        assert isinstance(devices, DevicesView)
        QWidget.setTabOrder(self.navigation, devices.network_selector)
        QWidget.setTabOrder(devices.network_selector, devices.search_edit)
        QWidget.setTabOrder(devices.search_edit, devices.refresh_button)
        QWidget.setTabOrder(devices.refresh_button, devices.capture_button)
        QWidget.setTabOrder(devices.capture_button, devices.table)
        alerts = self.page_widget(PageId.ALERTS)
        assert isinstance(alerts, AlertsView)
        QWidget.setTabOrder(self.navigation, alerts.status_filter)
        QWidget.setTabOrder(alerts.status_filter, alerts.severity_filter)
        QWidget.setTabOrder(alerts.severity_filter, alerts.confidence_filter)
        QWidget.setTabOrder(alerts.confidence_filter, alerts.rule_filter)
        QWidget.setTabOrder(alerts.rule_filter, alerts.refresh_button)
        QWidget.setTabOrder(alerts.refresh_button, alerts.table)
        QWidget.setTabOrder(alerts.table, alerts.previous_button)
        QWidget.setTabOrder(alerts.previous_button, alerts.next_button)
        QWidget.setTabOrder(alerts.next_button, alerts.acknowledge_button)


__all__ = ("MainWindow", "PAGE_LABELS", "PAGE_ORDER", "PageId")
