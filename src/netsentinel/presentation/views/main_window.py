"""Main desktop window and deterministic page navigation."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
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

from netsentinel.presentation.bridge import QtEngineBridge
from netsentinel.presentation.models.connections import ConnectionsTableModel
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.dns import DnsView


class PageId(str, Enum):
    """Stable identities for pages in the desktop shell."""

    DASHBOARD = "dashboard"
    CONNECTIONS = "connections"
    DEVICES = "devices"
    DNS = "dns"
    ALERTS = "alerts"


PAGE_ORDER: tuple[PageId, ...] = (
    PageId.DASHBOARD,
    PageId.CONNECTIONS,
    PageId.DEVICES,
    PageId.DNS,
    PageId.ALERTS,
)

PAGE_LABELS: dict[PageId, str] = {
    PageId.DASHBOARD: "Dashboard",
    PageId.CONNECTIONS: "Connections",
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
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_close = on_close
        self._close_notified = False
        self._current_page = PageId.DASHBOARD
        self._engine_bridge: QtEngineBridge | None = None
        self.connections_model = (
            ConnectionsTableModel(self)
            if connections_model is None
            else connections_model
        )

        self.setObjectName("mainWindow")
        self.setWindowTitle("NetSentinel")
        self.resize(1080, 680)
        self.setMinimumSize(760, 480)

        self.navigation = QListWidget(self)
        self.navigation.setObjectName("navigation")
        self.navigation.setAccessibleName("Primary navigation")
        self.navigation.setFixedWidth(220)
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
            PageId.DASHBOARD: DashboardView(self.content),
            PageId.CONNECTIONS: ConnectionsView(
                model=self.connections_model,
                parent=self.content,
            ),
            PageId.DEVICES: DevicesView(self.content),
            PageId.DNS: DnsView(self.content),
            PageId.ALERTS: AlertsView(self.content),
        }

        for page_id in PAGE_ORDER:
            item = QListWidgetItem(PAGE_LABELS[page_id])
            item.setData(Qt.ItemDataRole.UserRole, page_id.value)
            item.setSizeHint(QSize(0, 42))
            self.navigation.addItem(item)
            self.content.addWidget(self._pages[page_id])

        self.navigation.currentRowChanged.connect(self._on_navigation_changed)
        self.setCentralWidget(self._build_shell())
        self.navigate_to(PageId.DASHBOARD)

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
        self.content.setCurrentWidget(self._pages[page_id])
        self._current_page = page_id


__all__ = ("MainWindow", "PAGE_LABELS", "PAGE_ORDER", "PageId")
