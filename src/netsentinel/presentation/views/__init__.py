"""Presentation view package."""

from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.dns import DnsView
from netsentinel.presentation.views.main_window import MainWindow, PageId

__all__ = (
    "AlertsView",
    "ConnectionsView",
    "DashboardView",
    "DevicesView",
    "DnsView",
    "MainWindow",
    "PageId",
)
from netsentinel.presentation.views.history import HistoryView

__all__ = ("HistoryView",)
