"""Presentation model package."""

from netsentinel.presentation.models.connection_filter import (
    ConnectionsFilterProxyModel,
)
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
    ConnectionsTableModel,
)
from netsentinel.presentation.models.dashboard import (
    DashboardHealthState,
    DashboardMetrics,
    DashboardViewModel,
)


__all__ = (
    "ConnectionColumn",
    "ConnectionRole",
    "ConnectionsFilterProxyModel",
    "ConnectionsTableModel",
    "DashboardHealthState",
    "DashboardMetrics",
    "DashboardViewModel",
)
from netsentinel.presentation.models.history import HistoryTableModel

__all__ = ("HistoryTableModel",)
