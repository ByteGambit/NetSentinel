"""Presentation model package."""

from netsentinel.presentation.models.connection_filter import (
    ConnectionsFilterProxyModel,
)
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
    ConnectionsTableModel,
)


__all__ = (
    "ConnectionColumn",
    "ConnectionRole",
    "ConnectionsFilterProxyModel",
    "ConnectionsTableModel",
)
