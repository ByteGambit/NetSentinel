"""Framework-independent domain layer."""

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
    ConnectionHistoryRecord,
    ConnectionKey,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TrackedConnection,
    TransportProtocol,
)
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind

__all__ = (
    "ConnectionClosed",
    "ConnectionClosureReason",
    "ConnectionHistoryRecord",
    "ConnectionKey",
    "ConnectionLifecycleEvent",
    "ConnectionOpened",
    "ConnectionSnapshot",
    "ConnectionState",
    "ConnectionUpdated",
    "Endpoint",
    "NetworkContext",
    "NetworkInterfaceKind",
    "ProcessIdentity",
    "ProcessInfo",
    "ProcessInfoStatus",
    "TrackedConnection",
    "TransportProtocol",
)
