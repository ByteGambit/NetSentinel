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
    "ProcessIdentity",
    "ProcessInfo",
    "ProcessInfoStatus",
    "TrackedConnection",
    "TransportProtocol",
)
