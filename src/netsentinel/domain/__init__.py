"""Framework-independent domain layer."""

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
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
