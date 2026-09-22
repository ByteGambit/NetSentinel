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
from netsentinel.domain.observations import (
    LinkLayerProtocol,
    NetworkLayerProtocol,
    ObservationSource,
    PacketObservation,
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
    "LinkLayerProtocol",
    "NetworkContext",
    "NetworkInterfaceKind",
    "NetworkLayerProtocol",
    "ObservationSource",
    "PacketObservation",
    "ProcessIdentity",
    "ProcessInfo",
    "ProcessInfoStatus",
    "TrackedConnection",
    "TransportProtocol",
)
