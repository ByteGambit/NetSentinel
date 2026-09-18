"""Framework-independent domain models for network connections.

The models in this module deliberately use only Python standard-library types.
Adapters are responsible for translating operating-system or third-party values
into these domain concepts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from ipaddress import ip_address
from typing import TypeAlias


class TransportProtocol(str, Enum):
    """Transport protocols supported by connection monitoring."""

    TCP = "tcp"
    UDP = "udp"


class ConnectionState(str, Enum):
    """Portable connection states, independent of OS-specific constants."""

    NONE = "none"
    LISTEN = "listen"
    ESTABLISHED = "established"
    SYN_SENT = "syn_sent"
    SYN_RECEIVED = "syn_received"
    FIN_WAIT_1 = "fin_wait_1"
    FIN_WAIT_2 = "fin_wait_2"
    CLOSE_WAIT = "close_wait"
    CLOSING = "closing"
    LAST_ACK = "last_ack"
    TIME_WAIT = "time_wait"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class ProcessInfoStatus(str, Enum):
    """Describes why process metadata is or is not available."""

    AVAILABLE = "available"
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"


class ConnectionClosureReason(str, Enum):
    """Domain-level reason for considering a connection closed."""

    NOT_OBSERVED = "not_observed"


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """An immutable, canonical IP address and transport port pair."""

    address: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.address, str):
            raise TypeError("address must be a string")
        try:
            canonical_address = str(ip_address(self.address))
        except ValueError as error:
            raise ValueError(f"invalid IP address: {self.address!r}") from error

        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port must be an integer")
        if not 0 <= self.port <= 65_535:
            raise ValueError("port must be between 0 and 65535")

        object.__setattr__(self, "address", canonical_address)

    @property
    def ip_version(self) -> int:
        """Return 4 or 6 for the endpoint's canonical address."""

        return ip_address(self.address).version


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Identity of one process instance rather than only a reusable PID.

    ``create_time`` may be absent when the operating system exposes a PID but
    denies or races process metadata access. When present, it distinguishes two
    process instances that reused the same PID.
    """

    pid: int
    create_time: datetime | None = None

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int):
            raise TypeError("pid must be an integer")
        if self.pid < 0:
            raise ValueError("pid must be zero or greater")
        if self.create_time is not None:
            object.__setattr__(
                self,
                "create_time",
                _require_utc(self.create_time, "create_time"),
            )


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Process identity plus explicitly modelled metadata availability."""

    status: ProcessInfoStatus
    identity: ProcessIdentity | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProcessInfoStatus):
            raise TypeError("status must be a ProcessInfoStatus")
        if self.identity is not None and not isinstance(
            self.identity, ProcessIdentity
        ):
            raise TypeError("identity must be a ProcessIdentity or None")
        if self.name is not None and not isinstance(self.name, str):
            raise TypeError("name must be a string or None")
        if self.name is not None and not self.name.strip():
            raise ValueError("name must not be empty")

        if self.status is ProcessInfoStatus.AVAILABLE:
            if self.identity is None or self.name is None:
                raise ValueError(
                    "available process info requires both identity and name"
                )
        elif self.name is not None:
            raise ValueError("unavailable process info cannot include a name")

        if (
            self.status
            in {ProcessInfoStatus.ACCESS_DENIED, ProcessInfoStatus.NOT_FOUND}
            and self.identity is None
        ):
            raise ValueError(f"{self.status.value} process info requires an identity")

    @classmethod
    def unavailable(cls) -> ProcessInfo:
        """Create an explicit value for a connection with no process data."""

        return cls(status=ProcessInfoStatus.UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class ConnectionKey:
    """Stable identity used to match one connection across observations.

    State and process metadata are intentionally excluded. A known process
    create time participates through ``process_identity`` so PID reuse creates
    a different key.
    """

    protocol: TransportProtocol
    local_endpoint: Endpoint
    remote_endpoint: Endpoint | None
    process_identity: ProcessIdentity | None

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, TransportProtocol):
            raise TypeError("protocol must be a TransportProtocol")
        if not isinstance(self.local_endpoint, Endpoint):
            raise TypeError("local_endpoint must be an Endpoint")
        if self.remote_endpoint is not None and not isinstance(
            self.remote_endpoint, Endpoint
        ):
            raise TypeError("remote_endpoint must be an Endpoint or None")
        if self.process_identity is not None and not isinstance(
            self.process_identity, ProcessIdentity
        ):
            raise TypeError("process_identity must be a ProcessIdentity or None")
        if (
            self.remote_endpoint is not None
            and self.local_endpoint.ip_version != self.remote_endpoint.ip_version
        ):
            raise ValueError("local and remote endpoints must use the same IP version")


@dataclass(frozen=True, slots=True)
class ConnectionSnapshot:
    """One normalized observation of a TCP or UDP connection."""

    protocol: TransportProtocol
    local_endpoint: Endpoint
    remote_endpoint: Endpoint | None
    state: ConnectionState
    process: ProcessInfo
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, TransportProtocol):
            raise TypeError("protocol must be a TransportProtocol")
        if not isinstance(self.local_endpoint, Endpoint):
            raise TypeError("local_endpoint must be an Endpoint")
        if self.remote_endpoint is not None and not isinstance(
            self.remote_endpoint, Endpoint
        ):
            raise TypeError("remote_endpoint must be an Endpoint or None")
        if not isinstance(self.state, ConnectionState):
            raise TypeError("state must be a ConnectionState")
        if not isinstance(self.process, ProcessInfo):
            raise TypeError("process must be a ProcessInfo")
        if (
            self.remote_endpoint is not None
            and self.local_endpoint.ip_version != self.remote_endpoint.ip_version
        ):
            raise ValueError("local and remote endpoints must use the same IP version")

        if self.protocol is TransportProtocol.UDP:
            if self.state is not ConnectionState.NONE:
                raise ValueError("UDP snapshots must use ConnectionState.NONE")
        elif self.state is ConnectionState.NONE:
            raise ValueError("TCP snapshots cannot use ConnectionState.NONE")

        if self.state is ConnectionState.LISTEN:
            if self.protocol is not TransportProtocol.TCP:
                raise ValueError("only TCP snapshots can be in LISTEN state")
            if self.remote_endpoint is not None:
                raise ValueError("a listening TCP socket cannot have a remote endpoint")

        object.__setattr__(
            self,
            "observed_at",
            _require_utc(self.observed_at, "observed_at"),
        )

    @property
    def key(self) -> ConnectionKey:
        """Build the stable identity for this observation."""

        return ConnectionKey(
            protocol=self.protocol,
            local_endpoint=self.local_endpoint,
            remote_endpoint=self.remote_endpoint,
            process_identity=self.process.identity,
        )


@dataclass(frozen=True, slots=True)
class ConnectionOpened:
    """Signals that a connection key appeared in a snapshot."""

    snapshot: ConnectionSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, ConnectionSnapshot):
            raise TypeError("snapshot must be a ConnectionSnapshot")

    @property
    def key(self) -> ConnectionKey:
        return self.snapshot.key

    @property
    def occurred_at(self) -> datetime:
        return self.snapshot.observed_at


@dataclass(frozen=True, slots=True)
class ConnectionUpdated:
    """Signals a new observation for an already known connection key."""

    previous: ConnectionSnapshot
    current: ConnectionSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.previous, ConnectionSnapshot):
            raise TypeError("previous must be a ConnectionSnapshot")
        if not isinstance(self.current, ConnectionSnapshot):
            raise TypeError("current must be a ConnectionSnapshot")
        if self.previous.key != self.current.key:
            raise ValueError("updated snapshots must have the same connection key")
        if self.current.observed_at < self.previous.observed_at:
            raise ValueError("current observation cannot precede previous observation")

    @property
    def key(self) -> ConnectionKey:
        return self.current.key

    @property
    def occurred_at(self) -> datetime:
        return self.current.observed_at


@dataclass(frozen=True, slots=True)
class ConnectionClosed:
    """Signals that a connection is no longer present in a later snapshot.

    ``NOT_OBSERVED`` describes snapshot visibility only. It does not claim that
    a TCP FIN/RST was captured, and for UDP it must not be interpreted as a
    protocol-level session close.
    """

    last_snapshot: ConnectionSnapshot
    occurred_at: datetime
    reason: ConnectionClosureReason = ConnectionClosureReason.NOT_OBSERVED

    def __post_init__(self) -> None:
        if not isinstance(self.last_snapshot, ConnectionSnapshot):
            raise TypeError("last_snapshot must be a ConnectionSnapshot")
        if not isinstance(self.reason, ConnectionClosureReason):
            raise TypeError("reason must be a ConnectionClosureReason")
        object.__setattr__(
            self,
            "occurred_at",
            _require_utc(self.occurred_at, "occurred_at"),
        )
        if self.occurred_at < self.last_snapshot.observed_at:
            raise ValueError("close time cannot precede the last observation")

    @property
    def key(self) -> ConnectionKey:
        return self.last_snapshot.key


@dataclass(frozen=True, slots=True)
class TrackedConnection:
    """Current lifecycle state retained for one active connection key."""

    first_seen: datetime
    last_seen: datetime
    snapshot: ConnectionSnapshot

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "first_seen",
            _require_utc(self.first_seen, "first_seen"),
        )
        object.__setattr__(
            self,
            "last_seen",
            _require_utc(self.last_seen, "last_seen"),
        )
        if not isinstance(self.snapshot, ConnectionSnapshot):
            raise TypeError("snapshot must be a ConnectionSnapshot")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        if self.snapshot.observed_at != self.last_seen:
            raise ValueError("snapshot observation time must equal last_seen")

    @property
    def key(self) -> ConnectionKey:
        return self.snapshot.key

    @property
    def state(self) -> ConnectionState:
        return self.snapshot.state

    @property
    def process(self) -> ProcessInfo:
        return self.snapshot.process


ConnectionLifecycleEvent: TypeAlias = (
    ConnectionOpened | ConnectionUpdated | ConnectionClosed
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
