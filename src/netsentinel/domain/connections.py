"""Framework-independent domain models for network connections.

The models in this module deliberately use only Python standard-library types.
Adapters are responsible for translating operating-system or third-party values
into these domain concepts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from ipaddress import ip_address
from typing import TypeAlias
from uuid import UUID, uuid4


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
    """Describes why process metadata or an individual field is unavailable."""

    AVAILABLE = "available"
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"


MAX_EXECUTABLE_PATH_LENGTH = 4096
MAX_PARENT_NAME_LENGTH = 255


class ParentProcessStatus(str, Enum):
    """Outcome of a current, best-effort parent observation, not lineage."""

    OBSERVED = "observed"
    ABSENT = "absent"
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    REUSED = "reused"
    UNAVAILABLE = "unavailable"


class ConnectionClosureReason(str, Enum):
    """Domain-level reason for considering a connection closed."""

    NOT_OBSERVED = "not_observed"


class ObservationOrigin(str, Enum):
    """Whether a key was already visible at the first complete observation."""

    INITIAL = "initial"
    OBSERVED = "observed"


class ObservationQuality(str, Enum):
    """Completeness of one connection collection round."""

    COMPLETE = "complete"
    REDUCED = "reduced"
    FAILED = "failed"


class NetworkScopeStatus(str, Enum):
    """Certainty of local-address attribution to a current context."""

    RESOLVED = "resolved"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


class NetworkAttributionMethod(str, Enum):
    """Evidence used for an attributed context, without claiming a route."""

    LOCAL_ADDRESS_MATCH = "local_address_match"


@dataclass(frozen=True, slots=True)
class ConnectionNetworkScope:
    """A local interface/subnet/gateway context, not a physical network ID."""

    status: NetworkScopeStatus
    fingerprint: str | None = None
    interface_id: str | None = None
    interface_index: int | None = None
    method: NetworkAttributionMethod | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, NetworkScopeStatus):
            raise TypeError("status must be a NetworkScopeStatus")
        details = (self.fingerprint, self.interface_id, self.interface_index, self.method)
        if self.status is not NetworkScopeStatus.RESOLVED:
            if any(value is not None for value in details):
                raise ValueError("unresolved scope cannot carry a context")
            return
        if not isinstance(self.fingerprint, str) or len(self.fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.fingerprint
        ):
            raise ValueError("resolved scope requires a network fingerprint")
        if not isinstance(self.interface_id, str) or not self.interface_id or len(self.interface_id) > 512:
            raise ValueError("resolved scope requires an interface ID")
        if isinstance(self.interface_index, bool) or not isinstance(self.interface_index, int) or self.interface_index < 0:
            raise ValueError("resolved scope requires a non-negative interface index")
        if self.method is not NetworkAttributionMethod.LOCAL_ADDRESS_MATCH:
            raise ValueError("resolved scope requires local-address evidence")

    @classmethod
    def unknown(cls) -> ConnectionNetworkScope:
        return cls(NetworkScopeStatus.UNKNOWN)

    @classmethod
    def ambiguous(cls) -> ConnectionNetworkScope:
        return cls(NetworkScopeStatus.AMBIGUOUS)


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
class ParentProcessInfo:
    """Conservative parent context observed during one process lookup.

    ``parent_pid`` is only a reported PID. ``identity`` is set only when the
    parent instance was checked for consistency; neither is historical lineage.
    """

    status: ParentProcessStatus
    observed_at: datetime
    parent_pid: int | None = None
    identity: ProcessIdentity | None = None
    name: str | None = None
    pid_status: ProcessInfoStatus = ProcessInfoStatus.UNAVAILABLE
    create_time_status: ProcessInfoStatus = ProcessInfoStatus.UNAVAILABLE
    name_status: ProcessInfoStatus = ProcessInfoStatus.UNAVAILABLE

    def __post_init__(self) -> None:
        if not isinstance(self.status, ParentProcessStatus):
            raise TypeError("status must be a ParentProcessStatus")
        object.__setattr__(
            self, "observed_at", _require_utc(self.observed_at, "observed_at")
        )
        if self.parent_pid is not None:
            if isinstance(self.parent_pid, bool) or not isinstance(
                self.parent_pid, int
            ):
                raise TypeError("parent_pid must be an integer or None")
            if self.parent_pid <= 0:
                raise ValueError("parent_pid must be positive")
        if self.identity is not None:
            if not isinstance(self.identity, ProcessIdentity):
                raise TypeError("identity must be a ProcessIdentity or None")
            if (
                self.identity.pid != self.parent_pid
                or self.identity.create_time is None
            ):
                raise ValueError(
                    "parent identity requires matching PID and create_time"
                )
        if self.name is not None:
            if not isinstance(self.name, str):
                raise TypeError("name must be a string or None")
            if (
                not self.name.strip()
                or len(self.name) > MAX_PARENT_NAME_LENGTH
                or any(ord(char) < 32 for char in self.name)
            ):
                raise ValueError("parent name is invalid or exceeds the limit")
        for field_name, value, present in (
            ("pid_status", self.pid_status, self.parent_pid is not None),
            ("create_time_status", self.create_time_status, self.identity is not None),
            ("name_status", self.name_status, self.name is not None),
        ):
            if not isinstance(value, ProcessInfoStatus):
                raise TypeError(f"{field_name} must be a ProcessInfoStatus")
            if (value is ProcessInfoStatus.AVAILABLE) != present:
                raise ValueError(f"{field_name} does not match its value")
        if (self.status is ParentProcessStatus.OBSERVED) != (self.identity is not None):
            raise ValueError("observed parent requires a verified instance")
        if self.status is not ParentProcessStatus.OBSERVED and self.name is not None:
            raise ValueError("unverified parent cannot include a name")
        if self.status is ParentProcessStatus.ABSENT and self.parent_pid is not None:
            raise ValueError("absent parent cannot include a PID")


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Process identity and independent availability of its metadata fields.

    ``status`` retains the legacy name availability contract. A missing path
    defaults to unavailable so older callers and stored records stay valid.
    """

    status: ProcessInfoStatus
    identity: ProcessIdentity | None = None
    name: str | None = None
    executable_path: str | None = field(default=None, repr=False)
    name_status: ProcessInfoStatus | None = None
    create_time_status: ProcessInfoStatus | None = None
    executable_path_status: ProcessInfoStatus | None = None
    parent: ParentProcessInfo | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProcessInfoStatus):
            raise TypeError("status must be a ProcessInfoStatus")
        if self.identity is not None and not isinstance(self.identity, ProcessIdentity):
            raise TypeError("identity must be a ProcessIdentity or None")
        if self.parent is not None:
            if not isinstance(self.parent, ParentProcessInfo):
                raise TypeError("parent must be a ParentProcessInfo or None")
            if self.identity is None:
                raise ValueError("parent requires a process identity")
        if self.name is not None and not isinstance(self.name, str):
            raise TypeError("name must be a string or None")
        if self.name is not None and not self.name.strip():
            raise ValueError("name must not be empty")
        if self.executable_path is not None:
            if not isinstance(self.executable_path, str):
                raise TypeError("executable_path must be a string or None")
            if (
                not self.executable_path.strip()
                or len(self.executable_path) > MAX_EXECUTABLE_PATH_LENGTH
                or any(ord(char) < 32 for char in self.executable_path)
            ):
                raise ValueError("executable_path is invalid or exceeds the limit")

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

        create_time = self.identity.create_time if self.identity is not None else None
        default_create_status = (
            ProcessInfoStatus.AVAILABLE
            if create_time is not None
            else ProcessInfoStatus.UNAVAILABLE
        )
        default_path_status = (
            ProcessInfoStatus.AVAILABLE
            if self.executable_path is not None
            else ProcessInfoStatus.UNAVAILABLE
        )
        if self.name_status is None:
            object.__setattr__(self, "name_status", self.status)
        if self.create_time_status is None:
            object.__setattr__(self, "create_time_status", default_create_status)
        if self.executable_path_status is None:
            object.__setattr__(self, "executable_path_status", default_path_status)

        for field_name, field_status, has_value in (
            ("name_status", self.name_status, self.name is not None),
            ("create_time_status", self.create_time_status, create_time is not None),
            (
                "executable_path_status",
                self.executable_path_status,
                self.executable_path is not None,
            ),
        ):
            if not isinstance(field_status, ProcessInfoStatus):
                raise TypeError(f"{field_name} must be a ProcessInfoStatus")
            if (field_status is ProcessInfoStatus.AVAILABLE) != has_value:
                raise ValueError(f"{field_name} does not match its value")
        if self.executable_path is not None and self.identity is None:
            raise ValueError("executable_path requires a process identity")

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
    network_scope: ConnectionNetworkScope = field(default_factory=ConnectionNetworkScope.unknown)

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
        if not isinstance(self.network_scope, ConnectionNetworkScope):
            raise TypeError("network_scope must be a ConnectionNetworkScope")
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
    origin: ObservationOrigin = field(default=ObservationOrigin.OBSERVED, compare=False)
    session_id: UUID = field(default_factory=uuid4, compare=False)
    lifecycle_id: UUID = field(default_factory=uuid4, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, ConnectionSnapshot):
            raise TypeError("snapshot must be a ConnectionSnapshot")
        _validate_observation_identity(self.session_id, self.lifecycle_id)
        if not isinstance(self.origin, ObservationOrigin):
            raise TypeError("origin must be an ObservationOrigin")

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
    session_id: UUID = field(default_factory=uuid4, compare=False)
    lifecycle_id: UUID = field(default_factory=uuid4, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.previous, ConnectionSnapshot):
            raise TypeError("previous must be a ConnectionSnapshot")
        if not isinstance(self.current, ConnectionSnapshot):
            raise TypeError("current must be a ConnectionSnapshot")
        _validate_observation_identity(self.session_id, self.lifecycle_id)
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
    session_id: UUID = field(default_factory=uuid4, compare=False)
    lifecycle_id: UUID = field(default_factory=uuid4, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.last_snapshot, ConnectionSnapshot):
            raise TypeError("last_snapshot must be a ConnectionSnapshot")
        if not isinstance(self.reason, ConnectionClosureReason):
            raise TypeError("reason must be a ConnectionClosureReason")
        _validate_observation_identity(self.session_id, self.lifecycle_id)
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
    session_id: UUID = field(default_factory=uuid4, compare=False)
    lifecycle_id: UUID = field(default_factory=uuid4, compare=False)
    origin: ObservationOrigin = field(default=ObservationOrigin.OBSERVED, compare=False)

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
        _validate_observation_identity(self.session_id, self.lifecycle_id)
        if not isinstance(self.origin, ObservationOrigin):
            raise TypeError("origin must be an ObservationOrigin")
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


@dataclass(frozen=True, slots=True)
class ConnectionHistoryRecord:
    """Portable persisted view of one observed connection lifecycle.

    ``record_id`` is persistence identity and is deliberately distinct from
    :class:`ConnectionKey`, which identifies an active lifecycle across
    observations.  A later lifecycle may therefore reuse the same key while
    retaining a different record ID.
    """

    record_id: UUID
    first_seen: datetime
    last_seen: datetime
    snapshot: ConnectionSnapshot
    closed_at: datetime | None = None
    close_reason: ConnectionClosureReason | None = None
    observation_gap: bool = False
    session_id: UUID | None = None
    lifecycle_id: UUID | None = None
    network_scope_since: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, UUID):
            raise TypeError("record_id must be a UUID")
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
        if (self.closed_at is None) != (self.close_reason is None):
            raise ValueError("closed_at and close_reason must be set together")
        if self.closed_at is not None:
            object.__setattr__(
                self,
                "closed_at",
                _require_utc(self.closed_at, "closed_at"),
            )
            if self.closed_at < self.last_seen:
                raise ValueError("closed_at cannot precede last_seen")
        if self.close_reason is not None and not isinstance(
            self.close_reason, ConnectionClosureReason
        ):
            raise TypeError("close_reason must be a ConnectionClosureReason or None")
        if not isinstance(self.observation_gap, bool):
            raise TypeError("observation_gap must be a bool")
        if self.observation_gap and self.closed_at is not None:
            raise ValueError("a gap record cannot have a close timestamp")
        if self.session_id is not None and not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID or None")
        if self.lifecycle_id is not None and not isinstance(self.lifecycle_id, UUID):
            raise TypeError("lifecycle_id must be a UUID or None")
        if (self.session_id is None) != (self.lifecycle_id is None):
            raise ValueError("session_id and lifecycle_id must be set together")
        if self.network_scope_since is not None:
            object.__setattr__(self, "network_scope_since", _require_utc(self.network_scope_since, "network_scope_since"))
            if not self.first_seen <= self.network_scope_since <= self.last_seen:
                raise ValueError("network_scope_since must be within the observed interval")

    @property
    def key(self) -> ConnectionKey:
        return self.snapshot.key

    @property
    def is_closed(self) -> bool:
        return self.closed_at is not None


ConnectionLifecycleEvent: TypeAlias = (
    ConnectionOpened | ConnectionUpdated | ConnectionClosed
)


@dataclass(frozen=True, slots=True)
class ConnectionRoundObservation:
    """Bounded, metadata-free quality report for one collection round."""

    session_id: UUID
    observed_at: datetime
    quality: ObservationQuality
    discarded_observations: int = 0
    capacity_drops: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        object.__setattr__(self, "observed_at", _require_utc(self.observed_at, "observed_at"))
        if not isinstance(self.quality, ObservationQuality):
            raise TypeError("quality must be an ObservationQuality")
        if isinstance(self.discarded_observations, bool) or not isinstance(self.discarded_observations, int) or self.discarded_observations < 0:
            raise ValueError("discarded_observations must be a non-negative integer")
        if isinstance(self.capacity_drops, bool) or not isinstance(self.capacity_drops, int) or not 0 <= self.capacity_drops <= self.discarded_observations:
            raise ValueError("capacity_drops must be between zero and discarded_observations")


def _validate_observation_identity(session_id: UUID, lifecycle_id: UUID) -> None:
    if not isinstance(session_id, UUID) or not isinstance(lifecycle_id, UUID):
        raise TypeError("session_id and lifecycle_id must be UUID values")


__all__ = (
    "ConnectionNetworkScope",
    "NetworkAttributionMethod",
    "NetworkScopeStatus",
    "ConnectionClosed",
    "ConnectionClosureReason",
    "ConnectionHistoryRecord",
    "ConnectionKey",
    "ConnectionLifecycleEvent",
    "ConnectionOpened",
    "ConnectionRoundObservation",
    "ConnectionSnapshot",
    "ConnectionState",
    "ConnectionUpdated",
    "ObservationOrigin",
    "ObservationQuality",
    "Endpoint",
    "MAX_PARENT_NAME_LENGTH",
    "ParentProcessInfo",
    "ParentProcessStatus",
    "ProcessIdentity",
    "ProcessInfo",
    "ProcessInfoStatus",
    "TrackedConnection",
    "TransportProtocol",
)
