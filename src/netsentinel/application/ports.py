"""Framework-independent ports used by the application layer."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionHistoryRecord,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionUpdated,
    ObservationQuality,
    ProcessInfo,
    TransportProtocol,
)
from netsentinel.domain.behavior_baseline import BaselineLoad, BaselineSummary
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.destination_context import DestinationContext
from netsentinel.domain.executable_hash import ExecutableHash
from netsentinel.domain.executable_signer import ExecutableSigner
from netsentinel.domain.devices import (
    DeviceIdentity, DeviceProfile, GatewayBaseline, GatewayBaselineChange, IdentityBinding, NetworkContext,
)
from netsentinel.domain.observations import PacketObservation
from netsentinel.domain.vlan_summary import VlanSummarySnapshot
from netsentinel.domain.dns import (
    DnsHistoryRecord, DnsTransactionStatus, DnsTransport, canonical_dns_name,
)
from netsentinel.domain.alerts import Alert, AlertCandidate, AlertStatus
from netsentinel.domain.risk_evidence import RiskEvidenceBatch
from netsentinel.shared.diagnostics import (
    CaptureCapabilitySnapshot,
    CaptureHealthSnapshot,
    DestinationDatasetDiagnostic,
)


MAX_HISTORY_QUERY_LIMIT = 500
MAX_ALERT_QUERY_LIMIT = 100
MAX_DNS_HISTORY_QUERY_LIMIT = 500


class RiskEvidenceConsumer(Protocol):
    """Local typed handoff only; no persistence, scoring or delivery guarantee."""

    def consume(self, evidence: RiskEvidenceBatch) -> None: ...


class BaselineRepository(Protocol):
    """Blocking operations; owned exclusively by the baseline worker."""

    def load(self, limit: int) -> BaselineLoad: ...

    def write(self, summary: BaselineSummary | None, scope: BehaviorScopeKey, *, reset: bool = False) -> int: ...

    def cleanup(self, now: datetime) -> int: ...


class DestinationContextProvider(Protocol):
    """Local dataset lookup for canonical public IPs only; never performs network I/O."""

    @property
    def generation(self) -> int: ...

    def lookup(self, ip: str) -> DestinationContext: ...

    def diagnostic(self) -> DestinationDatasetDiagnostic: ...


class DnsHistoryRepositoryError(RuntimeError):
    """Sanitized DNS history storage failure."""


class DnsHistoryDataCorrupt(DnsHistoryRepositoryError):
    """A persisted DNS row does not satisfy the portable model."""


class DnsHistoryQueryCancelled(DnsHistoryRepositoryError):
    """An obsolete DNS read was cancelled."""


@dataclass(frozen=True, slots=True)
class DnsHistoryQuery:
    """Bounded exact filters; event time is query time, or response time if unmatched."""

    limit: int
    offset: int = 0
    event_from: datetime | None = None
    event_to: datetime | None = None
    network_fingerprint: str | None = None
    qname: str | None = None
    qtype: int | None = None
    server_ip: str | None = None
    status: DnsTransactionStatus | None = None
    transport: DnsTransport | None = None

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_DNS_HISTORY_QUERY_LIMIT:
            raise ValueError("limit must be between 1 and 500")
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("offset must be nonnegative")
        for field in ("event_from", "event_to"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _require_utc(value, field))
        if self.event_from and self.event_to and self.event_from > self.event_to:
            raise ValueError("event_from cannot follow event_to")
        if self.network_fingerprint is not None and (
            len(self.network_fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in self.network_fingerprint)
        ):
            raise ValueError("network_fingerprint must be a SHA-256 hex digest")
        if self.qname is not None:
            object.__setattr__(self, "qname", canonical_dns_name(self.qname))
        if self.qtype is not None and (type(self.qtype) is not int or not 0 <= self.qtype <= 65535):
            raise ValueError("qtype is outside the DNS range")
        if self.server_ip is not None:
            if not isinstance(self.server_ip, str) or len(self.server_ip) > 45:
                raise ValueError("server_ip is invalid")
            object.__setattr__(self, "server_ip", str(ip_address(self.server_ip)))
        if self.status is not None and not isinstance(self.status, DnsTransactionStatus):
            raise TypeError("status must be a DnsTransactionStatus")
        if self.transport is not None and not isinstance(self.transport, DnsTransport):
            raise TypeError("transport must be a DnsTransport")


class DnsHistoryRepository(Protocol):
    def record(self, record: DnsHistoryRecord) -> None: ...
    def get(self, record_id: UUID) -> DnsHistoryRecord | None: ...
    def query(self, query: DnsHistoryQuery, *, is_cancelled: Callable[[], bool] | None = None) -> tuple[DnsHistoryRecord, ...]: ...


class DnsHistoryWriteSession(Protocol):
    def write_batch(self, records: tuple[DnsHistoryRecord, ...]) -> None: ...


class DnsHistoryRetentionRepository(Protocol):
    def delete_before(self, cutoff: datetime, limit: int) -> int: ...
    def delete_oldest_over_limit(self, max_rows: int, limit: int) -> int: ...


class AlertRepositoryError(RuntimeError):
    """Sanitized alert storage failure."""


class AlertDataCorrupt(AlertRepositoryError):
    """Persisted alert does not satisfy the portable model."""


class AlertQueryCancelled(AlertRepositoryError):
    """An obsolete alert read was cancelled before delivery."""


@dataclass(frozen=True, slots=True)
class AlertQuery:
    limit: int
    offset: int = 0
    rule_id: str | None = None
    network_fingerprint: str | None = None
    entity_id: str | None = None
    severity: str | None = None
    confidence: str | None = None
    status: AlertStatus | None = None

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_ALERT_QUERY_LIMIT:
            raise ValueError("limit must be between 1 and 100")
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("offset must be nonnegative")
        if self.status is not None and not isinstance(self.status, AlertStatus):
            raise TypeError("status must be AlertStatus")
        if self.severity is not None and self.severity not in {"info", "low", "medium", "high"}:
            raise ValueError("invalid severity")
        if self.confidence is not None and self.confidence not in {"passive_observation", "low", "moderate", "high"}:
            raise ValueError("invalid confidence")
        if self.rule_id is not None and (not isinstance(self.rule_id, str) or not 1 <= len(self.rule_id) <= 64 or not self.rule_id.isascii()):
            raise ValueError("invalid rule_id")
        if self.network_fingerprint is not None and (not isinstance(self.network_fingerprint, str) or len(self.network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.network_fingerprint)):
            raise ValueError("invalid network_fingerprint")
        if self.entity_id is not None and (not isinstance(self.entity_id, str) or not 1 <= len(self.entity_id) <= 128):
            raise ValueError("invalid entity_id")


class AlertRepository(Protocol):
    def record(self, candidate: AlertCandidate, now: datetime, rate_window: timedelta) -> tuple[Alert, bool]: ...
    def set_status(self, alert_id: UUID, status: AlertStatus, now: datetime) -> Alert | None: ...
    def get(self, alert_id: UUID) -> Alert | None: ...
    def query(self, query: AlertQuery, *, is_cancelled: Callable[[], bool] | None = None) -> tuple[Alert, ...]: ...


class ConnectionCollectionError(RuntimeError):
    """Base error raised when a connection snapshot cannot be collected."""


class ConnectionCollectionPermissionDenied(ConnectionCollectionError):
    """The operating system denied access to connection information."""


class ConnectionCollectionTransientError(ConnectionCollectionError):
    """Collection failed because of a transient OS or process race."""


class ConnectionCollector(Protocol):
    """Port for obtaining one normalized system connection snapshot."""

    def collect(self) -> tuple[ConnectionSnapshot, ...]:
        """Return the connections visible in one collection pass."""


@dataclass(frozen=True, slots=True)
class ConnectionCollectionRound:
    """Portable collector outcome; reduced rows cannot prove absence."""

    snapshots: tuple[ConnectionSnapshot, ...]
    quality: ObservationQuality = ObservationQuality.COMPLETE
    discarded_rows: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.snapshots, tuple) or not all(isinstance(row, ConnectionSnapshot) for row in self.snapshots):
            raise TypeError("snapshots must be a tuple of ConnectionSnapshot")
        if not isinstance(self.quality, ObservationQuality) or self.quality is ObservationQuality.FAILED:
            raise ValueError("collected rounds must be complete or reduced")
        if isinstance(self.discarded_rows, bool) or not isinstance(self.discarded_rows, int) or self.discarded_rows < 0:
            raise ValueError("discarded_rows must be non-negative")


class ProcessMetadataResolver(Protocol):
    """Port for portable process and best-effort observed parent metadata by PID."""

    def resolve(self, pid: int) -> ProcessInfo:
        """Return process metadata without leaking provider-specific types."""


class ExecutableHasher(Protocol):
    """Blocking local file reader; called only from a bounded worker."""

    def hash(self, path: str, *, is_cancelled: Callable[[], bool]) -> ExecutableHash:
        """Return portable file-content evidence or a typed failure."""


class ExecutableSignerVerifier(Protocol):
    """Blocking local verification; only the application worker invokes it."""

    def verify(self, path: str, *, is_cancelled: Callable[[], bool]) -> ExecutableSigner: ...


class NetworkContextCollectionError(RuntimeError):
    """Base error for a sanitized local network-context read failure."""


class NetworkContextPermissionDenied(NetworkContextCollectionError):
    """Windows denied access to local adapter configuration."""


class NetworkContextUnavailable(NetworkContextCollectionError):
    """Local adapter configuration is temporarily unavailable."""


class NetworkContextProvider(Protocol):
    """Port for a current, normalized snapshot of active IPv4 contexts."""

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        """Read current contexts without starting polling or active discovery."""


class DeviceRepositoryError(RuntimeError):
    """Sanitized failure to store or read observed device state."""


class DeviceDataCorrupt(DeviceRepositoryError):
    """Persisted device or binding data violates the portable model."""


class DeviceRepository(Protocol):
    """Atomic observed-device persistence, scoped by network fingerprint."""

    def record_binding(
        self, device: DeviceIdentity, binding: IdentityBinding
    ) -> tuple[DeviceIdentity, IdentityBinding]:
        """Upsert one sender observation without moving first/last seen backward."""

    def list_devices(self, network_fingerprint: str) -> tuple[DeviceIdentity, ...]:
        """Return scoped devices in canonical MAC order."""

    def list_bindings(self, device_id: UUID, limit: int | None = None) -> tuple[IdentityBinding, ...]:
        """Return observed IP bindings; an optional limit bounds UI reads."""

    def latest_binding_for_ip(self, network_fingerprint: str, ip_address: str) -> IdentityBinding | None:
        """Return the most recently observed sender binding for one scoped IPv4 address."""


class DeviceProfileRepositoryError(RuntimeError):
    """Sanitized user-profile storage failure."""


class DeviceProfileDataCorrupt(DeviceProfileRepositoryError):
    """Persisted profile violates the portable model."""


class DeviceProfileMergeConflict(DeviceProfileRepositoryError):
    """Two explicit user annotations cannot be merged without losing meaning."""


class DeviceProfileRepository(Protocol):
    """User-owned profiles and their observed-device links, separate from ARP writes."""

    def create(self, device_id: UUID, profile: DeviceProfile) -> DeviceProfile: ...
    def get(self, profile_id: UUID) -> DeviceProfile | None: ...
    def get_for_device(self, device_id: UUID) -> DeviceProfile | None: ...
    def update(self, profile: DeviceProfile, *, expected_updated_at: datetime | None = None) -> DeviceProfile: ...
    def delete(self, profile_id: UUID) -> bool: ...
    def merge_devices(self, target_device_id: UUID, source_device_id: UUID, at: datetime) -> DeviceProfile: ...
    def snapshot_for_network(self, network_fingerprint: str, since: datetime) -> tuple[tuple[DeviceProfile, tuple[UUID, ...], tuple[IdentityBinding, ...]], ...]:
        """Return a bounded, consistent active-profile/member snapshot for one network."""


class GatewayBaselineRepositoryError(RuntimeError):
    """Sanitized gateway baseline storage failure."""


class GatewayBaselineDataCorrupt(GatewayBaselineRepositoryError):
    """Stored gateway baseline does not satisfy portable model constraints."""


class GatewayBaselineRepository(Protocol):
    def get(self, network_fingerprint: str) -> GatewayBaseline | None: ...

    def save(
        self, baseline: GatewayBaseline, change: GatewayBaselineChange | None = None
    ) -> GatewayBaseline: ...

    def changes(self, network_fingerprint: str) -> tuple[GatewayBaselineChange, ...]: ...


class VlanSummaryRepositoryError(RuntimeError):
    """Sanitized VLAN aggregate persistence failure."""


class VlanSummaryDataCorrupt(VlanSummaryRepositoryError):
    """Persisted VLAN aggregate is invalid."""


class VlanSummaryRepository(Protocol):
    def get(self, network_fingerprint: str, interface_id: str,
            interface_index: int) -> VlanSummarySnapshot | None: ...

    def save(self, summary: VlanSummarySnapshot) -> VlanSummarySnapshot: ...

    def verify(self, network_fingerprint: str, interface_id: str,
               interface_index: int, verified_at: datetime) -> VlanSummarySnapshot: ...


class PacketCaptureError(RuntimeError):
    """Base error for sanitized passive packet-capture failures."""


class PacketCapturePermissionDenied(PacketCaptureError):
    """The OS or capture driver denied access to the selected interface."""


class PacketCaptureDependencyUnavailable(PacketCaptureError):
    """Scapy or the platform capture driver is unavailable."""


class PacketCaptureInterfaceUnavailable(PacketCaptureError):
    """The explicitly selected interface no longer exists or is unusable."""


class PacketCaptureNetworkChanged(PacketCaptureError):
    """The selected NS-019 network context is no longer current."""


class PacketCaptureTransientError(PacketCaptureError):
    """Capture failed because of a temporary platform or driver condition."""


@dataclass(frozen=True, slots=True)
class PacketCaptureRequest:
    """Explicit, bounded request for passive capture on one current context."""

    context: NetworkContext
    capture_filter: str

    def __post_init__(self) -> None:
        if not isinstance(self.context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        if not isinstance(self.capture_filter, str):
            raise TypeError("capture_filter must be a string")
        capture_filter = self.capture_filter.strip()
        if not capture_filter:
            raise ValueError("capture_filter must not be empty")
        if len(capture_filter) > 256:
            raise ValueError("capture_filter must not exceed 256 characters")
        if any(character in capture_filter for character in ("\0", "\r", "\n")):
            raise ValueError("capture_filter contains a forbidden control character")
        object.__setattr__(self, "capture_filter", capture_filter)


class PacketCapture(Protocol):
    """Application-facing passive capture lifecycle and bounded output port."""

    def probe(self, context: NetworkContext) -> CaptureCapabilitySnapshot:
        """Check dependency/interface capability without starting capture."""

    def start(self, request: PacketCaptureRequest) -> bool:
        """Start one worker for an explicitly selected context and filter."""

    def stop(self, timeout: float | None = None) -> bool:
        """Stop accepting observations and wait for a bounded duration."""

    def drain(self, limit: int) -> tuple[PacketObservation, ...]:
        """Return up to ``limit`` queued portable observations in FIFO order."""

    def health_snapshot(self) -> CaptureHealthSnapshot:
        """Return an immutable, sanitized lifecycle/capability snapshot."""


class HistoryRepositoryError(RuntimeError):
    """A sanitized connection-history persistence operation failed."""


class HistoryRecordNotFound(HistoryRepositoryError):
    """No lifecycle record matches the requested identity or active key."""


class HistoryDataCorrupt(HistoryRepositoryError):
    """Persisted history data cannot be mapped to the portable model."""


class HistoryQueryCancelled(HistoryRepositoryError):
    """A connection-history read was cancelled before completion."""


class HistoryRetentionRepositoryError(RuntimeError):
    """A sanitized history-retention storage operation failed."""


@dataclass(frozen=True, slots=True)
class HistoryStorageDiagnostics:
    """Portable local history storage measurements with no filesystem path.

    ``database_bytes`` and ``wal_bytes`` are actual file sizes observed while
    the diagnostic connection is open.  An absent WAL is reported as zero.
    SQLite may retain free pages after deletes, so these values need not shrink
    after cleanup.
    """

    database_bytes: int
    wal_bytes: int
    total_rows: int
    active_rows: int
    completed_rows: int

    def __post_init__(self) -> None:
        for field_name in (
            "database_bytes",
            "wal_bytes",
            "total_rows",
            "active_rows",
            "completed_rows",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value < 0:
                raise ValueError(f"{field_name} must be zero or greater")
        if self.active_rows + self.completed_rows != self.total_rows:
            raise ValueError("active and completed row counts must equal total_rows")

    @property
    def total_local_storage_bytes(self) -> int:
        """Return the measured main database plus WAL file sizes."""

        return self.database_bytes + self.wal_bytes


@dataclass(frozen=True, slots=True)
class ConnectionHistoryQuery:
    """Bounded, portable filters for connection-history reads.

    Time bounds are inclusive and apply to ``first_seen``.  Endpoint filtering
    matches either the local or remote canonical IP address.  Ordering is an
    adapter contract: newest ``first_seen`` first, then stable record ID.
    """

    limit: int
    offset: int = 0
    first_seen_from: datetime | None = None
    first_seen_to: datetime | None = None
    protocol: TransportProtocol | None = None
    process_name: str | None = None
    pid: int | None = None
    endpoint_address: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= self.limit <= MAX_HISTORY_QUERY_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_HISTORY_QUERY_LIMIT}"
            )
        if isinstance(self.offset, bool) or not isinstance(self.offset, int):
            raise TypeError("offset must be an integer")
        if self.offset < 0:
            raise ValueError("offset must be zero or greater")
        if self.first_seen_from is not None:
            object.__setattr__(
                self,
                "first_seen_from",
                _require_utc(self.first_seen_from, "first_seen_from"),
            )
        if self.first_seen_to is not None:
            object.__setattr__(
                self,
                "first_seen_to",
                _require_utc(self.first_seen_to, "first_seen_to"),
            )
        if (
            self.first_seen_from is not None
            and self.first_seen_to is not None
            and self.first_seen_from > self.first_seen_to
        ):
            raise ValueError("first_seen_from cannot follow first_seen_to")
        if self.protocol is not None and not isinstance(
            self.protocol, TransportProtocol
        ):
            raise TypeError("protocol must be a TransportProtocol or None")
        if self.process_name is not None:
            if not isinstance(self.process_name, str):
                raise TypeError("process_name must be a string or None")
            if not self.process_name.strip():
                raise ValueError("process_name must not be empty")
        if self.pid is not None:
            if isinstance(self.pid, bool) or not isinstance(self.pid, int):
                raise TypeError("pid must be an integer or None")
            if self.pid < 0:
                raise ValueError("pid must be zero or greater")
        if self.endpoint_address is not None:
            if not isinstance(self.endpoint_address, str):
                raise TypeError("endpoint_address must be a string or None")
            try:
                canonical = str(ip_address(self.endpoint_address))
            except ValueError as error:
                raise ValueError("endpoint_address must be a valid IP address") from error
            object.__setattr__(self, "endpoint_address", canonical)


class ConnectionHistoryRepository(Protocol):
    """Application port for synchronous connection-lifecycle persistence."""

    def record_opened(self, event: ConnectionOpened) -> ConnectionHistoryRecord:
        """Create a lifecycle record, idempotently handling the same event."""

    def record_updated(self, event: ConnectionUpdated) -> ConnectionHistoryRecord:
        """Update the matching active lifecycle without changing first_seen."""

    def record_closed(self, event: ConnectionClosed) -> ConnectionHistoryRecord:
        """Close the matching lifecycle, idempotently handling the same event."""

    def get(self, record_id: UUID) -> ConnectionHistoryRecord | None:
        """Return one record by persistence identity, if present."""

    def query(
        self,
        query: ConnectionHistoryQuery,
        *,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> tuple[ConnectionHistoryRecord, ...]:
        """Return one bounded page, cooperatively cancelling when requested."""


class HistoryRetentionRepository(Protocol):
    """Narrow storage port for safe, bounded connection-history cleanup."""

    def delete_completed_before(self, cutoff: datetime, limit: int) -> int:
        """Delete at most ``limit`` completed rows strictly before cutoff."""

    def delete_oldest_completed_over_total_limit(
        self,
        max_rows: int,
        limit: int,
    ) -> int:
        """Trim at most ``limit`` completed rows while total rows exceed limit."""

    def storage_diagnostics(self) -> HistoryStorageDiagnostics:
        """Return counts and local SQLite file sizes without exposing a path."""


class ConnectionHistoryWriteSession(Protocol):
    """One writer-owned repository session with portable batch semantics.

    The session is created inside the persistence worker and is never shared
    with producers.  Infrastructure adapters may use one connection for the
    lifetime of the session and one transaction for each ``batch`` scope.
    """

    def batch(self) -> AbstractContextManager[None]:
        """Return an atomic write scope for one ordered event batch."""

    def record_opened(self, event: ConnectionOpened) -> ConnectionHistoryRecord:
        """Persist one opened event within the current batch."""

    def record_updated(self, event: ConnectionUpdated) -> ConnectionHistoryRecord:
        """Persist one updated event within the current batch."""

    def record_checkpoint(self, event: ConnectionUpdated) -> None:
        """Refresh only this lifecycle when it is still open."""

    def record_closed(self, event: ConnectionClosed) -> ConnectionHistoryRecord:
        """Persist one closed event within the current batch."""


class ConnectionHistoryWriteSessionFactory(Protocol):
    """Create a worker-owned history session when called by the writer thread."""

    def __call__(
        self,
    ) -> AbstractContextManager[ConnectionHistoryWriteSession]: ...


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


__all__ = (
    "VlanSummaryDataCorrupt",
    "VlanSummaryRepository",
    "VlanSummaryRepositoryError",
    "DnsHistoryDataCorrupt",
    "DnsHistoryQuery",
    "DnsHistoryQueryCancelled",
    "DnsHistoryRepository",
    "DnsHistoryRepositoryError",
    "DnsHistoryRetentionRepository",
    "DnsHistoryWriteSession",
    "MAX_DNS_HISTORY_QUERY_LIMIT",
    "AlertDataCorrupt",
    "AlertQuery",
    "AlertQueryCancelled",
    "AlertRepository",
    "AlertRepositoryError",
    "MAX_ALERT_QUERY_LIMIT",
    "DeviceDataCorrupt",
    "DeviceProfileDataCorrupt",
    "DeviceProfileMergeConflict",
    "DeviceProfileRepository",
    "DeviceProfileRepositoryError",
    "DeviceRepository",
    "DeviceRepositoryError",
    "GatewayBaselineRepository",
    "GatewayBaselineRepositoryError",
    "GatewayBaselineDataCorrupt",
    "ConnectionHistoryQuery",
    "ConnectionHistoryRepository",
    "ConnectionHistoryWriteSession",
    "ConnectionHistoryWriteSessionFactory",
    "ConnectionCollectionError",
    "ConnectionCollectionPermissionDenied",
    "ConnectionCollectionTransientError",
    "ConnectionCollector",
    "HistoryDataCorrupt",
    "HistoryRecordNotFound",
    "HistoryQueryCancelled",
    "HistoryRepositoryError",
    "HistoryRetentionRepository",
    "HistoryRetentionRepositoryError",
    "HistoryStorageDiagnostics",
    "MAX_HISTORY_QUERY_LIMIT",
    "NetworkContextCollectionError",
    "NetworkContextPermissionDenied",
    "NetworkContextProvider",
    "NetworkContextUnavailable",
    "PacketCapture",
    "PacketCaptureDependencyUnavailable",
    "PacketCaptureError",
    "PacketCaptureInterfaceUnavailable",
    "PacketCaptureNetworkChanged",
    "PacketCapturePermissionDenied",
    "PacketCaptureRequest",
    "PacketCaptureTransientError",
    "ProcessMetadataResolver",
    "ExecutableHasher",
    "ExecutableSignerVerifier",
)
