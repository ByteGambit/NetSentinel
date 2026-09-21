"""Framework-independent ports used by the application layer."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Protocol
from uuid import UUID

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionHistoryRecord,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionUpdated,
    ProcessInfo,
    TransportProtocol,
)


MAX_HISTORY_QUERY_LIMIT = 500


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


class ProcessMetadataResolver(Protocol):
    """Port for resolving portable metadata for one process identifier."""

    def resolve(self, pid: int) -> ProcessInfo:
        """Return process metadata without leaking provider-specific types."""


class HistoryRepositoryError(RuntimeError):
    """A sanitized connection-history persistence operation failed."""


class HistoryRecordNotFound(HistoryRepositoryError):
    """No lifecycle record matches the requested identity or active key."""


class HistoryDataCorrupt(HistoryRepositoryError):
    """Persisted history data cannot be mapped to the portable model."""


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
        self, query: ConnectionHistoryQuery
    ) -> tuple[ConnectionHistoryRecord, ...]:
        """Return one bounded, deterministically ordered history page."""


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
    "HistoryRepositoryError",
    "HistoryRetentionRepository",
    "HistoryRetentionRepositoryError",
    "HistoryStorageDiagnostics",
    "MAX_HISTORY_QUERY_LIMIT",
    "ProcessMetadataResolver",
)
