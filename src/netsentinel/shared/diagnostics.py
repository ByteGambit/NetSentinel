"""Portable, presentation-safe diagnostics for application workers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum


class EngineState(str, Enum):
    """Lifecycle state of a monitoring engine worker."""

    STOPPED = "stopped"
    RUNNING = "running"
    STOPPING = "stopping"


class PersistenceState(str, Enum):
    """Lifecycle state of the asynchronous persistence writer."""

    STOPPED = "stopped"
    RUNNING = "running"
    STOPPING = "stopping"


class CapabilityStatus(str, Enum):
    """Availability of one monitoring capability."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class DiagnosticSeverity(str, Enum):
    """Portable diagnostic severity, independent of a logging framework."""

    WARNING = "warning"
    ERROR = "error"


class DiagnosticCode(str, Enum):
    """Stable codes suitable for translation and presentation mapping."""

    COLLECTOR_PERMISSION_DENIED = "collector_permission_denied"
    COLLECTOR_TRANSIENT_ERROR = "collector_transient_error"
    COLLECTOR_UNEXPECTED_ERROR = "collector_unexpected_error"
    PROCESS_ENRICHMENT_ERROR = "process_enrichment_error"
    PROCESS_METADATA_DEGRADED = "process_metadata_degraded"
    TRACKER_ERROR = "tracker_error"
    DISPATCHER_ERROR = "dispatcher_error"
    SUBSCRIBER_ERROR = "subscriber_error"
    POLLING_OVERRUN = "polling_overrun"
    SHUTDOWN_TIMEOUT = "shutdown_timeout"
    WORKER_ERROR = "worker_error"
    PERSISTENCE_OVERFLOW = "persistence_overflow"
    PERSISTENCE_WRITE_FAILED = "persistence_write_failed"
    PERSISTENCE_UNEXPECTED_ERROR = "persistence_unexpected_error"
    PERSISTENCE_START_FAILED = "persistence_start_failed"
    PERSISTENCE_SHUTDOWN_TIMEOUT = "persistence_shutdown_timeout"
    PERSISTENCE_NOT_RUNNING = "persistence_not_running"


class DiagnosticComponent(str, Enum):
    """Component which produced a diagnostic."""

    ENGINE = "engine"
    COLLECTOR = "collector"
    PROCESS_ENRICHER = "process_enricher"
    TRACKER = "tracker"
    DISPATCHER = "dispatcher"
    SUBSCRIBER = "subscriber"
    PERSISTENCE = "persistence"


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """A bounded diagnostic that deliberately excludes raw exception text."""

    code: DiagnosticCode
    component: DiagnosticComponent
    severity: DiagnosticSeverity
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.code, DiagnosticCode):
            raise TypeError("code must be a DiagnosticCode")
        if not isinstance(self.component, DiagnosticComponent):
            raise TypeError("component must be a DiagnosticComponent")
        if not isinstance(self.severity, DiagnosticSeverity):
            raise TypeError("severity must be a DiagnosticSeverity")
        object.__setattr__(
            self,
            "occurred_at",
            _require_utc(self.occurred_at, "occurred_at"),
        )


@dataclass(frozen=True, slots=True)
class CapabilitySnapshot:
    """Capabilities currently provided by the connection monitoring pipeline."""

    connection_monitoring: CapabilityStatus = CapabilityStatus.AVAILABLE
    process_metadata: CapabilityStatus = CapabilityStatus.AVAILABLE

    @property
    def overall(self) -> CapabilityStatus:
        statuses = (self.connection_monitoring, self.process_metadata)
        if CapabilityStatus.UNAVAILABLE in statuses:
            return CapabilityStatus.UNAVAILABLE
        if CapabilityStatus.DEGRADED in statuses:
            return CapabilityStatus.DEGRADED
        return CapabilityStatus.AVAILABLE


@dataclass(frozen=True, slots=True)
class EngineCounters:
    """Cumulative, bounded counters for one engine instance."""

    polling_rounds: int = 0
    successful_rounds: int = 0
    failed_rounds: int = 0
    lifecycle_events: int = 0
    subscriber_failures: int = 0
    process_metadata_unavailable: int = 0
    polling_overruns: int = 0


@dataclass(frozen=True, slots=True)
class EngineHealthSnapshot:
    """Immutable snapshot safe to consume outside the worker thread."""

    state: EngineState
    capabilities: CapabilitySnapshot
    counters: EngineCounters
    last_successful_poll_at: datetime | None = None
    last_poll_started_at: datetime | None = None
    last_poll_completed_at: datetime | None = None
    last_error: Diagnostic | None = None
    polling: bool = False
    worker_alive: bool = False

    @property
    def running(self) -> bool:
        return self.state is EngineState.RUNNING

    @property
    def capability(self) -> CapabilityStatus:
        """Convenient aggregate capability status."""

        return self.capabilities.overall


@dataclass(frozen=True, slots=True)
class PersistenceCounters:
    """Cumulative counters for one bounded persistence pipeline."""

    accepted_events: int = 0
    persisted_events: int = 0
    dropped_events: int = 0
    failed_writes: int = 0
    retry_attempts: int = 0
    batches: int = 0


@dataclass(frozen=True, slots=True)
class PersistenceHealthSnapshot:
    """Portable, immutable writer health safe for concurrent readers."""

    state: PersistenceState
    queue_depth: int
    queue_capacity: int
    counters: PersistenceCounters
    last_successful_write_at: datetime | None = None
    last_error: Diagnostic | None = None
    worker_alive: bool = False

    @property
    def running(self) -> bool:
        return self.state is PersistenceState.RUNNING


__all__ = (
    "CapabilitySnapshot",
    "CapabilityStatus",
    "Diagnostic",
    "DiagnosticCode",
    "DiagnosticComponent",
    "DiagnosticSeverity",
    "EngineCounters",
    "EngineHealthSnapshot",
    "EngineState",
    "PersistenceCounters",
    "PersistenceHealthSnapshot",
    "PersistenceState",
)
