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


class CaptureState(str, Enum):
    """Lifecycle state of a passive packet-capture worker."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"


class CapabilityStatus(str, Enum):
    """Availability of one monitoring capability."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class CaptureCapabilityReason(str, Enum):
    """Sanitized reason for the current packet-capture capability."""

    NONE = "none"
    NOT_PROBED = "not_probed"
    PERMISSION_DENIED = "permission_denied"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INTERFACE_UNAVAILABLE = "interface_unavailable"
    NETWORK_CHANGED = "network_changed"
    TRANSIENT_FAILURE = "transient_failure"


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
    CAPTURE_PERMISSION_DENIED = "capture_permission_denied"
    CAPTURE_DEPENDENCY_UNAVAILABLE = "capture_dependency_unavailable"
    CAPTURE_INTERFACE_UNAVAILABLE = "capture_interface_unavailable"
    CAPTURE_NETWORK_CHANGED = "capture_network_changed"
    CAPTURE_TRANSIENT_FAILURE = "capture_transient_failure"
    CAPTURE_MALFORMED_PACKET = "capture_malformed_packet"
    CAPTURE_QUEUE_OVERFLOW = "capture_queue_overflow"
    CAPTURE_SHUTDOWN_TIMEOUT = "capture_shutdown_timeout"
    DNS_CONFIG_UNAVAILABLE = "dns_config_unavailable"


class DiagnosticComponent(str, Enum):
    """Component which produced a diagnostic."""

    ENGINE = "engine"
    COLLECTOR = "collector"
    PROCESS_ENRICHER = "process_enricher"
    TRACKER = "tracker"
    DISPATCHER = "dispatcher"
    SUBSCRIBER = "subscriber"
    PERSISTENCE = "persistence"
    CAPTURE = "capture"
    DNS_CONFIG = "dns_config"


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


@dataclass(frozen=True, slots=True)
class CaptureCapabilitySnapshot:
    """Portable packet-capture availability without raw OS error text."""

    status: CapabilityStatus
    reason: CaptureCapabilityReason
    checked_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.status, CapabilityStatus):
            raise TypeError("status must be a CapabilityStatus")
        if not isinstance(self.reason, CaptureCapabilityReason):
            raise TypeError("reason must be a CaptureCapabilityReason")
        if self.status is CapabilityStatus.AVAILABLE:
            if self.reason is not CaptureCapabilityReason.NONE:
                raise ValueError("available capture capability must have no reason")
        elif self.reason is CaptureCapabilityReason.NONE:
            raise ValueError("non-available capture capability requires a reason")
        object.__setattr__(
            self,
            "checked_at",
            _require_utc(self.checked_at, "checked_at"),
        )


@dataclass(frozen=True, slots=True)
class CaptureCounters:
    """Cumulative bounded counters for one capture worker instance."""

    captured_packets: int = 0
    enqueued_observations: int = 0
    dropped_observations: int = 0
    malformed_packets: int = 0
    worker_failures: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "captured_packets",
            "enqueued_observations",
            "dropped_observations",
            "malformed_packets",
            "worker_failures",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value < 0:
                raise ValueError(f"{field_name} must be zero or greater")


@dataclass(frozen=True, slots=True)
class CaptureHealthSnapshot:
    """Immutable capture health safe for application and presentation use."""

    state: CaptureState
    capability: CaptureCapabilitySnapshot
    queue_depth: int
    queue_capacity: int
    counters: CaptureCounters
    selected_interface_id: str | None = None
    network_fingerprint: str | None = None
    last_observation_at: datetime | None = None
    last_error: Diagnostic | None = None
    worker_alive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.state, CaptureState):
            raise TypeError("state must be a CaptureState")
        if not isinstance(self.capability, CaptureCapabilitySnapshot):
            raise TypeError("capability must be a CaptureCapabilitySnapshot")
        if isinstance(self.queue_capacity, bool) or not isinstance(
            self.queue_capacity, int
        ):
            raise TypeError("queue_capacity must be an integer")
        if self.queue_capacity <= 0:
            raise ValueError("queue_capacity must be greater than zero")
        if isinstance(self.queue_depth, bool) or not isinstance(self.queue_depth, int):
            raise TypeError("queue_depth must be an integer")
        if not 0 <= self.queue_depth <= self.queue_capacity:
            raise ValueError("queue_depth must be within queue capacity")
        if not isinstance(self.counters, CaptureCounters):
            raise TypeError("counters must be CaptureCounters")
        if (self.selected_interface_id is None) != (
            self.network_fingerprint is None
        ):
            raise ValueError(
                "selected interface and network fingerprint must be set together"
            )
        if self.last_observation_at is not None:
            object.__setattr__(
                self,
                "last_observation_at",
                _require_utc(self.last_observation_at, "last_observation_at"),
            )

    @property
    def running(self) -> bool:
        return self.state is CaptureState.RUNNING


__all__ = (
    "CaptureCapabilityReason",
    "CaptureCapabilitySnapshot",
    "CaptureCounters",
    "CaptureHealthSnapshot",
    "CaptureState",
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
