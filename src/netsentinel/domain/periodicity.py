"""NS-074 observed appearance intervals, never exact OS connect timers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from math import isfinite
from uuid import UUID

from netsentinel.domain.behavior_baseline import validate_baseline_scope
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.connections import Endpoint, ProcessIdentity, TransportProtocol

RULE_ID = "observed_appearance_periodicity"


class PeriodicityClassification(str, Enum):
    INSUFFICIENT_DATA = "insufficient_data"
    IRREGULAR = "irregular"
    PERIODIC_CANDIDATE = "periodic_candidate"
    RESOLUTION_LIMITED = "resolution_limited"


class PeriodicityReason(str, Enum):
    MINIMUM_INTERVALS = "minimum_intervals"
    JITTER_EXCEEDED = "jitter_exceeded"
    PERIOD_OUT_OF_RANGE = "period_out_of_range"
    OBSERVATION_RESOLUTION = "observation_resolution"
    INTERVALS_REGULAR = "intervals_regular"
    MULTIPLES_COMPATIBLE = "multiples_compatible"


class PeriodicityReset(str, Enum):
    MONITORING_GAP = "monitoring_gap"
    REDUCED_QUALITY = "reduced_quality"
    CAPACITY_LOSS = "capacity_loss"
    SESSION_CHANGED = "session_changed"
    CLOCK_REGRESSION = "clock_regression"
    INACTIVITY = "inactivity"
    CONCURRENT_APPEARANCES = "concurrent_appearances"


class PeriodicityLimitation(str, Enum):
    POLLING_QUANTIZED = "polling_quantized_exact_timer_not_inferred"
    BENIGN_SCHEDULE_COMPATIBLE = "benign_updates_telemetry_sync_reconnects_compatible"
    BEHAVIORAL_ONLY_LOW_SECURITY_SIGNIFICANCE = "behavioral_only_low_security_significance"
    REVISION_UNVERIFIED = "revision_unverified"
    MISSED_MULTIPLE_COMPATIBLE = "missed_multiple_compatible_not_proven"
    SEQUENCE_TRUNCATED = "recent_bounded_sequence_only"
    PRIOR_HISTORY_UNAVAILABLE = "prior_history_unavailable"


def validate_monotonic(value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0 <= value <= 1e12:
        raise ValueError("invalid explicit monotonic time")


@dataclass(frozen=True, slots=True)
class PeriodicityPolicy:
    version: int = 1
    minimum_intervals: int = 5
    maximum_intervals: int = 32
    maximum_scopes: int = 128
    minimum_period_seconds: float = 10.0
    maximum_period_seconds: float = 3600.0
    absolute_jitter_seconds: float = 1.0
    relative_jitter: float = 0.05
    resolution_factor: float = 3.0
    maximum_multiple: int = 3
    inactivity_seconds: float = 10800.0
    horizon_seconds: float = 86400.0

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported periodicity policy")
        for name, minimum, maximum in (
            ("minimum_intervals", 5, 32), ("maximum_intervals", 5, 32),
            ("maximum_scopes", 1, 128), ("maximum_multiple", 1, 3),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("threshold outside bounded policy")
        for name, lower, upper in (
            ("minimum_period_seconds", 1, 3600), ("maximum_period_seconds", 1, 3600),
            ("absolute_jitter_seconds", 0, 1), ("relative_jitter", 0, 0.1),
            ("resolution_factor", 3, 10), ("inactivity_seconds", 1, 10800),
            ("horizon_seconds", 1, 86400),
        ):
            threshold = getattr(self, name)
            if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not isfinite(threshold) or not lower <= threshold <= upper:
                raise ValueError("invalid finite policy threshold")
        if (self.minimum_intervals > self.maximum_intervals
                or self.minimum_period_seconds > self.maximum_period_seconds
                or self.inactivity_seconds < self.maximum_multiple * self.maximum_period_seconds
                or self.horizon_seconds < self.minimum_intervals * self.maximum_period_seconds):
            raise ValueError("inconsistent periodicity bounds")


@dataclass(frozen=True, slots=True)
class PeriodicityScope:
    """Exact behavior scope plus runtime instance and canonical remote endpoint."""

    behavior: BehaviorScopeKey
    process_identity: ProcessIdentity
    remote_endpoint: Endpoint
    protocol: TransportProtocol

    def __post_init__(self) -> None:
        if not isinstance(self.behavior, BehaviorScopeKey):
            raise TypeError("typed behavior scope required")
        validate_baseline_scope(self.behavior)
        if not isinstance(self.process_identity, ProcessIdentity) or self.process_identity.create_time is None:
            raise ValueError("periodicity requires a known process instance")
        if not isinstance(self.remote_endpoint, Endpoint) or not isinstance(self.protocol, TransportProtocol):
            raise TypeError("typed endpoint and protocol required")
        if "%" in self.remote_endpoint.address or self.remote_endpoint.address in ("0.0.0.0", "::"):
            raise ValueError("unavailable remote destination")


@dataclass(frozen=True, slots=True)
class PeriodicitySequence:
    scope: PeriodicityScope
    session_id: UUID
    intervals: tuple[float, ...]
    polling_interval_seconds: float
    observed_at: datetime
    sequence_truncated: bool = False
    prior_history_unavailable: bool = False
    last_reset: PeriodicityReset | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, PeriodicityScope) or not isinstance(self.session_id, UUID):
            raise TypeError("typed scope and session required")
        if not isinstance(self.intervals, tuple) or len(self.intervals) > 32:
            raise ValueError("sequence exceeds hard interval bound")
        for value in self.intervals:
            validate_monotonic(value)
            if not 0 < value <= 10800:
                raise ValueError("interval must be positive and bounded")
        validate_monotonic(self.polling_interval_seconds)
        if not 0 < self.polling_interval_seconds <= 3600:
            raise ValueError("invalid observation cadence")
        offset = self.observed_at.utcoffset() if isinstance(self.observed_at, datetime) else None
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("reference metadata must be UTC")
        if type(self.sequence_truncated) is not bool or type(self.prior_history_unavailable) is not bool:
            raise TypeError("invalid sequence quality")
        if self.last_reset is not None and not isinstance(self.last_reset, PeriodicityReset):
            raise TypeError("invalid reset reason")


@dataclass(frozen=True, slots=True)
class PeriodicityEvidence:
    rule_id: str
    policy: PeriodicityPolicy
    classification: PeriodicityClassification
    reason: PeriodicityReason
    scope: PeriodicityScope
    session_id: UUID
    retained_interval_count: int
    base_interval_seconds: float | None
    maximum_deviation_seconds: float | None
    normalized_jitter: float | None
    tolerance_seconds: float | None
    minimum_observed_interval_seconds: float | None
    maximum_observed_interval_seconds: float | None
    compatible_multiple_count: int
    polling_interval_seconds: float
    limitations: tuple[PeriodicityLimitation, ...]
    last_reset: PeriodicityReset | None
    observed_at: datetime

    @property
    def policy_version(self) -> int:
        return self.policy.version
