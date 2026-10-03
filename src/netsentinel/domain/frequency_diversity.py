"""NS-073 polling appearance/diversity evidence, never an OS connect rate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from math import isfinite
from uuid import UUID

from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineSnapshot, BaselineState, BaselineStorageState,
    MAX_BASELINE_COUNTER,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey
from netsentinel.domain.connections import ObservationQuality


class BehaviorRule(str, Enum):
    APPEARANCE_FREQUENCY = "observed_appearance_frequency"
    DESTINATION_DIVERSITY = "destination_window_diversity"


class BehaviorClassification(str, Enum):
    NORMAL = "normal"
    ELEVATED_UNCONFIRMED = "elevated_unconfirmed"
    ELEVATED_CONFIRMED = "elevated_confirmed"
    INSUFFICIENT_DATA = "insufficient_data"
    INSUFFICIENT_QUALITY = "insufficient_quality"
    NOT_EVALUATED = "not_evaluated"


class BehaviorReason(str, Enum):
    WITHIN_EXPECTED_RANGE = "within_expected_range"
    APPEARANCE_RATE_ELEVATED = "appearance_rate_elevated"
    DESTINATION_DIVERSITY_ELEVATED = "destination_diversity_elevated"
    BASELINE_NOT_READY = "baseline_not_ready"
    BASELINE_UNAVAILABLE = "baseline_unavailable"
    BASELINE_INVALID = "baseline_invalid"
    POLICY_MISMATCH = "policy_mismatch"
    SCOPE_UNAVAILABLE = "scope_unavailable"
    SCOPE_MISMATCH = "scope_mismatch"
    CURRENT_WINDOW_TOO_SHORT = "current_window_too_short"
    CURRENT_SAMPLE_TOO_SMALL = "current_sample_too_small"
    CURRENT_INVALID = "current_invalid"
    QUALITY_INSUFFICIENT = "quality_insufficient"
    CAPACITY_LIMITED = "capacity_limited"
    REFERENCE_TOO_SMALL = "reference_too_small"
    REFERENCE_NOT_COMPARABLE = "reference_not_comparable"
    COOLDOWN_ACTIVE = "cooldown_active"
    WINDOW_NOT_INDEPENDENT = "window_not_independent"
    CLOCK_ANOMALY = "clock_anomaly"


@dataclass(frozen=True, slots=True)
class FrequencyDiversityPolicy:
    version: int = 1
    minimum_baseline_samples: int = 20
    minimum_baseline_seconds: float = 600.0
    minimum_current_seconds: float = 120.0
    minimum_current_appearances: int = 20
    frequency_multiplier: int = 3
    minimum_frequency_per_minute: float = 10.0
    minimum_reference_frequency_per_minute: float = 1.0
    diversity_multiplier: int = 3
    minimum_current_destinations: int = 10
    minimum_reference_windows: int = 3
    coverage_tolerance_percent: int = 20
    confirmation_windows: int = 2
    cooldown_seconds: float = 600.0
    maximum_confirmation_gap_seconds: float = 1440.0
    maximum_reference_age_seconds: float = 86_400.0
    maximum_scopes: int = 128

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported frequency/diversity policy")
        for name, maximum in (
            ("minimum_baseline_samples", 1_000_000), ("minimum_current_appearances", 1_000_000),
            ("frequency_multiplier", 100), ("diversity_multiplier", 100),
            ("minimum_current_destinations", 64), ("minimum_reference_windows", 8),
            ("coverage_tolerance_percent", 100), ("confirmation_windows", 8),
            ("maximum_scopes", 128),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("threshold outside bounded policy")
        for name, maximum in (
            ("minimum_baseline_seconds", 86_400), ("minimum_current_seconds", 720),
            ("minimum_frequency_per_minute", 1_000_000),
            ("minimum_reference_frequency_per_minute", 1_000_000),
            ("cooldown_seconds", 86_400), ("maximum_confirmation_gap_seconds", 86_400),
            ("maximum_reference_age_seconds", 86_400),
        ):
            value = getattr(self, name)
            minimum = 1e-6 if name in ("minimum_frequency_per_minute", "minimum_reference_frequency_per_minute") else 1.0
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not isfinite(value) or not minimum <= value <= maximum:
                raise ValueError("invalid finite policy threshold")


@dataclass(frozen=True, slots=True)
class BehaviorWindow:
    """Post-accumulator snapshot with its conservative monotonic envelope.

    Caller supplies the actual retained bucket envelope (60 s x 12); endpoints
    are NOT monitored coverage. Session ID distinguishes monotonic epochs.
    The caller serializes snapshot acquisition; this contract cannot prove it.
    """

    features: BehaviorFeatureSnapshot
    session_id: UUID
    started_monotonic: float
    ended_monotonic: float
    observed_at: datetime
    quality: ObservationQuality = ObservationQuality.COMPLETE

    def __post_init__(self) -> None:
        if not isinstance(self.features, BehaviorFeatureSnapshot) or not isinstance(self.session_id, UUID):
            raise TypeError("invalid behavior window")
        for value in (self.started_monotonic, self.ended_monotonic):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0 <= value <= 1e12:
                raise ValueError("invalid monotonic endpoint")
        if not 0 < self.ended_monotonic - self.started_monotonic <= 720:
            raise ValueError("window must fit the NS-070 bounded horizon")
        offset = self.observed_at.utcoffset() if isinstance(self.observed_at, datetime) else None
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("window time must be UTC")
        if not isinstance(self.quality, ObservationQuality):
            raise TypeError("invalid window quality")


@dataclass(frozen=True, slots=True)
class BehaviorRangeSample:
    """A clean, independent bounded window, with no destination lists."""

    started_monotonic: float
    ended_monotonic: float
    monitored_seconds: float
    observed_appearances: int
    retained_destinations: int

    def __post_init__(self) -> None:
        for value in (self.started_monotonic, self.ended_monotonic, self.monitored_seconds):
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not isfinite(value) or not 0 <= value <= 1e12:
                raise ValueError("invalid reference duration")
        if not 0 < self.monitored_seconds <= self.ended_monotonic - self.started_monotonic <= 720:
            raise ValueError("reference coverage outside bounded horizon")
        if type(self.observed_appearances) is not int or not 0 <= self.observed_appearances < MAX_BASELINE_COUNTER:
            raise ValueError("invalid reference appearances")
        if type(self.retained_destinations) is not int or not 0 <= self.retained_destinations <= min(64, self.observed_appearances):
            raise ValueError("invalid reference diversity")


@dataclass(frozen=True, slots=True)
class BehaviorRangeReference:
    """Session-only range supplement; NS-071 lifecycle remains authoritative."""

    scope: BehaviorScopeKey
    session_id: UUID
    policy: FrequencyDiversityPolicy
    samples: tuple[BehaviorRangeSample, ...]
    baseline_policy_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.scope, BehaviorScopeKey) or not isinstance(self.session_id, UUID) or not isinstance(self.policy, FrequencyDiversityPolicy):
            raise TypeError("invalid range reference")
        if not isinstance(self.baseline_policy_key, str) or not 1 <= len(self.baseline_policy_key) <= 512:
            raise ValueError("invalid baseline policy key")
        if not isinstance(self.samples, tuple) or len(self.samples) > 8 or any(not isinstance(s, BehaviorRangeSample) for s in self.samples):
            raise ValueError("reference exceeds eight bounded samples")
        if any(b.started_monotonic < a.ended_monotonic for a, b in zip(self.samples, self.samples[1:])):
            raise ValueError("reference windows must be ordered and independent")


@dataclass(frozen=True, slots=True)
class FrequencyDiversityInput:
    window: BehaviorWindow
    baseline: BaselineSnapshot | None
    reference: BehaviorRangeReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.window, BehaviorWindow):
            raise TypeError("window must be BehaviorWindow")
        if self.baseline is not None and not isinstance(self.baseline, BaselineSnapshot):
            raise TypeError("baseline must be BaselineSnapshot or None")
        if self.reference is not None and not isinstance(self.reference, BehaviorRangeReference):
            raise TypeError("reference must be BehaviorRangeReference or None")


@dataclass(frozen=True, slots=True)
class BehaviorDeviationEvidence:
    """Distinct rule IDs carry separate contributors for future explanations."""

    rule_id: BehaviorRule
    policy: FrequencyDiversityPolicy
    classification: BehaviorClassification
    reason: BehaviorReason
    scope: BehaviorScopeKey
    baseline_scope: BehaviorScopeKey | None
    baseline_state: BaselineState | None
    baseline_origin: BaselineOrigin | None
    baseline_storage: BaselineStorageState | None
    baseline_policy_key: str | None
    baseline_sample_count: int | None
    baseline_monitored_seconds: float | None
    baseline_observed_at: datetime | None
    current_appearances: int | None
    current_monitored_seconds: float | None
    current_retained_destinations: int | None
    current_other_destinations: int | None
    reduced_appearances: int | None
    unknown_destinations: int | None
    gap_seen: bool
    capacity_loss: bool
    quality: ObservationQuality
    current_per_monitored_minute: float | None
    reference_per_monitored_minute: float | None
    historical_mean_appearances_per_minute: float | None
    reference_window_count: int
    reference_monitored_seconds: float
    reference_maximum_destinations: int | None
    reference_ended_monotonic: float | None
    deviation_factor: float | None
    confirmation_count: int
    emission_eligible: bool
    observed_at: datetime
    revision_unverified: bool

    @property
    def policy_version(self) -> int:
        return self.policy.version
