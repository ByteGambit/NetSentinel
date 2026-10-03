"""NS-072 retained IP familiarity evidence, never a safety or risk verdict."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from math import isfinite

from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineSnapshot, BaselineState, BaselineStorageState,
)
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.connections import ObservationOrigin, ObservationQuality


class DestinationNoveltyClassification(str, Enum):
    KNOWN = "known"
    RARE = "rare"
    FIRST_SEEN = "first_seen"
    INSUFFICIENT_DATA = "insufficient_data"
    INSUFFICIENT_QUALITY = "insufficient_quality"
    NOT_EVALUATED = "not_evaluated"


class DestinationNoveltyReason(str, Enum):
    DESTINATION_ESTABLISHED = "destination_established"
    DESTINATION_RARELY_OBSERVED = "destination_rarely_observed"
    DESTINATION_NOT_PREVIOUSLY_OBSERVED = "destination_not_previously_observed"
    INITIAL_OBSERVATION = "initial_observation"
    FAILED_ROUND = "failed_round"
    REMOTE_UNAVAILABLE = "remote_unavailable"
    APPLICATION_SCOPE_UNAVAILABLE = "application_scope_unavailable"
    NETWORK_SCOPE_UNAVAILABLE = "network_scope_unavailable"
    APPLICATION_SCOPE_MISMATCH = "application_scope_mismatch"
    REVISION_MISMATCH = "revision_mismatch"
    NETWORK_SCOPE_MISMATCH = "network_scope_mismatch"
    BASELINE_LEARNING = "baseline_learning"
    BASELINE_INSUFFICIENT_DATA = "baseline_insufficient_data"
    BASELINE_INSUFFICIENT_QUALITY = "baseline_insufficient_quality"
    BASELINE_STALE = "baseline_stale"
    BASELINE_EXPIRED = "baseline_expired"
    BASELINE_CLOCK_ANOMALY = "baseline_clock_anomaly"
    BASELINE_CORRUPT = "baseline_corrupt"
    BASELINE_UNSUPPORTED_VERSION = "baseline_unsupported_version"
    BASELINE_POLICY_MISMATCH = "baseline_policy_mismatch"
    BASELINE_UNAVAILABLE = "baseline_unavailable"
    HISTORY_INCOMPLETE = "history_incomplete"
    DESTINATION_OVERFLOW = "destination_overflow"
    CAPACITY_LOSS = "capacity_loss"
    COUNTER_SATURATED = "counter_saturated"
    MINIMUM_SAMPLES = "minimum_samples"
    MINIMUM_MONITORED_DURATION = "minimum_monitored_duration"
    RARITY_MINIMUM_SAMPLES = "rarity_minimum_samples"


class DestinationNoveltyLimitation(str, Enum):
    IP_ONLY_SERVICE_NOT_INFERRED = "ip_only_service_not_inferred"
    REVISION_UNVERIFIED = "revision_unverified"
    REDUCED_CURRENT_OBSERVATION = "reduced_current_observation"


@dataclass(frozen=True, slots=True)
class DestinationNoveltyPolicy:
    """Inclusive rarity bounds over eligible appearances, never poll counts."""

    version: int = 1
    minimum_samples: int = 20
    minimum_monitored_seconds: float = 600.0
    rarity_minimum_samples: int = 100
    rare_maximum_appearances: int = 2
    rare_maximum_percent: int = 1

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported novelty policy version")
        for name in ("minimum_samples", "rarity_minimum_samples", "rare_maximum_appearances"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError("novelty threshold outside bounded policy")
        seconds = self.minimum_monitored_seconds
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not isfinite(seconds) or not 1 <= seconds <= 86_400:
            raise ValueError("invalid novelty monitored duration")
        if type(self.rare_maximum_percent) is not int or not 1 <= self.rare_maximum_percent <= 100:
            raise ValueError("invalid rarity percentage")
        if self.rarity_minimum_samples < self.minimum_samples:
            raise ValueError("rarity requires at least the novelty sample minimum")


@dataclass(frozen=True, slots=True)
class DestinationNoveltyInput:
    """Caller supplies a fresh lifecycle snapshot BEFORE adding this appearance.

    The baseline service owns freshness/config compatibility. A future pipeline
    owner must serialize snapshot/evaluate/mutate; this value cannot prove that
    ordering or provide a transaction across independently called services.
    """

    scope: BehaviorScopeKey | None
    remote_ip: str | None
    observed_at: datetime
    origin: ObservationOrigin
    quality: ObservationQuality
    baseline: BaselineSnapshot | None

    def __post_init__(self) -> None:
        if self.scope is not None and not isinstance(self.scope, BehaviorScopeKey):
            raise TypeError("scope must be BehaviorScopeKey or None")
        if self.remote_ip is not None and not isinstance(self.remote_ip, str):
            raise TypeError("remote_ip must be str or None")
        stamp = self.observed_at
        offset = stamp.utcoffset() if isinstance(stamp, datetime) else None
        if not isinstance(stamp, datetime) or stamp.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("observation time must be UTC")
        if not isinstance(self.origin, ObservationOrigin) or not isinstance(self.quality, ObservationQuality):
            raise TypeError("invalid observation origin or quality")
        if self.baseline is not None and not isinstance(self.baseline, BaselineSnapshot):
            raise TypeError("baseline must be BaselineSnapshot or None")


@dataclass(frozen=True, slots=True)
class DestinationNoveltyEvidence:
    rule_id: str
    policy: DestinationNoveltyPolicy
    classification: DestinationNoveltyClassification
    reason: DestinationNoveltyReason
    scope: BehaviorScopeKey | None
    baseline_scope: BehaviorScopeKey | None
    destination_ip: str | None
    destination_appearances: int | None
    baseline_sample_count: int | None
    monitored_seconds: float | None
    baseline_state: BaselineState | None
    baseline_origin: BaselineOrigin | None
    baseline_storage: BaselineStorageState | None
    baseline_policy_key: str | None
    capacity_loss: bool
    other_destinations: int | None
    reduced_appearances: int | None
    unknown_destinations: int | None
    gap_seen: bool
    observed_at: datetime
    origin: ObservationOrigin
    quality: ObservationQuality
    limitations: tuple[DestinationNoveltyLimitation, ...]

    @property
    def total_eligible_baseline_appearances(self) -> int | None:
        """NS-071 samples are eligible OBSERVED appearances, not polling rounds."""
        return self.baseline_sample_count

    @property
    def policy_version(self) -> int:
        return self.policy.version
