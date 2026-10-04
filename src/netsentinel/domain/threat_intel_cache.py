"""NS-085 local cache contracts; freshness never changes provider status."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from netsentinel.domain.threat_intelligence import (
    TI_POLICY_VERSION, TI_RESULT_CONTRACT_VERSION, ThreatIntelDataType, ThreatIntelProviderId, ThreatIntelIpFacts,
    ThreatIntelQuery, ThreatIntelResult, ThreatIntelResultStatus, ThreatIntelSubject,
    ThreatIntelTrigger, _utc,
)


@dataclass(frozen=True, slots=True)
class ThreatIntelCachePolicy:
    hit_ttl: timedelta = timedelta(hours=24)
    negative_ttl: timedelta = timedelta(hours=1)
    stale_grace: timedelta = timedelta(hours=24)
    future_tolerance: timedelta = timedelta(minutes=5)
    max_disk_entries: int = 1024
    max_payload_bytes: int = 4096
    cleanup_chunk: int = 128

    def __post_init__(self) -> None:
        for value in (self.hit_ttl, self.negative_ttl):
            if not isinstance(value, timedelta) or not timedelta(0) < value <= timedelta(days=30):
                raise ValueError("invalid fresh TTL")
        for value in (self.stale_grace, self.future_tolerance):
            if not isinstance(value, timedelta) or not timedelta(0) <= value <= timedelta(days=30):
                raise ValueError("invalid cache time bound")
        for capacity, cap in ((self.max_disk_entries, 1024), (self.max_payload_bytes, 4096),
                           (self.cleanup_chunk, 128)):
            if type(capacity) is not int or not 1 <= capacity <= cap:
                raise ValueError("invalid cache capacity")


@dataclass(frozen=True, slots=True)
class ThreatIntelCacheKey:
    provider: ThreatIntelProviderId
    data_type: ThreatIntelDataType
    subject: ThreatIntelSubject = field(repr=False)
    result_version: int = TI_RESULT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if (not isinstance(self.provider, ThreatIntelProviderId)
                or not isinstance(self.data_type, ThreatIntelDataType)
                or not isinstance(self.subject, ThreatIntelSubject)):
            raise TypeError("cache key requires typed dimensions")
        if self.data_type.subject_kind is not self.subject.kind:
            raise ValueError("cache data type does not match subject")
        if type(self.result_version) is not int or not 1 <= self.result_version <= 2**31 - 1:
            raise ValueError("invalid result contract version")

    @classmethod
    def from_result(cls, result: ThreatIntelResult) -> "ThreatIntelCacheKey":
        return cls(result.query.provider, result.query.data_type, result.query.subject)


@dataclass(frozen=True, slots=True)
class ThreatIntelCachedResult:
    """Minimum normalized NS-084 provenance; no consent credential or raw blob."""

    status: ThreatIntelResultStatus
    request_id: UUID
    queried_at: datetime
    received_at: datetime
    trigger: ThreatIntelTrigger
    query_policy_version: int
    ip_facts: ThreatIntelIpFacts | None = None

    def __post_init__(self) -> None:
        if (self.status not in (ThreatIntelResultStatus.HIT, ThreatIntelResultStatus.NO_HIT)
                or not isinstance(self.status, ThreatIntelResultStatus)
                or not isinstance(self.request_id, UUID)
                or not isinstance(self.trigger, ThreatIntelTrigger)
                or type(self.query_policy_version) is not int
                or self.query_policy_version != TI_POLICY_VERSION):
            raise ValueError("invalid normalized cached result")
        _utc(self.queried_at)
        _utc(self.received_at)
        if self.received_at < self.queried_at:
            raise ValueError("cached result precedes query")
        if self.ip_facts is not None and not isinstance(self.ip_facts, ThreatIntelIpFacts):
            raise TypeError("invalid cached IP facts")

    @classmethod
    def from_result(cls, result: ThreatIntelResult) -> "ThreatIntelCachedResult":
        if result.status is ThreatIntelResultStatus.ERROR:
            raise ValueError("operational errors are not cached")
        query = result.query
        return cls(result.status, query.request_id, query.queried_at, result.received_at,
                   query.trigger, query.policy_version, result.ip_facts)


@dataclass(frozen=True, slots=True)
class ThreatIntelCacheEntry:
    key: ThreatIntelCacheKey = field(repr=False)
    result: ThreatIntelCachedResult = field(repr=False)
    fresh_until: datetime
    stale_until: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.key, ThreatIntelCacheKey) or not isinstance(self.result, ThreatIntelCachedResult):
            raise TypeError("invalid cache entry")
        result = self.result
        # Reuse NS-084 validation rather than duplicating subject/query/result rules.
        query = ThreatIntelQuery(result.request_id, self.key.provider, self.key.subject,
                                 self.key.data_type, result.trigger, None,
                                 result.queried_at, result.query_policy_version)
        ThreatIntelResult(query, result.status, result.received_at, ip_facts=result.ip_facts)
        if result.status is ThreatIntelResultStatus.ERROR:
            raise ValueError("operational errors are not cached")
        _utc(self.fresh_until)
        _utc(self.stale_until)
        if not (result.received_at < self.fresh_until <= self.stale_until
                and self.stale_until - result.received_at <= timedelta(days=60)):
            raise ValueError("invalid absolute cache horizon")


class ThreatIntelCacheFreshness(str, Enum):
    MISS = "miss"
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    CORRUPT = "corrupt"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    CLOCK_ANOMALY = "clock_anomaly"


@dataclass(frozen=True, slots=True)
class ThreatIntelCacheLookup:
    freshness: ThreatIntelCacheFreshness
    entry: ThreatIntelCacheEntry | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.freshness, ThreatIntelCacheFreshness):
            raise TypeError("invalid cache freshness")
        visible = self.freshness in (ThreatIntelCacheFreshness.FRESH, ThreatIntelCacheFreshness.STALE)
        if visible != (self.entry is not None):
            raise ValueError("only fresh/stale lookups expose a result")


def classify_entry(entry: ThreatIntelCacheEntry, now: datetime,
                   policy: ThreatIntelCachePolicy) -> ThreatIntelCacheLookup:
    _utc(now)
    state = ThreatIntelCacheFreshness
    if entry.result.received_at - now > policy.future_tolerance:
        return ThreatIntelCacheLookup(state.CORRUPT)
    if now < entry.result.received_at:
        return ThreatIntelCacheLookup(state.CLOCK_ANOMALY)
    if now < entry.fresh_until:
        return ThreatIntelCacheLookup(state.FRESH, entry)
    if now < entry.stale_until:
        return ThreatIntelCacheLookup(state.STALE, entry)
    return ThreatIntelCacheLookup(state.EXPIRED)


class ThreatIntelCacheMutationStatus(str, Enum):
    STORED = "stored"
    NO_CHANGE = "no_change"
    ERROR_SKIPPED = "error_skipped"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    PURGED = "purged"


@dataclass(frozen=True, slots=True)
class ThreatIntelCacheMutation:
    status: ThreatIntelCacheMutationStatus
    affected: int = 0
    evicted: int = 0
    remaining: bool = False

    def __post_init__(self) -> None:
        if (not isinstance(self.status, ThreatIntelCacheMutationStatus)
                or type(self.remaining) is not bool
                or any(type(n) is not int or not 0 <= n <= 128 for n in (self.affected, self.evicted))):
            raise ValueError("invalid bounded cache mutation result")
