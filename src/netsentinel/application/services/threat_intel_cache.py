"""NS-085 local single-result cache boundary; no provider calls or scheduling."""

from datetime import datetime

from netsentinel.application.ports import ThreatIntelCacheRepository
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheEntry, ThreatIntelCacheKey, ThreatIntelCacheLookup,
    ThreatIntelCacheMutation, ThreatIntelCacheMutationStatus,
    ThreatIntelCachePolicy, ThreatIntelCachedResult,
)
from netsentinel.domain.threat_intelligence import (
    ThreatIntelProviderDescriptor, ThreatIntelProviderId, ThreatIntelResult,
    ThreatIntelResultStatus, _utc,
)
from netsentinel.application.services.threat_intelligence import validate_descriptors
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness


class ThreatIntelCacheService:
    """Explicit registry permits local reads independently of cloud consent.

    Repository and service share one immutable policy. Construct lazily in a
    component-owned worker; no desktop composition is introduced in NS-085.
    """

    def __init__(self, repository: ThreatIntelCacheRepository,
                 descriptors: tuple[ThreatIntelProviderDescriptor, ...],
                 policy: ThreatIntelCachePolicy | None = None) -> None:
        validate_descriptors(descriptors)
        if policy is not None and policy != repository.policy:
            raise ValueError("service/repository cache policies must agree")
        self._repository = repository
        self._descriptors = descriptors
        self._policy = repository.policy

    def _supported(self, key: ThreatIntelCacheKey) -> bool:
        return any(d.provider == key.provider and key.data_type in d.supported_data_types
                   for d in self._descriptors)

    def get(self, key: ThreatIntelCacheKey, now: datetime) -> ThreatIntelCacheLookup:
        _utc(now)
        if not self._supported(key):
            return ThreatIntelCacheLookup(ThreatIntelCacheFreshness.UNSUPPORTED)
        return self._repository.get(key, now)

    def put(self, result: ThreatIntelResult, now: datetime) -> ThreatIntelCacheMutation:
        _utc(now)
        if not isinstance(result, ThreatIntelResult):
            raise TypeError("cache write requires a typed provider result")
        status = ThreatIntelCacheMutationStatus
        if result.status is ThreatIntelResultStatus.ERROR:
            return ThreatIntelCacheMutation(status.ERROR_SKIPPED)
        key = ThreatIntelCacheKey.from_result(result)
        if not self._supported(key):
            return ThreatIntelCacheMutation(status.UNSUPPORTED)
        # Reject future completions even within read-time clock tolerance.
        if result.received_at > now:
            return ThreatIntelCacheMutation(status.INVALID)
        ttl = (self._policy.hit_ttl if result.status is ThreatIntelResultStatus.HIT
               else self._policy.negative_ttl)
        try:
            fresh = result.received_at + ttl
            entry = ThreatIntelCacheEntry(key, ThreatIntelCachedResult.from_result(result),
                                          fresh, fresh + self._policy.stale_grace)
        except (ValueError, OverflowError):
            return ThreatIntelCacheMutation(status.INVALID)
        return self._repository.put(entry, now)

    def purge(self, *, key: ThreatIntelCacheKey | None = None,
              provider: ThreatIntelProviderId | None = None) -> ThreatIntelCacheMutation:
        return self._repository.purge(key=key, provider=provider)

    def cleanup(self, now: datetime) -> ThreatIntelCacheMutation:
        _utc(now)
        return self._repository.cleanup(now)
