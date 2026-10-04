"""Local service has no provider/consent/network side effects."""

from datetime import timedelta

import pytest

from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheKey, ThreatIntelCachePolicy, ThreatIntelCacheMutation,
    ThreatIntelCacheMutationStatus as M, ThreatIntelCacheLookup, ThreatIntelCacheFreshness as F,
)
from netsentinel.domain.threat_intelligence import ThreatIntelResult, ThreatIntelResultStatus as R
from tests.fixtures.threat_intelligence import NOW, DESCRIPTORS, query


class RecordingRepository:
    policy = ThreatIntelCachePolicy()

    def __init__(self):
        self.entries = []
        self.reads = 0

    def put(self, entry, now):
        self.entries.append(entry)
        return ThreatIntelCacheMutation(M.STORED, 1)

    def get(self, key, now):
        self.reads += 1
        return ThreatIntelCacheLookup(F.MISS)


def test_lazy_construction_and_single_local_access():
    repository = RecordingRepository()
    service = ThreatIntelCacheService(repository, DESCRIPTORS)
    assert repository.reads == 0 and repository.entries == []
    value = ThreatIntelResult(query(), R.NO_HIT, NOW)
    assert service.put(value, NOW).status is M.STORED
    assert repository.entries[0].fresh_until == NOW + timedelta(hours=1)
    assert repository.entries[0].stale_until == NOW + timedelta(hours=25)
    assert service.get(ThreatIntelCacheKey.from_result(value), NOW).freshness is F.MISS
    assert repository.reads == 1


def test_one_immutable_policy_and_no_mismatched_limits():
    with pytest.raises(ValueError):
        ThreatIntelCacheService(RecordingRepository(), DESCRIPTORS,
                                ThreatIntelCachePolicy(max_disk_entries=2))
