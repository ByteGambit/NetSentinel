"""Pure cache contracts: identity, typed separation and explicit UTC policy."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheEntry, ThreatIntelCacheFreshness as F, ThreatIntelCacheKey,
    ThreatIntelCachePolicy, ThreatIntelCachedResult, classify_entry,
)
from netsentinel.domain.threat_intelligence import ThreatIntelResult, ThreatIntelResultStatus as R
from tests.fixtures.threat_intelligence import NOW, grant, query


def entry(at=NOW):
    request = replace(query(consent=grant()), queried_at=at, request_id=UUID(int=1))
    value = ThreatIntelResult(request, R.HIT, at)
    return ThreatIntelCacheEntry(ThreatIntelCacheKey.from_result(value),
                                ThreatIntelCachedResult.from_result(value),
                                at + timedelta(hours=24), at + timedelta(hours=48))


def test_consent_identity_is_not_cache_identity_or_persisted_provenance():
    first = ThreatIntelResult(query(consent=grant()), R.HIT, NOW)
    second = ThreatIntelResult(query(consent=grant()), R.HIT, NOW)
    assert first.query.consent != second.query.consent
    assert ThreatIntelCacheKey.from_result(first) == ThreatIntelCacheKey.from_result(second)
    assert not hasattr(ThreatIntelCachedResult.from_result(first), 'consent')


def test_absolute_horizon_not_recomputed_from_new_policy():
    value = entry()
    new_policy = ThreatIntelCachePolicy(hit_ttl=timedelta(minutes=1), stale_grace=timedelta(0))
    assert classify_entry(value, NOW + timedelta(hours=2), new_policy).freshness is F.FRESH
    assert classify_entry(value, NOW + timedelta(hours=24), new_policy).freshness is F.STALE
    assert classify_entry(value, NOW + timedelta(hours=48), new_policy).freshness is F.EXPIRED


def test_zero_stale_grace_and_datetime_extremes():
    value = replace(entry(), stale_until=NOW + timedelta(hours=24))
    assert classify_entry(value, value.fresh_until, ThreatIntelCachePolicy()).freshness is F.EXPIRED
    assert classify_entry(value, datetime.max.replace(tzinfo=UTC), ThreatIntelCachePolicy()).freshness is F.EXPIRED
    assert classify_entry(value, datetime.min.replace(tzinfo=UTC), ThreatIntelCachePolicy()).freshness is F.CORRUPT


@pytest.mark.parametrize('change', [dict(fresh_until=NOW), dict(stale_until=NOW),
                                   dict(stale_until=NOW + timedelta(days=61)),
                                   dict(fresh_until=NOW.replace(tzinfo=None))])
def test_invalid_absolute_horizons(change):
    with pytest.raises(ValueError):
        replace(entry(), **change)
