"""Normalized TI outcomes with no network or credentials."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupTicket, ThreatIntelScheduledOutcome, LookupState
from netsentinel.application.services.threat_intel_evidence import ThreatIntelEvidenceAdapter
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheKey, ThreatIntelCachedResult, ThreatIntelCacheEntry,
    ThreatIntelCacheFreshness as F, ThreatIntelCacheLookup,
)
from netsentinel.domain.threat_intelligence import (
    ThreatIntelResult, ThreatIntelResultStatus as S, ThreatIntelIpFacts,
    ThreatIntelProviderId,
)
from tests.fixtures.threat_intelligence import NOW, query


def outcome(*, status=S.HIT, freshness=F.FRESH, provider="abuseipdb",
            address="8.8.8.8", error=None, stamp=NOW, score=75, reports=12,
            cached=False, terminal=True):
    q = replace(query(provider=ThreatIntelProviderId(provider), value=address), queried_at=stamp, request_id=UUID(int=101))
    facts = ThreatIntelIpFacts(1, 30, score if status is S.HIT else 0,
        reports if status is S.HIT else 0, 3 if status is S.HIT else 0,
        stamp - timedelta(days=1) if status is S.HIT else None, True)
    result = ThreatIntelResult(q, status, stamp, ip_facts=facts)
    cache = None
    if cached or freshness is not F.FRESH:
        cache = ThreatIntelCacheLookup(freshness,
            ThreatIntelCacheEntry(ThreatIntelCacheKey.from_result(result), ThreatIntelCachedResult.from_result(result),
                stamp + timedelta(hours=1), stamp + timedelta(days=2)) if freshness in (F.FRESH, F.STALE) else None)
    if error:
        result = ThreatIntelResult(q, S.ERROR, stamp, error)
    return ThreatIntelScheduledOutcome(ThreatIntelLookupTicket(UUID(int=123)),
        LookupState.PROVIDER_ERROR if error else LookupState.FRESH_CACHE if cached else LookupState.PROVIDER_RESULT,
        cache=cache, result=None if cached or freshness is not F.FRESH and not error else result,
        terminal=terminal)


def mapping(**kwargs):
    value = outcome(**kwargs)
    subject = value.result.query.subject if value.result else value.cache.entry.key.subject
    return ThreatIntelEvidenceAdapter().map(value, subject)
