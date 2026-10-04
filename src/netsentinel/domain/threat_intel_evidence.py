"""Bounded historical external context, separate from local scoring inputs."""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from uuid import UUID

from netsentinel.domain.risk_evidence import _digest
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheFreshness, ThreatIntelCacheKey, ThreatIntelCachedResult,
)
from netsentinel.domain.threat_intelligence import ThreatIntelError, ThreatIntelSubjectKind, ThreatIntelQuery, ThreatIntelResult, _utc

MAX_TI_ASSESSMENT_PROVIDERS = 16
TI_EVIDENCE_RULE = "threat_intelligence_reputation_context"


class ThreatIntelEvidenceStatus(str, Enum):
    ATTACHED = "attached"
    NO_CONTEXT = "no_context"
    SUBJECT_MISMATCH = "subject_mismatch"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ThreatIntelEvidenceContext:
    evidence_id: str
    key: ThreatIntelCacheKey = field(repr=False)
    result: ThreatIntelCachedResult = field(repr=False)
    freshness: ThreatIntelCacheFreshness
    refresh_error: ThreatIntelError | None = None
    cache_unavailable: bool = False

    def __post_init__(self) -> None:
        _digest(self.evidence_id)
        if type(self.key) is not ThreatIntelCacheKey or type(self.result) is not ThreatIntelCachedResult:
            raise TypeError("TI context requires normalized typed provenance")
        if self.key.subject.kind is not ThreatIntelSubjectKind.IP:
            raise ValueError("assessment TI context currently supports IP only")
        if self.freshness not in (ThreatIntelCacheFreshness.FRESH, ThreatIntelCacheFreshness.STALE) or type(self.freshness) is not ThreatIntelCacheFreshness:
            raise ValueError("only visible fresh/stale context can be attached")
        if self.refresh_error is not None and type(self.refresh_error) is not ThreatIntelError:
            raise TypeError("refresh limitation must be typed")
        if self.refresh_error is not None and self.freshness is not ThreatIntelCacheFreshness.STALE:
            raise ValueError("refresh error accompanies stale context only")
        if type(self.cache_unavailable) is not bool:
            raise TypeError("cache limitation must be typed")
        query = ThreatIntelQuery(self.result.request_id, self.key.provider, self.key.subject,
            self.key.data_type, self.result.trigger, None, self.result.queried_at, self.result.query_policy_version)
        ThreatIntelResult(query, self.result.status, self.result.received_at, ip_facts=self.result.ip_facts)


@dataclass(frozen=True, slots=True)
class ThreatIntelAssessmentSignal:
    lifecycle_id: UUID
    context: ThreatIntelEvidenceContext
    assessed_at: datetime

    def __post_init__(self) -> None:
        if type(self.lifecycle_id) is not UUID or type(self.context) is not ThreatIntelEvidenceContext:
            raise TypeError("TI reassessment requires immutable lifecycle and context")
        _utc(self.assessed_at)
