"""Central NS-088 mapping: normalized scheduler outcome to supporting evidence."""

from netsentinel.shared.enum_sources import enum_source
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP


from dataclasses import dataclass, replace
from hashlib import sha256

from netsentinel.application.services.threat_intel_scheduler import ThreatIntelScheduledOutcome, LookupState
from netsentinel.domain.risk_assessment import canonical_json
from netsentinel.domain.risk_evidence import (
    EvidenceQuality, EvidenceReference, EvidenceReferenceKind, EvidenceScope,
    EvidenceScopeKind, EvidenceSource, EvidenceSubject, EvidenceSubjectKind, RiskEvidence,
)
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheFreshness as F, ThreatIntelCacheKey, ThreatIntelCachedResult,
    ThreatIntelCacheMutationStatus,
)
from netsentinel.domain.threat_intel_evidence import (
    ThreatIntelEvidenceContext, ThreatIntelEvidenceStatus, TI_EVIDENCE_RULE,
)
from netsentinel.domain.threat_intelligence import (
    ThreatIntelSubject, ThreatIntelSubjectKind, ThreatIntelResultStatus as S,
)


def evidence_for_context(context: ThreatIntelEvidenceContext) -> RiskEvidence:
    """Generic source/rule; provider identity remains separate typed provenance."""
    digest = sha256(canonical_json(replace(context, evidence_id="0" * 64)).encode("ascii")).hexdigest()
    return RiskEvidence(EvidenceSource.THREAT_INTELLIGENCE, TI_EVIDENCE_RULE,
        "provider_reports_present" if context.result.status is S.HIT else "provider_no_reports",
        context.result.received_at, EvidenceScope(EvidenceScopeKind.HOST),
        EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=context.key.subject.value),
        EvidenceQuality(None), policy_version=1, result_code=context.result.status.value,
        references=(EvidenceReference(EvidenceReferenceKind.EVIDENCE, digest),))


@dataclass(frozen=True, slots=True)
class ThreatIntelEvidenceMapping:
    status: ThreatIntelEvidenceStatus
    context: ThreatIntelEvidenceContext | None = None
    evidence: RiskEvidence | None = None


class ThreatIntelEvidenceAdapter:
    def map(self, outcome: ThreatIntelScheduledOutcome,
            subject: ThreatIntelSubject) -> ThreatIntelEvidenceMapping:
        if subject.kind is not ThreatIntelSubjectKind.IP:
            return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.UNSUPPORTED)
        if outcome.state in (LookupState.CANCELLED_CONSENT, LookupState.CANCELLED_SHUTDOWN):
            return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.NO_CONTEXT)
        result = outcome.result
        if result is not None and result.query.subject != subject:
            return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.SUBJECT_MISMATCH)
        error = result.error if result is not None and result.status is S.ERROR else None
        cache_unavailable = bool(outcome.cache_write and outcome.cache_write.status is ThreatIntelCacheMutationStatus.UNAVAILABLE)
        if result is not None and result.status is not S.ERROR:
            key, cached, freshness = ThreatIntelCacheKey.from_result(result), ThreatIntelCachedResult.from_result(result), F.FRESH
        elif outcome.cache is not None and outcome.cache.entry is not None:
            key, cached, freshness = outcome.cache.entry.key, outcome.cache.entry.result, outcome.cache.freshness
        else:
            return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.NO_CONTEXT)
        if key.subject != subject:
            return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.SUBJECT_MISMATCH)
        seed = ThreatIntelEvidenceContext("0" * 64, key, cached, freshness, error, cache_unavailable)
        evidence = evidence_for_context(seed)
        context = replace(seed, evidence_id=evidence.evidence_id)
        return ThreatIntelEvidenceMapping(ThreatIntelEvidenceStatus.ATTACHED, context, evidence)


TI_DISCLAIMER = QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'External reputation is supporting context, not a malware verdict.')


def context_lines(context: ThreatIntelEvidenceContext, *, historical: bool = False) -> tuple[str, ...]:
    """Shared bounded plain-text view for lookup and stored risk explanations."""
    key, result = context.key, context.result
    provider = "AbuseIPDB" if key.provider.value == "abuseipdb" else key.provider.value
    facts = result.ip_facts
    lines = [TI_DISCLAIMER, QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Provider: {value1} ({value2})').format(value1=provider, value2=key.provider.value),
        QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Subject: {value1} {value2}').format(value1=key.subject.kind.value, value2=key.subject.value),
        QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Result: {value1}; {value2}: {value3}').format(value1=enum_source(result.status, 'upper'), value2=QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'freshness at assessment time') if historical else QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'lookup freshness'), value3=enum_source(context.freshness, 'upper')),
        QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Queried at: {value1} UTC; fetched at: {value2} UTC').format(value1=result.queried_at.isoformat(), value2=result.received_at.isoformat()),
        QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Result contract: v{value1}; evidence adapter: v1; source reference: {value2}').format(value1=key.result_version, value2=result.request_id),
        QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Informational evidence; zero risk points; provider metric is separate from NetSentinel confidence and measurement quality.')]
    if result.status is S.NO_HIT:
        lines.append(QT_TRANSLATE_NOOP('ThreatIntelEvidence', '{value1}Provider returned no reports/context for the queried lookback. This does not establish that the destination is safe.').format(value1=QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'STALE context: ') if context.freshness is F.STALE else ''))
    if facts is not None and key.provider.value == "abuseipdb":
        lines += [QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'AbuseIPDB mapping: v{value1}; lookback: {value2} days').format(value1=facts.mapping_version, value2=facts.lookback_days),
            QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'AbuseIPDB abuse confidence score: {value1} / 100 (provider metric; not malware probability)').format(value1=facts.abuse_confidence_score),
            QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Reports in provider lookback window: {value1}').format(value1=facts.total_reports),
            QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Distinct reporting users: {value1}').format(value1=facts.distinct_users),
            QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Last reported at: {value1}').format(value1=facts.last_reported_at.isoformat() + ' UTC' if facts.last_reported_at else QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Not reported')),
            QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Provider whitelist context: {value1}; does not imply trust or reduce risk.').format(value1=facts.is_whitelisted)]
    if context.refresh_error:
        lines.append(QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'STALE cached context; refresh failed: {value1}. Local detection continues.').format(value1=enum_source(context.refresh_error, 'words')))
    if context.cache_unavailable:
        lines.append(QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Cache persistence unavailable; provider result remains visible.'))
    if historical:
        lines.append(QT_TRANSLATE_NOOP('ThreatIntelEvidence', 'Stored historical snapshot; current cache freshness is not inferred and cache changes do not rewrite this revision.'))
    return tuple(lines)
