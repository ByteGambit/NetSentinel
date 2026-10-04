"""NS-088 pure mapping, semantic identities, privacy and bounded provenance."""

from dataclasses import fields, replace
from datetime import timedelta

import pytest

from netsentinel.application.services.threat_intel_evidence import ThreatIntelEvidenceAdapter, context_lines, evidence_for_context
from netsentinel.domain.risk_assessment import canonical_json
from netsentinel.domain.risk_evidence import EvidenceSource, EvidenceRole
from netsentinel.domain.threat_intel_evidence import ThreatIntelEvidenceStatus, ThreatIntelEvidenceContext
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness as F, ThreatIntelCacheLookup
from netsentinel.domain.threat_intelligence import ThreatIntelResultStatus as S, ThreatIntelError as E, ThreatIntelSubject, ThreatIntelSubjectKind
from tests.fixtures.threat_intel_evidence import outcome, mapping, NOW


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
@pytest.mark.parametrize("freshness", [F.FRESH, F.STALE])
@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111"])
def test_successful_mapping_preserves_independent_context(status, freshness, address):
    mapped = mapping(status=status, freshness=freshness, address=address)
    assert mapped.status is ThreatIntelEvidenceStatus.ATTACHED
    c, e = mapped.context, mapped.evidence
    assert c.key.provider.value == "abuseipdb" and c.key.subject.value == address
    assert c.freshness is freshness and c.result.status is status
    assert c.result.ip_facts.mapping_version == 1 and c.key.result_version == 2
    assert e.source is EvidenceSource.THREAT_INTELLIGENCE and e.role is EvidenceRole.OBSERVATION
    assert e.rule_id == "threat_intelligence_reputation_context"
    assert e.confidence is None and e.quality.measurement is None
    assert c.evidence_id == e.evidence_id == evidence_for_context(c).evidence_id
    text = "\n".join(context_lines(c))
    assert freshness.name in text and status.name in text
    assert "supporting context, not a malware verdict" in text
    assert "AbuseIPDB abuse confidence score:" in text
    assert "Reports in provider lookback window:" in text
    assert "Distinct reporting users:" in text and "Last reported at:" in text
    assert "does not imply trust or reduce risk" in text
    assert "not malware probability" in text and "75%" not in text
    if status is S.NO_HIT:
        assert "does not establish that the destination is safe" in text


@pytest.mark.parametrize("error", list(E))
def test_errors_never_become_security_context(error):
    value = outcome(error=error)
    result = ThreatIntelEvidenceAdapter().map(value, value.result.query.subject)
    assert result.status is ThreatIntelEvidenceStatus.NO_CONTEXT and result.evidence is None


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
@pytest.mark.parametrize("error", [E.TIMEOUT, E.RATE_LIMITED, E.CREDENTIAL_UNAVAILABLE])
def test_stale_refresh_error_keeps_both_states(status, error):
    mapped = mapping(status=status, freshness=F.STALE, error=error)
    assert mapped.context.freshness is F.STALE and mapped.context.refresh_error is error
    text = "\n".join(context_lines(mapped.context))
    assert "STALE cached context; refresh failed:" in text and error.value.replace("_", " ") in text


@pytest.mark.parametrize("freshness", [F.EXPIRED, F.MISS, F.UNAVAILABLE, F.CORRUPT, F.UNSUPPORTED, F.CLOCK_ANOMALY])
def test_unusable_cache_not_attached(freshness):
    value = replace(outcome(), result=None, cache=ThreatIntelCacheLookup(freshness))
    assert ThreatIntelEvidenceAdapter().map(value, ThreatIntelSubject(ThreatIntelSubjectKind.IP, "8.8.8.8")).status is ThreatIntelEvidenceStatus.NO_CONTEXT


def test_subject_mismatch_and_unsupported_subject():
    adapter = ThreatIntelEvidenceAdapter()
    assert adapter.map(outcome(), ThreatIntelSubject(ThreatIntelSubjectKind.IP, "1.1.1.1")).status is ThreatIntelEvidenceStatus.SUBJECT_MISMATCH
    assert adapter.map(outcome(), ThreatIntelSubject(ThreatIntelSubjectKind.DOMAIN, "example.com")).status is ThreatIntelEvidenceStatus.UNSUPPORTED


def test_cache_reread_no_identity_churn_new_fetch_has_new_identity():
    first = mapping()
    assert first == mapping(cached=True)
    assert first.context.evidence_id != mapping(stamp=NOW + timedelta(hours=1)).context.evidence_id
    assert first.context.evidence_id != mapping(score=80).context.evidence_id
    assert first.context.evidence_id != mapping(provider="fake_provider_b").context.evidence_id
    assert first.context.evidence_id != mapping(status=S.NO_HIT).context.evidence_id


def test_context_is_closed_and_historical_truth_is_explicit():
    assert {f.name for f in fields(ThreatIntelEvidenceContext)} == {"evidence_id", "key", "result", "freshness", "refresh_error", "cache_unavailable"}
    text = canonical_json(mapping().context)
    for forbidden in ("secret", "api_key", "raw_response", "headers", "metadata", "payload", "consent"):
        assert forbidden not in text
    assert "current cache freshness is not inferred" in "\n".join(context_lines(mapping().context, historical=True))
    with pytest.raises(ValueError):
        replace(mapping().context, freshness=F.EXPIRED)


def test_ti_alone_cannot_gain_risk_or_attack_confidence():
    from netsentinel.domain.risk_evidence import RiskEvidenceBatch
    from netsentinel.domain.risk_scoring import RiskScoringInput, EvidenceFreshness, Freshness, score_risk, AssessmentAvailability, RiskScoringPolicy
    evidence = mapping().evidence
    result = score_risk(RiskScoringInput(RiskEvidenceBatch((evidence,)), (EvidenceFreshness(evidence.evidence_id, Freshness.CURRENT),)), RiskScoringPolicy())
    assert result.score == 0 and result.confidence is None and result.severity is None
    assert result.availability is AssessmentAvailability.UNKNOWN and result.policy_version == 1
