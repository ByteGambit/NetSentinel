"""NS-081 matching, precedence, support groups and fail-open contract."""

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from itertools import permutations
from uuid import UUID

import pytest

from netsentinel.application.services.suppression import (
    SuppressionEvaluationService, evaluate_suppression, match_context,
)
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.preferences import (
    PreferenceAuditAction, PreferencePage, PreferenceResult, PreferenceResultStatus as ReadStatus,
    PreferenceSelector, PreferenceStatus,
)
from netsentinel.domain.risk_evidence import (
    EvidenceLimitation, EvidenceQuality, EvidenceScope, EvidenceScopeKind, EvidenceSubject,
    EvidenceSubjectKind, RiskEvidenceBatch,
)
from netsentinel.domain.risk_scoring import EvidenceFreshness, Freshness, RiskScoringInput, RiskScoringPolicy, score_risk
from netsentinel.domain.suppression import (
    MAX_SUPPRESSION_MATCHES, SuppressionDisposition as Disposition, SuppressionLimitation as Limitation,
)
from tests.fixtures.preferences import NOW, RULE, application, destination
from tests.fixtures.risk_assessments import APP, evidence
from tests.fixtures.suppression import EXPIRES, REFERENCE, frequency, page, periodic, preference, risk


def evaluate(result=None, *preferences, candidates=None, now=NOW):
    return evaluate_suppression(result or risk(), REFERENCE, now,
                               candidates if candidates is not None else page(*preferences))


@pytest.mark.parametrize("selector", [
    PreferenceSelector(rule_id=RULE), PreferenceSelector(application=APP),
    PreferenceSelector(destination=destination("192.0.2.1")),
    PreferenceSelector(application=APP, destination=destination("192.0.2.1")),
])
def test_exact_single_and_combined_scopes_suppress(selector):
    result = evaluate(risk(), preference(selector))
    assert result.disposition is Disposition.SUPPRESSED and not result.alert_eligible
    assert result.evidence[0].primary.preference_id == UUID(int=1)
    assert result.evidence[0].primary.reason == "Explicit scoped policy"
    assert result.evidence[0].context.rule_id == RULE


@pytest.mark.parametrize("selector", [
    PreferenceSelector(rule_id=RULE + "_future"), PreferenceSelector(application=application("c:\\other\\example.exe")),
    PreferenceSelector(destination=destination("192.0.2.2")), PreferenceSelector(network_fingerprint="a" * 64),
    PreferenceSelector(application=APP, destination=destination("192.0.2.2")),
])
def test_mismatch_is_never_fuzzy_or_wildcard(selector):
    result = evaluate(risk(), preference(selector))
    assert result.disposition is Disposition.NOT_SUPPRESSED and result.alert_eligible


def test_ipv6_canonical_no_ipv4_mapped_expansion():
    e = evidence(subject=replace(evidence().subject, ip_address="2001:db8::1"))
    p = preference(PreferenceSelector(destination=destination("2001:0DB8:0000:0000:0000:0000:0000:0001")))
    assert evaluate(risk(e), p).disposition is Disposition.SUPPRESSED
    mapped = evidence(subject=replace(evidence().subject, ip_address="::ffff:192.0.2.1"))
    assert evaluate(risk(mapped), preference(PreferenceSelector(destination=destination("192.0.2.1")))).alert_eligible


@pytest.mark.parametrize("status", [NetworkScopeStatus.RESOLVED, NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_network_exact_resolved_and_unresolved_hostwide(status):
    scope = EvidenceScope(EvidenceScopeKind.NETWORK, status, "a" * 64) if status is NetworkScopeStatus.RESOLVED else EvidenceScope(EvidenceScopeKind.UNKNOWN, status)
    r = risk(evidence(scope=scope))
    p = preference(PreferenceSelector(network_fingerprint="a" * 64))
    assert (evaluate(r, p).disposition is Disposition.SUPPRESSED) == (status is NetworkScopeStatus.RESOLVED)
    assert evaluate(r, preference(PreferenceSelector(rule_id=RULE))).disposition is Disposition.SUPPRESSED
    assert evaluate(r, preference(PreferenceSelector(network_fingerprint="b" * 64))).alert_eligible


@pytest.mark.parametrize("digest", ["a" * 64, "b" * 64, None])
def test_application_revision_exact_unknown_and_unconstrained(digest):
    selector_revision = ApplicationRevision("a" * 64, ExecutableHashStatus.AVAILABLE)
    revision = ApplicationRevision(digest, ExecutableHashStatus.AVAILABLE if digest else None)
    r = risk(evidence(subject=replace(evidence().subject, revision=revision)))
    exact = preference(PreferenceSelector(application=APP, application_revision=selector_revision))
    assert (evaluate(r, exact).disposition is Disposition.SUPPRESSED) == (digest == "a" * 64)
    assert evaluate(r, preference(PreferenceSelector(application=APP))).disposition is Disposition.SUPPRESSED


@pytest.mark.parametrize("dimension", ["application", "destination"])
def test_missing_subject_dimension_cannot_match(dimension):
    subject = replace(evidence().subject, application=None) if dimension == "application" else EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=APP)
    selector = PreferenceSelector(application=APP) if dimension == "application" else PreferenceSelector(destination=destination("192.0.2.1"))
    assert evaluate(risk(evidence(subject=subject)), preference(selector)).alert_eligible


def test_all_five_constraints_and_one_mismatch():
    revision = ApplicationRevision("a" * 64, ExecutableHashStatus.AVAILABLE)
    scope = EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "b" * 64)
    e = evidence(scope=scope, subject=replace(evidence().subject, revision=revision))
    selector = PreferenceSelector(APP, revision, destination("192.0.2.1"), "b" * 64, RULE)
    assert evaluate(risk(e), preference(selector)).disposition is Disposition.SUPPRESSED
    for changes in ({"application": application()}, {"application_revision": ApplicationRevision("c" * 64, ExecutableHashStatus.AVAILABLE)},
                    {"destination": destination("192.0.2.2")}, {"network_fingerprint": "c" * 64}, {"rule_id": "other_rule"}):
        assert evaluate(risk(e), preference(replace(selector, **changes))).alert_eligible


@pytest.mark.parametrize("delta,expected", [(-1, Disposition.SUPPRESSED), (0, Disposition.NOT_SUPPRESSED), (1, Disposition.NOT_SUPPRESSED)])
def test_expiry_exact_boundary(delta, expected):
    p = preference(expires_at=EXPIRES)
    result = evaluate(risk(), p, now=EXPIRES + timedelta(microseconds=delta))
    assert result.disposition is expected
    assert result.evidence[0].expired_match_count == int(delta >= 0)


def test_permanent_revoked_expired_distinct_explanations():
    permanent = preference()
    assert evaluate(risk(), permanent, now=NOW + timedelta(days=36500)).disposition is Disposition.SUPPRESSED
    revoked = replace(preference(expires_at=EXPIRES), revision=2, action=PreferenceAuditAction.REVOKE, status=PreferenceStatus.REVOKED)
    result = evaluate(risk(), revoked, preference(index=2, expires_at=NOW))
    assert result.alert_eligible
    assert result.evidence[0].revoked_match_count == result.evidence[0].expired_match_count == 1


def test_specificity_and_incomparable_ties_are_order_independent():
    policies = (preference(PreferenceSelector(rule_id=RULE), index=1),
                preference(PreferenceSelector(application=APP), index=2),
                preference(PreferenceSelector(application=APP, destination=destination("192.0.2.1")), index=3))
    first = evaluate(risk(), *policies)
    assert first.evidence[0].primary.preference_id == UUID(int=3)
    assert [m.preference_id.int for m in first.evidence[0].matches] == [3, 1, 2]
    for order in permutations(policies):
        assert evaluate(risk(), *order) == first


@pytest.mark.parametrize("count", [MAX_SUPPRESSION_MATCHES, MAX_SUPPRESSION_MATCHES + 1, 100])
def test_match_reference_cap_and_explicit_truncation(count):
    result = evaluate(risk(), *(preference(index=i + 1) for i in range(count)))
    entry = result.evidence[0]
    assert len(entry.matches) == MAX_SUPPRESSION_MATCHES and entry.observed_match_count == count
    assert (Limitation.MATCHES_TRUNCATED in result.limitations) == (count > MAX_SUPPRESSION_MATCHES)
    assert result.disposition is Disposition.SUPPRESSED


@pytest.mark.parametrize("fault,limitation", [
    (ReadStatus.CORRUPT, Limitation.CORRUPT_PREFERENCE),
    (ReadStatus.UNSUPPORTED_VERSION, Limitation.UNSUPPORTED_PREFERENCE_FORMAT),
])
def test_bad_candidate_alone_fail_open_and_valid_match_still_works(fault, limitation):
    bad = PreferenceResult(fault, preference_id=UUID(int=99))
    result = evaluate(candidates=PreferencePage(ReadStatus.FOUND, (bad,)))
    assert result.disposition is Disposition.INDETERMINATE and result.alert_eligible
    assert limitation in result.limitations
    candidates = replace(page(preference()), entries=page(preference()).entries + (bad,))
    result = evaluate(candidates=candidates)
    assert result.disposition is Disposition.SUPPRESSED and limitation in result.limitations


def test_incomplete_candidate_set_does_not_claim_no_preference():
    result = evaluate(candidates=page(truncated=True))
    assert result.disposition is Disposition.INDETERMINATE and result.alert_eligible
    assert Limitation.CANDIDATES_TRUNCATED in result.limitations
    assert evaluate(candidates=page(preference(), truncated=True)).disposition is Disposition.SUPPRESSED


def test_lookup_unavailable_has_explicit_fail_open_semantics():
    result = evaluate(candidates=PreferencePage(ReadStatus.UNAVAILABLE))
    assert result.disposition is Disposition.UNAVAILABLE and result.alert_eligible
    assert result.evidence[0].disposition is Disposition.UNAVAILABLE
    assert result.reason_code == "policy_evaluation_unavailable_fail_open"


def test_duplicate_candidate_revisions_are_not_silently_arbitrated():
    result = evaluate(risk(), preference(), preference(revision=2))
    assert result.disposition is Disposition.INDETERMINATE and result.alert_eligible
    assert Limitation.CORRUPT_PREFERENCE in result.limitations


def test_partial_independent_groups_and_full_suppression_preserve_score():
    r = risk(evidence(), periodic())
    before = r
    partial = evaluate(r, preference())
    assert partial.disposition is Disposition.PARTIALLY_SUPPRESSED and partial.alert_eligible
    assert len(partial.suppressed_evidence_ids) == len(partial.unsuppressed_evidence_ids) == 1
    full = evaluate(r, preference(), preference(PreferenceSelector(rule_id="observed_appearance_periodicity"), index=2))
    assert full.disposition is Disposition.SUPPRESSED and not full.alert_eligible
    assert r == before and r.score == 35


def test_correlated_superseded_support_keeps_group_eligible():
    r = risk(evidence(), frequency())
    assert r.score == 35 and len(r.contributors) == 2
    assert sorted(c.applied_points for c in r.contributors) == [0, 35]
    partial = evaluate(r, preference(PreferenceSelector(rule_id="observed_appearance_frequency")))
    assert partial.disposition is Disposition.PARTIALLY_SUPPRESSED and partial.alert_eligible
    assert len(partial.groups) == 1 and len(partial.groups[0].remaining_evidence_ids) == 1
    assert evaluate(r, preference(PreferenceSelector(application=APP))).disposition is Disposition.SUPPRESSED


def test_negative_contributor_cannot_increase_score_or_add_support():
    base = evidence()
    benign = periodic(quality=EvidenceQuality(base.quality.measurement, (EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE,)))
    r = risk(base, benign)
    score = r.score
    result = evaluate(r, preference(PreferenceSelector(rule_id=benign.rule_id)))
    assert result.disposition is Disposition.PARTIALLY_SUPPRESSED and result.alert_eligible
    assert len(result.groups) == 2 and len(result.evidence) == 2
    assert r.score == score == 32


def test_excluded_evidence_never_becomes_alert_support():
    a, b = evidence(), periodic()
    scored = score_risk(RiskScoringInput(RiskEvidenceBatch((a, b)), (EvidenceFreshness(a.evidence_id, Freshness.CURRENT),
                        EvidenceFreshness(b.evidence_id, Freshness.STALE))), RiskScoringPolicy())
    result = evaluate(scored, preference(PreferenceSelector(rule_id=b.rule_id)))
    assert result.disposition is Disposition.NOT_SUPPRESSED and result.alert_eligible
    assert next(e for e in result.evidence if e.evidence_id == b.evidence_id).disposition is Disposition.NOT_APPLICABLE


class Repository:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def find_candidates(self, contexts, *, evaluated_at, limit):
        assert evaluated_at == NOW
        self.calls.append((contexts, limit))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_service_queries_once_and_normalizes_from_evidence():
    repo = Repository(page(preference()))
    r = risk(evidence(), periodic())
    result = SuppressionEvaluationService(repo).evaluate(r, REFERENCE, evaluated_at=NOW)
    assert len(repo.calls) == 1 and repo.calls[0][1] == 100
    assert set(repo.calls[0][0]) == {match_context(c.evidence) for c in r.contributors}
    assert result.evaluated_at == NOW and result.assessment == REFERENCE


@pytest.mark.parametrize("reply", [RuntimeError("private note/path"), None, PreferencePage(ReadStatus.UNAVAILABLE)])
def test_service_failure_is_sanitized_and_fail_open(reply):
    result = SuppressionEvaluationService(Repository(reply)).evaluate(risk(), REFERENCE, evaluated_at=NOW)
    assert result.disposition is Disposition.UNAVAILABLE and result.alert_eligible
    assert "private note" not in repr(result)


@pytest.mark.parametrize("kind", ["empty", "normal", "unknown"])
def test_no_driving_risk_never_queries_or_fakes_suppression(kind):
    r = score_risk(RiskScoringInput(RiskEvidenceBatch(())), RiskScoringPolicy()) if kind == "empty" else (
        risk(evidence(result_code="known")) if kind == "normal" else risk(evidence(policy_version=999)))
    repo = Repository(RuntimeError("must not query"))
    result = SuppressionEvaluationService(repo).evaluate(r, REFERENCE, evaluated_at=NOW)
    assert result.disposition is Disposition.NOT_APPLICABLE and not result.alert_eligible
    assert not repo.calls and not result.suppressed_evidence_ids


def test_result_immutable_utc_and_sensitive_repr():
    result = evaluate(risk(), preference(reason="User private note"))
    with pytest.raises(FrozenInstanceError):
        result.disposition = Disposition.NOT_SUPPRESSED
    with pytest.raises(ValueError):
        evaluate(now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        SuppressionEvaluationService(Repository(page())).evaluate(risk(), REFERENCE, evaluated_at=NOW.replace(tzinfo=None))
    assert "User private note" not in repr(result) and "winpath" not in repr(result)


def test_evidence_and_group_hard_caps():
    r = risk(*(evidence(i) for i in range(1, 33)))
    result = evaluate(r, preference())
    assert len(result.evidence) == len(result.groups[0].supporting_evidence_ids) == 32
    assert result.disposition is Disposition.SUPPRESSED
    with pytest.raises(ValueError):
        replace(result, evidence=result.evidence + (result.evidence[0],))
    with pytest.raises(ValueError):
        replace(result.evidence[0], matches=result.evidence[0].matches * 9)
    with pytest.raises(ValueError):
        replace(result.evidence[0], observed_match_count=101)
    with pytest.raises(ValueError):
        replace(result, limitations=(Limitation.LOOKUP_UNAVAILABLE,) * 8)
    with pytest.raises(ValueError):
        replace(result.groups[0], supporting_evidence_ids=result.groups[0].supporting_evidence_ids + ("0" * 64,))
