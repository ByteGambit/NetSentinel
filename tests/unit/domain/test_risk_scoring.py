"""NS-077 frozen policy decisions and offline compatibility/purity checks."""

import ast
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from itertools import combinations, permutations
from pathlib import Path
from uuid import UUID

import pytest

from netsentinel.application.services.risk_evidence import evidence_from_arp
from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityEvidence, ArpIdentityReason, ArpIdentityRule,
    ArpRiskAssessment, ArpScoreComponent, ArpScoreRule,
)
from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationIdentityQuality, ApplicationIdentityEvidence, ApplicationRevision
from netsentinel.domain.connections import NetworkScopeStatus, ObservationQuality, ProcessInfoStatus, ProcessIdentity
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.devices import GatewayBaselineStatus
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceLimitation, EvidenceQuality, EvidenceReference,
    EvidenceReferenceKind, EvidenceRole, EvidenceScope, EvidenceScopeKind,
    EvidenceSource, EvidenceSubject, EvidenceSubjectKind, RiskEvidence, RiskEvidenceBatch,
)
from netsentinel.domain.risk_scoring import (
    MAX_SCORE_CONTRIBUTORS, AssessmentAvailability, ContributionDirection,
    ContributorFamily, CorrelationGroup, EvidenceFreshness, Freshness,
    RiskScoringInput, RiskScoringPolicy, RiskSeverity, ScoringAdjustment,
    ScoringReason, SeverityCapReason, score_risk, severity_for_score,
)

NOW = datetime(2026, 10, 3, tzinfo=UTC)
SCOPE = EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64)
APP = ApplicationIdentity(ApplicationIdentityQuality.STABLE, r"winpath:v1:c:\apps\example.exe", ApplicationIdentityEvidence.EXECUTABLE_PATH, ProcessInfoStatus.AVAILABLE)
POLICY = RiskScoringPolicy()


def evidence(rule="novelty", result="first_seen", *, index=1, **changes):
    source, rule_id = {
        "novelty": (EvidenceSource.DESTINATION_NOVELTY, "destination_ip_novelty_rarity"),
        "frequency": (EvidenceSource.FREQUENCY_DIVERSITY, "observed_appearance_frequency"),
        "diversity": (EvidenceSource.FREQUENCY_DIVERSITY, "destination_window_diversity"),
        "periodicity": (EvidenceSource.PERIODICITY, "observed_appearance_periodicity"),
    }[rule]
    values = dict(source=source, rule_id=rule_id, reason_code="test_observation",
                  result_code=result, policy_version=1, observed_at=NOW, scope=SCOPE,
                  subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, application=APP,
                                          ip_address=f"192.0.2.{index}"),
                  quality=EvidenceQuality(ObservationQuality.COMPLETE), role=EvidenceRole.FINDING,
                  confidence=EvidenceConfidence.MODERATE)
    values.update(changes)
    return RiskEvidence(**values)


def evaluate(*items, statuses=None):
    statuses = statuses or {}
    batch = RiskEvidenceBatch(tuple(items))
    return score_risk(RiskScoringInput(batch, tuple(EvidenceFreshness(e.evidence_id, statuses.get(e.evidence_id, Freshness.CURRENT)) for e in items)), POLICY)


def legacy(*, gateway=False, verified=False, corroborated=False, index=1):
    event = ArpIdentityConflictDetected(
        ArpIdentityRule.GATEWAY_MAC_CHANGE if gateway else ArpIdentityRule.IP_MAC_CONFLICT,
        (ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT if verified else ArpIdentityReason.LEARNED_GATEWAY_CONFLICT)
        if gateway else ArpIdentityReason.RECENT_SENDER_CONFLICT,
        ArpIdentityEvidence("a" * 64, f"192.168.1.{index}", MacAddress("00:11:22:33:44:55"),
                            MacAddress("00:11:22:33:44:66"), NOW - timedelta(seconds=20), NOW,
                            GatewayBaselineStatus.VERIFIED if verified else GatewayBaselineStatus.LEARNED if gateway else None),
        "medium" if verified else "low", "low",
    )
    if corroborated:
        parts = (ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2), ArpScoreComponent(ArpScoreRule.REPEATED_OBSERVATION, 1))
        return evidence_from_arp(ArpRiskAssessment(event, NOW, NOW + timedelta(seconds=5), 3, parts, 3, "moderate"))
    return evidence_from_arp(event)


def mitigating(e):
    return replace(e, quality=EvidenceQuality(e.quality.measurement, (EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE, EvidenceLimitation.POLLING_QUANTIZED)))


MAPPING = [
    ("novelty", "known", 0, ContributorFamily.NOVELTY),
    ("novelty", "rare", 10, ContributorFamily.NOVELTY),
    ("novelty", "first_seen", 20, ContributorFamily.NOVELTY),
    ("frequency", "normal", 0, ContributorFamily.FREQUENCY),
    ("frequency", "elevated_unconfirmed", 15, ContributorFamily.FREQUENCY),
    ("frequency", "elevated_confirmed", 35, ContributorFamily.FREQUENCY),
    ("diversity", "normal", 0, ContributorFamily.DIVERSITY),
    ("diversity", "elevated_unconfirmed", 10, ContributorFamily.DIVERSITY),
    ("diversity", "elevated_confirmed", 25, ContributorFamily.DIVERSITY),
    ("periodicity", "irregular", 0, ContributorFamily.PERIODICITY),
    ("periodicity", "periodic_candidate", 15, ContributorFamily.PERIODICITY),
]


@pytest.mark.parametrize("rule,result,points,family", MAPPING)
def test_frozen_m13_mapping(rule, result, points, family):
    e = evidence(rule, result, role=EvidenceRole.FINDING if points else EvidenceRole.OBSERVATION)
    r = evaluate(e)
    c, = r.contributors
    assert (r.score, r.policy_version, c.raw_points, c.applied_points, c.family) == (points, 1, points, points, family)
    assert c.reason is (ScoringReason.RULE_APPLIED if points else ScoringReason.OBSERVATION_ONLY)
    assert c.evidence == e and c.eligible and not c.adjustments
    assert r.availability is AssessmentAvailability.AVAILABLE
    assert r.severity is not RiskSeverity.HIGH


@pytest.mark.parametrize("gateway,verified,corroborated,points", [
    (False, False, False, 30), (False, False, True, 45),
    (True, False, False, 35), (True, False, True, 50),
    (True, True, False, 45), (True, True, True, 60),
])
def test_legacy_mapping_preserves_context_and_does_not_sum_legacy_score(gateway, verified, corroborated, points):
    e = legacy(gateway=gateway, verified=verified, corroborated=corroborated)
    context = e.legacy_arp
    r = evaluate(e)
    assert r.score == points and r.contributors[0].evidence.legacy_arp is context
    assert r.confidence is e.confidence and r.measurement_quality is None
    assert r.severity is RiskSeverity.LOW
    assert context.source.severity == ("medium" if verified else "low")
    if corroborated:
        assert context.correlation.score == 3 and context.correlation.confidence == "moderate"


@pytest.mark.parametrize("a,b,expected", [
    (("novelty", "first_seen"), ("diversity", "elevated_confirmed"), 25),
    (("novelty", "first_seen"), ("frequency", "elevated_confirmed"), 35),
    (("frequency", "elevated_confirmed"), ("diversity", "elevated_confirmed"), 35),
    (("periodicity", "periodic_candidate"), ("frequency", "elevated_confirmed"), 50),
    (("periodicity", "periodic_candidate"), ("novelty", "first_seen"), 35),
])
def test_correlation_matrix(a, b, expected):
    r = evaluate(evidence(*a), evidence(*b))
    assert r.score == expected
    assert sum(c.applied_points for c in r.contributors) == expected
    assert any(ScoringAdjustment.CORRELATED_SUPERSEDED in c.adjustments for c in r.contributors) == (a[0] != "periodicity")


def test_three_m13_signals_are_explainable_and_order_invariant():
    items = (evidence(), evidence("frequency", "elevated_confirmed"), evidence("periodicity", "periodic_candidate"))
    expected = evaluate(*items)
    assert expected.score == 50
    for order in permutations(items):
        assert evaluate(*order) == expected
    assert tuple(c.evidence.evidence_id for c in expected.contributors) == tuple(sorted(e.evidence_id for e in items))


def test_same_fact_revisions_references_and_rule_names_do_not_multiply():
    original = evidence()
    revision = replace(original, observed_at=NOW + timedelta(seconds=1), references=(EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=1)),))
    assert evaluate(original, revision).score == 20
    a, b = legacy(), legacy(gateway=True)
    assert evaluate(a, b).score == 35
    assert evaluate(a, legacy(index=2)).score == 60
    current = legacy(corroborated=True)
    assert evaluate(a, current).score == 45
    assert len(evaluate(a, current).contributors) == 2


@pytest.mark.parametrize("rule,result,cap", [("novelty", "first_seen", 40), ("periodicity", "periodic_candidate", 30)])
def test_family_spam_is_bounded(rule, result, cap):
    items = tuple(evidence(rule, result, index=i, subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=f"192.0.2.{i}")) for i in range(1, 33))
    r = evaluate(*items)
    assert r.score == cap and len(r.contributors) == 32
    assert any(ScoringAdjustment.FAMILY_CAP in c.adjustments for c in r.contributors)


def test_global_score_cap_and_high_severity_keep_missing_legacy_quality_visible():
    items = (legacy(index=1, corroborated=True), legacy(index=2, corroborated=True),
             evidence("frequency", "elevated_confirmed"), evidence("periodicity", "periodic_candidate"))
    r = evaluate(*items)
    assert r.score == r.positive_subtotal == 100
    assert r.score_severity is RiskSeverity.HIGH and r.severity is RiskSeverity.LOW
    assert r.measurement_quality is None
    assert any(ScoringAdjustment.SCORE_CAP in c.adjustments for c in r.contributors)


def test_empty_missing_freshness_and_all_stale_are_unknown():
    assert evaluate().availability is AssessmentAvailability.UNKNOWN
    e = evidence()
    for value in (RiskScoringInput(RiskEvidenceBatch()), RiskScoringInput(RiskEvidenceBatch((e,)))):
        r = score_risk(value, POLICY)
        assert r.score == 0 and r.severity is None and r.confidence is None
        assert r.availability is AssessmentAvailability.UNKNOWN
    assert score_risk(RiskScoringInput(RiskEvidenceBatch((e,))), POLICY).contributors[0].reason is ScoringReason.UNKNOWN_FRESHNESS


@pytest.mark.parametrize("status,reason", [(Freshness.STALE, ScoringReason.STALE), (Freshness.EXPIRED, ScoringReason.EXPIRED), (Freshness.UNKNOWN, ScoringReason.UNKNOWN_FRESHNESS)])
def test_stale_and_expired_never_become_negative_or_normal(status, reason):
    e = evidence()
    r = evaluate(e, statuses={e.evidence_id: status})
    assert r.availability is AssessmentAvailability.UNKNOWN and r.score == 0 and r.severity is None
    assert r.contributors[0].reason is reason and not r.contributors[0].eligible
    fresh = evidence("novelty", "known", role=EvidenceRole.OBSERVATION)
    mixed = evaluate(fresh, e, statuses={e.evidence_id: status})
    assert mixed.score == 0 and mixed.availability is AssessmentAvailability.PARTIAL
    assert not any(c.reason is ScoringReason.CONFLICT for c in mixed.contributors)


@pytest.mark.parametrize("result,reason", [("insufficient_data", ScoringReason.INSUFFICIENT_DATA), ("insufficient_quality", ScoringReason.INSUFFICIENT_QUALITY), ("not_evaluated", ScoringReason.NOT_EVALUATED)])
@pytest.mark.parametrize("rule", ["novelty", "frequency", "diversity"])
def test_insufficient_m13_results_are_not_scored(rule, result, reason):
    r = evaluate(evidence(rule, result))
    assert r.score == 0 and r.contributors[0].reason is reason
    assert r.availability is AssessmentAvailability.UNKNOWN


def test_resolution_limitation_and_role_only_do_not_score():
    e = evidence("periodicity", "resolution_limited")
    assert evaluate(e).contributors[0].reason is ScoringReason.RESOLUTION_LIMITED
    e = evidence("periodicity", "periodic_candidate", quality=EvidenceQuality(ObservationQuality.COMPLETE, (EvidenceLimitation.RESOLUTION_LIMITED,)))
    assert evaluate(e).score == 0
    for quality in (ObservationQuality.COMPLETE, ObservationQuality.REDUCED, ObservationQuality.FAILED, None):
        e = evidence(role=EvidenceRole.LIMITATION, quality=EvidenceQuality(quality))
        r = evaluate(e)
        assert r.score == 0 and r.measurement_quality is quality
        assert r.contributors[0].reason is ScoringReason.LIMITATION_ONLY


@pytest.mark.parametrize("change,reason", [
    ({"rule_id": "destination_future_signal"}, ScoringReason.UNSUPPORTED_RULE),
    ({"result_code": "future_result"}, ScoringReason.UNSUPPORTED_RULE),
    ({"source": EvidenceSource.PERIODICITY}, ScoringReason.UNSUPPORTED_RULE),
    ({"policy_version": 2}, ScoringReason.UNSUPPORTED_PRODUCER_VERSION),
    ({"policy_version": None}, ScoringReason.UNSUPPORTED_PRODUCER_VERSION),
    ({"role": EvidenceRole.OBSERVATION}, ScoringReason.ROLE_MISMATCH),
])
def test_unknown_rules_versions_roles_are_explained(change, reason):
    r = evaluate(evidence(**change))
    assert r.score == 0 and r.contributors[0].reason is reason and r.severity is None
    if reason is ScoringReason.UNSUPPORTED_PRODUCER_VERSION:
        assert r.contributors[0].raw_points == 0


@pytest.mark.parametrize("code", ["trusted_device", "signed_executable", "microsoft_signer", "country", "asn", "user_suppression"])
def test_context_is_never_implicit_negative(code):
    e = evidence(rule_id=code, role=EvidenceRole.OBSERVATION)
    r = evaluate(e, legacy(corroborated=True))
    assert r.score == 45 and r.applied_mitigation == 0
    assert next(c for c in r.contributors if c.evidence is e).reason is ScoringReason.UNSUPPORTED_RULE


def test_conflicting_novelty_is_excluded_without_order_guessing():
    items = (evidence(), evidence(result="known", role=EvidenceRole.OBSERVATION), evidence(result="rare"))
    for order in permutations(items):
        r = evaluate(*order)
        assert r.score == 0 and r.availability is AssessmentAvailability.UNKNOWN
        assert all(c.reason is ScoringReason.CONFLICT for c in r.contributors)
    # Another timestamp is a correlated summary, not a same-time contradiction.
    assert evaluate(items[0], replace(items[1], observed_at=NOW + timedelta(seconds=1))).score == 20


@pytest.mark.parametrize("quality,confidence,expected", [
    (ObservationQuality.COMPLETE, EvidenceConfidence.MODERATE, RiskSeverity.MEDIUM),
    (ObservationQuality.REDUCED, EvidenceConfidence.HIGH, RiskSeverity.MEDIUM),
    (None, EvidenceConfidence.HIGH, RiskSeverity.LOW),
    (ObservationQuality.COMPLETE, EvidenceConfidence.LOW, RiskSeverity.LOW),
    (ObservationQuality.COMPLETE, EvidenceConfidence.PASSIVE_OBSERVATION, RiskSeverity.LOW),
    (ObservationQuality.COMPLETE, None, RiskSeverity.LOW),
])
def test_quality_confidence_severity_are_separate(quality, confidence, expected):
    e = evidence("frequency", "elevated_confirmed", quality=EvidenceQuality(quality), confidence=confidence)
    r = evaluate(e)
    assert r.score == 35 and r.severity is expected
    assert r.confidence is confidence and r.measurement_quality is quality
    assert r.contributors[0].evidence.quality.measurement is quality


@pytest.mark.parametrize("quality,expected", [(ObservationQuality.COMPLETE, RiskSeverity.HIGH), (ObservationQuality.REDUCED, RiskSeverity.MEDIUM), (None, RiskSeverity.LOW)])
def test_high_score_quality_caps(quality, expected):
    a = evidence("frequency", "elevated_confirmed", quality=EvidenceQuality(quality))
    b = replace(a, subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address="192.0.2.2"))
    r = evaluate(a, b, evidence("periodicity", "periodic_candidate", index=1), evidence("periodicity", "periodic_candidate", index=2))
    assert r.score == 70 and r.score_severity is RiskSeverity.HIGH and r.severity is expected


@pytest.mark.parametrize("limitation", [EvidenceLimitation.CAPACITY_LOSS, EvidenceLimitation.MONITORING_GAP, EvidenceLimitation.REDUCED_OBSERVATION, EvidenceLimitation.PRIOR_HISTORY_UNAVAILABLE])
def test_loss_limits_confidence_without_fabricating_measurement_quality(limitation):
    e = evidence("frequency", "elevated_confirmed", confidence=EvidenceConfidence.HIGH, quality=EvidenceQuality(ObservationQuality.COMPLETE, (limitation,)))
    r = evaluate(e)
    assert r.confidence is EvidenceConfidence.LOW and r.measurement_quality is ObservationQuality.COMPLETE
    assert r.score == 35 and r.severity is RiskSeverity.LOW
    assert SeverityCapReason.INSUFFICIENT_CONFIDENCE in r.severity_caps


@pytest.mark.parametrize("score,severity", [(0, RiskSeverity.INFO), (9, RiskSeverity.INFO), (10, RiskSeverity.LOW), (11, RiskSeverity.LOW), (29, RiskSeverity.LOW), (30, RiskSeverity.MEDIUM), (31, RiskSeverity.MEDIUM), (59, RiskSeverity.MEDIUM), (60, RiskSeverity.HIGH), (61, RiskSeverity.HIGH), (100, RiskSeverity.HIGH)])
def test_every_severity_boundary(score, severity):
    assert severity_for_score(score, POLICY) is severity


@pytest.mark.parametrize("score", [-1, 101, True, float("nan"), float("inf"), 10.5])
def test_numeric_scale_rejects_non_integer_or_out_of_bounds(score):
    with pytest.raises(ValueError):
        severity_for_score(score, POLICY)


def test_mitigation_has_two_explanations_and_cannot_erase_strong_evidence():
    a, b = evidence("periodicity", "periodic_candidate", index=1), evidence("periodicity", "periodic_candidate", index=2)
    original = evaluate(a, b, legacy(corroborated=True))
    r = evaluate(mitigating(a), mitigating(b), legacy(corroborated=True))
    assert original.score == 75 and r.score == 70
    assert (r.raw_mitigation, r.applied_mitigation) == (6, 5)
    assert r.applied_mitigation <= r.positive_subtotal // 4
    assert sum(c.direction is ContributionDirection.NEGATIVE for c in r.contributors) == 2
    assert any(ScoringAdjustment.MITIGATION_CAP in c.adjustments for c in r.contributors)
    assert evaluate(mitigating(a)).score == 12
    assert evaluate(replace(mitigating(a), role=EvidenceRole.LIMITATION)).score == 0


def test_mitigating_duplicate_and_family_spam_are_bounded():
    items = tuple(mitigating(evidence("periodicity", "periodic_candidate", index=i)) for i in range(1, 33))
    r = evaluate(*items)
    assert r.score == 25 and r.raw_mitigation == 96 and r.applied_mitigation == 5
    assert len(r.contributors) == MAX_SCORE_CONTRIBUTORS == 64
    original = items[0]
    duplicate_fact = replace(original, observed_at=NOW + timedelta(seconds=1))
    r = evaluate(original, duplicate_fact)
    assert r.score == 12 and r.raw_mitigation == 3


def test_positive_monotonicity_across_bounded_combinations_and_saturation():
    items = (evidence(), evidence("frequency", "elevated_confirmed"),
             evidence("diversity", "elevated_confirmed"),
             evidence("periodicity", "periodic_candidate", index=1),
             evidence("periodicity", "periodic_candidate", index=2),
             legacy(index=1, corroborated=True), legacy(index=2, corroborated=True))
    for size in range(len(items)):
        for subset in combinations(items, size):
            score = evaluate(*subset).score
            for extra in items:
                if extra not in subset:
                    assert evaluate(*subset, extra).score >= score


def test_stronger_replacements_and_negative_monotonicity():
    for rule in ("frequency", "diversity"):
        weak = evidence(rule, "elevated_unconfirmed")
        strong = replace(weak, result_code="elevated_confirmed")
        assert evaluate(strong).score >= evaluate(weak).score
    for positives in ((), (evidence(),), (legacy(corroborated=True),)):
        a, b = evidence("periodicity", "periodic_candidate", index=1), evidence("periodicity", "periodic_candidate", index=2)
        r0, r1, r2 = evaluate(*positives, a, b), evaluate(*positives, mitigating(a), b), evaluate(*positives, mitigating(a), mitigating(b))
        assert r2.score <= r1.score <= r0.score
        assert r0.score - r2.score <= POLICY.maximum_mitigation


def test_independent_application_revision_network_keys_and_fallback():
    a = evidence()
    new_app = replace(APP, key=r"winpath:v1:c:\apps\other.exe")
    b = replace(a, subject=replace(a.subject, application=new_app))
    assert evaluate(a, b).score == 40
    assert evaluate(a, replace(a, scope=replace(SCOPE, network_fingerprint="b" * 64))).score == 40
    # An application window and destination share a key despite different kinds.
    b = evidence("frequency", "elevated_confirmed", subject=EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=APP))
    assert evaluate(a, b).score == 35
    revision = ApplicationRevision("c" * 64, ExecutableHashStatus.AVAILABLE)
    assert evaluate(a, replace(a, subject=replace(a.subject, revision=revision))).score == 40
    unknown_app = ApplicationIdentity(ApplicationIdentityQuality.UNKNOWN, None, ApplicationIdentityEvidence.NONE, ProcessInfoStatus.UNAVAILABLE)
    p1 = EvidenceSubject(EvidenceSubjectKind.PROCESS, application=unknown_app, process=ProcessIdentity(1, NOW))
    p2 = replace(p1, process=ProcessIdentity(2, NOW))
    assert evaluate(replace(a, subject=p1), replace(a, subject=p2)).score == 40


def test_quality_and_confidence_mixed_context_remains_explicit():
    finding = evidence("frequency", "elevated_confirmed", confidence=EvidenceConfidence.HIGH)
    failed = evidence(role=EvidenceRole.LIMITATION, quality=EvidenceQuality(ObservationQuality.FAILED))
    r = evaluate(finding, failed)
    assert r.score == 35 and r.measurement_quality is ObservationQuality.FAILED
    assert r.confidence is EvidenceConfidence.LOW and r.severity is RiskSeverity.LOW
    assert r.availability is AssessmentAvailability.PARTIAL
    passive = evidence("periodicity", "irregular", role=EvidenceRole.OBSERVATION, confidence=EvidenceConfidence.PASSIVE_OBSERVATION)
    r = evaluate(finding, passive)
    assert r.confidence is EvidenceConfidence.PASSIVE_OBSERVATION
    assert r.measurement_quality is ObservationQuality.COMPLETE and r.score == 35


@pytest.mark.parametrize("field_name,bad_value", [("confidence", {}), ("measurement_quality", "complete"), ("severity", "high"), ("availability", "available"), ("policy_version", True), ("raw_mitigation", 97)])
def test_result_model_rejects_mutable_untyped_or_unbounded_values(field_name, bad_value):
    with pytest.raises((TypeError, ValueError)):
        replace(evaluate(evidence()), **{field_name: bad_value})


@pytest.mark.parametrize("field_name,bad_value", [("direction", "positive"), ("reason", {}), ("family", {}), ("correlation_key", {}), ("eligible", 1), ("applied_points", -1), ("adjustments", []), ("policy_version", True)])
def test_contributor_model_rejects_mutable_untyped_or_inconsistent_values(field_name, bad_value):
    with pytest.raises((TypeError, ValueError)):
        replace(evaluate(evidence()).contributors[0], **{field_name: bad_value})


def test_missing_evidence_never_subtracts_score_and_full_output_orders_stably():
    e = mitigating(evidence("periodicity", "periodic_candidate"))
    unknown = evidence(rule_id="future_rule", confidence=EvidenceConfidence.HIGH)
    stale = evidence("frequency", "elevated_confirmed")
    expected = evaluate(e, unknown, stale, statuses={stale.evidence_id: Freshness.STALE})
    assert expected.score == evaluate(e).score == 12
    for order in permutations((e, unknown, stale)):
        assert evaluate(*order, statuses={stale.evidence_id: Freshness.STALE}) == expected


def test_duplicate_and_contract_version_rejected_before_scoring():
    e = evidence()
    with pytest.raises(ValueError, match="duplicate"):
        RiskEvidenceBatch((e, e))
    with pytest.raises(ValueError, match="contract version"):
        replace(e, contract_version=2)
    with pytest.raises(ValueError):
        RiskEvidenceBatch(tuple(replace(e, observed_at=NOW + timedelta(seconds=i)) for i in range(33)))
    for version in (0, 2, True):
        with pytest.raises(ValueError):
            RiskScoringPolicy(version)


def test_freshness_input_validation_immutability_and_determinism():
    e = evidence()
    batch = RiskEvidenceBatch((e,))
    state = EvidenceFreshness(e.evidence_id, Freshness.CURRENT)
    for statuses in ([state], (state, state), (EvidenceFreshness("b" * 64, Freshness.CURRENT),)):
        with pytest.raises(ValueError):
            RiskScoringInput(batch, statuses)
    with pytest.raises(TypeError):
        EvidenceFreshness(e.evidence_id, "current")
    with pytest.raises(ValueError):
        EvidenceFreshness("invalid", Freshness.CURRENT)
    r = evaluate(e)
    assert r == evaluate(e) and hash(r) == hash(evaluate(e))
    with pytest.raises(FrozenInstanceError):
        r.score = 1
    assert not hasattr(r, "__dict__")
    assert not any(f.name in {"details", "probability", "suppression", "trust"} for f in fields(r))
    with pytest.raises(ValueError):
        replace(r, score=101)
    with pytest.raises(ValueError):
        replace(r, contributors=list(r.contributors))


def test_pure_domain_imports_and_no_clock_io_ml_or_runtime_integration():
    import netsentinel.domain.risk_scoring as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module.startswith(("__future__", "dataclasses", "enum", "uuid", "netsentinel.domain"))
        if isinstance(node, ast.Import):
            assert not node.names
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
            assert name not in {"now", "utcnow", "time", "monotonic", "open", "connect", "execute"}
    assert {r.group for r in POLICY.rules} == set(CorrelationGroup)
    assert not any(c.direction is ContributionDirection.NEGATIVE for c in evaluate(evidence(result="known", role=EvidenceRole.OBSERVATION)).contributors)
