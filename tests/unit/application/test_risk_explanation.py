"""Stored semantics, exact pointers, honest missing data and read-only mapping."""

import ast
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.application.services.suppression import evaluate_suppression
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import NetworkScopeStatus, ObservationQuality
from netsentinel.domain.preferences import PreferenceSelector, PreferencePage, PreferenceResultStatus
from netsentinel.domain.risk_assessment import (
    AssessmentRead, AssessmentReadStatus, AssessmentReferenceState, AssessmentSourceStatus,
    RiskAssessmentRevision,
    snapshot_from_score,
)
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceLimitation, EvidenceQuality, EvidenceReference, EvidenceReferenceKind,
    EvidenceRole, EvidenceScope, EvidenceScopeKind,
)
from netsentinel.domain.risk_scoring import Freshness
from tests.fixtures.risk_assessments import NOW, evidence, key, scoring, snapshot
from tests.fixtures.risk_explanations import ExplanationRepository, all_text, model
from tests.fixtures.suppression import frequency, periodic, page, preference


REQUEST = RiskExplanationRequest(reference=AlertAssessmentReference(key().assessment_id, 3, None))


def test_exact_linked_revision_does_not_read_latest_or_score(monkeypatch):
    def fail(*args):
        raise AssertionError("scoring on read")
    monkeypatch.setattr("netsentinel.domain.risk_scoring.score_risk", fail)
    repo = ExplanationRepository()
    result = RiskExplanationQueryService(repo).lookup(REQUEST, now=NOW)
    assert repo.calls == [(key().assessment_id, 3)]
    assert result.revision == 3
    assert dict(result.summary)["Concern score"] == "20 / 100"
    assert "not a malware probability" in all_text(result)


@pytest.mark.parametrize("status,message", [
    (AssessmentReadStatus.NOT_FOUND, "No retained risk assessment"),
    (AssessmentReadStatus.CORRUPT, "corrupt"),
    (AssessmentReadStatus.UNSUPPORTED_VERSION, "Unsupported"),
    (AssessmentReadStatus.UNAVAILABLE, "unavailable"),
])
def test_typed_read_failures(status, message):
    repo = ExplanationRepository(AssessmentRead(status))
    result = RiskExplanationQueryService(repo).lookup(REQUEST, now=NOW)
    assert message in result.message
    assert not result.summary and not result.sections


def test_failure_is_sanitized_and_mismatched_pointer_is_corrupt():
    repo = ExplanationRepository()
    repo.revision = lambda *args: (_ for _ in ()).throw(RuntimeError("sqlite secret path traceback"))
    result = RiskExplanationQueryService(repo).lookup(REQUEST, now=NOW)
    assert result.status is AssessmentReadStatus.UNAVAILABLE
    assert "secret" not in all_text(result)
    repo = ExplanationRepository(AssessmentRead(AssessmentReadStatus.FOUND, RiskAssessmentRevision(key(), 4, NOW, snapshot())))
    assert RiskExplanationQueryService(repo).lookup(REQUEST, now=NOW).status is AssessmentReadStatus.CORRUPT
    # An unavailable/malformed optional explanation must not hide stored risk.
    repo = ExplanationRepository()
    result = RiskExplanationQueryService(repo, suppression_lookup=lambda *args: object()).lookup(REQUEST, now=NOW)
    assert dict(result.summary)["Concern score"] == "20 / 100"
    assert "Historical suppression not recorded" in all_text(result)


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
@pytest.mark.parametrize("ip", ["192.0.2.1", "2001:db8::1"])
def test_network_and_destination_are_exact_and_never_invented(status, ip):
    e = evidence(scope=EvidenceScope(EvidenceScopeKind.UNKNOWN, status), subject=replace(evidence().subject, ip_address=ip))
    text = all_text(model(snapshot(e)))
    assert status.value.capitalize() in text and "no resolved fingerprint" in text
    assert ip in text


@pytest.mark.parametrize("freshness", [Freshness.STALE, Freshness.EXPIRED, Freshness.UNKNOWN])
def test_zero_unknown_stale_expired_are_not_normal_or_safe(freshness):
    result = model(snapshot(freshness=freshness))
    assert dict(result.summary)["Concern score"] == "Unavailable / insufficient evidence"
    assert freshness.value.capitalize() in all_text(result)
    assert "0 / 100" not in all_text(result)


@pytest.mark.parametrize("confidence", [None, *EvidenceConfidence])
@pytest.mark.parametrize("quality", [None, ObservationQuality.COMPLETE, ObservationQuality.REDUCED, ObservationQuality.FAILED])
def test_quality_and_confidence_remain_distinct(confidence, quality):
    role = EvidenceRole.LIMITATION if quality is ObservationQuality.FAILED else EvidenceRole.FINDING
    result = model(snapshot(evidence(confidence=confidence, quality=EvidenceQuality(quality), role=role)))
    summary = dict(result.summary)
    assert "Confidence" in summary and "Measurement quality" in summary
    assert ("Unknown" in summary["Measurement quality"]) == (quality is None)
    assert "telemetry coverage/loss" in all_text(result)


@pytest.mark.parametrize("items,expected", [
    ((evidence(result_code="known", role=EvidenceRole.OBSERVATION),), "Info"),
    ((evidence(),), "Low"),
    ((frequency(),), "Medium"),
    ((frequency(), periodic(3), periodic(4)), "High"),
])
def test_stored_severity_bands(items, expected):
    result = model(snapshot(*items))
    assert dict(result.summary)["Effective severity"] == expected
    assert "%" not in dict(result.summary)["Concern score"]
    assert dict(result.summary)["Contributor context"]


def test_raw_effective_severity_caps_and_historical_policy_are_preserved():
    stored = snapshot(frequency(quality=EvidenceQuality(ObservationQuality.REDUCED)), periodic(3), periodic(4))
    stored = replace(stored, policy_version=99, contributors=tuple(replace(c, policy_version=99) for c in stored.contributors))
    result = model(stored)
    summary = dict(result.summary)
    assert summary["Raw score severity"] == "High"
    assert summary["Effective severity"] == "Medium"
    assert summary["Scoring policy"] == "v99"
    assert "telemetry quality was reduced" in all_text(result)
    assert "same observation" in all_text(result)
    assert summary["Observed at"].endswith("(UTC)")


def test_contributions_correlation_caps_mitigation_and_deterministic_order():
    mitigating = periodic(4, quality=EvidenceQuality(ObservationQuality.COMPLETE,
        (EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE, EvidenceLimitation.POLLING_QUANTIZED)))
    items = (evidence(), frequency(), frequency(3, subject=replace(frequency().subject, application=None)), mitigating)
    result = model(snapshot(*items))
    text = all_text(result)
    assert "raw +35; applied" in text
    assert "grouped to avoid double-counting" in text
    assert "family cap" in text and "Mitigating context" in text
    assert "does not prove an exact timer" in text
    assert model(snapshot(*reversed(items))) == result


@pytest.mark.parametrize("source_status", list(AssessmentSourceStatus))
def test_current_source_availability_does_not_overwrite_historical_freshness(source_status):
    ref = EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=1))
    result = model(snapshot(evidence(references=(ref,))), references=(AssessmentReferenceState(ref, source_status),))
    text = all_text(result)
    assert "Freshness at assessment: Current" in text
    if source_status is AssessmentSourceStatus.UNRESOLVED:
        assert "does not establish expiry" in text
    elif source_status is AssessmentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE:
        assert "minimum assessment snapshot remains" in text


def test_baseline_only_uses_stored_classifications_and_unknown_rule_fallback():
    result = model(snapshot(evidence(), frequency(), periodic(), evidence(3, rule_id="future_rule", policy_version=42)))
    text = all_text(result)
    assert "Not previously observed in the retained scoped baseline" in text
    assert "Observed appearance frequency" in text and "Regular observed appearance timing" in text
    assert "not persisted in format v1" in text and "Current learned baseline is shown separately" in text
    assert "future_rule (no display mapping available)" in text
    assert "Producer policy version" in text or "supported scoring rule" in text


@pytest.mark.parametrize("mode", ["none", "full", "partial", "fail_open", "incomplete", "not_applicable"])
def test_suppression_preserves_score_evidence_and_explains_effect(mode):
    items = (evidence(), periodic())
    if mode == "not_applicable":
        items = (evidence(role=EvidenceRole.OBSERVATION, result_code="known"),)
    value, result = scoring(*items)
    reference = AlertAssessmentReference(key().assessment_id, 3, None)
    candidates = {"none": page(), "full": page(preference(), preference(PreferenceSelector(rule_id=periodic().rule_id), index=2)),
        "partial": page(preference()), "fail_open": PreferencePage(PreferenceResultStatus.UNAVAILABLE),
        "incomplete": page(truncated=True), "not_applicable": page()}[mode]
    evaluation = evaluate_suppression(result, reference, NOW, candidates)
    displayed = model(snapshot_from_score(value, result), suppression=evaluation)
    text = all_text(displayed)
    assert dict(displayed.summary)["Concern score"] == f"{result.score} / 100"
    assert len([s for s in displayed.sections if s.title == "Evidence and source freshness"][0].lines) > 0
    assert "not a persisted assessment-time snapshot" in text
    if mode == "full":
        assert "all alert-driving evidence" in text and "Permanent" in text
    if mode == "partial":
        assert "supporting evidence remained" in text
    if mode in ("fail_open", "incomplete"):
        assert "fail-open" in text


def test_current_preferences_are_not_historical_suppression_and_are_bounded_plain_text():
    class Preferences:
        def find_candidates(self, contexts, *, evaluated_at, limit):
            assert evaluated_at == NOW and limit == 100
            return page(*(preference(index=i + 1, expires_at=NOW + timedelta(hours=1), reason="<b>local reason</b>") for i in range(40)))
    result = model(preferences=Preferences())
    text = all_text(result)
    assert "Historical suppression not recorded" in text
    assert "no alert re-evaluation" in text and "Past alert eligibility cannot be reconstructed" in text
    assert text.count("<b>local reason</b>") == 32
    assert "truncated" in text and "Lifetime:" in text
    assert "Rule: destination_ip_novelty_rarity" in text


def test_source_bounds_and_layering_no_score_sql_qt_or_commands():
    module = Path("src/netsentinel/application/services/risk_explanation.py")
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("infrastructure" in name or "PyQt" in name for name in imports)
    calls = [node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else "" for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert not {"score_risk", "save", "persist", "evaluate_suppression", "create", "revoke"} & set(calls)
    assert all(len(line) <= 722 for section in model().sections for line in section.lines)


def test_global_and_mitigation_caps_show_stored_adjustments():
    from tests.unit.domain.test_risk_scoring import legacy
    quality = EvidenceQuality(ObservationQuality.COMPLETE, (EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE,))
    result = model(snapshot(legacy(corroborated=True), legacy(corroborated=True, index=2),
                            frequency(), periodic(3, quality=quality), periodic(4, quality=quality)))
    text = all_text(result)
    assert "global score cap" in text
    assert "Mitigation limited" in text
    assert "Stored positive subtotal: 100" in text


def test_full_evidence_quota_and_preferences_do_not_expand_rendering_unboundedly():
    items = tuple(periodic(i + 1) for i in range(32))
    result = model(snapshot(*items))
    sections = {s.title: s.lines for s in result.sections}
    assert len(sections["Why this result"]) + len(sections["Not used in score"]) <= 64
    assert len(sections["Evidence and source freshness"]) <= 32 * 40
    assert len(result.sections) == 7


@pytest.mark.parametrize("reason,text", [
    ("insufficient_quality", "Insufficient measurement quality"),
    ("unsupported_producer_version", "Producer policy version was unsupported"),
    ("conflicting_novelty", "Conflicting novelty evidence"),
    ("not_evaluated", "not evaluated"),
])
def test_exclusion_reason_mapping_uses_stored_codes(reason, text):
    from netsentinel.domain.risk_scoring import ScoringReason, AssessmentAvailability
    stored = snapshot(freshness=Freshness.STALE)
    contributor = replace(stored.contributors[0], reason=ScoringReason(reason))
    stored = replace(stored, availability=AssessmentAvailability.UNKNOWN, contributors=(contributor,))
    assert text in all_text(model(stored))
