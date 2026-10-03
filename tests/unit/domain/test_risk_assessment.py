"""NS-078 canonical identity, minimal snapshots and historical invariants."""

import ast
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta, timezone
from pathlib import Path

import pytest

from netsentinel.domain.risk_assessment import (
    AssessmentStoragePolicy, RiskAssessmentRevision, canonical_json, snapshot_from_score,
)
from netsentinel.domain.risk_evidence import EvidenceQuality
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.risk_scoring import Freshness, RiskSeverity
from tests.fixtures.risk_assessments import NOW, evidence, key, scoring, snapshot


def test_stable_logical_identity_is_independent_of_evidence_policy_and_revision():
    first = RiskAssessmentRevision(key(), 1, NOW, snapshot())
    second = RiskAssessmentRevision(key(), 2, NOW + timedelta(hours=1), snapshot(evidence(result_code="rare")))
    assert first.key == second.key and first.key.assessment_id == second.key.assessment_id
    assert key(2).assessment_id != first.key.assessment_id
    assert replace(key(), kind="destination_behavior").assessment_id != first.key.assessment_id
    assert first.key.original_observed_at == second.key.original_observed_at == NOW
    assert key().assessment_id == key().assessment_id
    with pytest.raises(FrozenInstanceError):
        first.revision = 2


@pytest.mark.parametrize("stamp", [NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=3)))])
def test_naive_and_non_utc_times_rejected(stamp):
    with pytest.raises(ValueError):
        key(original_observed_at=stamp)
    with pytest.raises(ValueError):
        RiskAssessmentRevision(key(), 1, stamp, snapshot())


@pytest.mark.parametrize("number", [0, -1, True, 2**63, 1.5])
def test_invalid_revision_number_rejected(number):
    with pytest.raises(ValueError):
        RiskAssessmentRevision(key(), number, NOW, snapshot())


def test_order_independence_and_same_score_evidence_changes():
    a, b = evidence(), evidence(2)
    assert snapshot(a, b) == snapshot(b, a)
    assert snapshot(a).score == snapshot(a, b).score
    assert snapshot(a).content_fingerprint != snapshot(a, b).content_fingerprint
    assert snapshot(a).content_fingerprint != snapshot(replace(a, reason_code="new_reason")).content_fingerprint
    assert snapshot(a).content_fingerprint != snapshot(a, freshness=Freshness.STALE).content_fingerprint


@pytest.mark.parametrize("field,value", [("score", 101), ("score", True), ("policy_version", 0),
                                           ("severity", "bad"), ("evidence", []), ("contributors", [])])
def test_invalid_snapshot_rejected(field, value):
    with pytest.raises((ValueError, TypeError)):
        replace(snapshot(), **{field: value})


def test_policy_version_is_historical_and_not_current_policy_validation():
    old = snapshot()
    future = replace(old, policy_version=2, contributors=tuple(replace(c, policy_version=2) for c in old.contributors))
    assert future.score == old.score
    assert future.content_fingerprint != old.content_fingerprint
    assert old.policy_version == 1 and old.evidence[0].contract_version == 1


def test_contributor_explanation_and_context_changes_are_meaningful():
    old = snapshot()
    contributor = replace(old.contributors[0], raw_points=21)
    changed = replace(old, contributors=(contributor,))
    assert changed.score == old.score and changed.content_fingerprint != old.content_fingerprint
    severity = replace(old, severity=RiskSeverity.INFO)
    assert severity.content_fingerprint != old.content_fingerprint
    quality = snapshot(evidence(quality=EvidenceQuality(ObservationQuality.REDUCED)))
    assert quality.score == old.score and quality.content_fingerprint != old.content_fingerprint


def test_maximum_evidence_and_contributors_bounds():
    items = tuple(evidence(i + 1) for i in range(32))
    value = snapshot(*items)
    assert len(value.evidence) == 32
    with pytest.raises(ValueError):
        replace(value, evidence=(*value.evidence, value.evidence[0]))
    with pytest.raises(ValueError):
        replace(value, contributors=value.contributors * 3)


def test_payload_cap_is_independent_of_count_caps():
    from netsentinel.domain.application_identity import ApplicationIdentity
    from tests.fixtures.risk_assessments import APP
    app = ApplicationIdentity(APP.quality, "winpath:v1:c:\\" + "a" * 4000, APP.evidence, APP.path_status)
    items = tuple(evidence(i + 1, subject=replace(evidence(i + 1).subject, application=app)) for i in range(32))
    with pytest.raises(ValueError, match="payload quota"):
        snapshot(*items)


def test_snapshot_input_must_match_result():
    a, r = scoring(evidence())
    b, _ = scoring(evidence(2))
    with pytest.raises(ValueError):
        snapshot_from_score(b, r)
    assert snapshot_from_score(a, r).score == r.score


@pytest.mark.parametrize("changes", [{"max_revisions": 9}, {"max_assessments": 513},
                                    {"cleanup_chunk_size": 129}, {"cleanup_chunk_size": 1},
                                    {"retention_days": 0}, {"max_assessments": True}])
def test_storage_policy_hard_bounds(changes):
    with pytest.raises(ValueError):
        AssessmentStoragePolicy(**changes)


def test_minimal_snapshot_and_layer_boundaries():
    assert "legacy_arp" not in {f.name for f in fields(snapshot().evidence[0])}
    assert "occurrence_count" not in canonical_json(snapshot())
    assert not {"acknowledged_at", "resolved_at", "notification", "last_seen"} & {f.name for f in fields(RiskAssessmentRevision)}
    root = Path(__file__).resolve().parents[3] / "src/netsentinel"
    for path in (root / "domain/risk_assessment.py", root / "application/services/risk_assessments.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not any(m and any(part in m for part in ("sqlite", "PyQt", "services.alerts", "infrastructure")) for m in modules)
        assert "score_risk(" not in path.read_text(encoding="utf-8")
