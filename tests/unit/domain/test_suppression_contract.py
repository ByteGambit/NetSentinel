"""Domain explanations cannot invent policy matches or hide uncertain support."""

from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.services.suppression import evaluate_suppression
from netsentinel.domain.preferences import PreferenceSelector
from netsentinel.domain.suppression import SuppressionDisposition as Disposition, SuppressionLimitation as Limitation
from tests.fixtures.preferences import NOW
from tests.fixtures.suppression import REFERENCE, page, preference, risk


def evaluation():
    return evaluate_suppression(risk(), REFERENCE, NOW, page(preference()))


@pytest.mark.parametrize("change", [
    {"evaluated_at": NOW.replace(tzinfo=None)}, {"disposition": "suppressed"},
    {"assessment": None}, {"disposition": Disposition.NOT_APPLICABLE},
    {"disposition": Disposition.NOT_SUPPRESSED}, {"groups": ()},
])
def test_invalid_aggregate_context_is_rejected(change):
    with pytest.raises((ValueError, TypeError)):
        replace(evaluation(), **change)


def test_evidence_cannot_claim_a_nonmatching_or_expired_policy():
    result = evaluation()
    entry = result.evidence[0]
    wrong = replace(entry.matches[0], selector=PreferenceSelector(rule_id="unrelated_rule"))
    with pytest.raises(ValueError):
        replace(entry, matches=(wrong,))
    timed = preference(expires_at=NOW + timedelta(seconds=1))
    result = evaluate_suppression(risk(), REFERENCE, NOW, page(timed))
    with pytest.raises(ValueError):
        replace(result, evaluated_at=NOW + timedelta(seconds=1))


def test_group_cannot_remove_unknown_or_unsuppressed_evidence():
    result = evaluate_suppression(risk(), REFERENCE, NOW, page(truncated=True))
    assert result.disposition is Disposition.INDETERMINATE
    wrong = replace(result.groups[0], remaining_evidence_ids=())
    with pytest.raises(ValueError):
        replace(result, groups=(wrong,))
    with pytest.raises(ValueError):
        replace(result.groups[0], remaining_evidence_ids=("0" * 64,))


@pytest.mark.parametrize("change", [
    {"observed_match_count": True}, {"expired_match_count": -1}, {"revoked_match_count": 101},
    {"limitations": ("lookup_unavailable",)}, {"limitations": (Limitation.CORRUPT_PREFERENCE,) * 2},
    {"matches": ()}, {"evidence_id": "bad"},
])
def test_evidence_summary_requires_bounded_typed_values(change):
    with pytest.raises((ValueError, TypeError)):
        replace(evaluation().evidence[0], **change)
