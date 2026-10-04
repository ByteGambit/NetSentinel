"""Deterministic current user policies and NS-077 risk results."""

from datetime import timedelta
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.preferences import (
    PreferenceAuditAction, PreferenceDefinition, PreferenceLifetime, PreferenceLifetimeKind,
    PreferencePage, PreferenceResult, PreferenceResultStatus, PreferenceSelector,
    PreferenceStatus, ScopedPreference,
)
from tests.fixtures.preferences import NOW, ORIGIN, RULE
from tests.fixtures.risk_assessments import evidence, scoring

REFERENCE = AlertAssessmentReference("f" * 64, 1, None)


def preference(selector=None, *, index=1, expires_at=None, reason="Explicit scoped policy", revision=1):
    definition = PreferenceDefinition(selector or PreferenceSelector(rule_id=RULE),
        PreferenceLifetime(PreferenceLifetimeKind.PERMANENT) if expires_at is None else
        PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expires_at), reason)
    return ScopedPreference(UUID(int=index), revision, definition, NOW, ORIGIN, NOW, ORIGIN,
                            PreferenceAuditAction.CREATE if revision == 1 else PreferenceAuditAction.EDIT,
                            PreferenceStatus.ACTIVE)


def page(*preferences, truncated=False):
    return PreferencePage(PreferenceResultStatus.FOUND, tuple(
        PreferenceResult(PreferenceResultStatus.FOUND, p, p.preference_id) for p in preferences), truncated)


def periodic(index=2, **changes):
    from netsentinel.domain.risk_evidence import EvidenceSource
    return evidence(index, source=EvidenceSource.PERIODICITY, rule_id="observed_appearance_periodicity",
                    result_code="periodic_candidate", **changes)


def frequency(index=2, **changes):
    from netsentinel.domain.risk_evidence import EvidenceSource
    return evidence(index, source=EvidenceSource.FREQUENCY_DIVERSITY, rule_id="observed_appearance_frequency",
                    result_code="elevated_confirmed", **changes)


def risk(*items):
    return scoring(*(items or (evidence(),)))[1]


EXPIRES = NOW + timedelta(hours=1)
