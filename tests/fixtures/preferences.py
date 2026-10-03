"""Offline user policy fixtures, separate from observed baselines."""

from datetime import UTC, datetime, timedelta

from netsentinel.domain.application_identity import (
    ApplicationIdentity, ApplicationIdentityEvidence, ApplicationIdentityQuality, ApplicationRevision,
)
from netsentinel.domain.connections import NetworkScopeStatus, ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.preferences import (
    DestinationKind, PreferenceDefinition, PreferenceDestination, PreferenceLifetime,
    PreferenceLifetimeKind, PreferenceMatchContext, PreferenceOrigin, PreferenceSelector,
)
from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceScopeKind, EvidenceSubject, EvidenceSubjectKind

NOW = datetime(2026, 10, 4, 8, tzinfo=UTC)
ORIGIN = PreferenceOrigin.MANUAL_USER
FP = "a" * 64
RULE = "destination_ip_novelty_rarity"


def application(path="c:\\apps\\browser.exe"):
    return ApplicationIdentity(ApplicationIdentityQuality.STABLE, "winpath:v1:" + path,
                               ApplicationIdentityEvidence.EXECUTABLE_PATH, ProcessInfoStatus.AVAILABLE)


def revision(digest="b" * 64):
    return ApplicationRevision(digest, ExecutableHashStatus.AVAILABLE if digest else None)


def destination(value="203.0.113.10"):
    return PreferenceDestination(DestinationKind.IPV6 if ":" in value else DestinationKind.IPV4, value)


def definition(selector=None, *, permanent=False, reason="User chose a narrow notification preference"):
    return PreferenceDefinition(
        selector if selector is not None else PreferenceSelector(rule_id=RULE),
        PreferenceLifetime(PreferenceLifetimeKind.PERMANENT) if permanent else
        PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, NOW + timedelta(hours=1)), reason,
    )


def context(*, app=None, rev=None, ip="203.0.113.10", network=FP, rule=RULE, status=NetworkScopeStatus.RESOLVED):
    scope = EvidenceScope(EvidenceScopeKind.NETWORK, status, network) if status is NetworkScopeStatus.RESOLVED else EvidenceScope(EvidenceScopeKind.UNKNOWN, status)
    return PreferenceMatchContext(rule, EvidenceSubject(EvidenceSubjectKind.DESTINATION, application=app or application(), revision=rev, ip_address=ip), scope)
