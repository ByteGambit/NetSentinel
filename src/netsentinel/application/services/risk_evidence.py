"""NS-076 additive translation; existing detectors and alert paths stay owners."""

from netsentinel.domain.alerts import ArpIdentityConflictDetected, ArpIdentityRule, ArpRiskAssessment
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceQuality, EvidenceReference, EvidenceReferenceKind,
    EvidenceRole, EvidenceScope, EvidenceScopeKind, EvidenceSource, EvidenceSubject,
    EvidenceSubjectKind, LegacyArpContext, RiskEvidence,
)


def evidence_from_arp(value: ArpIdentityConflictDetected | ArpRiskAssessment) -> RiskEvidence:
    """Preserve source/reason, issue fingerprint and all original legacy context.

    Legacy policy/measurement quality is unreported, not invented as v1/complete.
    A correlation revision receives its own content ID; its legacy issue ID stays
    the same. No detector, score calculation, repository or AlertService is called.
    """
    if isinstance(value, ArpRiskAssessment):
        event, correlation = value.source, value
    elif isinstance(value, ArpIdentityConflictDetected):
        event, correlation = value, None
    else:
        raise TypeError("adapter requires typed ARP evidence or correlation")
    original = event.evidence
    return RiskEvidence(
        source=EvidenceSource.ARP_IDENTITY,
        rule_id=event.rule_id.value,
        reason_code=event.reason.value,
        observed_at=correlation.last_observed_at if correlation else event.observed_at,
        scope=EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, original.network_fingerprint),
        subject=EvidenceSubject(
            EvidenceSubjectKind.GATEWAY if event.rule_id is ArpIdentityRule.GATEWAY_MAC_CHANGE else EvidenceSubjectKind.DEVICE,
            ip_address=original.ip_address, mac=original.observed_mac,
        ),
        quality=EvidenceQuality(),
        role=EvidenceRole.FINDING,
        confidence=EvidenceConfidence(correlation.confidence if correlation else event.confidence),
        references=(EvidenceReference(EvidenceReferenceKind.LEGACY_ARP_EVENT, event.event_fingerprint),),
        legacy_arp=LegacyArpContext(event, correlation),
    )
