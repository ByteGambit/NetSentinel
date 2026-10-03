"""NS-076 additive translation; existing detectors and alert paths stay owners."""

from dataclasses import asdict
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json
from uuid import UUID

from netsentinel.domain.alerts import ArpIdentityConflictDetected, ArpIdentityRule, ArpRiskAssessment
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.risk_evidence import (
    EvidenceConfidence, EvidenceQuality, EvidenceReference, EvidenceReferenceKind,
    EvidenceRole, EvidenceScope, EvidenceScopeKind, EvidenceSource, EvidenceSubject,
    EvidenceSubjectKind, LegacyArpContext, RiskEvidence,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyEvidence
from netsentinel.domain.frequency_diversity import BehaviorDeviationEvidence
from netsentinel.domain.periodicity import PeriodicityEvidence
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.risk_evidence import EvidenceLimitation


BehaviorEvidence = DestinationNoveltyEvidence | BehaviorDeviationEvidence | PeriodicityEvidence


def _source_value(value: object) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")
    if isinstance(value, UUID):
        return str(value)
    raise TypeError("unsupported detector identity field")


def evidence_from_behavior(value: BehaviorEvidence, *, subject: EvidenceSubject,
                           scope: EvidenceScope,
                           references: tuple[EvidenceReference, ...]) -> RiskEvidence:
    """One explicit M13 adapter. Codes retain polling/retention semantics.

    Confidence describes this statistical finding, not measurement quality.
    Unsupported/insufficient outputs remain limitation evidence, never normal.
    The caller supplies canonical occurrence context instead of a random ID.
    """
    limitations: set[EvidenceLimitation] = set()
    confidence = None
    if type(value) not in (DestinationNoveltyEvidence, BehaviorDeviationEvidence, PeriodicityEvidence):
        raise TypeError("adapter requires a closed M13 evidence type")
    behavior_scope = value.scope.behavior if isinstance(value, PeriodicityEvidence) else value.scope
    if behavior_scope is not None:
        if (subject.application is None or subject.application.key != behavior_scope.application_key
                or subject.application.quality is not behavior_scope.identity_quality
                or (subject.revision.digest if subject.revision is not None else None) != behavior_scope.revision_digest
                or scope.network_status is not behavior_scope.network_status
                or (scope.network_fingerprint is not None and scope.network_fingerprint != behavior_scope.network_token)):
            raise ValueError("detector and occurrence scopes disagree")
    if isinstance(value, DestinationNoveltyEvidence) and value.destination_ip is not None:
        if subject.ip_address != value.destination_ip:
            raise ValueError("novelty destination differs from occurrence")
    if isinstance(value, PeriodicityEvidence):
        if (subject.process != value.scope.process_identity or subject.session_id != value.session_id
                or subject.ip_address != value.scope.remote_endpoint.address):
            raise ValueError("periodicity context differs from occurrence")
    if isinstance(value, DestinationNoveltyEvidence):
        source, rule = EvidenceSource.DESTINATION_NOVELTY, value.rule_id
        quality = value.quality
        positive = {"first_seen", "rare"}
        normal = {"known"}
        limitations.update(EvidenceLimitation(item.value) for item in value.limitations)
        if value.capacity_loss or value.other_destinations:
            limitations.add(EvidenceLimitation.CAPACITY_LOSS)
        if value.gap_seen:
            limitations.add(EvidenceLimitation.MONITORING_GAP)
        if value.classification.value in positive:
            confidence = EvidenceConfidence.LOW
    elif isinstance(value, BehaviorDeviationEvidence):
        source, rule = EvidenceSource.FREQUENCY_DIVERSITY, value.rule_id.value
        quality = value.quality
        positive = {"elevated_unconfirmed", "elevated_confirmed"}
        normal = {"normal"}
        if value.capacity_loss or value.current_other_destinations:
            limitations.add(EvidenceLimitation.CAPACITY_LOSS)
        if value.gap_seen:
            limitations.add(EvidenceLimitation.MONITORING_GAP)
        if value.revision_unverified:
            limitations.add(EvidenceLimitation.REVISION_UNVERIFIED)
        if quality is ObservationQuality.REDUCED:
            limitations.add(EvidenceLimitation.REDUCED_OBSERVATION)
        if value.classification.value in positive:
            confidence = (EvidenceConfidence.MODERATE if value.classification.value == "elevated_confirmed"
                          else EvidenceConfidence.LOW)
    elif isinstance(value, PeriodicityEvidence):
        source, rule = EvidenceSource.PERIODICITY, value.rule_id
        # NS-074 only produces these sequences from COMPLETE appearances.
        quality = ObservationQuality.COMPLETE
        positive, normal = {"periodic_candidate"}, {"irregular"}
        limitations.update(EvidenceLimitation(item.value) for item in value.limitations)
        if value.classification.value == "resolution_limited":
            limitations.add(EvidenceLimitation.RESOLUTION_LIMITED)
        if value.classification.value in positive:
            confidence = EvidenceConfidence.LOW
    else:
        raise TypeError("adapter requires typed M13 evidence")
    classification = value.classification.value
    role = (EvidenceRole.FINDING if classification in positive else
            EvidenceRole.OBSERVATION if classification in normal else EvidenceRole.LIMITATION)
    if quality is ObservationQuality.FAILED:
        role = EvidenceRole.LIMITATION
    # NS-076 has no numeric detector measurement payload. Keep its deterministic
    # content identity as an unresolved source pointer instead of arbitrary
    # details. A changed rate/count/interval still creates a meaningful revision.
    encoded = json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                         allow_nan=False, default=_source_value)
    source_reference = EvidenceReference(EvidenceReferenceKind.EVIDENCE, sha256(encoded.encode("ascii")).hexdigest())
    references = (*references, source_reference)
    return RiskEvidence(source, rule, value.reason.value, value.observed_at, scope, subject,
                        EvidenceQuality(quality, tuple(limitations)), role, value.policy_version,
                        classification, confidence, references)


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
