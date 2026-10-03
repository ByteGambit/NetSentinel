"""NS-076 offline contract validation and unchanged legacy semantics."""

from dataclasses import FrozenInstanceError, dataclass, fields, replace
from datetime import UTC, datetime, timedelta, timezone
import json
from uuid import UUID

import pytest

from netsentinel.application.detectors.destination_novelty import evaluate_destination_novelty
from netsentinel.application.detectors.frequency_diversity import evaluate_frequency_diversity
from netsentinel.application.detectors.periodicity import evaluate_periodicity
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.risk_evidence import evidence_from_arp
from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityEvidence, ArpIdentityReason, ArpIdentityRule,
    ArpRiskAssessment, ArpScoreComponent, ArpScoreRule,
)
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineSnapshot, BaselineState, BaselineStorageState, BaselineSummary,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import (
    ConnectionNetworkScope, Endpoint, NetworkAttributionMethod, NetworkScopeStatus,
    ObservationOrigin, ObservationQuality, ProcessIdentity, ProcessInfo, ProcessInfoStatus, TransportProtocol,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyInput
from netsentinel.domain.devices import GatewayBaselineStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.frequency_diversity import (
    BehaviorRangeReference, BehaviorRangeSample, BehaviorWindow, FrequencyDiversityInput, FrequencyDiversityPolicy,
)
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.periodicity import PeriodicityScope, PeriodicitySequence
from netsentinel.domain.risk_evidence import (
    EVIDENCE_CONTRACT_VERSION, MAX_EVIDENCE_CODE_LENGTH, MAX_EVIDENCE_CONTRIBUTORS,
    MAX_EVIDENCE_REFERENCES, EvidenceConfidence, EvidenceLimitation, EvidenceQuality,
    EvidenceReference, EvidenceReferenceKind, EvidenceRole, EvidenceScope,
    EvidenceScopeKind, EvidenceSource, EvidenceSubject, EvidenceSubjectKind,
    LegacyArpContext, RiskEvidence, RiskEvidenceBatch,
)

NOW = datetime(2026, 10, 3, tzinfo=UTC)
PROCESS = ProcessIdentity(12, NOW - timedelta(minutes=1))
APP = resolve_application_scope(ProcessInfo(
    ProcessInfoStatus.AVAILABLE, PROCESS, "browser", r"C:\Apps\browser.exe",
))
NETWORK = EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64)
BEHAVIOR = BehaviorScopeKey(APP.identity.key, APP.identity.quality, None, NetworkScopeStatus.RESOLVED, "a" * 64)


def generic(**changes):
    args = dict(
        source=EvidenceSource.DESTINATION_NOVELTY, rule_id="destination_ip_novelty_rarity",
        reason_code="destination_not_previously_observed", observed_at=NOW,
        scope=NETWORK, subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address="2001:0db8::1"),
        quality=EvidenceQuality(ObservationQuality.COMPLETE), policy_version=1,
    )
    args.update(changes)
    return RiskEvidence(**args)


def arp(*, gateway=False, verified=False):
    status = GatewayBaselineStatus.VERIFIED if verified else GatewayBaselineStatus.LEARNED
    return ArpIdentityConflictDetected(
        ArpIdentityRule.GATEWAY_MAC_CHANGE if gateway else ArpIdentityRule.IP_MAC_CONFLICT,
        (ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT if verified else ArpIdentityReason.LEARNED_GATEWAY_CONFLICT)
        if gateway else ArpIdentityReason.RECENT_SENDER_CONFLICT,
        ArpIdentityEvidence("a" * 64, "192.168.1.1", MacAddress("00:11:22:33:44:55"),
                            MacAddress("00:11:22:33:44:66"), NOW - timedelta(seconds=20), NOW,
                            status if gateway else None),
        "medium" if verified else "low", "low",
    )


def correlation(source):
    parts = (ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2),
             ArpScoreComponent(ArpScoreRule.REPEATED_OBSERVATION, 1))
    return ArpRiskAssessment(source, NOW, NOW + timedelta(seconds=10), 3, parts, 3, "moderate")


def test_minimal_value_immutable_hashable_and_portable():
    e = generic()
    assert e.contract_version == EVIDENCE_CONTRACT_VERSION == 1
    assert e.subject.ip_address == "2001:db8::1"
    assert e == generic() and hash(e) == hash(generic())
    assert e.evidence_id == generic().evidence_id and len(e.evidence_id) == 64
    with pytest.raises(FrozenInstanceError):
        e.reason_code = "changed"
    assert not hasattr(e, "__dict__")
    assert replace(e, observed_at=NOW + timedelta(microseconds=1)).evidence_id != e.evidence_id


@pytest.mark.parametrize("address,canonical", [("192.0.2.1", "192.0.2.1"), ("2001:0DB8:0000::1", "2001:db8::1")])
def test_ipv4_ipv6_canonical_round_trip(address, canonical):
    subject = EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=address)
    rebuilt = EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=subject.ip_address)
    assert subject == rebuilt and subject.ip_address == canonical
    assert generic(subject=subject).evidence_id == generic(subject=rebuilt).evidence_id


@pytest.mark.parametrize("address", ["invalid", "1.2.3.999", "fe80::1%eth", "x" * 10000, 123, object()])
def test_invalid_ip_rejected(address):
    with pytest.raises((ValueError, TypeError)):
        EvidenceSubject(EvidenceSubjectKind.DESTINATION, ip_address=address)


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_unresolved_scope_without_fabricated_fingerprint(status):
    scope = EvidenceScope.from_connection(ConnectionNetworkScope(status))
    assert scope.kind is EvidenceScopeKind.UNKNOWN and scope.network_status is status
    assert generic(scope=scope).scope.network_fingerprint is None
    with pytest.raises(ValueError):
        replace(scope, network_fingerprint="a" * 64)


def test_host_network_and_ambiguous_are_distinct():
    host = EvidenceScope(EvidenceScopeKind.HOST)
    network = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "eth", 1,
                                     NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
    assert EvidenceScope.from_connection(network) == NETWORK
    assert generic(scope=host, subject=EvidenceSubject(EvidenceSubjectKind.NETWORK)).scope == host
    assert generic(scope=EvidenceScope.from_connection(ConnectionNetworkScope.unknown())).evidence_id != generic(scope=EvidenceScope.from_connection(ConnectionNetworkScope.ambiguous())).evidence_id
    with pytest.raises(ValueError):
        replace(host, network_status=NetworkScopeStatus.UNKNOWN)
    with pytest.raises(ValueError):
        EvidenceScope(EvidenceScopeKind.UNKNOWN)
    with pytest.raises(ValueError):
        EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "unknown")


def test_process_application_revision_lifecycle_are_separate():
    revision = ApplicationRevision("b" * 64, ExecutableHashStatus.AVAILABLE)
    subject = EvidenceSubject(EvidenceSubjectKind.CONNECTION, application=APP.identity,
                              revision=revision, process=PROCESS, session_id=UUID(int=1), lifecycle_id=UUID(int=2))
    assert generic(subject=subject).subject == subject
    assert replace(subject, process=replace(PROCESS, create_time=NOW)) != subject
    assert replace(subject, revision=ApplicationRevision(None)).revision.known is False
    assert generic(subject=EvidenceSubject(EvidenceSubjectKind.PROCESS, process=PROCESS)).subject.application is None
    assert generic(subject=EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=APP.identity)).subject.process is None
    assert generic(subject=EvidenceSubject(EvidenceSubjectKind.NETWORK)).subject.ip_address is None


def test_pid_only_requires_session_and_provisional_requires_exact_process():
    pid = ProcessIdentity(PROCESS.pid)
    with pytest.raises(ValueError):
        EvidenceSubject(EvidenceSubjectKind.PROCESS, process=pid)
    valid = EvidenceSubject(EvidenceSubjectKind.PROCESS, process=pid, session_id=UUID(int=1))
    assert generic(subject=valid).subject.process.create_time is None
    assert generic(subject=replace(valid, session_id=UUID(int=2))).evidence_id != generic(subject=valid).evidence_id
    provisional = resolve_application_scope(ProcessInfo(ProcessInfoStatus.AVAILABLE, PROCESS, "browser"))
    valid = EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=provisional.identity, process=PROCESS)
    assert generic(subject=valid).subject.application == provisional.identity
    with pytest.raises(ValueError):
        replace(valid, process=replace(PROCESS, create_time=NOW))


@pytest.mark.parametrize("changes", [dict(revision=ApplicationRevision(None)), dict(process=object()),
    dict(application=object()), dict(lifecycle_id="123"), dict(mac="00:11:22:33:44:55")])
def test_invalid_subject_fields(changes):
    with pytest.raises((ValueError, TypeError)):
        EvidenceSubject(EvidenceSubjectKind.NETWORK, **changes)


@pytest.mark.parametrize("kind", [EvidenceSubjectKind.APPLICATION, EvidenceSubjectKind.PROCESS,
    EvidenceSubjectKind.CONNECTION, EvidenceSubjectKind.DESTINATION, EvidenceSubjectKind.DEVICE, EvidenceSubjectKind.GATEWAY])
def test_subject_requires_defining_identity(kind):
    with pytest.raises(ValueError):
        EvidenceSubject(kind)


def test_application_key_is_controlled_and_bounded():
    for key in ("winpath:v1:" + "x" * 5000, "winpath:v1:relative.exe", "winpath:v1:c:\\apps\\x.exe\n"):
        with pytest.raises(ValueError):
            EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=replace(APP.identity, key=key))


def test_unavailable_application_and_revision_are_explicit():
    unavailable = resolve_application_scope(ProcessInfo.unavailable())
    subject = EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=unavailable.identity,
                              revision=unavailable.revision)
    assert generic(subject=subject).subject.application.key is None
    assert subject.revision.digest is None


def test_extended_domain_dataclass_cannot_smuggle_sensitive_fields():
    @dataclass(frozen=True)
    class ExtendedProcess(ProcessIdentity):
        command_line: str = "secret"

    subject = EvidenceSubject(EvidenceSubjectKind.PROCESS, process=ExtendedProcess(12, NOW))
    with pytest.raises(TypeError, match="payload fields"):
        generic(subject=subject)


@pytest.mark.parametrize("measurement", [None, ObservationQuality.COMPLETE, ObservationQuality.REDUCED, ObservationQuality.FAILED])
def test_quality_is_separate_from_confidence(measurement):
    e = generic(quality=EvidenceQuality(measurement, (EvidenceLimitation.RESOLUTION_LIMITED,)),
                confidence=EvidenceConfidence.LOW, role=EvidenceRole.LIMITATION)
    assert e.quality.measurement is measurement and e.confidence is EvidenceConfidence.LOW
    assert e.quality.limitations == (EvidenceLimitation.RESOLUTION_LIMITED,)


def test_failed_collection_not_a_finding_or_normal_observation():
    for role in (EvidenceRole.FINDING, EvidenceRole.OBSERVATION):
        with pytest.raises(ValueError):
            generic(quality=EvidenceQuality(ObservationQuality.FAILED), role=role)
    with pytest.raises(TypeError):
        EvidenceQuality("complete")
    with pytest.raises(ValueError):
        EvidenceQuality(limitations=("resolution_limited",))


@pytest.mark.parametrize("stamp", [NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=3))), "now"])
def test_timestamp_requires_utc(stamp):
    with pytest.raises(ValueError):
        generic(observed_at=stamp)


@pytest.mark.parametrize("field_name", ["rule_id", "reason_code", "result_code"])
@pytest.mark.parametrize("code", ["", "x" * 65, "Bearer abc", "cookie=value", "C:\\secret.txt", "a\n", "Ü", object()])
def test_symbolic_explanations_reject_free_text(field_name, code):
    with pytest.raises(ValueError):
        generic(**{field_name: code})


def test_max_code_and_policy_contract_versions():
    assert generic(reason_code="x" * MAX_EVIDENCE_CODE_LENGTH).reason_code == "x" * 64
    for version in (0, -1, True, 1_000_001, "1"):
        with pytest.raises(ValueError):
            generic(policy_version=version)
    for version in (True, 2, 0):
        with pytest.raises(ValueError):
            generic(contract_version=version)
    assert generic(policy_version=None).policy_version is None
    assert generic(policy_version=2).evidence_id != generic().evidence_id


def test_references_bounds_duplicates_and_deterministic_order():
    refs = tuple(EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=i)) for i in range(1, 9))
    assert len(refs) == MAX_EVIDENCE_REFERENCES
    e = generic(references=refs)
    assert generic(references=refs[::-1]) == e
    assert generic(references=()).references == ()
    assert generic(references=refs[:1]).references == refs[:1]
    assert json.loads(json.dumps([str(r.value) for r in e.references])) == [str(r.value) for r in refs]
    for bad in (refs + (EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=9)),),
                (refs[0], refs[0]), list(refs), (object(),)):
        with pytest.raises(ValueError):
            generic(references=bad)


@pytest.mark.parametrize("kind", list(EvidenceReferenceKind))
def test_reference_target_validation(kind):
    value = "b" * 64 if kind in (EvidenceReferenceKind.EVIDENCE, EvidenceReferenceKind.LEGACY_ARP_EVENT) else UUID(int=1)
    assert EvidenceReference(kind, value).value == value
    for bad in ("C:\\secret.txt", "a" * 10000, object(), "not-an-id", "A" * 64):
        with pytest.raises((ValueError, TypeError)):
            EvidenceReference(kind, bad)
    with pytest.raises(TypeError):
        EvidenceReference(kind.value, value)


def test_flat_contributors_bounds_duplicates_order_and_immutability():
    evidence = tuple(generic(observed_at=NOW + timedelta(seconds=i)) for i in range(MAX_EVIDENCE_CONTRIBUTORS))
    batch = RiskEvidenceBatch(evidence)
    assert RiskEvidenceBatch(evidence[::-1]) == batch
    assert RiskEvidenceBatch().evidence == ()
    for bad in (evidence + (generic(observed_at=NOW + timedelta(days=1)),), (evidence[0], evidence[0]),
                list(evidence), (batch,)):
        with pytest.raises(ValueError):
            RiskEvidenceBatch(bad)
    with pytest.raises(FrozenInstanceError):
        batch.evidence = ()


def test_limitations_deterministic_and_reject_mutable_duplicates():
    limits = (EvidenceLimitation.POLLING_QUANTIZED, EvidenceLimitation.CAPACITY_LOSS)
    assert generic(quality=EvidenceQuality(limitations=limits)) == generic(quality=EvidenceQuality(limitations=limits[::-1]))
    for bad in (list(limits), (limits[0], limits[0]), limits * 9):
        with pytest.raises(ValueError):
            EvidenceQuality(limitations=bad)


@pytest.mark.parametrize("gateway,verified", [(False, False), (True, False), (True, True)])
def test_arp_field_mapping_keeps_every_original_field(gateway, verified):
    original = arp(gateway=gateway, verified=verified)
    e = evidence_from_arp(original)
    assert e.legacy_arp.source is original
    assert e.legacy_arp.correlation is None
    assert e.rule_id == original.rule_id.value and e.reason_code == original.reason.value
    assert e.scope.network_fingerprint == original.evidence.network_fingerprint
    assert e.subject.ip_address == original.evidence.ip_address and e.subject.mac == original.evidence.observed_mac
    assert e.subject.kind is (EvidenceSubjectKind.GATEWAY if gateway else EvidenceSubjectKind.DEVICE)
    assert e.subject.application is e.subject.process is e.subject.lifecycle_id is None
    assert e.references[0].value == original.event_fingerprint
    assert e.observed_at == original.observed_at
    assert e.confidence.value == original.confidence and e.legacy_arp.source.severity == original.severity
    assert e.quality.measurement is None and e.policy_version is None
    assert e.evidence_id != original.event_fingerprint and evidence_from_arp(original) == e


def test_arp_correlation_legacy_context_roundtrip_and_dedup_unchanged():
    original = correlation(arp(gateway=True, verified=True))
    before = AlertService._candidate(original)
    e = evidence_from_arp(original)
    assert e.legacy_arp.correlation is original
    assert (e.legacy_arp.correlation.score, e.legacy_arp.correlation.breakdown) == (original.score, original.breakdown)
    assert e.confidence is EvidenceConfidence.MODERATE
    assert e.observed_at == original.last_observed_at
    assert e.legacy_arp.source.observed_at == NOW
    assert AlertService._candidate(e.legacy_arp.correlation) == before
    assert before.fingerprint == original.event_fingerprint == e.references[0].value
    assert evidence_from_arp(original.source).evidence_id != e.evidence_id
    with pytest.raises(ValueError):
        replace(e, confidence=EvidenceConfidence.HIGH)
    with pytest.raises(ValueError):
        replace(e, reason_code="confirmed_mitm")
    with pytest.raises(ValueError):
        replace(e, references=())
    with pytest.raises(ValueError):
        replace(e, subject=replace(e.subject, kind=EvidenceSubjectKind.DESTINATION))
    with pytest.raises(ValueError):
        replace(e, role=EvidenceRole.OBSERVATION)
    with pytest.raises(ValueError):
        replace(e, policy_version=1)
    with pytest.raises(ValueError):
        LegacyArpContext(arp(), original)
    with pytest.raises(TypeError):
        evidence_from_arp(before)


def test_legacy_correlation_portable_bounds_reject_mutable_breakdown():
    original = correlation(arp())
    for value in (replace(original, observation_count=1_000_000_001),
                  replace(original, breakdown=list(original.breakdown))):
        with pytest.raises(ValueError):
            evidence_from_arp(value)


def features(count=40, diversity=4):
    return BehaviorFeatureSnapshot(BEHAVIOR, count, 0, 600.,
        tuple(FeatureCount(f"2001:db8::{i + 1}", count // diversity) for i in range(diversity)),
        (FeatureCount(443, count),), (FeatureCount(TransportProtocol.TCP, count),),
        0, 0, 0, 0, diversity, 1, 1, False, False)


def baseline(state=BaselineState.READY):
    return BaselineSnapshot(BEHAVIOR, state, BaselineOrigin.NEW, BaselineStorageState.AVAILABLE,
                            BaselineSummary(features(), NOW, NOW, "test-policy"))


def represent(result, source, role, *, subject=None, quality=None):
    """Contract examples only; no M13 runtime adapter or fact persistence."""
    return generic(source=source, rule_id=result.rule_id, reason_code=result.reason.value,
        result_code=result.classification.value, observed_at=result.observed_at, role=role,
        subject=subject or EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=APP.identity, revision=APP.revision),
        quality=quality or EvidenceQuality(result.quality), policy_version=result.policy_version)


@pytest.mark.parametrize("state,role", [(BaselineState.READY, EvidenceRole.FINDING),
                                      (BaselineState.LEARNING, EvidenceRole.LIMITATION)])
def test_ns072_retained_baseline_semantics_representable(state, role):
    result = evaluate_destination_novelty(DestinationNoveltyInput(BEHAVIOR, "2001:db8::99", NOW,
                                          ObservationOrigin.OBSERVED, ObservationQuality.REDUCED, baseline(state)))
    quality = EvidenceQuality(result.quality, tuple(EvidenceLimitation(x.value) for x in result.limitations))
    e = represent(result, EvidenceSource.DESTINATION_NOVELTY, role,
        subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, application=APP.identity,
                                revision=APP.revision, ip_address=result.destination_ip), quality=quality)
    assert e.result_code == ("first_seen" if state is BaselineState.READY else "insufficient_data")
    assert e.reason_code == result.reason.value
    assert e.quality.measurement is ObservationQuality.REDUCED and e.confidence is None
    assert EvidenceLimitation.REVISION_UNVERIFIED in e.quality.limitations
    assert e.policy_version == 1


@pytest.mark.parametrize("count,diversity,role", [(40, 4, EvidenceRole.OBSERVATION), (400, 20, EvidenceRole.FINDING)])
def test_ns073_observed_appearance_and_diversity_representable(count, diversity, role):
    policy = FrequencyDiversityPolicy()
    reference = BehaviorRangeReference(BEHAVIOR, UUID(int=1), policy,
        tuple(BehaviorRangeSample(i * 720., (i + 1) * 720., 600., 40, 4) for i in range(3)), "test-policy")
    window = BehaviorWindow(features(count, diversity), UUID(int=1), 2160., 2880., NOW)
    results = evaluate_frequency_diversity(FrequencyDiversityInput(window, baseline(), reference))
    for result in results:
        e = represent(result, EvidenceSource.FREQUENCY_DIVERSITY, role)
        assert e.result_code == ("normal" if count == 40 else "elevated_unconfirmed")
        assert e.rule_id in ("observed_appearance_frequency", "destination_window_diversity")
        assert e.reason_code == result.reason.value and e.policy_version == 1
        assert e.confidence is None


@pytest.mark.parametrize("period,classification,role", [(60., "periodic_candidate", EvidenceRole.FINDING),
                                                       (10., "resolution_limited", EvidenceRole.LIMITATION)])
def test_ns074_resolution_and_benign_schedule_limitations_representable(period, classification, role):
    scope = PeriodicityScope(BEHAVIOR, PROCESS, Endpoint("2001:db8::99", 443), TransportProtocol.TCP)
    result = evaluate_periodicity(PeriodicitySequence(scope, UUID(int=1), (period,) * 5, 5., NOW))
    limits = tuple(EvidenceLimitation(x.value) for x in result.limitations)
    if classification == "resolution_limited":
        limits += (EvidenceLimitation.RESOLUTION_LIMITED,)
    e = represent(result, EvidenceSource.PERIODICITY, role,
        subject=EvidenceSubject(EvidenceSubjectKind.DESTINATION, application=APP.identity, revision=APP.revision,
                                process=PROCESS, ip_address=scope.remote_endpoint.address),
        quality=EvidenceQuality(ObservationQuality.COMPLETE, limits))
    assert e.result_code == classification and e.rule_id == "observed_appearance_periodicity"
    assert EvidenceLimitation.POLLING_QUANTIZED in e.quality.limitations
    assert EvidenceLimitation.BENIGN_SCHEDULE_COMPATIBLE in e.quality.limitations
    assert e.quality.measurement is ObservationQuality.COMPLETE and e.confidence is None


def test_sensitive_dump_scoring_and_recursive_tree_have_no_field():
    forbidden = {"details", "metadata", "payload", "packet", "command_line", "executable_path",
                 "cookie", "token", "body", "children", "score", "weight", "probability", "assessment"}
    for model in (RiskEvidence, EvidenceSubject, EvidenceQuality, EvidenceReference, RiskEvidenceBatch):
        assert not forbidden.intersection(f.name for f in fields(model))
    for name in forbidden:
        with pytest.raises(TypeError):
            generic(**{name: object()})
    for changes in (dict(source="periodicity"), dict(subject={"payload": b"secret"}),
                    dict(quality={}), dict(confidence="high"), dict(role="finding")):
        with pytest.raises(TypeError):
            generic(**changes)
