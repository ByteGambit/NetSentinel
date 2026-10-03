"""Synthetic M13 detector inputs and canonical NS-079 occurrence context."""

from datetime import UTC, datetime
from uuid import UUID

from netsentinel.application.detectors.destination_novelty import evaluate_destination_novelty
from netsentinel.application.detectors.frequency_diversity import evaluate_frequency_diversity
from netsentinel.application.detectors.periodicity import evaluate_periodicity
from netsentinel.domain.application_identity import (
    ApplicationIdentity, ApplicationIdentityEvidence, ApplicationIdentityQuality, ApplicationRevision,
)
from netsentinel.domain.behavior_baseline import (
    BaselineSnapshot, BaselineState, BaselineOrigin, BaselineStorageState, BaselineSummary,
)
from netsentinel.domain.behavior_features import BehaviorScopeKey, BehaviorFeatureSnapshot, FeatureCount
from netsentinel.domain.connections import (
    NetworkScopeStatus, ProcessInfoStatus, ProcessIdentity, ObservationOrigin, ObservationQuality,
    Endpoint, TransportProtocol,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyInput
from netsentinel.domain.frequency_diversity import BehaviorWindow, FrequencyDiversityInput
from netsentinel.domain.periodicity import PeriodicityScope, PeriodicitySequence
from netsentinel.domain.risk_assessment import RiskAssessmentKey
from netsentinel.domain.risk_evidence import (
    EvidenceScope, EvidenceScopeKind, EvidenceSubject, EvidenceSubjectKind,
    EvidenceReference, EvidenceReferenceKind,
)

NOW = datetime(2026, 10, 3, tzinfo=UTC)
SESSION = UUID(int=1)
APP = ApplicationIdentity(ApplicationIdentityQuality.STABLE, r"winpath:v1:c:\apps\example.exe",
    ApplicationIdentityEvidence.EXECUTABLE_PATH, ProcessInfoStatus.AVAILABLE)
PROCESS = ProcessIdentity(12, NOW)
SCOPE = BehaviorScopeKey(APP.key, APP.quality, None, NetworkScopeStatus.RESOLVED, "a" * 64)


def features(*, scope=SCOPE, count=100, seconds=600.0, overflow=0, loss=False):
    return BehaviorFeatureSnapshot(scope, count, 0, seconds,
        (FeatureCount("192.0.2.1", count - overflow),), (FeatureCount(443, count),),
        (FeatureCount(TransportProtocol.TCP, count),), overflow, 0, 0, 0, 1, 1, 1, False, loss)


def baseline(*, scope=SCOPE, count=100, seconds=600.0, state=BaselineState.READY):
    return BaselineSnapshot(scope, state, BaselineOrigin.NEW, BaselineStorageState.AVAILABLE,
                           BaselineSummary(features(scope=scope, count=count, seconds=seconds), NOW, NOW, "test-policy"))


def key(*, index=1, stamp=NOW, address="203.0.113.2", application=APP, scope=None, process=PROCESS,
        session=SESSION, revision=None):
    return RiskAssessmentKey("connection_behavior", scope or EvidenceScope(
        EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64),
        EvidenceSubject(EvidenceSubjectKind.DESTINATION, application, revision or ApplicationRevision(None),
                        process, session, ip_address=address),
        EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, UUID(int=index)), stamp)


def novelty(*, scope=SCOPE, address="203.0.113.2", stamp=NOW, state=BaselineState.READY,
            quality=ObservationQuality.COMPLETE):
    return evaluate_destination_novelty(DestinationNoveltyInput(scope, address, stamp,
        ObservationOrigin.OBSERVED, quality, baseline(scope=scope, state=state)))


def deviations(*, count=500, overflow=0, loss=False):
    window = BehaviorWindow(features(count=count, seconds=600.0, overflow=overflow, loss=loss),
                            SESSION, 0.0, 720.0, NOW)
    return evaluate_frequency_diversity(FrequencyDiversityInput(window, baseline()))


def periodic(*, intervals=(60.0,) * 6, poll=1.0, address="203.0.113.2"):
    return evaluate_periodicity(PeriodicitySequence(
        PeriodicityScope(SCOPE, PROCESS, Endpoint(address, 443), TransportProtocol.TCP),
        SESSION, intervals, poll, NOW))
