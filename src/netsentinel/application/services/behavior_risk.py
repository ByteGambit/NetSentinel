"""Memory-only M13 ordering around the engine's accumulator mutation."""

from dataclasses import dataclass
from datetime import datetime
from math import floor

from netsentinel.application.detectors.destination_novelty import evaluate_destination_novelty
from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.behavior_baseline import BehaviorBaselineService
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.application.services.frequency_diversity import BehaviorRangeLearner, FrequencyDiversityService
from netsentinel.application.services.periodicity import PeriodicityService
from netsentinel.application.services.risk_alerts import BehaviorRiskSignal
from netsentinel.application.services.risk_evidence import BehaviorEvidence
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.domain.behavior_baseline import BaselineSnapshot, BaselineState
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.connections import (
    ConnectionLifecycleEvent, ConnectionOpened, ConnectionRoundObservation,
    ObservationOrigin, ObservationQuality,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyEvidence, DestinationNoveltyInput
from netsentinel.domain.frequency_diversity import BehaviorClassification, BehaviorWindow, FrequencyDiversityInput
from netsentinel.domain.risk_assessment import RiskAssessmentKey
from netsentinel.domain.risk_evidence import (
    EvidenceReference, EvidenceReferenceKind, EvidenceScope, EvidenceSubject, EvidenceSubjectKind,
)


@dataclass(frozen=True, slots=True)
class PreparedBehaviorSignal:
    key: RiskAssessmentKey
    scope: BehaviorScopeKey | None
    baseline: BaselineSnapshot | None
    novelty: DestinationNoveltyEvidence
    event: ConnectionOpened


class BehaviorRiskPipeline:
    """No SQL or GUI subscription. At most 128 prepared signals per round.

    The engine is the sole ordering owner. Dropped submissions are aggregate
    diagnostics, not security verdicts. No prior assessment is loaded/replayed.
    """

    def __init__(self, baselines: BehaviorBaselineService, worker: RiskAlertWorker, *,
                 polling_interval: float) -> None:
        self._baselines, self.worker = baselines, worker
        self._periodicity = PeriodicityService(polling_interval_seconds=polling_interval)
        self._frequency = FrequencyDiversityService()
        self._ranges = BehaviorRangeLearner(self._frequency.policy)
        self.dropped = 0

    def prepare(self, observation: ConnectionRoundObservation,
                events: tuple[ConnectionLifecycleEvent, ...]) -> tuple[PreparedBehaviorSignal, ...]:
        if observation.quality is ObservationQuality.FAILED:
            return ()
        prepared: list[PreparedBehaviorSignal] = []
        baselines: dict[BehaviorScopeKey, BaselineSnapshot] = {}
        for event in events:
            if (not isinstance(event, ConnectionOpened) or event.origin is not ObservationOrigin.OBSERVED
                    or event.session_id != observation.session_id):
                continue
            if len(prepared) >= 128:
                self.dropped += 1
                continue
            snapshot = event.snapshot
            remote = snapshot.remote_endpoint
            if remote is None or remote.address in ("0.0.0.0", "::") or "%" in remote.address:
                continue
            application = resolve_application_scope(snapshot.process)
            network = snapshot.network_scope
            scope = None
            if application.identity.key is not None:
                scope = BehaviorScopeKey(application.identity.key, application.identity.quality,
                    application.revision.digest, network.status,
                    network.fingerprint if network.fingerprint is not None else f"session:{observation.session_id}")
            baseline = None
            if scope is not None:
                if scope not in baselines:
                    baselines[scope] = self._baselines.snapshot(scope)
                baseline = baselines[scope]
            subject = EvidenceSubject(EvidenceSubjectKind.DESTINATION, application.identity,
                application.revision, snapshot.process.identity, observation.session_id,
                ip_address=remote.address)
            key = RiskAssessmentKey("connection_behavior", EvidenceScope.from_connection(network), subject,
                EvidenceReference(EvidenceReferenceKind.CONNECTION_LIFECYCLE, event.lifecycle_id), event.occurred_at)
            novelty = evaluate_destination_novelty(DestinationNoveltyInput(scope, remote.address,
                event.occurred_at, event.origin, observation.quality, baseline))
            prepared.append(PreparedBehaviorSignal(key, scope, baseline, novelty, event))
        return tuple(prepared)

    def finish(self, observation: ConnectionRoundObservation, events: tuple[ConnectionLifecycleEvent, ...],
               prepared: tuple[PreparedBehaviorSignal, ...], accumulator: BehaviorFeatureAccumulator, *,
               now_monotonic: float, assessed_at: datetime) -> None:
        periodic = self._periodicity.observe_round(observation, events, now_monotonic=now_monotonic)
        features = {feature.scope: feature for feature in accumulator.snapshot().scopes} if prepared else {}
        deviations: dict[BehaviorScopeKey, tuple[BehaviorEvidence, ...]] = {}
        # Conservative envelope of the actual retained 60s x 12 bucket window.
        capacity = accumulator.capacity
        start = max(0.0, (floor(now_monotonic / capacity.bucket_seconds) - capacity.bucket_count + 1)
                    * capacity.bucket_seconds)
        for item in prepared:
            output: list[BehaviorEvidence] = [item.novelty]
            scope = item.scope
            if scope is not None and scope in features and now_monotonic > start:
                if scope not in deviations:
                    baseline = item.baseline
                    if baseline is None or baseline.state is not BaselineState.READY:
                        self._ranges.reset(scope)
                        self._frequency.reset(scope)
                    window = BehaviorWindow(features[scope], observation.session_id, start,
                                            now_monotonic, observation.observed_at, observation.quality)
                    reference = self._ranges.snapshot(scope)
                    calculated = self._frequency.evaluate(FrequencyDiversityInput(window, baseline, reference),
                                                          now_monotonic=now_monotonic)
                    # Only clean normal windows seed a finite reference, then freeze.
                    if (baseline is not None and
                            all(e.classification is BehaviorClassification.NORMAL for e in calculated) and
                            (reference is None or len(reference.samples) < self._frequency.policy.minimum_reference_windows)):
                        self._ranges.learn(window, baseline)
                    deviations[scope] = calculated
                output.extend(deviations[scope])
            for evidence in periodic:
                if (evidence.scope.behavior == scope and evidence.scope.process_identity == item.key.subject.process
                        and evidence.scope.remote_endpoint == item.event.snapshot.remote_endpoint
                        and evidence.scope.protocol == item.event.snapshot.protocol):
                    output.append(evidence)
                    break
            self.worker.submit(BehaviorRiskSignal(item.key, tuple(output), assessed_at))

    def start(self) -> bool:
        return self.worker.start()

    def stop(self, timeout: float | None = None) -> bool:
        return self.worker.stop(timeout)
