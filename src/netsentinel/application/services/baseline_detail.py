"""NS-075 bounded local read model; never manufactures detector observations."""

from __future__ import annotations

from netsentinel.shared.enum_sources import enum_source
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP, join_text


from collections.abc import Callable
from dataclasses import dataclass

from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.behavior_baseline import BehaviorBaselineService, BaselineResetSubmission
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.domain.application_identity import ApplicationScope
from netsentinel.domain.behavior_baseline import BaselineState
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey
from netsentinel.domain.connections import ConnectionNetworkScope, ProcessInfo, TransportProtocol
from netsentinel.domain.destination_novelty import DestinationNoveltyEvidence
from netsentinel.domain.frequency_diversity import BehaviorDeviationEvidence, BehaviorClassification
from netsentinel.domain.periodicity import PeriodicityEvidence

PREVIEW_LIMIT = 8


@dataclass(frozen=True, slots=True)
class BaselineDetailRequest:
    application: ApplicationScope
    display_name: str
    network: ConnectionNetworkScope
    remote_ip: str | None
    remote_port: int | None = None
    protocol: TransportProtocol | None = None

    @property
    def scope(self) -> BehaviorScopeKey | None:
        identity = self.application.identity
        if identity.key is None or self.network.fingerprint is None:
            return None
        return BehaviorScopeKey(identity.key, identity.quality, self.application.revision.digest,
                                self.network.status, self.network.fingerprint)


def baseline_detail_request(process: ProcessInfo, network: ConnectionNetworkScope,
                            remote_ip: str | None, remote_port: int | None = None,
                            protocol: TransportProtocol | None = None) -> BaselineDetailRequest:
    return BaselineDetailRequest(resolve_application_scope(process), (process.name or QT_TRANSLATE_NOOP('BaselineDetail', 'Unknown application'))[:256],
                                 network, remote_ip, remote_port, protocol)


@dataclass(frozen=True, slots=True)
class BaselineDetailEvidence:
    novelty: DestinationNoveltyEvidence | None = None
    deviations: tuple[BehaviorDeviationEvidence, ...] = ()
    periodicity: PeriodicityEvidence | None = None


@dataclass(frozen=True, slots=True)
class BaselineDetail:
    request: BaselineDetailRequest
    scope: BehaviorScopeKey | None
    context: str
    text: str
    reset_available: bool


STATE_EXPLANATIONS = {
    BaselineState.LEARNING: QT_TRANSLATE_NOOP('BaselineDetail', 'No learned baseline yet; observing behavior.'),
    BaselineState.READY: QT_TRANSLATE_NOOP('BaselineDetail', 'Sufficient observed baseline data; this is not a safety verdict.'),
    BaselineState.INSUFFICIENT_DATA: QT_TRANSLATE_NOOP('BaselineDetail', 'More eligible appearances or monitored coverage are needed.'),
    BaselineState.INSUFFICIENT_QUALITY: QT_TRANSLATE_NOOP('BaselineDetail', 'Reduced visibility, unknown destinations or capacity loss limit the learned data.'),
    BaselineState.STALE: QT_TRANSLATE_NOOP('BaselineDetail', 'The last observation is too old for baseline evaluation.'),
    BaselineState.EXPIRED: QT_TRANSLATE_NOOP('BaselineDetail', 'The learned baseline has expired and is not ready for evaluation.'),
    BaselineState.CLOCK_ANOMALY: QT_TRANSLATE_NOOP('BaselineDetail', 'System clock changes prevent reliable freshness evaluation.'),
    BaselineState.CORRUPT: QT_TRANSLATE_NOOP('BaselineDetail', 'Stored baseline data cannot be read reliably.'),
    BaselineState.UNSUPPORTED_VERSION: QT_TRANSLATE_NOOP('BaselineDetail', 'Stored baseline data uses an unsupported format.'),
    BaselineState.POLICY_MISMATCH: QT_TRANSLATE_NOOP('BaselineDetail', 'Stored baseline data is incompatible with the current learning policy.'),
    BaselineState.UNAVAILABLE: QT_TRANSLATE_NOOP('BaselineDetail', 'Baseline data is unavailable; absence does not mean normal behavior.'),
}


def scope_context(request: BaselineDetailRequest) -> str:
    identity, revision = request.application.identity, request.application.revision
    return join_text('\n', (QT_TRANSLATE_NOOP('BaselineDetail', 'Application: {value1}').format(value1=request.display_name[:256]), QT_TRANSLATE_NOOP('BaselineDetail', 'Application identity ({value1}): {value2}').format(value1=enum_source(identity.quality), value2=(identity.key or QT_TRANSLATE_NOOP('BaselineDetail', 'Unavailable'))[:4096]), QT_TRANSLATE_NOOP('BaselineDetail', 'Artifact revision: {value1}').format(value1='SHA-256 ' + revision.digest if revision.digest else QT_TRANSLATE_NOOP('BaselineDetail', 'Unknown artifact revision')), QT_TRANSLATE_NOOP('BaselineDetail', 'Network scope: {value1}; {value2}').format(value1=enum_source(request.network.status), value2=request.network.fingerprint or QT_TRANSLATE_NOOP('BaselineDetail', 'no resolved fingerprint')), QT_TRANSLATE_NOOP('BaselineDetail', 'Application name and PID are display context, not persistent baseline identity.'), QT_TRANSLATE_NOOP('BaselineDetail', 'The artifact hash is revision context, not reputation evidence. The network fingerprint describes observed local context, not a proven physical network or route.')))


def feature_text(features: BehaviorFeatureSnapshot) -> str:
    destinations = sorted(features.destinations, key=lambda item: str(item.value))[:PREVIEW_LIMIT]
    ports = sorted(features.ports, key=lambda item: int(item.value))[:PREVIEW_LIMIT]
    protocols = sorted(features.protocols, key=lambda item: str(item.value))[:2]
    lines = [
        QT_TRANSLATE_NOOP('BaselineDetail', 'Observed connection appearances: {value1}').format(value1=features.observed_appearances),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Monitored coverage: {value1:g} seconds (observed active coverage)').format(value1=features.monitored_seconds),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Retained destinations: {value1}; preview (up to {value2}): ').format(value1=features.destination_diversity, value2=PREVIEW_LIMIT)
        + (join_text(', ', (f'{str(item.value)[:45]} ({item.observed_appearances})' for item in destinations)) or QT_TRANSLATE_NOOP('BaselineDetail', 'none')),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Retained ports: {value1}; preview: ').format(value1=features.port_diversity) + (join_text(', ', (str(item.value) for item in ports)) or QT_TRANSLATE_NOOP('BaselineDetail', 'none')),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Retained protocols: {value1}; ').format(value1=features.protocol_diversity) + (join_text(', ', (item.value.value.upper() if isinstance(item.value, TransportProtocol) else str(item.value) for item in protocols)) or QT_TRANSLATE_NOOP('BaselineDetail', 'none')),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Reduced appearances: {value1}; unknown destinations: {value2}').format(value1=features.reduced_appearances, value2=features.unknown_destinations),
        QT_TRANSLATE_NOOP('BaselineDetail', 'Observation gap recorded: {value1}').format(value1=QT_TRANSLATE_NOOP('BaselineDetail', 'yes') if features.gap_seen else QT_TRANSLATE_NOOP('BaselineDetail', 'no')),
    ]
    if features.capacity_loss or features.other_destinations or features.other_ports or features.other_protocols:
        lines.extend((QT_TRANSLATE_NOOP('BaselineDetail', 'Capacity loss / overflow: some behavior entries were not retained because the bounded baseline reached capacity.'),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Unretained appearances: destinations {value1}, ports {value2}, protocols {value3}.').format(value1=features.other_destinations, value2=features.other_ports, value3=features.other_protocols),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Retained diversity is not an exact total of unique destinations.')))
    return join_text('\n', lines)


def evidence_text(evidence: BaselineDetailEvidence, request: BaselineDetailRequest) -> str:
    scope = request.scope
    lines = [QT_TRANSLATE_NOOP('BaselineDetail', 'Current evidence (memory only; rebuilt after restart)')]
    novelty = evidence.novelty
    if novelty is not None and novelty.scope == scope and novelty.destination_ip == request.remote_ip:
        lines.extend((QT_TRANSLATE_NOOP('BaselineDetail', 'Destination familiarity: {value1}; {value2}').format(value1=enum_source(novelty.classification, 'upper'), value2=enum_source(novelty.reason, 'words')),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Retained destination appearances: {value1}; baseline appearances: {value2}; monitored coverage: {value3} seconds.').format(value1=novelty.destination_appearances, value2=novelty.baseline_sample_count, value3=novelty.monitored_seconds),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'First seen means not previously observed in the retained scoped baseline; known means observed familiarity.'),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Limitations: ') + join_text(', ', (enum_source(item, 'words') for item in novelty.limitations))))
        if novelty.capacity_loss:
            lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Capacity loss limits familiarity; missing retained data cannot prove first seen.'))
    else:
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Destination familiarity: no evidence available yet.'))
    for rule, title in (("observed_appearance_frequency", QT_TRANSLATE_NOOP('BaselineDetail', 'Observed appearance rate')),
                        ("destination_window_diversity", QT_TRANSLATE_NOOP('BaselineDetail', 'Retained destination diversity'))):
        value = next((e for e in evidence.deviations[:2] if e.scope == scope and e.rule_id.value == rule), None)
        if value is None:
            lines.append(QT_TRANSLATE_NOOP('BaselineDetail', '{value1}: no evidence available yet.').format(value1=title))
            continue
        classification = QT_TRANSLATE_NOOP('BaselineDetail', 'Within observed reference range') if value.classification is BehaviorClassification.NORMAL else enum_source(value.classification, 'upper')
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', '{title}: {classification}; {reason}').format(title=title, classification=classification, reason=enum_source(value.reason, 'words')))
        if rule == "observed_appearance_frequency":
            lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Current/reference appearances per monitored minute: {value1} / {value2}.').format(value1=value.current_per_monitored_minute, value2=value.reference_per_monitored_minute))
        else:
            lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Current/reference retained destinations: {value1} / {value2}.').format(value1=value.current_retained_destinations, value2=value.reference_maximum_destinations))
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Confirmation windows: {value1}; gap: {value2}; capacity loss: {value3}.').format(value1=value.confirmation_count, value2=value.gap_seen, value3=value.capacity_loss))
    periodicity = evidence.periodicity
    if (periodicity is not None and periodicity.scope.behavior == scope
            and periodicity.scope.remote_endpoint.address == request.remote_ip
            and periodicity.scope.remote_endpoint.port == request.remote_port
            and periodicity.scope.protocol == request.protocol
            and periodicity.scope.process_identity == request.application.process_identity):
        lines.extend((QT_TRANSLATE_NOOP('BaselineDetail', 'Periodic appearance evidence: {value1}; {value2}').format(value1=enum_source(periodicity.classification, 'upper'), value2=enum_source(periodicity.reason, 'words')),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Retained intervals: {value1}; base interval: {value2}; polling resolution: {value3} seconds.').format(value1=periodicity.retained_interval_count, value2=periodicity.base_interval_seconds, value3=periodicity.polling_interval_seconds),
                      QT_TRANSLATE_NOOP('BaselineDetail', 'Limitations: ') + join_text(', ', (enum_source(item, 'words') for item in periodicity.limitations))))
    else:
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Periodic appearance evidence: no current timing evidence; insufficient observations.'))
    lines.extend((QT_TRANSLATE_NOOP('BaselineDetail', 'Timing is derived from polling observations and does not prove an exact application timer.'),
                  QT_TRANSLATE_NOOP('BaselineDetail', 'Scheduled updaters and synchronization can also produce periodic appearances.')))
    return join_text('\n', lines)


class BaselineDetailService:
    def __init__(self, baselines: BehaviorBaselineService, features: BehaviorFeatureAccumulator,
                 evidence: Callable[[BaselineDetailRequest], BaselineDetailEvidence] | None = None) -> None:
        self.baselines = baselines
        self.features = features
        self._evidence = evidence

    def lookup(self, request: BaselineDetailRequest) -> BaselineDetail:
        scope = request.scope
        context = scope_context(request)
        if scope is None or not scope.identity_restart_stable:
            return BaselineDetail(request, scope, context,
                                  QT_TRANSLATE_NOOP('BaselineDetail', 'UNAVAILABLE: no persistent baseline for this unresolved network or provisional/unknown application scope.\nNo other application, revision or network baseline is used.'), False)
        baseline = self.baselines.snapshot(scope)
        summary = baseline.summary
        appearances = summary.features.observed_appearances if summary is not None else 0
        monitored = summary.features.monitored_seconds if summary is not None else 0
        lines = [QT_TRANSLATE_NOOP('BaselineDetail', '{state}: {explanation}').format(state=enum_source(baseline.state, 'upper'), explanation=STATE_EXPLANATIONS[baseline.state]),
                 QT_TRANSLATE_NOOP('BaselineDetail', 'Warm-up appearances: {value1} / {value2} eligible appearances; monitored coverage: {value3:g} / {value4:g} seconds.').format(value1=appearances, value2=self.baselines.config.minimum_samples, value3=monitored, value4=self.baselines.config.minimum_monitored_seconds),
                 QT_TRANSLATE_NOOP('BaselineDetail', 'Baseline origin: {value1}; storage: {value2}').format(value1=enum_source(baseline.origin), value2=enum_source(baseline.storage)),
                 QT_TRANSLATE_NOOP('BaselineDetail', 'Learned reference (cumulative observed data; may include an uncommitted memory tail)')]
        if summary is not None:
            lines.extend((feature_text(summary.features), QT_TRANSLATE_NOOP('BaselineDetail', 'Last observed: {value1}').format(value1=summary.last_observed_at.isoformat()),
                          QT_TRANSLATE_NOOP('BaselineDetail', 'Summary persistence timestamp: {value1} (not proof that the current memory tail is saved)').format(value1=summary.persisted_at.isoformat())))
        else:
            lines.extend((QT_TRANSLATE_NOOP('BaselineDetail', 'Observed connection appearances: 0'), QT_TRANSLATE_NOOP('BaselineDetail', 'Monitored coverage: 0 seconds; no learned reference available yet.')))
        current = next((item for item in self.features.snapshot().scopes if item.scope == scope), None)
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Current observation window (memory only; separate from the learned reference)'))
        lines.append(feature_text(current) if current is not None else QT_TRANSLATE_NOOP('BaselineDetail', 'No current window observations available yet.'))
        evidence = self._evidence(request) if self._evidence is not None else BaselineDetailEvidence()
        lines.append(evidence_text(evidence, request))
        lines.append(QT_TRANSLATE_NOOP('BaselineDetail', 'Observed learning is separate from user trust/preferences. Reset does not change trust or block the application.'))
        return BaselineDetail(request, scope, context, join_text('\n', lines), True)

    def reset(self, scope: BehaviorScopeKey) -> BaselineResetSubmission:
        if not scope.identity_restart_stable:
            raise ValueError("detail reset requires an exact persistent scope")
        return self.baselines.reset_with_result(scope)
