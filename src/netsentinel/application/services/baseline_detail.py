"""NS-075 bounded local read model; never manufactures detector observations."""

from __future__ import annotations

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
    return BaselineDetailRequest(resolve_application_scope(process), (process.name or "Unknown application")[:256],
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
    BaselineState.LEARNING: "No learned baseline yet; observing behavior.",
    BaselineState.READY: "Sufficient observed baseline data; this is not a safety verdict.",
    BaselineState.INSUFFICIENT_DATA: "More eligible appearances or monitored coverage are needed.",
    BaselineState.INSUFFICIENT_QUALITY: "Reduced visibility, unknown destinations or capacity loss limit the learned data.",
    BaselineState.STALE: "The last observation is too old for baseline evaluation.",
    BaselineState.EXPIRED: "The learned baseline has expired and is not ready for evaluation.",
    BaselineState.CLOCK_ANOMALY: "System clock changes prevent reliable freshness evaluation.",
    BaselineState.CORRUPT: "Stored baseline data cannot be read reliably.",
    BaselineState.UNSUPPORTED_VERSION: "Stored baseline data uses an unsupported format.",
    BaselineState.POLICY_MISMATCH: "Stored baseline data is incompatible with the current learning policy.",
    BaselineState.UNAVAILABLE: "Baseline data is unavailable; absence does not mean normal behavior.",
}


def scope_context(request: BaselineDetailRequest) -> str:
    identity, revision = request.application.identity, request.application.revision
    return "\n".join((
        f"Application: {request.display_name[:256]}",
        f"Application identity ({identity.quality.value}): {(identity.key or 'Unavailable')[:4096]}",
        f"Artifact revision: {'SHA-256 ' + revision.digest if revision.digest else 'Unknown artifact revision'}",
        f"Network scope: {request.network.status.value}; {request.network.fingerprint or 'no resolved fingerprint'}",
        "Application name and PID are display context, not persistent baseline identity.",
        "The artifact hash is revision context, not reputation evidence. The network fingerprint describes observed local context, not a proven physical network or route.",
    ))


def feature_text(features: BehaviorFeatureSnapshot) -> str:
    destinations = sorted(features.destinations, key=lambda item: str(item.value))[:PREVIEW_LIMIT]
    ports = sorted(features.ports, key=lambda item: int(item.value))[:PREVIEW_LIMIT]
    protocols = sorted(features.protocols, key=lambda item: str(item.value))[:2]
    lines = [
        f"Observed connection appearances: {features.observed_appearances}",
        f"Monitored coverage: {features.monitored_seconds:g} seconds (observed active coverage)",
        f"Retained destinations: {features.destination_diversity}; preview (up to {PREVIEW_LIMIT}): "
        + (", ".join(f"{str(item.value)[:45]} ({item.observed_appearances})" for item in destinations) or "none"),
        f"Retained ports: {features.port_diversity}; preview: " + (", ".join(str(item.value) for item in ports) or "none"),
        f"Retained protocols: {features.protocol_diversity}; " + (", ".join(item.value.value.upper() if isinstance(item.value, TransportProtocol) else str(item.value) for item in protocols) or "none"),
        f"Reduced appearances: {features.reduced_appearances}; unknown destinations: {features.unknown_destinations}",
        f"Observation gap recorded: {'yes' if features.gap_seen else 'no'}",
    ]
    if features.capacity_loss or features.other_destinations or features.other_ports or features.other_protocols:
        lines.extend(("Capacity loss / overflow: some behavior entries were not retained because the bounded baseline reached capacity.",
                      f"Unretained appearances: destinations {features.other_destinations}, ports {features.other_ports}, protocols {features.other_protocols}.",
                      "Retained diversity is not an exact total of unique destinations."))
    return "\n".join(lines)


def evidence_text(evidence: BaselineDetailEvidence, request: BaselineDetailRequest) -> str:
    scope = request.scope
    lines = ["Current evidence (memory only; rebuilt after restart)"]
    novelty = evidence.novelty
    if novelty is not None and novelty.scope == scope and novelty.destination_ip == request.remote_ip:
        lines.extend((f"Destination familiarity: {novelty.classification.name}; {novelty.reason.value.replace('_', ' ')}",
                      f"Retained destination appearances: {novelty.destination_appearances}; baseline appearances: {novelty.baseline_sample_count}; monitored coverage: {novelty.monitored_seconds} seconds.",
                      "First seen means not previously observed in the retained scoped baseline; known means observed familiarity.",
                      "Limitations: " + ", ".join(item.value.replace('_', ' ') for item in novelty.limitations)))
        if novelty.capacity_loss:
            lines.append("Capacity loss limits familiarity; missing retained data cannot prove first seen.")
    else:
        lines.append("Destination familiarity: no evidence available yet.")
    for rule, title in (("observed_appearance_frequency", "Observed appearance rate"),
                        ("destination_window_diversity", "Retained destination diversity")):
        value = next((e for e in evidence.deviations[:2] if e.scope == scope and e.rule_id.value == rule), None)
        if value is None:
            lines.append(f"{title}: no evidence available yet.")
            continue
        classification = "Within observed reference range" if value.classification is BehaviorClassification.NORMAL else value.classification.name
        lines.append(f"{title}: {classification}; {value.reason.value.replace('_', ' ')}")
        if rule == "observed_appearance_frequency":
            lines.append(f"Current/reference appearances per monitored minute: {value.current_per_monitored_minute} / {value.reference_per_monitored_minute}.")
        else:
            lines.append(f"Current/reference retained destinations: {value.current_retained_destinations} / {value.reference_maximum_destinations}.")
        lines.append(f"Confirmation windows: {value.confirmation_count}; gap: {value.gap_seen}; capacity loss: {value.capacity_loss}.")
    periodicity = evidence.periodicity
    if (periodicity is not None and periodicity.scope.behavior == scope
            and periodicity.scope.remote_endpoint.address == request.remote_ip
            and periodicity.scope.remote_endpoint.port == request.remote_port
            and periodicity.scope.protocol == request.protocol
            and periodicity.scope.process_identity == request.application.process_identity):
        lines.extend((f"Periodic appearance evidence: {periodicity.classification.name}; {periodicity.reason.value.replace('_', ' ')}",
                      f"Retained intervals: {periodicity.retained_interval_count}; base interval: {periodicity.base_interval_seconds}; polling resolution: {periodicity.polling_interval_seconds} seconds.",
                      "Limitations: " + ", ".join(item.value.replace('_', ' ') for item in periodicity.limitations)))
    else:
        lines.append("Periodic appearance evidence: no current timing evidence; insufficient observations.")
    lines.extend(("Timing is derived from polling observations and does not prove an exact application timer.",
                  "Scheduled updaters and synchronization can also produce periodic appearances."))
    return "\n".join(lines)


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
                                  "UNAVAILABLE: no persistent baseline for this unresolved network or provisional/unknown application scope.\n"
                                  "No other application, revision or network baseline is used.", False)
        baseline = self.baselines.snapshot(scope)
        summary = baseline.summary
        appearances = summary.features.observed_appearances if summary is not None else 0
        monitored = summary.features.monitored_seconds if summary is not None else 0
        lines = [f"{baseline.state.name}: {STATE_EXPLANATIONS[baseline.state]}",
                 f"Warm-up appearances: {appearances} / {self.baselines.config.minimum_samples} eligible appearances; "
                 f"monitored coverage: {monitored:g} / {self.baselines.config.minimum_monitored_seconds:g} seconds.",
                 f"Baseline origin: {baseline.origin.value}; storage: {baseline.storage.value}",
                 "Learned reference (cumulative observed data; may include an uncommitted memory tail)"]
        if summary is not None:
            lines.extend((feature_text(summary.features), f"Last observed: {summary.last_observed_at.isoformat()}",
                          f"Summary persistence timestamp: {summary.persisted_at.isoformat()} (not proof that the current memory tail is saved)"))
        else:
            lines.extend(("Observed connection appearances: 0", "Monitored coverage: 0 seconds; no learned reference available yet."))
        current = next((item for item in self.features.snapshot().scopes if item.scope == scope), None)
        lines.append("Current observation window (memory only; separate from the learned reference)")
        lines.append(feature_text(current) if current is not None else "No current window observations available yet.")
        evidence = self._evidence(request) if self._evidence is not None else BaselineDetailEvidence()
        lines.append(evidence_text(evidence, request))
        lines.append("Observed learning is separate from user trust/preferences. Reset does not change trust or block the application.")
        return BaselineDetail(request, scope, context, "\n".join(lines), True)

    def reset(self, scope: BehaviorScopeKey) -> BaselineResetSubmission:
        if not scope.identity_restart_stable:
            raise ValueError("detail reset requires an exact persistent scope")
        return self.baselines.reset_with_result(scope)
