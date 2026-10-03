"""Pure NS-072 evaluation against a pre-appearance NS-071 snapshot.

FIRST_SEEN means absent from this retained application/revision/network IP
baseline. It says nothing about first-ever OS connections or logical services:
CDN/address rotation can introduce an IP for an already used service. KNOWN
only means established observation history; neither classification is a verdict.
"""

from __future__ import annotations

from dataclasses import replace
from ipaddress import ip_address

from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineState, FEATURE_POLICY_VERSION, SUMMARY_VERSION,
    MAX_BASELINE_COUNTER, validate_baseline_scope, validate_baseline_summary,
)
from netsentinel.domain.connections import NetworkScopeStatus, ObservationOrigin, ObservationQuality
from netsentinel.domain.destination_novelty import (
    DestinationNoveltyClassification as Classification,
    DestinationNoveltyEvidence,
    DestinationNoveltyInput,
    DestinationNoveltyLimitation as Limitation,
    DestinationNoveltyPolicy,
    DestinationNoveltyReason as Reason,
)

RULE_ID = "destination_ip_novelty_rarity"

_LIFECYCLE_GATES = {
    BaselineState.LEARNING: (Classification.INSUFFICIENT_DATA, Reason.BASELINE_LEARNING),
    BaselineState.INSUFFICIENT_DATA: (Classification.INSUFFICIENT_DATA, Reason.BASELINE_INSUFFICIENT_DATA),
    BaselineState.INSUFFICIENT_QUALITY: (Classification.INSUFFICIENT_QUALITY, Reason.BASELINE_INSUFFICIENT_QUALITY),
    BaselineState.STALE: (Classification.NOT_EVALUATED, Reason.BASELINE_STALE),
    BaselineState.EXPIRED: (Classification.NOT_EVALUATED, Reason.BASELINE_EXPIRED),
    BaselineState.CLOCK_ANOMALY: (Classification.NOT_EVALUATED, Reason.BASELINE_CLOCK_ANOMALY),
    BaselineState.CORRUPT: (Classification.NOT_EVALUATED, Reason.BASELINE_CORRUPT),
    BaselineState.UNSUPPORTED_VERSION: (Classification.NOT_EVALUATED, Reason.BASELINE_UNSUPPORTED_VERSION),
    BaselineState.POLICY_MISMATCH: (Classification.NOT_EVALUATED, Reason.BASELINE_POLICY_MISMATCH),
    BaselineState.UNAVAILABLE: (Classification.NOT_EVALUATED, Reason.BASELINE_UNAVAILABLE),
}


def evaluate_destination_novelty(
    observation: DestinationNoveltyInput,
    policy: DestinationNoveltyPolicy = DestinationNoveltyPolicy(),
) -> DestinationNoveltyEvidence:
    """No I/O, state, learning, alerting or dedup; equal inputs give equal evidence.

    READY is authoritative from a fresh NS-071 snapshot. Defensive version,
    scope, summary and quality checks cannot promote a non-READY lifecycle.
    """
    if not isinstance(observation, DestinationNoveltyInput) or not isinstance(policy, DestinationNoveltyPolicy):
        raise TypeError("typed observation and policy required")
    baseline = observation.baseline
    summary = None if baseline is None else baseline.summary
    limitations = [Limitation.IP_ONLY_SERVICE_NOT_INFERRED]
    if observation.scope is not None and not observation.scope.revision_verified:
        limitations.append(Limitation.REVISION_UNVERIFIED)
    if observation.quality is ObservationQuality.REDUCED:
        limitations.append(Limitation.REDUCED_CURRENT_OBSERVATION)
    destination = None
    if observation.remote_ip is not None and len(observation.remote_ip) <= 45:
        try:
            address = ip_address(observation.remote_ip)
            if not address.is_unspecified and "%" not in observation.remote_ip:
                destination = str(address)
        except ValueError:
            pass
    result = DestinationNoveltyEvidence(
        RULE_ID, policy, Classification.NOT_EVALUATED, Reason.BASELINE_UNAVAILABLE,
        observation.scope, None if baseline is None else baseline.scope, destination,
        None, None, None, None if baseline is None else baseline.state,
        None if baseline is None else baseline.origin, None if baseline is None else baseline.storage,
        None, False, None, None, None, False,
        observation.observed_at, observation.origin, observation.quality, tuple(limitations),
    )
    # Only validated, exact-scope summaries can supply explanation counts.
    valid_summary = False
    if summary is not None and baseline is not None and summary.features.scope == baseline.scope == observation.scope:
        try:
            validate_baseline_summary(summary)
            valid_summary = True
        except (ValueError, TypeError):
            pass
        if valid_summary:
            f = summary.features
            result = replace(
                result, destination_appearances=None if destination is None else next(
                    (item.observed_appearances for item in f.destinations if item.value == destination), 0),
                baseline_sample_count=f.observed_appearances, monitored_seconds=f.monitored_seconds,
                baseline_policy_key=summary.policy_key, capacity_loss=f.capacity_loss,
                other_destinations=f.other_destinations, reduced_appearances=f.reduced_appearances,
                unknown_destinations=f.unknown_destinations, gap_seen=f.gap_seen,
            )

    def finish(reason: Reason, classification: Classification = Classification.NOT_EVALUATED) -> DestinationNoveltyEvidence:
        return replace(result, reason=reason, classification=classification)

    if observation.quality is ObservationQuality.FAILED:
        return finish(Reason.FAILED_ROUND)
    if observation.origin is ObservationOrigin.INITIAL:
        return finish(Reason.INITIAL_OBSERVATION)
    if destination is None:
        return finish(Reason.REMOTE_UNAVAILABLE)
    scope = observation.scope
    if scope is None or scope.identity_quality is not ApplicationIdentityQuality.STABLE:
        return finish(Reason.APPLICATION_SCOPE_UNAVAILABLE)
    if scope.network_status is not NetworkScopeStatus.RESOLVED:
        return finish(Reason.NETWORK_SCOPE_UNAVAILABLE)
    try:
        validate_baseline_scope(scope)
    except (ValueError, TypeError):
        return finish(Reason.BASELINE_CORRUPT)
    if baseline is None:
        return finish(Reason.BASELINE_UNAVAILABLE)
    if baseline.scope.application_key != scope.application_key or baseline.scope.identity_quality != scope.identity_quality:
        return finish(Reason.APPLICATION_SCOPE_MISMATCH)
    if baseline.scope.revision_digest != scope.revision_digest:
        return finish(Reason.REVISION_MISMATCH)
    if baseline.scope.network_status != scope.network_status or baseline.scope.network_token != scope.network_token:
        return finish(Reason.NETWORK_SCOPE_MISMATCH)
    if baseline.state is not BaselineState.READY:
        classification, reason = _LIFECYCLE_GATES[baseline.state]
        return finish(reason, classification)
    if summary is None:
        return finish(Reason.BASELINE_CORRUPT)
    if summary.summary_version != SUMMARY_VERSION:
        return finish(Reason.BASELINE_UNSUPPORTED_VERSION)
    if summary.feature_policy_version != FEATURE_POLICY_VERSION:
        return finish(Reason.BASELINE_POLICY_MISMATCH)
    if not valid_summary:
        return finish(Reason.BASELINE_CORRUPT)
    if observation.observed_at < summary.last_observed_at or observation.observed_at < summary.persisted_at:
        return finish(Reason.BASELINE_CLOCK_ANOMALY)
    f = summary.features
    if baseline.origin in (BaselineOrigin.PREVIOUS_UNAVAILABLE, BaselineOrigin.SESSION_ONLY):
        return finish(Reason.HISTORY_INCOMPLETE, Classification.INSUFFICIENT_QUALITY)
    if f.other_destinations:
        return finish(Reason.DESTINATION_OVERFLOW, Classification.INSUFFICIENT_QUALITY)
    if f.capacity_loss:
        return finish(Reason.CAPACITY_LOSS, Classification.INSUFFICIENT_QUALITY)
    if f.reduced_appearances or f.unknown_destinations:
        return finish(Reason.BASELINE_INSUFFICIENT_QUALITY, Classification.INSUFFICIENT_QUALITY)
    if f.observed_appearances == MAX_BASELINE_COUNTER:
        return finish(Reason.COUNTER_SATURATED, Classification.INSUFFICIENT_QUALITY)
    if f.observed_appearances < policy.minimum_samples:
        return finish(Reason.MINIMUM_SAMPLES, Classification.INSUFFICIENT_DATA)
    if f.monitored_seconds < policy.minimum_monitored_seconds:
        return finish(Reason.MINIMUM_MONITORED_DURATION, Classification.INSUFFICIENT_DATA)
    count = result.destination_appearances
    assert count is not None
    if count == 0:
        return finish(Reason.DESTINATION_NOT_PREVIOUSLY_OBSERVED, Classification.FIRST_SEEN)
    if count <= policy.rare_maximum_appearances:
        if f.observed_appearances < policy.rarity_minimum_samples:
            return finish(Reason.RARITY_MINIMUM_SAMPLES, Classification.INSUFFICIENT_DATA)
        # Integer cross multiplication preserves the inclusive percentage boundary.
        if count * 100 <= f.observed_appearances * policy.rare_maximum_percent:
            return finish(Reason.DESTINATION_RARELY_OBSERVED, Classification.RARE)
    return finish(Reason.DESTINATION_ESTABLISHED, Classification.KNOWN)
