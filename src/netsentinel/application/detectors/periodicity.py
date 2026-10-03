"""Pure deterministic NS-074 evidence over a bounded clean runtime sequence."""

from __future__ import annotations

from dataclasses import replace
from statistics import median

from netsentinel.domain.periodicity import (
    RULE_ID, PeriodicityClassification as Classification, PeriodicityEvidence,
    PeriodicityLimitation as Limitation, PeriodicityPolicy,
    PeriodicityReason as Reason, PeriodicitySequence,
)


def evaluate_periodicity(
    sequence: PeriodicitySequence,
    policy: PeriodicityPolicy = PeriodicityPolicy(),
) -> PeriodicityEvidence:
    """Median raw intervals; maximum residual against bounded nearest multiples.

    A strict majority must match 1x: no search for hidden subharmonics, no claim
    that a multiple proves missed events. Polling cannot establish exact timers.
    Caller owns clean coverage/reset and lifecycle eligibility, not this function.
    """
    if not isinstance(sequence, PeriodicitySequence) or not isinstance(policy, PeriodicityPolicy):
        raise TypeError("typed sequence and policy required")
    if len(sequence.intervals) > policy.maximum_intervals:
        raise ValueError("sequence exceeds policy interval bound")
    intervals = sequence.intervals
    limitations = [Limitation.POLLING_QUANTIZED, Limitation.BENIGN_SCHEDULE_COMPATIBLE,
                   Limitation.BEHAVIORAL_ONLY_LOW_SECURITY_SIGNIFICANCE]
    if not sequence.scope.behavior.revision_verified:
        limitations.append(Limitation.REVISION_UNVERIFIED)
    if sequence.sequence_truncated:
        limitations.append(Limitation.SEQUENCE_TRUNCATED)
    if sequence.prior_history_unavailable:
        limitations.append(Limitation.PRIOR_HISTORY_UNAVAILABLE)
    result = PeriodicityEvidence(
        RULE_ID, policy, Classification.INSUFFICIENT_DATA, Reason.MINIMUM_INTERVALS,
        sequence.scope, sequence.session_id, len(intervals), None, None, None, None,
        min(intervals) if intervals else None, max(intervals) if intervals else None,
        0, sequence.polling_interval_seconds, tuple(limitations), sequence.last_reset,
        sequence.observed_at,
    )
    if len(intervals) < policy.minimum_intervals:
        return result
    base = float(median(intervals))
    tolerance = max(policy.absolute_jitter_seconds, policy.relative_jitter * base)
    result = replace(result, base_interval_seconds=base, tolerance_seconds=tolerance)
    if not policy.minimum_period_seconds <= base <= policy.maximum_period_seconds:
        return replace(result, classification=Classification.IRREGULAR, reason=Reason.PERIOD_OUT_OF_RANGE)
    # Ties choose the smaller multiple; residual is in units of the base period.
    multiples = tuple(min(range(1, policy.maximum_multiple + 1),
                          key=lambda m: (abs(value / m - base), m)) for value in intervals)
    deviation = max(abs(value / multiple - base) for value, multiple in zip(intervals, multiples))
    compatible = sum(m > 1 and abs(value / m - base) <= tolerance
                     for value, m in zip(intervals, multiples))
    if compatible:
        limitations.append(Limitation.MISSED_MULTIPLE_COMPATIBLE)
    result = replace(result, base_interval_seconds=base, maximum_deviation_seconds=deviation,
                     normalized_jitter=deviation / base, tolerance_seconds=tolerance,
                     compatible_multiple_count=compatible, limitations=tuple(limitations))
    if deviation > tolerance or sum(m == 1 for m in multiples) <= len(intervals) // 2:
        return replace(result, classification=Classification.IRREGULAR, reason=Reason.JITTER_EXCEEDED)
    if base <= policy.resolution_factor * sequence.polling_interval_seconds:
        return replace(result, classification=Classification.RESOLUTION_LIMITED, reason=Reason.OBSERVATION_RESOLUTION)
    return replace(result, classification=Classification.PERIODIC_CANDIDATE,
                   reason=Reason.MULTIPLES_COMPATIBLE if compatible else Reason.INTERVALS_REGULAR)
