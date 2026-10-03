"""Pure NS-073 rules over explicit current and prior reference snapshots."""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from math import isfinite

from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineState, BaselineStorageState, BaselineSummary,
    MAX_BASELINE_COUNTER, validate_baseline_summary,
)
from netsentinel.domain.frequency_diversity import (
    BehaviorClassification as Classification, BehaviorDeviationEvidence,
    BehaviorRangeSample, BehaviorReason as Reason, BehaviorRule as Rule,
    FrequencyDiversityInput, FrequencyDiversityPolicy,
)
from netsentinel.domain.connections import ObservationQuality


def evaluate_frequency_diversity(
    observation: FrequencyDiversityInput,
    policy: FrequencyDiversityPolicy = FrequencyDiversityPolicy(),
) -> tuple[BehaviorDeviationEvidence, BehaviorDeviationEvidence]:
    """No mutation, clock or I/O; confirmation belongs to the runtime service.

    Frequency uses NS-071's monitored-time mean and, when supplied, the maximum
    of comparable independent prior windows. Diversity NEVER uses lifetime
    unique IP count: only the latter windows form a diversity reference.
    """
    window, baseline = observation.window, observation.baseline
    current = window.features
    summary = None if baseline is None else baseline.summary
    result = BehaviorDeviationEvidence(
        rule_id=Rule.APPEARANCE_FREQUENCY, policy=policy,
        classification=Classification.NOT_EVALUATED, reason=Reason.BASELINE_UNAVAILABLE,
        scope=current.scope, baseline_scope=None if baseline is None else baseline.scope,
        baseline_state=None if baseline is None else baseline.state,
        baseline_origin=None if baseline is None else baseline.origin,
        baseline_storage=None if baseline is None else baseline.storage,
        baseline_policy_key=None, baseline_sample_count=None,
        baseline_monitored_seconds=None, baseline_observed_at=None,
        current_appearances=_counter(current.observed_appearances),
        current_monitored_seconds=_seconds(current.monitored_seconds),
        current_retained_destinations=_counter(current.destination_diversity),
        current_other_destinations=_counter(current.other_destinations),
        reduced_appearances=_counter(current.reduced_appearances),
        unknown_destinations=_counter(current.unknown_destinations),
        gap_seen=current.gap_seen, capacity_loss=current.capacity_loss,
        quality=window.quality, current_per_monitored_minute=None,
        reference_per_monitored_minute=None, historical_mean_appearances_per_minute=None,
        reference_window_count=0, reference_monitored_seconds=0,
        reference_maximum_destinations=None, reference_ended_monotonic=None,
        deviation_factor=None, confirmation_count=0, emission_eligible=False,
        observed_at=window.observed_at, revision_unverified=not current.scope.revision_verified,
    )

    def finish(reason: Reason, classification: Classification = Classification.NOT_EVALUATED) -> tuple[BehaviorDeviationEvidence, BehaviorDeviationEvidence]:
        evidence = replace(result, reason=reason, classification=classification)
        return evidence, replace(evidence, rule_id=Rule.DESTINATION_DIVERSITY)

    if not current.scope.identity_restart_stable:
        return finish(Reason.SCOPE_UNAVAILABLE)
    if baseline is None:
        return finish(Reason.BASELINE_UNAVAILABLE)
    if baseline.scope != current.scope or (summary is not None and summary.features.scope != current.scope):
        return finish(Reason.SCOPE_MISMATCH)
    valid_summary = False
    if summary is not None:
        try:
            validate_baseline_summary(summary)
            valid_summary = True
        except (ValueError, TypeError, AttributeError, OverflowError):
            pass
        if valid_summary:
            historical = summary.features
            result = replace(
                result, baseline_policy_key=summary.policy_key,
                baseline_sample_count=historical.observed_appearances,
                baseline_monitored_seconds=historical.monitored_seconds,
                baseline_observed_at=summary.last_observed_at,
                capacity_loss=current.capacity_loss or historical.capacity_loss,
            )
    # Preserve the authoritative lifecycle; a future pipeline supplies fresh state.
    if baseline.state is not BaselineState.READY:
        classification = Classification.NOT_EVALUATED
        if baseline.state in (BaselineState.LEARNING, BaselineState.INSUFFICIENT_DATA):
            classification = Classification.INSUFFICIENT_DATA
        elif baseline.state is BaselineState.INSUFFICIENT_QUALITY:
            classification = Classification.INSUFFICIENT_QUALITY
        return finish(Reason.BASELINE_NOT_READY, classification)
    if summary is None or not valid_summary:
        return finish(Reason.BASELINE_INVALID)
    historical = summary.features
    if window.observed_at < max(summary.last_observed_at, summary.persisted_at):
        return finish(Reason.CLOCK_ANOMALY)
    if baseline.origin in (BaselineOrigin.SESSION_ONLY, BaselineOrigin.PREVIOUS_UNAVAILABLE) or baseline.storage is not BaselineStorageState.AVAILABLE:
        return finish(Reason.QUALITY_INSUFFICIENT, Classification.INSUFFICIENT_QUALITY)
    if historical.capacity_loss or historical.other_destinations:
        return finish(Reason.CAPACITY_LIMITED, Classification.INSUFFICIENT_QUALITY)
    if historical.reduced_appearances or historical.unknown_destinations or historical.observed_appearances == MAX_BASELINE_COUNTER:
        return finish(Reason.QUALITY_INSUFFICIENT, Classification.INSUFFICIENT_QUALITY)
    if historical.observed_appearances < policy.minimum_baseline_samples or historical.monitored_seconds < policy.minimum_baseline_seconds:
        return finish(Reason.REFERENCE_TOO_SMALL, Classification.INSUFFICIENT_DATA)
    try:
        # Reuse the NS-071 bounded/canonical counter and feature consistency contract.
        validate_baseline_summary(BaselineSummary(current, window.observed_at, window.observed_at, summary.policy_key))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return finish(Reason.CURRENT_INVALID)
    if current.monitored_seconds > window.ended_monotonic - window.started_monotonic:
        return finish(Reason.CURRENT_INVALID)
    if current.capacity_loss or current.other_destinations:
        return finish(Reason.CAPACITY_LIMITED, Classification.INSUFFICIENT_QUALITY)
    if window.quality is not ObservationQuality.COMPLETE or current.reduced_appearances or current.unknown_destinations or current.gap_seen or current.observed_appearances == MAX_BASELINE_COUNTER:
        return finish(Reason.QUALITY_INSUFFICIENT, Classification.INSUFFICIENT_QUALITY)
    if current.monitored_seconds < policy.minimum_current_seconds:
        return finish(Reason.CURRENT_WINDOW_TOO_SHORT, Classification.INSUFFICIENT_DATA)
    if current.observed_appearances < policy.minimum_current_appearances:
        return finish(Reason.CURRENT_SAMPLE_TOO_SMALL, Classification.INSUFFICIENT_DATA)

    reference = observation.reference
    samples: tuple[BehaviorRangeSample, ...] = ()
    if reference is not None:
        if reference.scope != current.scope:
            return finish(Reason.SCOPE_MISMATCH)
        if reference.policy != policy or reference.baseline_policy_key != summary.policy_key:
            return finish(Reason.POLICY_MISMATCH)
        if reference.session_id != window.session_id or any(s.ended_monotonic > window.started_monotonic for s in reference.samples):
            return finish(Reason.REFERENCE_NOT_COMPARABLE)
        samples = tuple(s for s in reference.samples if
            window.ended_monotonic - s.ended_monotonic <= policy.maximum_reference_age_seconds
            and s.monitored_seconds >= policy.minimum_current_seconds
            and s.observed_appearances >= policy.minimum_current_appearances
            and abs(s.monitored_seconds - current.monitored_seconds) * 100 <= policy.coverage_tolerance_percent * current.monitored_seconds)
    enough_windows = len(samples) >= policy.minimum_reference_windows
    if enough_windows:
        result = replace(result, reference_window_count=len(samples),
                         reference_monitored_seconds=sum(s.monitored_seconds for s in samples),
                         reference_maximum_destinations=max(s.retained_destinations for s in samples),
                         reference_ended_monotonic=max(s.ended_monotonic for s in samples))
    mean = Fraction(historical.observed_appearances * 60) / Fraction(historical.monitored_seconds)
    frequency_reference = max([mean] + ([Fraction(s.observed_appearances * 60) / Fraction(s.monitored_seconds) for s in samples] if enough_windows else []))
    result = replace(result, historical_mean_appearances_per_minute=float(mean))
    frequency = _compare(result, current.observed_appearances, current.monitored_seconds,
                         frequency_reference, policy.frequency_multiplier,
                         policy.minimum_frequency_per_minute, Reason.APPEARANCE_RATE_ELEVATED)
    if frequency_reference < Fraction(policy.minimum_reference_frequency_per_minute):
        frequency = replace(frequency, classification=Classification.INSUFFICIENT_DATA,
                            reason=Reason.REFERENCE_TOO_SMALL, deviation_factor=None)
    diversity = replace(result, rule_id=Rule.DESTINATION_DIVERSITY)
    if not enough_windows:
        diversity = replace(diversity, classification=Classification.INSUFFICIENT_DATA,
                            reason=Reason.REFERENCE_NOT_COMPARABLE)
    else:
        diversity_reference = max(Fraction(s.retained_destinations * 60) / Fraction(s.monitored_seconds) for s in samples)
        if diversity_reference == 0:
            diversity = replace(diversity, classification=Classification.INSUFFICIENT_DATA,
                                reason=Reason.REFERENCE_TOO_SMALL)
        else:
            diversity = _compare(diversity, current.destination_diversity, current.monitored_seconds,
                                 diversity_reference, policy.diversity_multiplier, 0,
                                 Reason.DESTINATION_DIVERSITY_ELEVATED)
            if current.destination_diversity < policy.minimum_current_destinations:
                diversity = replace(diversity, classification=Classification.NORMAL,
                                    reason=Reason.WITHIN_EXPECTED_RANGE)
    return frequency, diversity


def _compare(result: BehaviorDeviationEvidence, count: int, seconds: float,
             reference: Fraction, multiplier: int, floor: float,
             reason: Reason) -> BehaviorDeviationEvidence:
    rate = Fraction(count * 60) / Fraction(seconds)
    elevated = rate > multiplier * reference and rate >= Fraction(floor)
    return replace(result, current_per_monitored_minute=float(rate),
                   reference_per_monitored_minute=float(reference),
                   deviation_factor=None if reference == 0 else float(rate / reference),
                   classification=Classification.ELEVATED_UNCONFIRMED if elevated else Classification.NORMAL,
                   reason=reason if elevated else Reason.WITHIN_EXPECTED_RANGE)


def _counter(value: int) -> int | None:
    return value if type(value) is int and 0 <= value <= MAX_BASELINE_COUNTER else None


def _seconds(value: float) -> float | None:
    return value if not isinstance(value, bool) and isinstance(value, (int, float)) and isfinite(value) and 0 <= value <= 1e12 else None
