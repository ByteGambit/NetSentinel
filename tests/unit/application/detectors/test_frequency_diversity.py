"""NS-073 offline workload, quality, independent-window and scope contracts."""

from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from math import isfinite
from uuid import UUID

import pytest

from netsentinel.application.detectors.frequency_diversity import evaluate_frequency_diversity
from netsentinel.application.services.frequency_diversity import BehaviorRangeLearner, FrequencyDiversityService
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.behavior_baseline import (
    BaselineOrigin, BaselineSnapshot, BaselineState, BaselineStorageState,
    BaselineSummary, MAX_BASELINE_COUNTER,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import NetworkScopeStatus, ObservationQuality, TransportProtocol
from netsentinel.domain.frequency_diversity import (
    BehaviorClassification as C, BehaviorDeviationEvidence, BehaviorRangeReference,
    BehaviorRangeSample, BehaviorReason as R, BehaviorRule, BehaviorWindow,
    FrequencyDiversityInput, FrequencyDiversityPolicy,
)

NOW = datetime(2026, 10, 3, tzinfo=UTC)
SESSION = UUID(int=1)
SCOPE = BehaviorScopeKey(r"winpath:v1:c:\apps\browser.exe", ApplicationIdentityQuality.STABLE,
                         None, NetworkScopeStatus.RESOLVED, "a" * 64)
POLICY = FrequencyDiversityPolicy()


def features(count=40, seconds=600.0, diversity=4, *, scope=SCOPE, overflow=0,
             unknown=0, reduced=0, gap=False, loss=False, ipv6=False):
    remote = count - unknown
    retained = remote - overflow
    destinations = tuple(FeatureCount(f"2001:db8::{i + 1:x}" if ipv6 else f"203.0.113.{i + 1}",
                                     retained // diversity + int(i < retained % diversity))
                         for i in range(diversity))
    return BehaviorFeatureSnapshot(scope, count, reduced, seconds, destinations,
                                   (FeatureCount(443, remote),) if remote else (),
                                   (FeatureCount(TransportProtocol.TCP, count),) if count else (),
                                   overflow, 0, 0, unknown, diversity, int(remote > 0), int(count > 0),
                                   gap, loss or bool(overflow))


def baseline(count=120, seconds=3600.0, diversity=4, *, scope=SCOPE, state=BaselineState.READY, **kwargs):
    return BaselineSnapshot(scope, state, BaselineOrigin.NEW, BaselineStorageState.AVAILABLE,
                            BaselineSummary(features(count, seconds, diversity, scope=scope, **kwargs), NOW, NOW, "test-policy"))


def window(count=40, seconds=600.0, diversity=4, *, start=2160.0, span=720.0,
           scope=SCOPE, session=SESSION, stamp=NOW, quality=ObservationQuality.COMPLETE, **kwargs):
    return BehaviorWindow(features(count, seconds, diversity, scope=scope, **kwargs),
                          session, start, start + span, stamp, quality)


def reference(count=40, seconds=600.0, diversity=4, *, scope=SCOPE, policy=POLICY,
              samples=3, span=720.0, session=SESSION):
    return BehaviorRangeReference(scope, session, policy,
        tuple(BehaviorRangeSample(i * span, (i + 1) * span, seconds, count, diversity) for i in range(samples)), "test-policy")


def evaluate(current=None, historical=None, prior=None, policy=POLICY):
    return evaluate_frequency_diversity(FrequencyDiversityInput(current or window(), historical or baseline(), prior), policy)


def test_stable_and_clear_burst_have_separate_explainable_evidence():
    stable = evaluate(prior=reference())
    assert [e.classification for e in stable] == [C.NORMAL, C.NORMAL]
    burst = evaluate(window(500, diversity=20), prior=reference())
    assert [e.classification for e in burst] == [C.ELEVATED_UNCONFIRMED] * 2
    f, d = burst
    assert f.rule_id is BehaviorRule.APPEARANCE_FREQUENCY
    assert d.rule_id is BehaviorRule.DESTINATION_DIVERSITY
    assert (f.current_appearances, f.current_monitored_seconds, f.current_per_monitored_minute) == (500, 600, 50)
    assert (f.baseline_sample_count, f.baseline_monitored_seconds, f.historical_mean_appearances_per_minute) == (120, 3600, 2)
    assert (f.reference_per_monitored_minute, d.reference_per_monitored_minute) == (4, .4)
    assert (d.current_retained_destinations, d.reference_maximum_destinations, d.reference_window_count) == (20, 4, 3)
    assert f.baseline_state is BaselineState.READY and f.baseline_origin is BaselineOrigin.NEW
    assert f.baseline_observed_at == f.observed_at == NOW
    assert not f.emission_eligible and f.confirmation_count == 0
    assert f.revision_unverified and f.policy_version == d.policy_version == 1
    assert burst == evaluate(window(500, diversity=20), prior=reference())


@pytest.mark.parametrize("state", [s for s in BaselineState if s is not BaselineState.READY])
def test_authoritative_lifecycle_never_promoted(state):
    expected = C.INSUFFICIENT_DATA if state in (BaselineState.LEARNING, BaselineState.INSUFFICIENT_DATA) else C.INSUFFICIENT_QUALITY if state is BaselineState.INSUFFICIENT_QUALITY else C.NOT_EVALUATED
    for result in evaluate(window(500, diversity=20), baseline(state=state), reference()):
        assert result.classification is expected
        assert result.baseline_state is state and not result.emission_eligible
        assert result.baseline_sample_count == 120 and result.baseline_monitored_seconds == 3600


@pytest.mark.parametrize("count,seconds,reason", [(1, 10, R.CURRENT_WINDOW_TOO_SHORT), (20, 119.999, R.CURRENT_WINDOW_TOO_SHORT), (19, 120, R.CURRENT_SAMPLE_TOO_SMALL)])
def test_minimum_current_sample_and_duration(count, seconds, reason):
    assert all(e.reason is reason and e.classification is C.INSUFFICIENT_DATA for e in evaluate(window(count, seconds, 1)))


def test_minimum_duration_and_sample_are_inclusive():
    f, _ = evaluate(window(20, 120, 1))
    assert f.classification is C.ELEVATED_UNCONFIRMED and f.current_per_monitored_minute == 10


@pytest.mark.parametrize("count,expected", [(59, C.NORMAL), (60, C.NORMAL), (61, C.ELEVATED_UNCONFIRMED)])
def test_relative_frequency_cutoff_is_strict_and_exact(count, expected):
    policy = replace(POLICY, minimum_frequency_per_minute=1)
    assert evaluate(window(count), policy=policy)[0].classification is expected


@pytest.mark.parametrize("count,expected", [(99, C.NORMAL), (100, C.ELEVATED_UNCONFIRMED)])
def test_absolute_frequency_floor_inclusive(count, expected):
    assert evaluate(window(count))[0].classification is expected


@pytest.mark.parametrize("count,seconds", [(0, 3600), (20, 3600), (20, 1e12)])
def test_zero_or_low_historical_frequency_is_insufficient(count, seconds):
    result = evaluate(window(500), baseline(count, seconds, int(count > 0)))[0]
    assert result.classification is C.INSUFFICIENT_DATA
    assert result.reason is R.REFERENCE_TOO_SMALL and result.deviation_factor is None
    assert result.reference_per_monitored_minute is None or isfinite(result.reference_per_monitored_minute)


@pytest.mark.parametrize("kwargs,reason", [({"overflow": 1}, R.CAPACITY_LIMITED), ({"loss": True}, R.CAPACITY_LIMITED),
                                          ({"reduced": 1}, R.QUALITY_INSUFFICIENT), ({"unknown": 1}, R.QUALITY_INSUFFICIENT)])
@pytest.mark.parametrize("target", ["current", "historical"])
def test_capacity_and_quality_gate_both_rules(kwargs, reason, target):
    current = window(500, diversity=20, **kwargs) if target == "current" else window(500, diversity=20)
    historical = baseline(**kwargs) if target == "historical" else baseline()
    results = evaluate(current, historical, reference())
    assert all(e.reason is reason and e.classification is C.INSUFFICIENT_QUALITY for e in results)
    if kwargs.get("overflow"):
        assert all(e.capacity_loss for e in results)


@pytest.mark.parametrize("quality", [ObservationQuality.FAILED, ObservationQuality.REDUCED])
def test_failed_and_reduced_current_rounds_cannot_confirm(quality):
    assert all(e.classification is C.INSUFFICIENT_QUALITY for e in evaluate(window(500, quality=quality)))


def test_missing_rounds_do_not_synthesize_coverage_or_rate():
    results = evaluate(window(500, 120, 20, gap=True), baseline(gap=True), reference(seconds=120))
    assert all(e.classification is C.INSUFFICIENT_QUALITY and e.current_monitored_seconds == 120 for e in results)
    assert all(e.current_per_monitored_minute is None for e in results)
    # Historical known gaps remain valid; they did not contribute offline time.
    assert evaluate(window(), baseline(gap=True))[0].classification is C.NORMAL


def test_diversity_requires_comparable_horizon_never_lifetime_unique():
    assert evaluate(window(diversity=20), baseline(diversity=1))[1].reason is R.REFERENCE_NOT_COMPARABLE
    assert evaluate(window(diversity=20), prior=reference(seconds=120))[1].classification is C.INSUFFICIENT_DATA
    assert evaluate(window(diversity=20), prior=reference(samples=2))[1].classification is C.INSUFFICIENT_DATA


@pytest.mark.parametrize("destinations,expected", [(11, C.NORMAL), (12, C.NORMAL), (13, C.ELEVATED_UNCONFIRMED)])
def test_diversity_strict_relative_boundary(destinations, expected):
    assert evaluate(window(diversity=destinations), prior=reference())[1].classification is expected


def test_diversity_absolute_floor_and_coverage_normalization():
    assert evaluate(window(diversity=9), prior=reference(diversity=1))[1].classification is C.NORMAL
    # More retained IPs with proportionally more coverage yields the same rate.
    assert evaluate(window(48, 720, 12), prior=reference(40, 600, 10))[1].classification is C.NORMAL


@pytest.mark.parametrize("counts,diversities,current_count,current_diversity", [
    ([240, 400, 320], [24, 40, 32], 400, 40),  # browser/CDN rotation
    ([40, 200, 40], [4, 20, 4], 200, 20),     # normal updater burst
])
def test_learned_browser_and_updater_ranges_accept_normal_churn(counts, diversities, current_count, current_diversity):
    prior = BehaviorRangeReference(SCOPE, SESSION, POLICY,
        tuple(BehaviorRangeSample(i * 720, (i + 1) * 720, 600, c, d) for i, (c, d) in enumerate(zip(counts, diversities))), "test-policy")
    historical = baseline(sum(counts), 1800, max(diversities))
    assert all(e.classification is C.NORMAL for e in evaluate(window(current_count, diversity=current_diversity), historical, prior))
    assert evaluate(window(current_count * 4, diversity=current_diversity), historical, prior)[0].classification is C.ELEVATED_UNCONFIRMED


@pytest.mark.parametrize("scope", [replace(SCOPE, application_key=r"winpath:v1:c:\other\browser.exe"),
                                  replace(SCOPE, revision_digest="b" * 64), replace(SCOPE, network_token="b" * 64)])
def test_application_revision_network_baseline_isolation(scope):
    assert all(e.reason is R.SCOPE_MISMATCH for e in evaluate(window(scope=scope)))
    assert all(e.reason is R.SCOPE_MISMATCH for e in evaluate(prior=reference(scope=scope)))


@pytest.mark.parametrize("scope", [replace(SCOPE, identity_quality=ApplicationIdentityQuality.PROVISIONAL),
                                  replace(SCOPE, identity_quality=ApplicationIdentityQuality.UNKNOWN),
                                  replace(SCOPE, network_status=NetworkScopeStatus.UNKNOWN),
                                  replace(SCOPE, network_status=NetworkScopeStatus.AMBIGUOUS)])
def test_provisional_or_unresolved_scope_never_borrows_persistent_baseline(scope):
    assert all(e.reason is R.SCOPE_UNAVAILABLE for e in evaluate(window(scope=scope)))


@pytest.mark.parametrize("change", [{"summary_version": 2}, {"feature_policy_version": 2}])
def test_bad_baseline_versions_are_not_reinterpreted(change):
    historical = baseline()
    assert all(e.reason is R.BASELINE_INVALID for e in evaluate(historical=replace(historical, summary=replace(historical.summary, **change))))


@pytest.mark.parametrize("change", [{"observed_appearances": -1}, {"monitored_seconds": float("nan")},
                                   {"monitored_seconds": float("inf")}, {"destination_diversity": 63}])
def test_invalid_current_snapshot_returns_typed_result(change):
    current = window()
    results = evaluate(replace(current, features=replace(current.features, **change)))
    assert all(e.reason is R.CURRENT_INVALID for e in results)
    assert all(not isinstance(getattr(e, f.name), float) or isfinite(getattr(e, f.name)) for e in results for f in fields(e))


def test_no_remote_or_ipv6_handling():
    assert evaluate(window(40, diversity=0, unknown=40))[1].classification is C.INSUFFICIENT_QUALITY
    assert evaluate(window(ipv6=True), prior=reference())[1].classification is C.NORMAL


def test_finite_extreme_counts_and_no_verdict_features():
    current = window(MAX_BASELINE_COUNTER - 1, 120, 1)
    results = evaluate(current)
    for evidence in results:
        for field in fields(evidence):
            value = getattr(evidence, field.name)
            if isinstance(value, float):
                assert isfinite(value)
    names = {f.name for f in fields(BehaviorDeviationEvidence)}
    assert not names & {"risk_score", "malicious", "safe", "packet_rate", "bytes", "probability", "severity"}
    assert all(e.classification is C.INSUFFICIENT_QUALITY for e in evaluate(window(MAX_BASELINE_COUNTER, 120, 1)))


@pytest.mark.parametrize("field,value", [("version", 2), ("maximum_scopes", 129), ("minimum_reference_windows", 9),
                                       ("minimum_current_seconds", 0), ("cooldown_seconds", float("nan")),
                                       ("frequency_multiplier", True), ("minimum_current_seconds", 1e-300),
                                       ("minimum_reference_frequency_per_minute", 1e-300)])
def test_policy_bounds(field, value):
    with pytest.raises(ValueError):
        replace(POLICY, **{field: value})


def test_reference_future_overlap_session_policy_and_age_gates():
    assert evaluate(prior=reference(samples=4))[1].reason is R.REFERENCE_NOT_COMPARABLE
    assert evaluate(prior=reference(session=UUID(int=2)))[0].reason is R.REFERENCE_NOT_COMPARABLE
    assert evaluate(prior=reference(policy=replace(POLICY, confirmation_windows=3)))[0].reason is R.POLICY_MISMATCH
    assert evaluate(window(start=100_000), prior=reference())[1].classification is C.INSUFFICIENT_DATA
    with pytest.raises(ValueError):
        replace(reference(), samples=(reference().samples[0], reference().samples[0]))


def test_reference_collector_independence_bounds_reset_and_restart():
    policy = replace(POLICY, maximum_scopes=2)
    learner = BehaviorRangeLearner(policy)
    for i in range(12):
        assert learner.learn(window(start=i * 720), baseline())
    prior = learner.snapshot(SCOPE)
    assert len(prior.samples) == 8 and prior.samples[0].started_monotonic == 2880
    assert not learner.learn(window(start=11 * 720), baseline())
    assert not learner.learn(window(start=12 * 720, gap=True), baseline())
    for i in range(2):
        key = replace(SCOPE, network_token=str(i) * 64)
        assert learner.learn(window(scope=key), baseline(scope=key))
    assert learner.scope_count == 2 and learner.snapshot(SCOPE) is None
    assert BehaviorRangeLearner(policy).snapshot(SCOPE) is None
    key = replace(SCOPE, network_token="1" * 64)
    learner.reset(key)
    assert learner.snapshot(key) is None


def service_input(start, *, count=80, scope=SCOPE, gap=False, stamp=NOW, prior=None):
    current = window(count, 120, 20, start=start, span=120, scope=scope, gap=gap, stamp=stamp)
    return FrequencyDiversityInput(current, baseline(scope=scope), prior)


def test_confirmation_requires_independent_windows_and_cooldown_is_monotonic():
    service = FrequencyDiversityService()
    first = service.evaluate(service_input(2160), now_monotonic=2280)[0]
    assert first.confirmation_count == 1 and first.classification is C.ELEVATED_UNCONFIRMED
    for start in (2160, 2161, 2200):
        repeated = service.evaluate(service_input(start), now_monotonic=2400)[0]
        assert repeated.confirmation_count == 1 and not repeated.emission_eligible
    confirmed = service.evaluate(service_input(2280), now_monotonic=2400)[0]
    assert confirmed.classification is C.ELEVATED_CONFIRMED and confirmed.emission_eligible
    # UTC movement does not advance the cooldown; explicit monotonic time does.
    suppressed = service.evaluate(service_input(2400, stamp=NOW + timedelta(days=1)), now_monotonic=2520)[0]
    assert suppressed.classification is C.ELEVATED_CONFIRMED and suppressed.reason is R.COOLDOWN_ACTIVE
    assert not suppressed.emission_eligible
    resumed = service.evaluate(service_input(2880), now_monotonic=3000)[0]
    assert resumed.emission_eligible and resumed.confirmation_count == 2
    repeated = service.evaluate(service_input(2880), now_monotonic=4000)[0]
    assert not repeated.emission_eligible


def test_normal_quality_failure_or_long_gap_breaks_pending_confirmation():
    normal = replace(service_input(2280), window=window(40, 600, 4, start=2280))
    for middle in (normal, service_input(2280, gap=True)):
        service = FrequencyDiversityService()
        service.evaluate(service_input(2160), now_monotonic=2280)
        service.evaluate(middle, now_monotonic=3000)
        last = service.evaluate(service_input(3000), now_monotonic=3120)[0]
        assert last.confirmation_count == 1 and not last.emission_eligible
    service = FrequencyDiversityService()
    service.evaluate(service_input(2160), now_monotonic=2280)
    assert service.evaluate(service_input(5000), now_monotonic=5120)[0].confirmation_count == 1


@pytest.mark.parametrize("other", [replace(SCOPE, revision_digest="b" * 64),
                                  replace(SCOPE, network_token="b" * 64),
                                  replace(SCOPE, application_key=r"winpath:v1:c:\other\browser.exe")])
def test_both_rules_confirm_independently_and_scope_cooldowns_are_separate(other):
    prior = reference(count=20, seconds=120, diversity=4, span=120)
    service = FrequencyDiversityService()
    for start in (360, 480):
        results = service.evaluate(service_input(start, prior=prior), now_monotonic=start + 120)
    assert all(e.classification is C.ELEVATED_CONFIRMED and e.emission_eligible for e in results)
    assert service.evaluate(service_input(600, scope=other), now_monotonic=720)[0].confirmation_count == 1
    assert service.evaluate(service_input(720, scope=other), now_monotonic=840)[0].emission_eligible
    assert service.evaluate(service_input(840), now_monotonic=960)[0].reason is R.COOLDOWN_ACTIVE


def test_confirmation_state_eviction_is_bounded_and_conservative():
    service = FrequencyDiversityService(replace(POLICY, maximum_scopes=2))
    keys = [replace(SCOPE, revision_digest=str(i) * 64) for i in range(3)]
    for key in keys:
        assert service.evaluate(service_input(2160, scope=key), now_monotonic=2280)[0].confirmation_count == 1
    assert service.scope_count == 2
    assert service.evaluate(service_input(2280, scope=keys[0]), now_monotonic=2400)[0].confirmation_count == 1
    service.reset(keys[0])
    assert service.scope_count == 1


def test_runtime_clock_regression_never_emits_or_counts_confirmation():
    service = FrequencyDiversityService()
    service.evaluate(service_input(2160), now_monotonic=3000)
    results = service.evaluate(service_input(2280), now_monotonic=2900)
    assert all(e.reason is R.CLOCK_ANOMALY and not e.emission_eligible for e in results)
    assert service.evaluate(service_input(2280), now_monotonic=3000)[0].confirmation_count == 2


def test_baseline_utc_anomaly_and_unavailable_origin_storage():
    assert all(e.reason is R.CLOCK_ANOMALY for e in evaluate(window(stamp=NOW - timedelta(seconds=1))))
    for historical in (replace(baseline(), origin=BaselineOrigin.PREVIOUS_UNAVAILABLE),
                       replace(baseline(), origin=BaselineOrigin.SESSION_ONLY),
                       replace(baseline(), storage=BaselineStorageState.UNAVAILABLE)):
        assert all(e.classification is C.INSUFFICIENT_QUALITY for e in evaluate(historical=historical))


def test_no_baseline_and_no_reference_are_explicitly_insufficient():
    results = evaluate_frequency_diversity(FrequencyDiversityInput(window(), None))
    assert all(e.reason is R.BASELINE_UNAVAILABLE for e in results)
    assert evaluate()[1].classification is C.INSUFFICIENT_DATA


@pytest.mark.parametrize("historical", [baseline(count=19), baseline(seconds=599.999)])
def test_ready_label_does_not_bypass_baseline_minimums(historical):
    assert all(e.reason is R.REFERENCE_TOO_SMALL for e in evaluate(historical=historical))


def test_reference_coverage_tolerance_boundary_and_zero_diversity():
    # 720 s vs current 600 s is exactly at the 20% coverage band.
    assert evaluate(prior=reference(seconds=720))[1].reference_window_count == 3
    assert evaluate(window(seconds=599), prior=reference(seconds=720))[1].reason is R.REFERENCE_NOT_COMPARABLE
    assert evaluate(prior=reference(diversity=0))[1].reason is R.REFERENCE_TOO_SMALL


def test_baseline_gate_clears_confirmation_without_erasing_cooldown():
    service = FrequencyDiversityService()
    service.evaluate(service_input(2160), now_monotonic=2280)
    assert service.evaluate(service_input(2280), now_monotonic=2400)[0].emission_eligible
    gated = service_input(2400)
    gated = replace(gated, baseline=replace(gated.baseline, state=BaselineState.INSUFFICIENT_DATA))
    assert service.evaluate(gated, now_monotonic=2520)[0].classification is C.INSUFFICIENT_DATA
    assert service.evaluate(service_input(2520), now_monotonic=2640)[0].confirmation_count == 1
    result = service.evaluate(service_input(2640), now_monotonic=2760)[0]
    assert result.classification is C.ELEVATED_CONFIRMED and result.reason is R.COOLDOWN_ACTIVE


def test_session_or_baseline_policy_change_discards_old_pending_state():
    for session_change in (True, False):
        service = FrequencyDiversityService()
        service.evaluate(service_input(2160), now_monotonic=2280)
        changed = service_input(2280)
        if session_change:
            changed = replace(changed, window=replace(changed.window, session_id=UUID(int=2)))
        else:
            changed = replace(changed, baseline=replace(changed.baseline,
                              summary=replace(changed.baseline.summary, policy_key="new-policy")))
        assert service.evaluate(changed, now_monotonic=2400)[0].confirmation_count == 1


@pytest.mark.parametrize("field,value", [("started_monotonic", float("nan")),
                                       ("ended_monotonic", float("inf")), ("ended_monotonic", 4000),
                                       ("observed_at", NOW.replace(tzinfo=None))])
def test_window_rejects_invalid_clock_metadata(field, value):
    with pytest.raises(ValueError):
        replace(window(), **{field: value})


def test_detector_and_memory_services_do_not_read_io_or_hidden_clock(monkeypatch):
    import builtins
    import socket
    import sqlite3
    import time

    observation = FrequencyDiversityInput(window(500, diversity=20), baseline(), reference())
    learner = BehaviorRangeLearner()
    service = FrequencyDiversityService()

    def forbidden(*args, **kwargs):
        raise AssertionError("NS-073 cannot perform I/O or read a hidden clock")

    with monkeypatch.context() as hooks:
        hooks.setattr(builtins, "open", forbidden)
        hooks.setattr(sqlite3, "connect", forbidden)
        hooks.setattr(socket, "socket", forbidden)
        hooks.setattr(socket, "getaddrinfo", forbidden)
        hooks.setattr(time, "monotonic", forbidden)
        calculated = evaluate_frequency_diversity(observation)
        learned = learner.learn(observation.window, observation.baseline)
        evaluated = service.evaluate(observation, now_monotonic=2880)
    assert all(e.classification is C.ELEVATED_UNCONFIRMED for e in calculated)
    assert learned and evaluated[0].confirmation_count == 1
