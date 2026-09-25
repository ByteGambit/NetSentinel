"""NS-037 deterministic rate decisions without capture, driver, or network."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.detectors.traffic_rate import TrafficRateDetector
from netsentinel.application.services.traffic_metrics import (
    BaselineState, MeasurementConfidence, ProtocolRateSnapshot,
    TrafficBaselineSnapshot, TrafficMetricsSnapshot, TrafficProtocol,
)
from netsentinel.shared.config import TrafficRateConfig


AT = datetime(2026, 9, 25, tzinfo=UTC)


def metric(*, broadcast: int = 0, arp: int = 0, baseline: float = 0.1,
           quality: MeasurementConfidence = MeasurementConfidence.COMPLETE,
           network: str = "a" * 64, interface: str = "Wi-Fi", index: int = 1,
           learned: bool = True) -> TrafficMetricsSnapshot:
    def rate(protocol: TrafficProtocol, count: int) -> ProtocolRateSnapshot:
        return ProtocolRateSnapshot(protocol, count, count / 10,
            TrafficBaselineSnapshot(BaselineState.LEARNED if learned else BaselineState.LEARNING,
                                    baseline if learned else None, 3 if learned else 1, 3))
    return TrafficMetricsSnapshot(network, interface, index, 10, 1,
                                  rate(TrafficProtocol.ARP, arp),
                                  rate(TrafficProtocol.BROADCAST, broadcast),
                                  1 if quality is MeasurementConfidence.REDUCED else 0, quality)


def setup(**config: object) -> tuple[TrafficRateDetector, list[float]]:
    ticks = [0.0]
    detector = TrafficRateDetector(config=TrafficRateConfig(
        broadcast_floor_pps=0.5, arp_floor_pps=0.3, **config), clock=lambda: ticks[0])
    return detector, ticks


def sample(detector: TrafficRateDetector, ticks: list[float], value: TrafficMetricsSnapshot,
           second: float):
    ticks[0] = second
    return detector.assess(value, AT + timedelta(seconds=second))


def confirm(detector: TrafficRateDetector, ticks: list[float], value: TrafficMetricsSnapshot,
            start: float = 0):
    assert sample(detector, ticks, value, start) == ()
    assert sample(detector, ticks, value, start + 5) == ()
    return sample(detector, ticks, value, start + 10)


def test_learning_unknown_and_normal_are_quiet() -> None:
    detector, ticks = setup()
    for value in (metric(broadcast=100, learned=False),
                  metric(broadcast=100, quality=MeasurementConfidence.UNKNOWN),
                  metric(broadcast=1, arp=1)):
        assert sample(detector, ticks, value, ticks[0] + 1) == ()
    assert detector.tracked_states <= 2


@pytest.mark.parametrize("count,expected", [(4, False), (5, False), (6, True), (20, True)])
def test_strict_threshold_and_severity(count: int, expected: bool) -> None:
    detector, ticks = setup()
    decisions = confirm(detector, ticks, metric(broadcast=count))
    assert bool(decisions) is expected
    if decisions:
        candidate = decisions[0].candidate
        assert candidate is not None
        assert candidate.rule_id == "broadcast_rate_anomaly"
        assert candidate.severity == ("medium" if count > 10 else "low")
        assert candidate.confidence == "moderate"
        details = dict(candidate.evidence.details)
        assert details["baseline"] == "learned:0.100pps"
        assert details["window_seconds"] == "10"
        assert details["traffic_count"] == str(count)
        assert details["quality"] == "complete"
        assert not hasattr(candidate.evidence, "payload")


def test_short_transient_and_sparse_samples_do_not_confirm() -> None:
    detector, ticks = setup()
    assert sample(detector, ticks, metric(broadcast=20), 0) == ()
    assert sample(detector, ticks, metric(broadcast=20), 1) == ()
    assert sample(detector, ticks, metric(broadcast=20), 5) == ()
    assert sample(detector, ticks, metric(broadcast=0), 10) == ()
    assert confirm(detector, ticks, metric(broadcast=6), 20)


def test_arp_and_broadcast_are_separate_scoped_rules() -> None:
    detector, ticks = setup()
    decisions = confirm(detector, ticks, metric(arp=4, broadcast=6))
    assert {item.candidate.rule_id for item in decisions} == {"arp_rate_anomaly", "broadcast_rate_anomaly"}
    assert len({item.candidate.fingerprint for item in decisions}) == 2
    for changed in (metric(arp=4, broadcast=6, network="b" * 64),
                    metric(arp=4, broadcast=6, interface="Ethernet"),
                    metric(arp=4, broadcast=6, index=2)):
        assert len(confirm(detector, ticks, changed, ticks[0] + 20)) == 2


def test_zero_and_near_zero_baseline_use_absolute_floor() -> None:
    for baseline in (0.0, 0.001):
        detector, ticks = setup()
        assert confirm(detector, ticks, metric(baseline=baseline, broadcast=1)) == ()
        decisions = confirm(detector, ticks, metric(baseline=baseline, broadcast=6), 20)
        assert len(decisions) == 1
        multiplier = dict(decisions[0].candidate.evidence.details)["multiplier"]
        assert multiplier == ("undefined" if baseline == 0 else "600.00x")


def test_reduced_quality_caps_confidence_and_cannot_resolve() -> None:
    detector, ticks = setup()
    decisions = confirm(detector, ticks, metric(broadcast=6, quality=MeasurementConfidence.REDUCED))
    assert decisions[0].candidate.confidence == "low"
    assert sample(detector, ticks, metric(quality=MeasurementConfidence.REDUCED), 20) == ()
    assert sample(detector, ticks, metric(), 25) == ()
    recovered = sample(detector, ticks, metric(), 30)
    assert recovered[0].resolved_fingerprint == decisions[0].candidate.fingerprint


def test_cooldown_duplicate_out_of_order_hysteresis_and_reopen() -> None:
    detector, ticks = setup(cooldown_seconds=30)
    high = metric(broadcast=6)
    first = confirm(detector, ticks, high)[0].candidate
    assert sample(detector, ticks, high, 15) == ()
    ticks[0] = 16
    assert detector.assess(high, AT + timedelta(seconds=15)) == ()
    assert sample(detector, ticks, metric(broadcast=4), 20) == ()  # hysteresis band
    assert sample(detector, ticks, high, 40)[0].candidate.fingerprint == first.fingerprint
    assert sample(detector, ticks, metric(), 45) == ()
    assert sample(detector, ticks, metric(), 50)[0].resolved_fingerprint == first.fingerprint
    assert confirm(detector, ticks, high, 60)[0].candidate.fingerprint == first.fingerprint


def test_bounded_state_idle_expiry_and_validation() -> None:
    detector, ticks = setup(max_states=2, idle_expiry_seconds=30)
    sample(detector, ticks, metric(network="a" * 64, broadcast=6), 0)
    sample(detector, ticks, metric(network="b" * 64, broadcast=6), 1)
    sample(detector, ticks, metric(network="c" * 64, broadcast=6), 2)
    assert detector.tracked_states == 2
    sample(detector, ticks, metric(network="d" * 64, broadcast=6), 40)
    assert detector.tracked_states == 1
    with pytest.raises(ValueError, match="UTC"):
        detector.assess(metric(), datetime(2026, 9, 25))
    with pytest.raises(ValueError, match="finite"):
        TrafficRateConfig(broadcast_floor_pps=float("inf"))
    with pytest.raises(ValueError, match="rate"):
        detector.assess(replace(metric(), broadcast=replace(metric().broadcast,
                                  packets_per_second=float("nan"))), AT + timedelta(seconds=41))


def test_alert_write_failure_retries_without_waiting_for_cooldown() -> None:
    detector, ticks = setup()
    first = confirm(detector, ticks, metric(broadcast=6))[0]
    detector.retry_after_alert_failure(first)
    repeated = sample(detector, ticks, metric(broadcast=6), 11)[0]
    assert repeated.candidate.fingerprint == first.candidate.fingerprint
    assert sample(detector, ticks, metric(), 20) == ()
    recovered = sample(detector, ticks, metric(), 25)[0]
    detector.retry_after_alert_failure(recovered)
    assert sample(detector, ticks, metric(), 30) == ()
    assert sample(detector, ticks, metric(), 35)[0].resolved_fingerprint == first.candidate.fingerprint


def test_capacity_eviction_is_oldest_then_scope_key() -> None:
    detector, ticks = setup(max_states=2, minimum_samples=2)
    a, b, c = (metric(network=letter * 64, broadcast=6) for letter in "abc")
    for value in (b, a, c):
        assert sample(detector, ticks, value, 0) == ()
    # Equal tick: lexicographically smallest key (a) was evicted.
    assert sample(detector, ticks, b, 10)[0].candidate is not None
    assert sample(detector, ticks, a, 10) == ()
