"""NS-045 decisions use only portable, synthetic VLAN metadata."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.detectors.vlan_anomaly import (
    DEVICE_SWITCH_RULE, DIVERSITY_RULE, NEW_VID_RULE, VlanAnomalyDetector,
)
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.domain.devices import DeviceIdentity
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.vlan import VlanTagKind
from netsentinel.domain.vlan_summary import VlanBaselineState
from tests.unit.application.test_vlan_baseline import AT, Clock, MemoryRepository, context, packet


def ready():
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock, warmup=timedelta(0))
    ctx = context()
    service.observe(ctx, packet(ctx, 10, at=AT))
    summary = service.observe(ctx, packet(ctx, 10, at=AT + timedelta(seconds=1)))
    assert summary.baseline_state is VlanBaselineState.LEARNED
    service.verify_baseline(ctx)
    ticks = [0.0]
    detector = VlanAnomalyDetector(clock=lambda: ticks[0])
    return service, ctx, detector, ticks


def observe(service, ctx, detector, ticks, vid, second, *, kind=None, source=None):
    ticks[0] = float(second)
    sample = packet(ctx, vid, kind=kind, at=AT + timedelta(seconds=second))
    if source is not None:
        sample = replace(sample, ethernet_source_mac=MacAddress(source))
    summary = service.observe(ctx, sample)
    return detector.observe(summary, sample)


def test_learning_known_vid_and_special_categories_are_quiet():
    ctx = context()
    service = VlanSummaryService(MemoryRepository(), clock=Clock(), warmup=timedelta(0))
    detector = VlanAnomalyDetector(clock=lambda: 0)
    for second, vid, kind in ((0, 30, None), (1, 0, None), (2, 4095, None),
                              (3, 30, VlanTagKind.STACKED), (4, None, None)):
        sample = packet(ctx, vid, kind=kind, at=AT + timedelta(seconds=second))
        assert detector.observe(service.observe(ctx, sample), sample) == ()
    assert detector.tracked_states == 0
    service, ctx, detector, ticks = ready()
    assert observe(service, ctx, detector, ticks, 10, 2) == ()
    assert observe(service, ctx, detector, ticks, 0, 3) == ()
    assert observe(service, ctx, detector, ticks, 4095, 4) == ()
    assert observe(service, ctx, detector, ticks, 20, 5, kind=VlanTagKind.STACKED) == ()
    assert observe(service, ctx, detector, ticks, None, 6) == ()
    assert detector.tracked_states == 0


def test_new_vid_confirmation_fingerprint_and_evidence():
    service, ctx, detector, ticks = ready()
    assert observe(service, ctx, detector, ticks, 30, 2) == ()
    result = observe(service, ctx, detector, ticks, 30, 3)
    assert len(result) == 1
    candidate = result[0]
    assert candidate.rule_id == NEW_VID_RULE
    assert (candidate.severity, candidate.confidence) == ("low", "low")
    assert candidate.evidence.observation_count == 2
    details = dict(candidate.evidence.details)
    assert details["vid"] == "30" and details["baseline"] == "verified_observed"
    assert details["learned_vids"] == "10" and "nic_offload" in details["visibility"]
    assert candidate.network_fingerprint == ctx.fingerprint
    assert not hasattr(candidate.evidence, "payload")
    assert observe(service, ctx, detector, ticks, 30, 4) == ()
    assert observe(service, ctx, detector, ticks, 40, 5) == ()
    other = observe(service, ctx, detector, ticks, 40, 6)[0]
    assert other.fingerprint != candidate.fingerprint
    assert service.get(ctx).learned_vlan_ids == (10,)


def test_duplicate_old_stale_and_expired_confirmation():
    service, ctx, detector, ticks = ready()
    assert observe(service, ctx, detector, ticks, 30, 2) == ()
    assert observe(service, ctx, detector, ticks, 30, 2) == ()
    assert observe(service, ctx, detector, ticks, 30, 1) == ()
    assert observe(service, ctx, detector, ticks, 30, 130) == ()
    assert observe(service, ctx, detector, ticks, 30, 131)[0].rule_id == NEW_VID_RULE
    ticks[0] = 800
    assert detector.observe(service.get(ctx), packet(ctx, 0, at=AT + timedelta(seconds=800))) == ()
    assert detector.tracked_states == 0


def test_diversity_needs_three_confirmed_new_vids_within_window():
    service, ctx, detector, ticks = ready()
    for vid, second in ((30, 2), (40, 4), (50, 6)):
        assert observe(service, ctx, detector, ticks, vid, second) == ()
    for vid, second in ((30, 3), (40, 5)):
        assert observe(service, ctx, detector, ticks, vid, second)[0].rule_id == NEW_VID_RULE
    result = observe(service, ctx, detector, ticks, 50, 7)
    assert {candidate.rule_id for candidate in result} == {NEW_VID_RULE, DIVERSITY_RULE}
    diversity = next(candidate for candidate in result if candidate.rule_id == DIVERSITY_RULE)
    assert (diversity.severity, diversity.confidence) == ("medium", "low")
    assert diversity.evidence.observation_count == 3
    assert dict(diversity.evidence.details)["vid"] == "30,40,50"
    assert observe(service, ctx, detector, ticks, 50, 8) == ()


def test_device_switch_uses_portable_source_mac_and_observed_device_id():
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock)
    ctx = context()
    for vid, second in ((10, 0), (20, 1), (10, 2), (20, 3)):
        service.observe(ctx, packet(ctx, vid, at=AT + timedelta(seconds=second)))
    clock.at += timedelta(seconds=60)
    service.observe(ctx, packet(ctx, None, at=AT + timedelta(seconds=60)))
    assert service.get(ctx).learned_vlan_ids == (10, 20)
    service.verify_baseline(ctx)
    ticks = [0.0]
    detector = VlanAnomalyDetector(clock=lambda: ticks[0])
    source = "02:11:22:33:44:55"
    device = DeviceIdentity(ctx.fingerprint, MacAddress(source), AT, AT).device_id
    assert observe(service, ctx, detector, ticks, 10, 61, source=source) == ()
    assert observe(service, ctx, detector, ticks, 20, 62, source=source) == ()
    result = observe(service, ctx, detector, ticks, 20, 63, source=source)
    assert len(result) == 1 and result[0].rule_id == DEVICE_SWITCH_RULE
    assert dict(result[0].evidence.details)["device_id"] == str(device)
    assert observe(service, ctx, detector, ticks, 20, 64, source=source) == ()
    assert observe(service, ctx, detector, ticks, 20, 65) == ()


def test_scope_overflow_validation_bounds_and_eviction():
    service, ctx, detector, ticks = ready()
    sample = packet(ctx, 30, at=AT + timedelta(seconds=2))
    summary = service.observe(ctx, sample)
    other = context("Other", 2)
    with pytest.raises(ValueError, match="scopes"):
        detector.observe(summary, packet(other, 30, at=sample.observed_at))
    assert detector.observe(replace(summary, overflow_count=1), sample) == ()
    assert detector.tracked_states == 0
    small = VlanAnomalyDetector(clock=lambda: ticks[0], max_states=2)
    for vid, second in ((30, 2), (40, 3), (50, 4)):
        value = packet(ctx, vid, at=AT + timedelta(seconds=second))
        small.observe(service.observe(ctx, value), value)
    assert small.tracked_states == 2
    # Oldest pending VID was evicted; its next sighting starts anew.
    value = packet(ctx, 30, at=AT + timedelta(seconds=5))
    assert small.observe(service.observe(ctx, value), value) == ()
    assert small.tracked_states == 2
    with pytest.raises(ValueError, match="finite"):
        VlanAnomalyDetector(clock=lambda: float("nan")).observe(summary, sample)
    with pytest.raises(ValueError, match="512"):
        VlanAnomalyDetector(max_states=513)
    with pytest.raises(ValueError, match="UTC"):
        packet(ctx, 30, at=datetime(2026, 9, 26))


def test_network_and_interface_states_are_independent():
    service, ctx, detector, ticks = ready()
    others = (context("Other", 2), context("WiFi", 3),
              context("WiFi", 1, "198.51.100.0/24"))
    for other in others:
        service.observe(other, packet(other, 30, at=AT))
        service.observe(other, packet(other, 30, at=AT + timedelta(seconds=1)))
    assert observe(service, ctx, detector, ticks, 30, 2) == ()
    for other in others:
        ticks[0] += 1
        sample = packet(other, 30, at=AT + timedelta(seconds=3))
        assert detector.observe(service.observe(other, sample), sample) == ()
    assert observe(service, ctx, detector, ticks, 30, 4)[0].rule_id == NEW_VID_RULE


def test_diversity_window_expires_without_accumulating_old_vids():
    service, ctx, detector, ticks = ready()
    for vid, second in ((30, 2), (30, 3), (40, 4), (40, 5), (50, 70), (50, 71)):
        results = observe(service, ctx, detector, ticks, vid, second)
        assert all(item.rule_id != DIVERSITY_RULE for item in results)


def test_confirmation_window_exact_boundary_starts_new_candidate():
    service, ctx, detector, ticks = ready()
    assert observe(service, ctx, detector, ticks, 30, 2) == ()
    assert observe(service, ctx, detector, ticks, 30, 122) == ()
    assert observe(service, ctx, detector, ticks, 30, 123)[0].rule_id == NEW_VID_RULE


def test_learned_but_unverified_baseline_never_emits_candidate():
    service, ctx, detector, ticks = ready()
    current = service.get(ctx)
    service._repository.rows[(ctx.fingerprint, ctx.interface_id.casefold(),
                              ctx.interface_index)] = replace(
        current, baseline_state=VlanBaselineState.LEARNED, verified_at=None)
    for second in (2, 3, 4):
        assert observe(service, ctx, detector, ticks, 30, second,
                       source="02:11:22:33:44:55") == ()
    assert detector.tracked_states == 0


def test_device_separation_same_vid_and_duplicate_old_observations():
    service, ctx, detector, ticks = ready()
    a, b = "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee"
    assert observe(service, ctx, detector, ticks, 10, 2, source=a) == ()
    assert observe(service, ctx, detector, ticks, 10, 3, source=a) == ()
    assert not any(item.rule_id == DEVICE_SWITCH_RULE for item in
                   observe(service, ctx, detector, ticks, 20, 4, source=b))
    assert not any(item.rule_id == DEVICE_SWITCH_RULE for item in
                   observe(service, ctx, detector, ticks, 20, 5, source=a))
    assert not any(item.rule_id == DEVICE_SWITCH_RULE for item in
                   observe(service, ctx, detector, ticks, 20, 5, source=a))
    assert not any(item.rule_id == DEVICE_SWITCH_RULE for item in
                   observe(service, ctx, detector, ticks, 20, 1, source=a))
    result = observe(service, ctx, detector, ticks, 20, 6, source=a)
    assert [item.rule_id for item in result].count(DEVICE_SWITCH_RULE) == 1
    assert observe(service, ctx, detector, ticks, 20, 7, source=a) == ()


def test_same_source_mac_is_scoped_to_network_and_interface():
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock, warmup=timedelta(0))
    contexts = (context(), context("Other", 2),
                context("WiFi", 1, "198.51.100.0/24"))
    for ctx, vid in zip(contexts, (10, 20, 20)):
        for second in (0, 1):
            service.observe(ctx, packet(ctx, vid, at=AT + timedelta(seconds=second)))
        service.verify_baseline(ctx)
    ticks = [2.0]
    detector = VlanAnomalyDetector(clock=lambda: ticks[0])
    source = "02:11:22:33:44:55"
    for ctx, vid in zip(contexts, (10, 20, 20)):
        assert observe(service, ctx, detector, ticks, vid, 2, source=source) == ()
    assert detector.tracked_states == 3


@pytest.mark.parametrize("source", ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
                                           "01:00:5e:00:00:01"])
def test_non_device_source_mac_cannot_start_device_tag_history(source):
    service, ctx, detector, ticks = ready()
    observe(service, ctx, detector, ticks, 10, 2, source=source)
    observe(service, ctx, detector, ticks, 20, 3, source=source)
    result = observe(service, ctx, detector, ticks, 20, 4, source=source)
    assert all(item.rule_id != DEVICE_SWITCH_RULE for item in result)


def test_device_state_expires_and_is_bounded_with_global_confirmation_state():
    service, ctx, _, ticks = ready()
    detector = VlanAnomalyDetector(clock=lambda: ticks[0], max_states=3)
    for number in range(1, 7):
        source = f"02:11:22:33:44:{number:02x}"
        observe(service, ctx, detector, ticks, 10, number + 1, source=source)
        assert detector.tracked_states <= 3
    ticks[0] = 700
    detector.observe(service.get(ctx), packet(ctx, 0, at=AT + timedelta(seconds=700)))
    assert detector.tracked_states == 0
