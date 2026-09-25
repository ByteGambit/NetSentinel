"""NS-036 deterministic, portable rolling traffic metrics tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.traffic_metrics import (
    BaselineState, MeasurementConfidence, TrafficMetricsService,
)
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    BroadcastKind, BroadcastObservation, LinkLayerProtocol,
    NetworkLayerProtocol, PacketObservation,
)
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)


AT = datetime(2026, 9, 25, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.tick = 0.0

    def __call__(self) -> float:
        return self.tick


def context(interface: str = "wifi", index: int = 1, subnet: str = "192.0.2.0/24") -> NetworkContext:
    return NetworkContext(interface, index, interface, NetworkInterfaceKind.WIFI,
                          subnet.replace("0/24", "20"), subnet, None, (), AT)


def packet(ctx: NetworkContext, kind: BroadcastKind, at: datetime = AT) -> PacketObservation:
    return PacketObservation(
        ctx.interface_id, ctx.interface_index, ctx.fingerprint, at, 64, 64,
        LinkLayerProtocol.ETHERNET,
        NetworkLayerProtocol.ARP if kind is BroadcastKind.ARP else NetworkLayerProtocol.IPV4,
        broadcast=BroadcastObservation(kind, kind is BroadcastKind.ARP),
    )


def health(ctx: NetworkContext, dropped: int = 0) -> CaptureHealthSnapshot:
    return CaptureHealthSnapshot(
        CaptureState.RUNNING,
        CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
        0, 128, CaptureCounters(dropped_observations=dropped),
        ctx.interface_id, ctx.fingerprint,
    )


def test_empty_first_packet_and_exclusive_categories() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10, bucket_seconds=1)
    ctx = context()
    empty = service.snapshot(ctx)
    assert empty.arp.packet_count == empty.broadcast.packet_count == 0
    assert empty.broadcast.packets_per_second == 0
    assert empty.confidence is MeasurementConfidence.UNKNOWN
    assert empty.broadcast.baseline.state is BaselineState.LEARNING
    assert service.record_capture_health(ctx, health(ctx))
    for kind in (BroadcastKind.ARP, BroadcastKind.ETHERNET_BROADCAST,
                 BroadcastKind.IPV4_LIMITED_BROADCAST, BroadcastKind.IPV4_DIRECTED_BROADCAST):
        assert service.observe(ctx, packet(ctx, kind))
    for kind in (BroadcastKind.MULTICAST, BroadcastKind.UNICAST):
        assert not service.observe(ctx, packet(ctx, kind))
    result = service.snapshot(ctx)
    assert (result.arp.packet_count, result.broadcast.packet_count) == (1, 3)
    assert (result.arp.packets_per_second, result.broadcast.packets_per_second) == (0.1, 0.3)
    assert result.confidence is MeasurementConfidence.COMPLETE
    assert result.broadcast.baseline.state is BaselineState.LEARNING
    assert result.broadcast.baseline.packets_per_second is None
    with pytest.raises(FrozenInstanceError):
        result.broadcast.packet_count = 10  # type: ignore[misc]
    assert not hasattr(result, "payload") and not hasattr(result, "packet")


def test_exact_boundary_idle_rollover_and_large_jump() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=4, bucket_seconds=1,
                                    idle_expiry_seconds=100_000)
    ctx = context()
    service.observe(ctx, packet(ctx, BroadcastKind.ARP))
    clock.tick = 3.999
    assert service.snapshot(ctx).arp.packet_count == 1
    clock.tick = 4.0  # bucket [0, 1) expires at the exact four-second boundary
    assert service.snapshot(ctx).arp.packet_count == 0
    clock.tick = 5.0
    assert service.snapshot(ctx).arp.packet_count == 0
    assert service.snapshot(ctx).arp.packets_per_second == 0
    clock.tick = 10_000.0
    assert service.snapshot(ctx).arp.packet_count == 0
    assert service.retained_buckets == 0
    assert service.tracked_contexts == 1
    assert service.snapshot(ctx).arp.baseline.state is BaselineState.LEARNING


def test_baseline_requires_multiple_completed_clean_windows_and_freezes() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10, bucket_seconds=1)
    ctx = context()
    service.record_capture_health(ctx, health(ctx))
    service.observe(ctx, packet(ctx, BroadcastKind.IPV4_DIRECTED_BROADCAST))
    clock.tick = 10
    first = service.snapshot(ctx).broadcast.baseline
    assert (first.state, first.completed_windows, first.observed_packets) == (BaselineState.LEARNING, 1, 1)
    service.observe(ctx, packet(ctx, BroadcastKind.ETHERNET_BROADCAST))
    clock.tick = 20
    assert service.snapshot(ctx).broadcast.baseline.state is BaselineState.LEARNING
    service.observe(ctx, packet(ctx, BroadcastKind.IPV4_LIMITED_BROADCAST))
    clock.tick = 30
    learned = service.snapshot(ctx).broadcast.baseline
    assert learned.state is BaselineState.LEARNED
    assert learned.packets_per_second == 0.1
    assert learned.completed_windows == 3
    assert learned.observed_packets == 3
    for _ in range(100):
        service.observe(ctx, packet(ctx, BroadcastKind.ETHERNET_BROADCAST))
    assert service.snapshot(ctx).broadcast.packet_count == 100
    clock.tick = 40
    assert service.snapshot(ctx).broadcast.baseline == learned
    assert service.snapshot(ctx).arp.baseline.state is BaselineState.LEARNING


def test_spike_in_one_learning_window_is_not_a_single_packet_baseline() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10, bucket_seconds=1)
    ctx = context()
    for _ in range(100):
        service.observe(ctx, packet(ctx, BroadcastKind.ARP))
    clock.tick = 10
    assert service.snapshot(ctx).arp.baseline.state is BaselineState.LEARNING
    clock.tick = 20
    assert service.snapshot(ctx).arp.baseline.state is BaselineState.LEARNING
    clock.tick = 30
    assert service.snapshot(ctx).arp.baseline.state is BaselineState.LEARNING


def test_learning_windows_start_at_first_scope_tick_not_partial_clock_bucket() -> None:
    clock = Clock()
    clock.tick = 5.5
    service = TrafficMetricsService(clock=clock, window_seconds=10)
    ctx = context()
    service.observe(ctx, packet(ctx, BroadcastKind.ARP))
    clock.tick = 10.0  # absolute boundary does not complete a partial warm-up
    assert service.snapshot(ctx).arp.baseline.completed_windows == 0
    clock.tick = 15.5
    assert service.snapshot(ctx).arp.baseline.completed_windows == 1


def test_scope_separation_duplicate_multiplicity_and_out_of_order_utc() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10)
    a, b = context(), context("ethernet", 2)
    same_fingerprint_new_index = context("wifi", 9)
    frame = packet(a, BroadcastKind.ARP)
    assert service.observe(a, frame)
    assert service.observe(a, frame)  # two delivered frames; no packet identity exists
    clock.tick = 1
    assert service.observe(a, replace(frame, observed_at=AT - timedelta(days=1)))
    assert not service.observe(b, frame)
    assert not service.observe(same_fingerprint_new_index, frame)
    assert service.observe(b, packet(b, BroadcastKind.ARP))
    assert service.observe(same_fingerprint_new_index,
                           packet(same_fingerprint_new_index, BroadcastKind.ARP))
    assert (service.snapshot(a).arp.packet_count, service.snapshot(b).arp.packet_count,
            service.snapshot(same_fingerprint_new_index).arp.packet_count) == (3, 1, 1)
    clock.tick = 0  # a faulty clock reading cannot move expiry backwards
    assert service.snapshot(a).arp.packet_count == 3


def test_idle_expiry_and_deterministic_capacity_eviction() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=4, max_contexts=2,
                                    idle_expiry_seconds=10)
    a, b, c = context("a"), context("b"), context("c")
    for ctx in (a, b):
        service.observe(ctx, packet(ctx, BroadcastKind.ARP))
    service.observe(c, packet(c, BroadcastKind.ARP))
    assert service.tracked_contexts == 2
    assert service.snapshot(a).arp.packet_count == 0  # key tie-break evicts a
    assert service.snapshot(b).arp.packet_count == 1
    clock.tick = 10
    assert service.snapshot(b).arp.packet_count == 0
    assert service.tracked_contexts == 0


def test_bounded_buckets_under_long_traffic_and_time_jump() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=5, bucket_seconds=1,
                                    max_contexts=2, idle_expiry_seconds=100_000)
    ctx = context()
    for tick in range(1000):
        clock.tick = tick
        service.observe(ctx, packet(ctx, BroadcastKind.ARP))
        assert service.retained_buckets <= 5
    clock.tick = 10_000
    assert service.snapshot(ctx).arp.packet_count == 0
    assert service.retained_buckets == 0


def test_capture_overflow_reduces_measurement_confidence_and_skips_learning() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10)
    ctx = context()
    service.record_capture_health(ctx, health(ctx))
    service.observe(ctx, packet(ctx, BroadcastKind.ARP))
    assert service.snapshot(ctx).confidence is MeasurementConfidence.COMPLETE
    assert service.record_capture_health(ctx, health(ctx, 2))
    degraded = service.snapshot(ctx)
    assert degraded.dropped_observations == 2
    assert degraded.confidence is MeasurementConfidence.REDUCED
    clock.tick = 10
    assert service.snapshot(ctx).arp.baseline.completed_windows == 0
    clock.tick = 11
    assert service.snapshot(ctx).dropped_observations == 0
    assert service.snapshot(ctx).confidence is MeasurementConfidence.COMPLETE

    fresh = TrafficMetricsService(clock=clock, window_seconds=10)
    assert fresh.record_capture_health(ctx, health(ctx, 3))
    assert fresh.snapshot(ctx).confidence is MeasurementConfidence.REDUCED


def test_capture_drop_counters_do_not_cross_network_contexts() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10)
    a, b = context("wifi"), context("vpn", 2)
    service.record_capture_health(a, health(a))
    service.record_capture_health(a, health(a, 4))
    service.record_capture_health(b, health(b, 4))  # global worker counter, new scope
    assert service.snapshot(a).dropped_observations == 4
    assert service.snapshot(b).dropped_observations == 0
    service.record_capture_health(b, health(b, 5))
    assert service.snapshot(b).dropped_observations == 1


def test_invalid_inputs_do_not_change_state_and_config_is_bounded() -> None:
    clock = Clock()
    service = TrafficMetricsService(clock=clock, window_seconds=10)
    ctx = context()
    assert not service.observe(ctx, object())  # type: ignore[arg-type]
    assert not service.observe(ctx, packet(context("other"), BroadcastKind.ARP))
    damaged = packet(ctx, BroadcastKind.ARP)
    object.__setattr__(damaged, "broadcast", "damaged")
    assert not service.observe(ctx, damaged)
    assert not service.record_capture_health(ctx, object())  # type: ignore[arg-type]
    assert service.tracked_contexts == 0
    for config in ({"window_seconds": 0}, {"bucket_seconds": 7, "window_seconds": 10},
                   {"max_contexts": 0}, {"baseline_windows": 1},
                   {"idle_expiry_seconds": 5, "window_seconds": 10}):
        with pytest.raises(ValueError):
            TrafficMetricsService(**config)
    clock.tick = float("nan")
    with pytest.raises(ValueError):
        service.snapshot(ctx)
    assert service.tracked_contexts == 0
