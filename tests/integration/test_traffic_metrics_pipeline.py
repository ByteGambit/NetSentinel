"""NS-036 offline packet classification -> consumer -> portable metrics."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime

from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.traffic_metrics import MeasurementConfidence, TrafficMetricsService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)


AT = datetime(2026, 9, 25, tzinfo=UTC)


class Contexts:
    def __init__(self, context: NetworkContext) -> None:
        self.context = context

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        return (self.context,)


class Capture:
    def __init__(self, observations: tuple[object, ...], context: NetworkContext) -> None:
        self.observations = deque(observations)
        self.context = context
        self.request = None
        self.health = CaptureHealthSnapshot(
            CaptureState.STOPPED,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
            0, 128, CaptureCounters(),
        )

    def health_snapshot(self) -> CaptureHealthSnapshot:
        return self.health

    def start(self, request: object) -> bool:
        self.request = request
        self.health = replace(self.health, state=CaptureState.RUNNING,
                              selected_interface_id=self.context.interface_id,
                              network_fingerprint=self.context.fingerprint)
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.health = replace(self.health, state=CaptureState.STOPPED)
        return True

    def drain(self, limit: int) -> tuple[object, ...]:
        result = []
        while self.observations and len(result) < limit:
            result.append(self.observations.popleft())
        self.health = replace(self.health, counters=CaptureCounters(dropped_observations=2))
        return tuple(result)


def test_synthetic_packets_through_existing_consumer(tmp_path) -> None:
    ctx = NetworkContext("adapter", 1, "Wi-Fi", NetworkInterfaceKind.WIFI,
                         "192.168.50.20", "192.168.50.0/24", None, (), AT)
    arp = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.2",
            hwdst="00:00:00:00:00:00", pdst="192.168.50.20"), ctx, AT,
    )
    broadcast = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.50.2", dst="192.168.50.255"), ctx, AT,
    )
    multicast = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:01") /
        IP(src="192.168.50.2", dst="224.0.0.1"), ctx, AT,
    )
    assert arp.broadcast is not None and broadcast.broadcast is not None
    capture = Capture((arp, broadcast, broadcast, multicast), ctx)
    ticks = [0.0]
    service = DeviceInventoryService(
        Contexts(ctx), SQLiteDeviceRepository(SQLiteDatabase(tmp_path / "metrics.sqlite3")),
        capture, traffic_metrics=TrafficMetricsService(clock=lambda: ticks[0], window_seconds=10),
    )
    try:
        snapshot = service.refresh(start_capture=True)
        assert "ether broadcast" in capture.request.capture_filter
        assert "ip broadcast" in capture.request.capture_filter
        assert snapshot.traffic_metrics is not None
        assert snapshot.traffic_metrics.arp.packet_count == 1
        assert snapshot.traffic_metrics.broadcast.packet_count == 2
        assert snapshot.traffic_metrics.broadcast.packets_per_second == 0.2
        assert snapshot.traffic_metrics.dropped_observations == 2
        assert snapshot.traffic_metrics.confidence is MeasurementConfidence.REDUCED
        assert not hasattr(snapshot.traffic_metrics, "payload")
        ticks[0] = 10.0
        idle = service.refresh().traffic_metrics
        assert idle is not None
        assert idle.arp.packet_count == idle.broadcast.packet_count == 0
    finally:
        assert service.close()
