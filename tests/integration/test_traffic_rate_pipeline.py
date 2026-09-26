"""NS-037 offline classifier -> metrics -> detector -> AlertService -> SQLite."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from netsentinel.application.detectors.traffic_rate import TrafficRateDetector
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.traffic_metrics import TrafficMetricsService
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.shared.config import TrafficRateConfig
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)


AT = datetime(2026, 9, 25, tzinfo=UTC)


class Contexts:
    def __init__(self, context: NetworkContext) -> None:
        self.context = context

    def get_contexts(self):
        return (self.context,)


class Capture:
    def __init__(self, context: NetworkContext) -> None:
        self.items = deque()
        self.context = context
        self.health = CaptureHealthSnapshot(
            CaptureState.STOPPED,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
            0, 128, CaptureCounters(),
        )

    def health_snapshot(self):
        return self.health

    def start(self, request):
        self.health = replace(self.health, state=CaptureState.RUNNING,
                              selected_interface_id=self.context.interface_id,
                              network_fingerprint=self.context.fingerprint)
        return True

    def stop(self, timeout=None):
        self.health = replace(self.health, state=CaptureState.STOPPED)
        return True

    def drain(self, limit):
        result = []
        while self.items and len(result) < limit:
            result.append(self.items.popleft())
        return tuple(result)


def test_offline_normal_then_sustained_alert_and_recovery(tmp_path) -> None:
    context = NetworkContext("adapter", 1, "Wi-Fi", NetworkInterfaceKind.WIFI,
                             "192.168.50.20", "192.168.50.0/24", None, (), AT)
    broadcast = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.50.2", dst="192.168.50.255"), context, AT)
    arp = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.2",
            hwdst="00:00:00:00:00:00", pdst="192.168.50.20"), context, AT)
    assert broadcast.broadcast is not None and arp.broadcast is not None
    ticks = [0.0]
    database = SQLiteDatabase(tmp_path / "rate.sqlite3")
    alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: AT + timedelta(seconds=ticks[0]))
    capture = Capture(context)
    service = DeviceInventoryService(
        Contexts(context), SQLiteDeviceRepository(database), capture,
        alerts=alerts,
        traffic_metrics=TrafficMetricsService(clock=lambda: ticks[0], window_seconds=10),
        traffic_detector=TrafficRateDetector(
            config=TrafficRateConfig(broadcast_floor_pps=0.5, arp_floor_pps=0.3),
            clock=lambda: ticks[0]),
        traffic_observed_clock=lambda: AT + timedelta(seconds=ticks[0]),
    )
    try:
        for t in (0, 10, 20):
            ticks[0] = t
            capture.items.extend((broadcast, arp))
            snapshot = service.refresh(start_capture=t == 0)
            assert snapshot.traffic_metrics is not None
        ticks[0] = 30
        snapshot = service.refresh()
        assert snapshot.traffic_metrics.broadcast.baseline.packets_per_second == 0.1
        assert snapshot.traffic_metrics.arp.baseline.packets_per_second == 0.1
        assert alerts.query(_all_alerts()) == ()

        for t in (31, 36, 41):
            ticks[0] = t
            capture.items.extend((broadcast,) * 6 + (arp,) * 4)
            snapshot = service.refresh()
        assert snapshot.traffic_alert_changed
        persisted = {item.rule_id: item for item in alerts.query(_all_alerts())}
        assert set(persisted) == {"broadcast_rate_anomaly", "arp_rate_anomaly"}
        for rule, item in persisted.items():
            assert item.status is AlertStatus.OPEN
            assert item.confidence == "moderate"
            assert item.network_fingerprint == context.fingerprint
            assert dict(item.evidence[-1].details)["quality"] == "complete"
            assert dict(item.evidence[-1].details)["interface"] == "adapter#1"
            assert item.occurrence_count == 1
            assert "payload" not in str(item.evidence)
        ticks[0] = 46
        service.refresh()
        assert all(item.occurrence_count == 1 for item in alerts.query(_all_alerts()))
        ticks[0] = 56
        service.refresh()
        ticks[0] = 61
        assert service.refresh().traffic_alert_changed
        assert all(item.status is AlertStatus.RESOLVED for item in alerts.query(_all_alerts()))
        restarted = AlertService(SQLiteAlertRepository(database))
        assert {item.id for item in restarted.query(_all_alerts())} == {item.id for item in persisted.values()}
    finally:
        assert service.close()


def _all_alerts():
    from netsentinel.application.ports import AlertQuery
    return AlertQuery(limit=50)
