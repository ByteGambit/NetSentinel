"""NS-040 synthetic ARP -> registry/profile -> AlertService -> SQLite."""

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from scapy.layers.l2 import ARP, Ether

from netsentinel.application.detectors.device_identity import MAC_RULE
from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.device_inventory import DeviceInventoryProblem, DeviceInventoryService
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.devices import DeviceProfile, DeviceTrust, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceProfileRepository, SQLiteDeviceRepository
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)


AT = datetime(2026, 9, 26, 12, tzinfo=UTC)
EXPECTED = "00:11:22:33:44:55"
UNEXPECTED = "00:11:22:33:44:66"


class Contexts:
    def __init__(self, context):
        self.context = context

    def get_contexts(self):
        return (self.context,)


class Capture:
    def __init__(self, context):
        self.items = deque()
        self.health = CaptureHealthSnapshot(
            CaptureState.RUNNING,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
            0, 128, CaptureCounters(), selected_interface_id=context.interface_id,
            network_fingerprint=context.fingerprint, worker_alive=True,
        )

    def health_snapshot(self):
        return self.health

    def drain(self, limit):
        result = []
        while self.items and len(result) < limit:
            result.append(self.items.popleft())
        return tuple(result)

    def stop(self, timeout=None):
        self.health = replace(self.health, state=CaptureState.STOPPED, worker_alive=False)
        return True


def packet(ctx, mac, ip, seconds):
    at = AT + timedelta(seconds=seconds)
    frame = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst="192.168.1.10",
    )
    result = _packet_observation(frame, ctx, at)
    assert result.arp is not None
    return result


def test_profile_identity_alert_persists_and_deduplicates_without_user_state_mutation(tmp_path):
    ctx = NetworkContext("wifi", 1, "Lab", NetworkInterfaceKind.WIFI,
                         "192.168.1.10", "192.168.1.0/24", None, (), AT)
    database = SQLiteDatabase(tmp_path / "identity.sqlite3")
    devices = SQLiteDeviceRepository(database)
    profiles = SQLiteDeviceProfileRepository(database)
    capture = Capture(ctx)
    clocks = [AT + timedelta(seconds=10)]
    alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: clocks[0])
    service = DeviceInventoryService(
        Contexts(ctx), devices, capture, alerts=alerts, profiles=profiles,
        traffic_observed_clock=lambda: clocks[0],
    )
    try:
        capture.items.append(packet(ctx, EXPECTED, "192.168.1.20", 1))
        service.refresh()
        original_device = devices.list_devices(ctx.fingerprint)[0]
        original = profiles.create(original_device.device_id, DeviceProfile(
            uuid4(), ctx.fingerprint, "Laptop", "private owner note", DeviceTrust.TRUSTED,
            AT + timedelta(seconds=2), AT + timedelta(seconds=2), AT + timedelta(seconds=2),
            (MacAddress(EXPECTED),), ("192.168.1.20",),
        ))
        capture.items.append(packet(ctx, EXPECTED, "192.168.1.20", 10))
        assert not service.refresh().identity_alert_changed
        assert not [item for item in alerts.query(AlertQuery(limit=20)) if item.rule_id == MAC_RULE]

        clocks[0] = AT + timedelta(seconds=20)
        capture.items.append(packet(ctx, UNEXPECTED, "192.168.1.20", 20))
        result = service.refresh()
        assert result.identity_alert_changed
        stored = [item for item in alerts.query(AlertQuery(limit=20)) if item.rule_id == MAC_RULE]
        assert len(stored) == 1
        alert = stored[0]
        assert alert.status is AlertStatus.OPEN and alert.occurrence_count == 1
        assert alert.entity_id == str(original.profile_id)
        assert alert.severity == "medium" and alert.confidence == "moderate"
        assert "private owner note" not in str(alert)
        assert "payload" not in str(alert).lower()
        assert profiles.get(original.profile_id) == original
        assert len(devices.list_devices(ctx.fingerprint)) == 2

        capture.items.append(packet(ctx, UNEXPECTED, "192.168.1.20", 20))
        assert not service.refresh().identity_alert_changed
        assert alerts.get(alert.id).occurrence_count == 1
        restarted_alerts = AlertService(SQLiteAlertRepository(SQLiteDatabase(database.path)))
        assert restarted_alerts.get(alert.id).fingerprint == alert.fingerprint
        assert SQLiteDeviceProfileRepository(SQLiteDatabase(database.path)).get(original.profile_id) == original
        updated = replace(original, expected_macs=(MacAddress(EXPECTED), MacAddress(UNEXPECTED)),
                          updated_at=AT + timedelta(seconds=21))
        profiles.update(updated)
        clocks[0] = AT + timedelta(seconds=22)
        capture.items.append(packet(ctx, UNEXPECTED, "192.168.1.20", 22))
        assert not service.refresh().identity_alert_changed
        assert profiles.get(original.profile_id).trust_changed_at == original.trust_changed_at
    finally:
        assert service.close()


def test_profile_repository_failure_isolated_from_device_registry(tmp_path):
    ctx = NetworkContext("wifi", 1, "Lab", NetworkInterfaceKind.WIFI,
                         "192.168.1.10", "192.168.1.0/24", None, (), AT)
    class BrokenProfiles:
        def snapshot_for_network(self, *_):
            raise RuntimeError("unavailable")

    database = SQLiteDatabase(tmp_path / "profile_failure.sqlite3")
    devices = SQLiteDeviceRepository(database)
    capture = Capture(ctx)
    service = DeviceInventoryService(Contexts(ctx), devices, capture, profiles=BrokenProfiles())
    try:
        capture.items.append(packet(ctx, EXPECTED, "192.168.1.20", 10))
        result = service.refresh()
        assert result.problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
        assert len(devices.list_devices(ctx.fingerprint)) == 1
    finally:
        assert service.close()


def test_alert_write_failure_retries_without_losing_observation(tmp_path):
    ctx = NetworkContext("wifi", 1, "Lab", NetworkInterfaceKind.WIFI,
                         "192.168.1.10", "192.168.1.0/24", None, (), AT)
    database = SQLiteDatabase(tmp_path / "retry.sqlite3")
    devices = SQLiteDeviceRepository(database)
    profiles = SQLiteDeviceProfileRepository(database)
    capture = Capture(ctx)
    inner = AlertService(SQLiteAlertRepository(database), clock=lambda: AT + timedelta(seconds=30))

    class FailOnceAlerts:
        def __init__(self):
            self.failed = False

        def record(self, candidate):
            if getattr(candidate, "rule_id", None) == MAC_RULE and not self.failed:
                self.failed = True
                raise RuntimeError("write unavailable")
            return inner.record(candidate)

    service = DeviceInventoryService(
        Contexts(ctx), devices, capture, alerts=FailOnceAlerts(), profiles=profiles,
        traffic_observed_clock=lambda: AT + timedelta(seconds=30),
    )
    try:
        capture.items.append(packet(ctx, EXPECTED, "192.168.1.20", 1))
        service.refresh()
        original_device = devices.list_devices(ctx.fingerprint)[0]
        profiles.create(original_device.device_id, DeviceProfile(
            uuid4(), ctx.fingerprint, "", "", DeviceTrust.UNKNOWN,
            AT + timedelta(seconds=2), AT + timedelta(seconds=2), None,
            (MacAddress(EXPECTED),), ("192.168.1.20",),
        ))
        capture.items.append(packet(ctx, UNEXPECTED, "192.168.1.20", 20))
        failed = service.refresh()
        assert failed.problem is DeviceInventoryProblem.ALERT_UNAVAILABLE
        assert len(devices.list_devices(ctx.fingerprint)) == 2
        capture.items.append(packet(ctx, UNEXPECTED, "192.168.1.20", 20))
        assert service.refresh().identity_alert_changed
        assert len([item for item in inner.query(AlertQuery(limit=20)) if item.rule_id == MAC_RULE]) == 1
    finally:
        assert service.close()
