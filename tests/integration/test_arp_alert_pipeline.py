"""NS-029 synthetic packet to SQLite and offscreen alert view path."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.domain.alerts import AlertCandidate, AlertEvidence, AlertStatus, ArpIdentityRule
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import LinkLayerProtocol, NetworkLayerProtocol, PacketObservation
from netsentinel.infrastructure.parsers.arp import parse_arp_packet
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository, SQLiteGatewayBaselineRepository
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.shared.diagnostics import (CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState, CapabilityStatus)
from tests.fixtures.packets.arp_scenarios import NORMAL, SPOOF_LIKE, sender


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)


class Contexts:
    def __init__(self, context):
        self.context = context

    def get_contexts(self):
        return (self.context,)


class Capture:
    def __init__(self, context):
        self.items = []
        self.health = CaptureHealthSnapshot(CaptureState.RUNNING,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, T0),
            0, 128, CaptureCounters(), selected_interface_id=context.interface_id,
            network_fingerprint=context.fingerprint, worker_alive=True)

    def health_snapshot(self):
        return self.health

    def drain(self, limit):
        items = tuple(self.items[:limit])
        del self.items[:limit]
        return items

    def stop(self, timeout=None):
        self.health = replace(self.health, state=CaptureState.STOPPED, worker_alive=False)
        return True


def observation(context, mac, ip, seconds):
    metadata = PacketObservation(context.interface_id, context.interface_index, context.fingerprint,
        T0 + timedelta(seconds=seconds), 42, 42, LinkLayerProtocol.ETHERNET,
        NetworkLayerProtocol.ARP)
    parsed = parse_arp_packet(sender(mac, ip), metadata)
    assert parsed is not None
    return replace(metadata, arp=parsed)


def test_normal_and_spoof_like_packet_to_sqlite_query_and_view(tmp_path, qtbot):
    context = NetworkContext("wifi", 1, "Lab Wi-Fi", NetworkInterfaceKind.WIFI,
                             "192.168.1.10", "192.168.1.0/24", "192.168.1.1", (), T0)
    contexts = Contexts(context)
    capture = Capture(context)
    database = SQLiteDatabase(tmp_path / "alerts.sqlite3")
    clock = [T0]
    alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: clock[0])
    baseline = GatewayBaselineService(SQLiteGatewayBaselineRepository(database), contexts, clock=lambda: clock[0])
    inventory = DeviceInventoryService(contexts, SQLiteDeviceRepository(database), capture, baseline, alerts)
    coordinator = AlertQueryCoordinator(lambda: AlertQueryService(
        AlertService(SQLiteAlertRepository(database), clock=lambda: clock[0])))
    view = AlertsView(coordinator=coordinator)
    qtbot.addWidget(view)
    assert coordinator.start()
    view.show()
    qtbot.waitUntil(lambda: not view._loading)
    try:
        capture.items = [observation(context, mac, ip, seconds) for mac, ip, seconds in NORMAL[:2]]
        assert inventory.refresh().identity_events == ()
        clock[0] += timedelta(seconds=61)
        capture.items = [observation(context, mac, ip, seconds) for mac, ip, seconds in NORMAL[2:]]
        normal = inventory.refresh()
        assert normal.identity_events == ()
        assert all(alert.severity != "high" for alert in alerts.query(AlertQuery(limit=10)))
        clock[0] += timedelta(seconds=1)
        capture.items = [observation(context, mac, ip, seconds) for mac, ip, seconds in SPOOF_LIKE[:2]]
        suspicious = inventory.refresh()
        assert {event.rule_id for event in suspicious.identity_events} == {
            ArpIdentityRule.IP_MAC_CONFLICT, ArpIdentityRule.GATEWAY_MAC_CHANGE}
        view.set_network_contexts((context,))
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() >= 2)
        assert {alert.rule_id for alert in view.model.alerts}.issuperset(
            {"ip_mac_conflict", "gateway_mac_change"})
        assert len({alert.id for alert in view.model.alerts}) == view.model.rowCount()
        gateway = next(alert for alert in view.model.alerts if alert.rule_id == "gateway_mac_change")
        view.table.selectRow(view.model.row_for_id(gateway.id))
        assert view.details.values["network"].text() == "Lab Wi-Fi · 192.168.1.0/24"
        assert view.details.values["expected"].text() == "00:11:22:33:44:55"
        assert view.details.values["observed"].text() == "00:11:22:33:44:66"
        assert "Identity conflict" in view.details.evidence.toPlainText()
        view.acknowledge_button.click()
        qtbot.waitUntil(lambda: alerts.get(gateway.id).status is AlertStatus.ACKNOWLEDGED)
        qtbot.waitUntil(lambda: not view._loading)
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.model.alert_at(view.model.row_for_id(gateway.id)).status is AlertStatus.ACKNOWLEDGED
        capture.items = [observation(context, *SPOOF_LIKE[2])]
        clock[0] += timedelta(seconds=1)
        inventory.refresh()
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading)
        assert len([a for a in view.model.alerts if a.rule_id == "gateway_mac_change"]) == 1
    finally:
        assert inventory.close()
        assert coordinator.stop()


def test_real_sqlite_alert_pages_and_restart_ack(tmp_path, qtbot):
    database = SQLiteDatabase(tmp_path / "pages.sqlite3")
    alerts = AlertService(SQLiteAlertRepository(database), clock=lambda: T0 + timedelta(days=1))
    for n in range(52):
        candidate = AlertCandidate(f"{n + 1:064x}", "new_device", "a" * 64 if n < 51 else "b" * 64,
                                   f"device_{n}", "info", "passive_observation",
                                   AlertEvidence(T0 + timedelta(seconds=n), observed_mac=None))
        alerts.record(candidate)
    coordinator = AlertQueryCoordinator(lambda: AlertQueryService(AlertService(SQLiteAlertRepository(database))))
    view = AlertsView(coordinator=coordinator)
    qtbot.addWidget(view)
    assert coordinator.start()
    view.show()
    qtbot.waitUntil(lambda: not view._loading)
    try:
        assert view.model.rowCount() == 50
        assert view.next_button.isEnabled()
        first_ids = {alert.id for alert in view.model.alerts}
        view.next_page()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.model.rowCount() == 2
        assert first_ids.isdisjoint({alert.id for alert in view.model.alerts})
        assert not view.next_button.isEnabled()
        item = view.model.alert_at(0)
        view.table.selectRow(0)
        view.acknowledge_button.click()
        qtbot.waitUntil(lambda: alerts.get(item.id).status is AlertStatus.ACKNOWLEDGED)
        qtbot.waitUntil(lambda: not view._loading)
        assert AlertService(SQLiteAlertRepository(database)).get(item.id).status is AlertStatus.ACKNOWLEDGED
        assert view.model.alert_at(view.model.row_for_id(item.id)).status is AlertStatus.ACKNOWLEDGED
    finally:
        assert coordinator.stop()
