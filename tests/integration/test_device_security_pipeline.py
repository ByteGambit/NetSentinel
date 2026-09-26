"""NS-042 offline decision matrix and persistent device-security flow."""

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from scapy.layers.l2 import ARP, Ether

from netsentinel.application.detectors.device_identity import (
    CONTEXT_RULE, IP_CHURN_RULE, MAC_RULE, DeviceIdentityChangeDetector,
)
from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.device_inventory import (
    DeviceInventoryEntry, DeviceInventoryService, DeviceInventorySnapshot,
)
from netsentinel.application.services.device_profiles import DeviceProfileService
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.devices import (
    DeviceIdentity, DeviceProfile, DeviceTrust, IdentityBinding, NetworkContext,
    NetworkInterfaceKind,
)
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceProfileRepository, SQLiteDeviceRepository
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.device_profile import DeviceProfileCoordinator
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)
from tests.fixtures.devices.scenarios import A, B, CASES, IP, OTHER_IP, PRIVATE


T0 = datetime(2026, 9, 26, 12, tzinfo=UTC)


def context(name="wifi", subnet="192.168.1.0/24"):
    return NetworkContext(name, 1, name, NetworkInterfaceKind.WIFI,
                          "192.168.1.2", subnet, None, (), T0)


def profile(ctx, *, macs=(A,), ips=(IP,), trust=DeviceTrust.UNKNOWN, label="Laptop", note="private note"):
    return DeviceProfile(uuid4(), ctx.fingerprint, label, note, trust, T0, T0,
                         T0 if trust is not DeviceTrust.UNKNOWN else None,
                         tuple(MacAddress(mac) for mac in macs), ips)


def observed(ctx, mac, ip, seconds):
    at = T0 + timedelta(seconds=seconds)
    address = MacAddress(mac)
    return DeviceIdentity(ctx.fingerprint, address, at, at), IdentityBinding(ctx.fingerprint, address, ip, at, at), at


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_identity_decision_matrix(case):
    ctx = context()
    detector = DeviceIdentityChangeDetector()
    device, binding, at = observed(ctx, case.observed_mac, case.observed_ip, 20)
    rows = ()
    if case.member or case.expected_macs or case.expected_ips:
        owner = profile(ctx, macs=case.expected_macs, ips=case.expected_ips,
                        trust=DeviceTrust(case.trust))
        recent = (observed(ctx, A, case.observed_ip, 15)[1],) if case.recent_expected else ()
        members = (device.device_id,) if case.member else ()
        if recent:
            members += (recent[0].device_id,)
        rows = ((owner, members, recent),)
    detector.replace_snapshot(ctx.fingerprint, rows, at)
    candidates = detector.observe(ctx, device, binding, at)
    assert [item.rule_id for item in candidates] == ([case.rule] if case.rule else [])
    if candidates:
        candidate = candidates[0]
        assert (candidate.severity, candidate.confidence) == (case.severity, case.confidence)
        assert candidate.entity_id == str(owner.profile_id)
        assert "private note" not in str(candidate)
        assert candidate.evidence.observed_mac == device.mac


def test_context_mismatch_positive_and_negative():
    ctx = context()
    first = profile(ctx, macs=(A,), ips=(IP,))
    second = profile(ctx, macs=(B,), ips=(OTHER_IP,))
    device, binding, at = observed(ctx, A, OTHER_IP, 20)
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((first, (device.device_id,), ()), (second, (), ())), at)
    (candidate,) = detector.observe(ctx, device, binding, at)
    assert (candidate.rule_id, candidate.severity, candidate.confidence) == (CONTEXT_RULE, "low", "low")
    assert candidate.entity_id == str(first.profile_id)
    detector.replace_snapshot(ctx.fingerprint, ((first, (device.device_id,), ()),), at)
    assert detector.observe(ctx, device, binding, at) == ()


def test_churn_boundaries_duplicates_and_out_of_order():
    ctx = context()
    owner = profile(ctx)
    device, _, _ = observed(ctx, A, IP, 1)
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((owner, (device.device_id,), ()),), T0 + timedelta(seconds=10))
    for ip, seconds, signal in (("192.168.1.21", 10, False), ("192.168.1.21", 10, False),
                                ("192.168.1.22", 20, False), ("192.168.1.23", 30, True)):
        item = detector.observe(ctx, *observed(ctx, A, ip, seconds))
        assert bool(item) is signal
        if item:
            assert (item[0].rule_id, item[0].severity, item[0].confidence) == (IP_CHURN_RULE, "low", "moderate")
    # A stale packet cannot add another distinct address or advance detector state.
    stale_device, stale_binding, stale_at = observed(ctx, A, "192.168.1.24", 19)
    stale_device = replace(stale_device, last_seen=T0 + timedelta(seconds=30))
    assert detector.observe(ctx, stale_device, stale_binding, stale_at) == ()
    fresh = DeviceIdentityChangeDetector()
    old = observed(ctx, A, "192.168.1.21", 10)[1]
    second = observed(ctx, A, "192.168.1.22", 310)[1]
    fresh.replace_snapshot(ctx.fingerprint, ((owner, (device.device_id,), (old, second)),), T0 + timedelta(seconds=320))
    assert fresh.observe(ctx, *observed(ctx, A, "192.168.1.23", 320)) == ()


def test_freshness_boundary_and_stable_fingerprint():
    ctx = context()
    owner = profile(ctx)
    snapshot_at = T0 + timedelta(seconds=600)

    def assess(at_seconds, saved=owner, mac=B):
        detector = DeviceIdentityChangeDetector()
        detector.replace_snapshot(ctx.fingerprint, ((saved, (), ()),), snapshot_at)
        return detector.observe(ctx, *observed(ctx, mac, IP, at_seconds))

    assert assess(299) == ()
    (at_boundary,) = assess(300)
    (inside,) = assess(301)
    assert at_boundary.rule_id == MAC_RULE
    assert inside.fingerprint == at_boundary.fingerprint
    renamed = replace(owner, label="New laptop", note="a different private note",
                      updated_at=T0 + timedelta(seconds=1))
    (after_text_edit,) = assess(301, renamed)
    assert after_text_edit.fingerprint == at_boundary.fingerprint
    (different_identity,) = assess(301, owner, PRIVATE)
    assert different_identity.fingerprint != at_boundary.fingerprint
    assert "a different private note" not in str(after_text_edit)


def test_exact_churn_window_boundary():
    ctx = context()
    owner = profile(ctx)
    device, first, _ = observed(ctx, A, "192.168.1.21", 10)
    second = observed(ctx, A, "192.168.1.22", 20)[1]
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((owner, (device.device_id,), (first, second)),),
                              T0 + timedelta(seconds=310))
    assert detector.observe(ctx, *observed(ctx, A, "192.168.1.23", 310))[0].rule_id == IP_CHURN_RULE
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((owner, (device.device_id,), (first, second)),),
                              T0 + timedelta(seconds=311))
    assert detector.observe(ctx, *observed(ctx, A, "192.168.1.24", 311)) == ()


class Contexts:
    def __init__(self, ctx):
        self.ctx = ctx

    def get_contexts(self):
        return (self.ctx,)


class Capture:
    def __init__(self, ctx):
        self.items = deque()
        self.health = CaptureHealthSnapshot(
            CaptureState.RUNNING,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, T0),
            0, 128, CaptureCounters(), selected_interface_id=ctx.interface_id,
            network_fingerprint=ctx.fingerprint, worker_alive=True,
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
    at = T0 + timedelta(seconds=seconds)
    frame = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=IP,
    )
    result = _packet_observation(frame, ctx, at)
    assert result.arp is not None
    assert not hasattr(result, "payload")
    return result


def compose(db, ctx, clock):
    devices = SQLiteDeviceRepository(db)
    profiles = SQLiteDeviceProfileRepository(db)
    alerts = AlertService(SQLiteAlertRepository(db), clock=lambda: clock[0])
    capture = Capture(ctx)
    service = DeviceInventoryService(Contexts(ctx), devices, capture, alerts=alerts,
                                     profiles=profiles, traffic_observed_clock=lambda: clock[0])
    return devices, profiles, alerts, capture, service


def identity_alerts(alerts, ctx):
    return tuple(item for item in alerts.query(AlertQuery(limit=100, network_fingerprint=ctx.fingerprint))
                 if item.rule_id in {MAC_RULE, CONTEXT_RULE, IP_CHURN_RULE})


def test_synthetic_parser_to_alert_restart_and_user_state(tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "security.sqlite3")
    clock = [T0 + timedelta(seconds=1)]
    devices, profiles, alerts, capture, service = compose(db, ctx, clock)
    try:
        capture.items.append(packet(ctx, A, IP, 1))
        service.refresh()
        device = devices.list_devices(ctx.fingerprint)[0]
        saved = profiles.create(device.device_id, profile(ctx, macs=(A,), ips=(IP,), trust=DeviceTrust.TRUSTED))
        clock[0] = T0 + timedelta(seconds=20)
        capture.items.append(packet(ctx, A, OTHER_IP, 20))
        assert not service.refresh().identity_alert_changed  # one normal DHCP change
        assert identity_alerts(alerts, ctx) == ()
        capture.items.append(packet(ctx, B, IP, 21))
        clock[0] = T0 + timedelta(seconds=21)
        assert service.refresh().identity_alert_changed
        (alert,) = identity_alerts(alerts, ctx)
        assert (alert.severity, alert.confidence, alert.occurrence_count) == ("medium", "moderate", 1)
        assert "private note" not in str(alert)
        assert profiles.get(saved.profile_id) == saved
        capture.items.append(packet(ctx, B, IP, 21))
        service.refresh()
        assert alerts.get(alert.id).occurrence_count == 1
        capture.items.append(packet(ctx, B, IP, 20))
        service.refresh()
        assert alerts.get(alert.id).last_seen == alert.last_seen
        assert alerts.get(alert.id).occurrence_count == 1
    finally:
        assert service.close()

    # Reconstruct all repositories/services and replay the same logical identity.
    reopened = SQLiteDatabase(db.path)
    devices, profiles, alerts, capture, service = compose(reopened, ctx, clock)
    try:
        assert profiles.get(saved.profile_id) == saved
        assert profiles.get_for_device(device.device_id) == saved
        assert alerts.get(alert.id).id == alert.id
        capture.items.append(packet(ctx, B, IP, 21))
        service.refresh()
        (replayed,) = identity_alerts(alerts, ctx)
        assert replayed.id == alert.id and replayed.occurrence_count == 1
        assert replayed.last_seen == alert.last_seen
        alerts.acknowledge(alert.id)
        assert alerts.get(alert.id).status is AlertStatus.ACKNOWLEDGED
    finally:
        assert service.close()

    reopened = SQLiteDatabase(db.path)
    devices, profiles, alerts, capture, service = compose(reopened, ctx, clock)
    try:
        assert alerts.get(alert.id).status is AlertStatus.ACKNOWLEDGED
        assert profiles.get(saved.profile_id).trust is DeviceTrust.TRUSTED
        clock[0] = T0 + timedelta(seconds=22)
        capture.items.append(packet(ctx, B, IP, 22))
        service.refresh()
        assert alerts.get(alert.id).status is AlertStatus.ACKNOWLEDGED
        assert alerts.get(alert.id).occurrence_count == 2
        alerts.resolve(alert.id)
        assert alerts.get(alert.id).status is AlertStatus.RESOLVED
    finally:
        assert service.close()

    # NS-028 reopens a persisted resolved issue on a later observation after restart.
    reopened = SQLiteDatabase(db.path)
    devices, profiles, alerts, capture, service = compose(reopened, ctx, clock)
    try:
        assert alerts.get(alert.id).status is AlertStatus.RESOLVED
        clock[0] = T0 + timedelta(seconds=30)
        capture.items.append(packet(ctx, B, IP, 30))
        service.refresh()
        (reopened_alert,) = identity_alerts(alerts, ctx)
        assert reopened_alert.id == alert.id
        assert reopened_alert.status is AlertStatus.OPEN
        assert reopened_alert.occurrence_count == 3
        assert reopened_alert.last_seen == T0 + timedelta(seconds=30)
        assert profiles.get(saved.profile_id) == saved
        changed = replace(saved, expected_macs=(MacAddress(A), MacAddress(B)),
                          updated_at=T0 + timedelta(seconds=31))
        profiles.update(changed)
        clock[0] = T0 + timedelta(seconds=32)
        capture.items.append(packet(ctx, B, IP, 32))
        assert not service.refresh().identity_alert_changed
        assert len(identity_alerts(alerts, ctx)) == 1
        assert profiles.get(saved.profile_id).trust_changed_at == saved.trust_changed_at
        assert profiles.get(saved.profile_id).note == saved.note
    finally:
        assert service.close()


def test_network_scope_and_profile_membership(tmp_path):
    a, b = context("wifi-a"), context("wifi-b")
    db = SQLiteDatabase(tmp_path / "scopes.sqlite3")
    clock = [T0 + timedelta(seconds=1)]
    devices, profiles, alerts, capture, service = compose(db, a, clock)
    try:
        capture.items.append(packet(a, A, IP, 1))
        capture.items.append(packet(a, B, OTHER_IP, 1))
        service.refresh()
        members = devices.list_devices(a.fingerprint)
        owner = next(item for item in members if item.mac == MacAddress(A))
        saved = profiles.create(owner.device_id, profile(a, macs=(A, B), ips=(IP, OTHER_IP)))
        other = next(item for item in members if item.mac == MacAddress(B))
        # A merged repository profile owns both observed UUIDs and expected identities.
        second = profiles.create(other.device_id, profile(a, macs=(B,), ips=(OTHER_IP,), label="", note=""))
        merged = profiles.merge_devices(owner.device_id, other.device_id, T0 + timedelta(seconds=2))
        assert merged.profile_id == saved.profile_id
        assert profiles.get(second.profile_id).merged_into == saved.profile_id
        clock[0] = T0 + timedelta(seconds=20)
        capture.items.append(packet(a, B, OTHER_IP, 20))
        assert not service.refresh().identity_alert_changed
    finally:
        assert service.close()
    # A foreign network observation never compares against network A's user profile.
    devices, profiles, alerts, capture, service = compose(db, b, clock)
    try:
        capture.items.append(packet(b, PRIVATE, IP, 20))
        assert not service.refresh().identity_alert_changed
        assert identity_alerts(alerts, b) == ()
        assert profiles.snapshot_for_network(b.fingerprint, T0) == ()
    finally:
        assert service.close()


def test_offscreen_profile_reload_and_related_alert_scope(tmp_path, qtbot):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "ui.sqlite3")
    devices = SQLiteDeviceRepository(db)
    profiles = SQLiteDeviceProfileRepository(db)
    alerts = AlertService(SQLiteAlertRepository(db), clock=lambda: T0 + timedelta(seconds=40))
    original, binding, _ = observed(ctx, A, IP, 1)
    devices.record_binding(original, binding)
    saved = profiles.create(original.device_id, profile(ctx, macs=(A,), ips=(IP,), trust=DeviceTrust.TRUSTED))
    changed, changed_binding, at = observed(ctx, B, IP, 20)
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((saved, (original.device_id,), (binding,)),), at)
    (candidate,) = detector.observe(ctx, changed, changed_binding, at)
    target = alerts.record(candidate)[0]
    unrelated = alerts.record(replace(candidate, fingerprint="f" * 64, entity_id=str(uuid4())))[0]

    # A new worker/view pair represents UI reconstruction after restart.
    profile_worker = DeviceProfileCoordinator(lambda: DeviceProfileService(SQLiteDeviceProfileRepository(SQLiteDatabase(db.path))))
    alert_worker = AlertQueryCoordinator(lambda: AlertQueryService(AlertService(SQLiteAlertRepository(SQLiteDatabase(db.path)))))
    device_view = DevicesView(profiles=profile_worker)
    alert_view = AlertsView(coordinator=alert_worker)
    qtbot.addWidget(device_view)
    qtbot.addWidget(alert_view)
    device_view.profile_alerts_requested.connect(alert_view.show_profile_identity_alerts)
    assert profile_worker.start() and alert_worker.start()
    try:
        entry = DeviceInventoryEntry(original, (binding,), ctx.interface_name, ctx.subnet)
        device_view.set_snapshot(DeviceInventorySnapshot((ctx,), ctx.fingerprint, (entry,), None))
        device_view.table.selectRow(0)
        qtbot.waitUntil(lambda: device_view.profile_values["label"].text() == "Laptop")
        assert device_view.profile_values["trust"].text() == "Trusted"
        assert device_view.profile_values["macs"].text() == A
        assert device_view.profile_values["ips"].text() == IP
        renamed = replace(saved, label="Renamed Laptop", note="new private note",
                          updated_at=T0 + timedelta(seconds=30))
        profiles.update(renamed)
        device_view.profile_refresh_button.click()
        qtbot.waitUntil(lambda: device_view.profile_values["label"].text() == "Renamed Laptop")
        assert device_view.profile_values["note"].text() == "new private note"
        device_view.profile_alerts_button.click()
        qtbot.waitUntil(lambda: not alert_view._loading and alert_view.model.rowCount() == 1)
        assert alert_view.model.alerts[0].id == target.id
        assert alert_view.model.alerts[0].id != unrelated.id
        assert alert_view._linked_profile == (str(saved.profile_id), ctx.fingerprint)
    finally:
        assert profile_worker.stop() and alert_worker.stop()
        assert not profile_worker.worker_alive and not alert_worker.worker_alive
