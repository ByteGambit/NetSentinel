"""NS-026 portable observation to persisted identity to event integration."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.device_inventory import DeviceInventoryProblem, DeviceInventoryService
from netsentinel.domain.alerts import ArpIdentityRule
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress, NetworkLayerProtocol, PacketObservation,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository, SQLiteGatewayBaselineRepository
from netsentinel.shared.diagnostics import (
    CaptureCapabilityReason, CaptureCapabilitySnapshot, CaptureCounters, CaptureHealthSnapshot,
    CaptureState, CapabilityStatus,
)


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)


class Contexts:
    def __init__(self, ctx):
        self.ctx = ctx

    def get_contexts(self):
        return (self.ctx,)


class Capture:
    def __init__(self, ctx):
        self.items = []
        self.health = CaptureHealthSnapshot(
            CaptureState.RUNNING,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, T0),
            0, 128, CaptureCounters(), selected_interface_id=ctx.interface_id,
            network_fingerprint=ctx.fingerprint, worker_alive=True,
        )

    def health_snapshot(self):
        return self.health

    def drain(self, limit):
        result = tuple(self.items[:limit])
        del self.items[:limit]
        return result

    def stop(self, timeout=None):
        self.health = replace(self.health, state=CaptureState.STOPPED, worker_alive=False)
        return True


def packet(ctx, mac, ip, at):
    return PacketObservation(ctx.interface_id, ctx.interface_index, ctx.fingerprint, at, 42, 42,
                             LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.ARP,
                             arp=ArpObservation(ArpOpcode.REPLY, MacAddress(mac), ip,
                                                MacAddress("ff:ff:ff:ff:ff:ff"), ctx.ipv4_address))


def test_existing_consumer_emits_two_scoped_events_without_alert_persistence_or_extra_worker(tmp_path):
    ctx = NetworkContext("wifi", 1, "wifi", NetworkInterfaceKind.WIFI,
                         "192.168.1.10", "192.168.1.0/24", "192.168.1.1", (), T0)
    source = Contexts(ctx)
    capture = Capture(ctx)
    db = SQLiteDatabase(tmp_path / "identity.sqlite3")
    tick = [T0]
    baseline = GatewayBaselineService(SQLiteGatewayBaselineRepository(db), source, clock=lambda: tick[0])
    service = DeviceInventoryService(source, SQLiteDeviceRepository(db), capture, baseline)
    capture.items = [packet(ctx, "00:11:22:33:44:55", ctx.gateway, T0),
                     packet(ctx, "00:11:22:33:44:55", "192.168.1.20", T0)]
    assert service.refresh().identity_events == ()
    tick[0] += timedelta(seconds=61)
    capture.items = [packet(ctx, "00:11:22:33:44:55", ctx.gateway, tick[0]),
                     packet(ctx, "00:11:22:33:44:55", "192.168.1.20", tick[0])]
    assert service.refresh().identity_events == ()
    capture.items = [packet(ctx, "00:11:22:33:44:66", ctx.gateway, T0 + timedelta(seconds=62)),
                     packet(ctx, "00:11:22:33:44:66", "192.168.1.20", T0 + timedelta(seconds=62))]
    events = service.refresh().identity_events
    assert {e.rule_id for e in events} == {ArpIdentityRule.IP_MAC_CONFLICT, ArpIdentityRule.GATEWAY_MAC_CHANGE}
    capture.items = [packet(ctx, "00:11:22:33:44:66", ctx.gateway, T0 + timedelta(seconds=63)),
                     packet(ctx, "00:11:22:33:44:66", "192.168.1.20", T0 + timedelta(seconds=63))]
    assert service.refresh().identity_events == ()
    capture.items = [object(), packet(ctx, "00:11:22:33:44:77", "192.168.1.30", T0 + timedelta(seconds=64))]
    after_bad = service.refresh()
    assert after_bad.problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
    assert any(binding.ip_address == "192.168.1.30" for entry in after_bad.entries for binding in entry.bindings)
    with db.connection() as connection:
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "alerts" not in names and "security_events" not in names
    assert service.close()
