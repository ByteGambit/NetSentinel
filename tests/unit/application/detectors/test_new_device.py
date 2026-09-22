"""NS-023 detector scenarios use fake time and portable ARP observations."""

import ast
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netsentinel.application.detectors.new_device import NewDeviceConfig, NewDeviceDetector
from netsentinel.application.ports import DeviceDataCorrupt, DeviceRepositoryError
from netsentinel.application.services.devices import DeviceObservationRejected, DeviceRegistryService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress,
    NetworkLayerProtocol, PacketObservation,
)


T0 = datetime(2026, 9, 23, 10, tzinfo=UTC)


class Repository:
    def __init__(self):
        self.devices = {}
        self.bindings = {}
        self.fail_write = False
        self.fail_read = False

    def record_binding(self, device, binding):
        if self.fail_write:
            raise DeviceRepositoryError("write failed")
        old_device = self.devices.get(device.device_id)
        old_binding = self.bindings.get(binding.binding_id)
        if old_device is not None:
            device = replace(old_device, last_seen=max(old_device.last_seen, device.last_seen))
        if old_binding is not None:
            binding = replace(old_binding, last_seen=max(old_binding.last_seen, binding.last_seen))
        self.devices[device.device_id] = device
        self.bindings[binding.binding_id] = binding
        return device, binding

    def list_devices(self, fingerprint):
        if self.fail_read:
            raise DeviceRepositoryError("read failed")
        return tuple(sorted(
            (d for d in self.devices.values() if d.network_fingerprint == fingerprint),
            key=lambda d: str(d.mac),
        ))

    def list_bindings(self, device_id):
        return tuple(b for b in self.bindings.values() if b.device_id == device_id)


def context(*, interface="if-a", subnet="192.168.1.0/24"):
    return NetworkContext(
        interface_id=interface, interface_index=1 if interface == "if-a" else 2,
        interface_name=interface, interface_kind=NetworkInterfaceKind.ETHERNET,
        ipv4_address="192.168.1.10" if subnet == "192.168.1.0/24" else "10.0.0.10",
        subnet=subnet, gateway=None, dns_servers=(), observed_at=T0,
    )


def packet(ctx, *, mac="02:11:22:33:44:55", ip="192.168.1.20", at=T0,
           opcode=ArpOpcode.REPLY, target_mac="ff:ff:ff:ff:ff:ff"):
    return PacketObservation(
        interface_id=ctx.interface_id, interface_index=ctx.interface_index,
        network_fingerprint=ctx.fingerprint, observed_at=at,
        captured_length=42, original_length=42,
        link_layer=LinkLayerProtocol.ETHERNET, network_layer=NetworkLayerProtocol.ARP,
        arp=ArpObservation(opcode, MacAddress(mac), ip, MacAddress(target_mac),
                           "192.168.1.10"),
    )


def detector(repo, ticks, *, warmup=10):
    return NewDeviceDetector(
        DeviceRegistryService(repo), config=NewDeviceConfig(warmup),
        clock=lambda: ticks[0],
    )


def test_empty_context_import_warmup_and_new_device_event_once():
    repo = Repository()
    ticks = [100.0]
    detect = detector(repo, ticks)
    ctx = context()
    assert detect.observe(ctx, packet(ctx)) is None
    ticks[0] = 109.99
    assert detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56")) is None
    assert len(repo.devices) == 2  # Import is persisted without events.
    ticks[0] = 110.0
    event = detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:57"))
    assert event.rule_id == "new_device"
    assert event.severity == "info"
    assert event.confidence == "passive_observation"
    assert event.device.network_fingerprint == ctx.fingerprint
    assert event.entity_id == event.device.device_id
    assert event.binding.ip_address == "192.168.1.20"
    assert event.observed_at == T0
    assert detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:57")) is None
    assert detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:55")) is None


def test_seeded_restart_known_device_and_new_mac_without_warmup():
    repo = Repository()
    ctx = context()
    registry = DeviceRegistryService(repo)
    registry.observe(ctx, packet(ctx))
    ticks = [0.0]
    detect = detector(repo, ticks, warmup=600)
    assert detect.observe(ctx, packet(ctx)) is None
    event = detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56"))
    assert event is not None
    assert len(repo.devices) == 2
    restarted = detector(repo, ticks, warmup=600)
    assert restarted.observe(ctx, packet(ctx, mac="02:11:22:33:44:56")) is None
    assert restarted.observe(ctx, packet(ctx, mac="02:11:22:33:44:55")) is None
    assert restarted.observe(ctx, packet(ctx, mac="02:11:22:33:44:57")) is not None


def test_ip_binding_changes_do_not_create_device_events_or_change_identity():
    repo = Repository()
    ctx = context()
    initial = DeviceRegistryService(repo).observe(ctx, packet(ctx))[0]
    detect = detector(repo, [0.0])
    assert detect.observe(ctx, packet(ctx, ip="192.168.1.21")) is None
    assert len(repo.devices) == 1
    assert len(repo.bindings) == 2
    event = detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56"))
    assert event is not None
    assert event.binding.ip_address == "192.168.1.20"  # Same IP, other MAC.
    assert event.device.device_id != initial.device_id


def test_network_fingerprint_scope_and_mismatched_observation():
    repo = Repository()
    a = context()
    b = context(subnet="10.0.0.0/24")
    c = context(interface="if-b")
    for ctx in (a, b, c):
        DeviceRegistryService(repo).observe(ctx, packet(ctx))
    detect = detector(repo, [0.0])
    events = [detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56")) for ctx in (a, b, c)]
    assert all(event is not None for event in events)
    assert len({event.entity_id for event in events}) == 3
    assert len({event.event_fingerprint for event in events}) == 3
    with pytest.raises(DeviceObservationRejected):
        detect.observe(a, packet(b, mac="02:11:22:33:44:57"))
    assert len(repo.devices) == 6


@pytest.mark.parametrize("mac,ip", [
    ("00:00:00:00:00:00", "192.168.1.20"),
    ("ff:ff:ff:ff:ff:ff", "192.168.1.20"),
    ("01:00:5e:00:00:01", "192.168.1.20"),
    ("02:11:22:33:44:55", "0.0.0.0"),
    ("02:11:22:33:44:55", "127.0.0.1"),
    ("02:11:22:33:44:55", "224.0.0.1"),
])
def test_special_sender_does_not_start_warmup_or_create_event(mac, ip):
    repo = Repository()
    ticks = [0.0]
    detect = detector(repo, ticks)
    ctx = context()
    assert detect.observe(ctx, packet(ctx, mac=mac, ip=ip)) is None
    ticks[0] = 100.0
    assert detect.observe(ctx, packet(ctx)) is None
    assert len(repo.devices) == 1


def test_non_arp_invalid_time_and_error_isolation():
    repo = Repository()
    ctx = context()
    ticks = [0.0]
    detect = detector(repo, ticks)
    no_arp = replace(packet(ctx), network_layer=NetworkLayerProtocol.IPV4, arp=None)
    assert detect.observe(ctx, no_arp) is None
    with pytest.raises(ValueError):
        packet(ctx, at=T0.replace(tzinfo=None))
    with pytest.raises(TypeError):
        detect.observe(ctx, object())
    repo.fail_read = True
    # Already initialized context; a read failure on a new context is isolated.
    with pytest.raises(DeviceRepositoryError):
        detect.observe(context(interface="if-b"), packet(context(interface="if-b")))
    repo.fail_read = False
    repo.fail_write = True
    with pytest.raises(DeviceRepositoryError):
        detect.observe(ctx, packet(ctx))
    repo.fail_write = False
    assert detect.observe(ctx, packet(ctx)) is None
    assert len(repo.devices) == 1


def test_old_and_duplicate_observations_never_advance_event_or_device_time():
    repo = Repository()
    ctx = context()
    DeviceRegistryService(repo).observe(ctx, packet(ctx, at=T0))
    detect = detector(repo, [0.0])
    event = detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56", at=T0 + timedelta(seconds=2)))
    assert event is not None
    assert detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56", at=T0 - timedelta(seconds=2))) is None
    assert detect.observe(ctx, packet(ctx, mac="02:11:22:33:44:56", at=T0 + timedelta(seconds=2))) is None
    assert repo.devices[event.entity_id].last_seen == T0 + timedelta(seconds=2)


@pytest.mark.parametrize("value", [-1, float("inf"), float("nan"), True, "5"])
def test_invalid_warmup_config(value):
    with pytest.raises((TypeError, ValueError)):
        NewDeviceConfig(value)


def test_zero_warmup_explicitly_emits_first_device():
    repo = Repository()
    ctx = context()
    event = detector(repo, [0.0], warmup=0).observe(ctx, packet(ctx, opcode=ArpOpcode.REQUEST))
    assert event is not None
    assert event.device.mac == MacAddress("02:11:22:33:44:55")


def test_sender_only_event_is_immutable_and_dedup_id_ignores_ip_and_time():
    repo = Repository()
    ctx = context()
    detect = detector(repo, [0.0], warmup=0)
    event = detect.observe(ctx, packet(
        ctx, opcode=ArpOpcode.REQUEST, target_mac="02:ff:ee:dd:cc:bb"))
    assert event is not None
    assert event.device.mac == MacAddress("02:11:22:33:44:55")
    assert len(repo.devices) == 1  # ARP target is not a second device.
    with pytest.raises(AttributeError):
        event.rule_id = "other"
    other = detector(Repository(), [0.0], warmup=0).observe(
        ctx, packet(ctx, ip="192.168.1.99", at=T0 + timedelta(days=1)))
    assert other is not None
    assert event.event_fingerprint == other.event_fingerprint


def test_corrupt_known_device_state_blocks_detection_without_write():
    class CorruptRepository(Repository):
        def list_devices(self, fingerprint):
            raise DeviceDataCorrupt("invalid stored device")

    repo = CorruptRepository()
    ctx = context()
    with pytest.raises(DeviceDataCorrupt):
        detector(repo, [0.0], warmup=0).observe(ctx, packet(ctx))
    assert repo.devices == {}


def test_ns023_domain_and_application_dependency_boundary():
    source_root = Path(__file__).resolve().parents[4] / "src" / "netsentinel"
    forbidden = {"PyQt6", "scapy", "sqlite3", "ctypes", "netsentinel.infrastructure"}
    for path in (source_root / "domain" / "alerts.py",
                 source_root / "application" / "detectors" / "new_device.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        assert not any(name == blocked or name.startswith(blocked + ".")
                       for name in imported for blocked in forbidden)
