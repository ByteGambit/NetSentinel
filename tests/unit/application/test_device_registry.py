"""NS-022 registry tests use portable observations, never a live interface."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.devices import (
    DeviceObservationRejected,
    DeviceRegistryService,
)
from netsentinel.domain.devices import (
    DeviceIdentity,
    IdentityBinding,
    NetworkContext,
    NetworkInterfaceKind,
)
from netsentinel.domain.observations import (
    ArpObservation,
    ArpOpcode,
    LinkLayerProtocol,
    MacAddress,
    NetworkLayerProtocol,
    PacketObservation,
)


NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)


class FakeDeviceRepository:
    def __init__(self) -> None:
        self.devices: dict[object, DeviceIdentity] = {}
        self.bindings: dict[object, IdentityBinding] = {}

    def record_binding(self, device, binding):
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
        return tuple(sorted(
            (d for d in self.devices.values() if d.network_fingerprint == fingerprint),
            key=lambda d: str(d.mac),
        ))

    def list_bindings(self, device_id):
        return tuple(sorted(
            (b for b in self.bindings.values() if b.device_id == device_id),
            key=lambda b: b.ip_address,
        ))


def context(interface="if-a", subnet="192.168.1.0/24"):
    return NetworkContext(
        interface_id=interface, interface_index=1 if interface == "if-a" else 2,
        interface_name=interface, interface_kind=NetworkInterfaceKind.ETHERNET,
        ipv4_address="192.168.1.10" if subnet == "192.168.1.0/24" else "10.0.0.10",
        subnet=subnet, gateway=None, dns_servers=(), observed_at=NOW,
    )


def packet(ctx, *, mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.20", at=NOW,
           opcode=ArpOpcode.REPLY, target_mac="ff:ff:ff:ff:ff:ff",
           target_ip="192.168.1.10"):
    return PacketObservation(
        interface_id=ctx.interface_id, interface_index=ctx.interface_index,
        network_fingerprint=ctx.fingerprint, observed_at=at,
        captured_length=42, original_length=42,
        link_layer=LinkLayerProtocol.ETHERNET,
        network_layer=NetworkLayerProtocol.ARP,
        arp=ArpObservation(opcode, MacAddress(mac), ip,
                           MacAddress(target_mac), target_ip),
    )


def test_empty_first_duplicate_and_out_of_order_timestamps():
    repo = FakeDeviceRepository()
    service = DeviceRegistryService(repo)
    ctx = context()
    assert service.devices(ctx) == ()
    first = service.observe(ctx, packet(ctx))
    assert first is not None
    device, binding = first
    assert device.first_seen == device.last_seen == NOW
    assert binding.first_seen == binding.last_seen == NOW
    service.observe(ctx, packet(ctx, at=NOW + timedelta(seconds=5)))
    service.observe(ctx, packet(ctx, at=NOW - timedelta(seconds=5)))
    service.observe(ctx, packet(ctx, at=NOW + timedelta(seconds=5)))
    current = service.devices(ctx)[0]
    assert current.device_id == device.device_id
    assert current.first_seen == NOW
    assert current.last_seen == NOW + timedelta(seconds=5)
    assert service.bindings(current)[0].first_seen == NOW
    assert service.bindings(current)[0].last_seen == current.last_seen
    assert len(service.devices(ctx)) == len(service.bindings(current)) == 1


def test_ip_change_preserves_binding_history_and_ip_reuse_is_separate_state():
    service = DeviceRegistryService(FakeDeviceRepository())
    ctx = context()
    first = service.observe(ctx, packet(ctx))
    second = service.observe(ctx, packet(ctx, ip="192.168.1.21", at=NOW + timedelta(seconds=1)))
    assert first[0].device_id == second[0].device_id
    assert {b.ip_address for b in service.bindings(second[0])} == {
        "192.168.1.20", "192.168.1.21"
    }
    replacement = service.observe(ctx, packet(ctx, mac="02:11:22:33:44:55"))
    assert replacement[0].device_id != first[0].device_id
    assert len(service.devices(ctx)) == 2
    assert replacement[1].ip_address == first[1].ip_address


def test_network_fingerprint_and_interface_scope():
    service = DeviceRegistryService(FakeDeviceRepository())
    a = context()
    b = context(subnet="10.0.0.0/24")
    c = context(interface="if-b")
    a_device = service.observe(a, packet(a))[0]
    b_device = service.observe(b, packet(b))[0]
    c_device = service.observe(c, packet(c))[0]
    assert len({a_device.device_id, b_device.device_id, c_device.device_id}) == 3
    assert all(len(service.devices(ctx)) == 1 for ctx in (a, b, c))
    with pytest.raises(DeviceObservationRejected):
        service.observe(a, packet(b))
    assert service.devices(a) == (a_device,)


@pytest.mark.parametrize("mac", [
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"
])
def test_non_device_mac_is_ignored(mac):
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    assert service.observe(ctx, packet(ctx, mac=mac)) is None
    assert service.devices(ctx) == ()


@pytest.mark.parametrize("ip", ["0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.1"])
def test_non_device_sender_ip_is_ignored(ip):
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    assert service.observe(ctx, packet(ctx, ip=ip)) is None
    assert service.devices(ctx) == ()


@pytest.mark.parametrize("opcode", [ArpOpcode.REQUEST, ArpOpcode.REPLY])
def test_request_and_reply_use_sender_only(opcode):
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    result = service.observe(ctx, packet(ctx, opcode=opcode,
        target_mac="02:00:00:00:00:02", target_ip="192.168.1.99"))
    assert result[0].mac == MacAddress("aa:bb:cc:dd:ee:ff")
    assert result[1].ip_address == "192.168.1.20"
    assert len(service.devices(ctx)) == 1


def test_local_mac_canonical_equality_stable_order_and_invalid_isolation():
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    service.observe(ctx, packet(ctx, mac="02-00-00-00-00-02"))
    service.observe(ctx, packet(ctx, mac="02:00:00:00:00:01"))
    service.observe(ctx, packet(ctx, mac="02:00:00:00:00:02"))
    assert [str(d.mac) for d in service.devices(ctx)] == [
        "02:00:00:00:00:01", "02:00:00:00:00:02"
    ]
    with pytest.raises(TypeError):
        service.observe(ctx, object())
    assert len(service.devices(ctx)) == 2


def test_naive_timestamp_rejected_before_state_mutation():
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    with pytest.raises(ValueError):
        packet(ctx, at=NOW.replace(tzinfo=None))
    assert service.devices(ctx) == ()


def test_non_arp_packet_does_not_create_device():
    ctx = context()
    service = DeviceRegistryService(FakeDeviceRepository())
    non_arp = PacketObservation(
        interface_id=ctx.interface_id, interface_index=ctx.interface_index,
        network_fingerprint=ctx.fingerprint, observed_at=NOW,
        captured_length=42, original_length=42,
        link_layer=LinkLayerProtocol.ETHERNET,
        network_layer=NetworkLayerProtocol.IPV4,
    )
    assert service.observe(ctx, non_arp) is None
    assert service.devices(ctx) == ()
