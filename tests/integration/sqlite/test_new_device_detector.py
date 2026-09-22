"""NS-023 restart behavior against the existing migrated device repository."""

from datetime import UTC, datetime

from netsentinel.application.detectors.new_device import NewDeviceConfig, NewDeviceDetector
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress,
    NetworkLayerProtocol, PacketObservation,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository


AT = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _context():
    return NetworkContext(
        interface_id="test-adapter", interface_index=1, interface_name="Test adapter",
        interface_kind=NetworkInterfaceKind.ETHERNET, ipv4_address="192.168.1.10",
        subnet="192.168.1.0/24", gateway=None, dns_servers=(), observed_at=AT,
    )


def _packet(context, mac):
    return PacketObservation(
        interface_id=context.interface_id, interface_index=context.interface_index,
        network_fingerprint=context.fingerprint, observed_at=AT,
        captured_length=42, original_length=42,
        link_layer=LinkLayerProtocol.ETHERNET, network_layer=NetworkLayerProtocol.ARP,
        arp=ArpObservation(ArpOpcode.REPLY, MacAddress(mac), "192.168.1.20",
                           MacAddress("ff:ff:ff:ff:ff:ff"), "192.168.1.10"),
    )


def _detector(path):
    return NewDeviceDetector(
        DeviceRegistryService(SQLiteDeviceRepository(SQLiteDatabase(path))),
        config=NewDeviceConfig(warmup_seconds=0), clock=lambda: 0.0,
    )


def test_restart_loads_known_devices_and_only_a_new_mac_emits(tmp_path):
    path = tmp_path / "new-device.sqlite3"
    context = _context()
    first = _detector(path)
    event = first.observe(context, _packet(context, "02:00:00:00:00:01"))
    assert event is not None
    assert first.observe(context, _packet(context, "02:00:00:00:00:01")) is None

    restarted = _detector(path)
    assert restarted.observe(context, _packet(context, "02:00:00:00:00:01")) is None
    next_event = restarted.observe(context, _packet(context, "02:00:00:00:00:02"))
    assert next_event is not None
    assert next_event.event_fingerprint != event.event_fingerprint
    assert _detector(path).observe(context, _packet(context, "02:00:00:00:00:02")) is None

    repository = SQLiteDeviceRepository(SQLiteDatabase(path))
    assert len(repository.list_devices(context.fingerprint)) == 2
    with SQLiteDatabase(path).connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM device_bindings").fetchone()[0] == 2
