"""NS-024 persisted inventory load and bounded binding reads."""

from datetime import UTC, datetime, timedelta
import os
import sys
from time import sleep

import pytest

from netsentinel.application.services.device_inventory import DeviceInventoryService, MAX_VISIBLE_BINDINGS
from netsentinel.bootstrap import create_network_context_provider, create_packet_capture
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.shared.diagnostics import (CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState, CapabilityStatus)


AT = datetime(2026, 9, 22, 12, tzinfo=UTC)


class Contexts:
    def __init__(self, context):
        self.context = context

    def get_contexts(self):
        return (self.context,)


class DormantCapture:
    def __init__(self):
        self.stopped = False
        self.snapshot = CaptureHealthSnapshot(CaptureState.STOPPED,
            CaptureCapabilitySnapshot(CapabilityStatus.UNAVAILABLE, CaptureCapabilityReason.NOT_PROBED, AT),
            0, 128, CaptureCounters())

    def health_snapshot(self):
        return self.snapshot

    def probe(self, _context):
        return self.snapshot.capability

    def stop(self, timeout=None):
        self.stopped = True
        return True

    def start(self, _request):
        raise AssertionError("capture must not start on inventory load")

    def drain(self, _limit):
        return ()


def test_restart_loads_saved_device_and_recent_bindings_without_capture(tmp_path):
    ctx = NetworkContext("adapter", 1, "Ethernet", NetworkInterfaceKind.ETHERNET,
        "192.168.1.10", "192.168.1.0/24", None, (), AT)
    database = SQLiteDatabase(tmp_path / "inventory.sqlite3")
    repo = SQLiteDeviceRepository(database)
    mac = MacAddress("02:11:22:33:44:55")
    for number in range(1, MAX_VISIBLE_BINDINGS + 5):
        at = AT + timedelta(seconds=number)
        device = DeviceIdentity(ctx.fingerprint, mac, at, at)
        binding = IdentityBinding(ctx.fingerprint, mac, f"192.168.1.{number}", at, at)
        repo.record_binding(device, binding)
    capture = DormantCapture()
    service = DeviceInventoryService(Contexts(ctx), SQLiteDeviceRepository(database), capture)
    inventory = service.refresh()
    assert len(inventory.entries) == 1
    assert len(inventory.entries[0].bindings) == MAX_VISIBLE_BINDINGS
    assert inventory.entries[0].bindings[0].ip_address == f"192.168.1.{MAX_VISIBLE_BINDINGS + 4}"
    assert inventory.entries[0].device.first_seen == AT + timedelta(seconds=1)
    assert inventory.entries[0].device.last_seen == AT + timedelta(seconds=MAX_VISIBLE_BINDINGS + 4)
    assert inventory.capture.state is CaptureState.STOPPED
    assert not capture.stopped
    assert service.close()
    assert capture.stopped


@pytest.mark.lab_live
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only passive lab capture")
def test_authorized_lab_device_pipeline_is_passive(tmp_path):
    if os.environ.get("NETSENTINEL_LAB_CAPTURE") != "1":
        pytest.skip("set NETSENTINEL_LAB_CAPTURE=1 only on an authorized lab network")
    interface_name = os.environ.get("NETSENTINEL_LAB_INTERFACE_NAME")
    subnet = os.environ.get("NETSENTINEL_LAB_SUBNET")
    if not interface_name or not subnet:
        pytest.skip("explicit NETSENTINEL_LAB_INTERFACE_NAME and NETSENTINEL_LAB_SUBNET are required")
    provider = create_network_context_provider()
    contexts = tuple(context for context in provider.get_contexts()
        if context.is_default_capture_candidate and context.interface_name == interface_name and context.subnet == subnet)
    if len(contexts) != 1:
        pytest.skip("selected authorized interface/subnet is not uniquely available")
    context = contexts[0]
    capture = create_packet_capture(context_provider=provider, startup_timeout=1.0, shutdown_timeout=1.0)
    service = DeviceInventoryService(provider, SQLiteDeviceRepository(SQLiteDatabase(tmp_path / "lab-devices.sqlite3")), capture)
    try:
        initial = service.refresh(select=context.fingerprint)
        if initial.capture.capability.status is not CapabilityStatus.AVAILABLE:
            pytest.skip("passive capture unavailable on selected interface")
        started = service.refresh(start_capture=True)
        if started.capture.state is not CaptureState.RUNNING:
            pytest.skip("passive capture could not start on selected interface")
        sleep(0.5)
        result = service.refresh()
        assert all(entry.device.network_fingerprint == context.fingerprint for entry in result.entries)
        assert all(len(entry.bindings) <= MAX_VISIBLE_BINDINGS for entry in result.entries)
    finally:
        assert service.close()
