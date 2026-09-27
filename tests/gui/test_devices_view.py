"""NS-024 offscreen device inventory and worker-boundary tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread
import ast

import pytest
from PyQt6.QtCore import QThread, Qt
from pytestqt.qtbot import QtBot

from netsentinel.application.services.device_inventory import (
    DeviceInventoryEntry, DeviceInventoryProblem, DeviceInventoryService,
    DeviceInventorySnapshot,
)
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.domain.alerts import NewDeviceDetected
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress, NetworkLayerProtocol, PacketObservation
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator
from netsentinel.presentation.app import create_application
from netsentinel.presentation.models.devices import format_seen
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.shared.diagnostics import (CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState, CapabilityStatus)
from tests.gui._ns013_support import FakeEngine


AT = datetime(2026, 9, 22, 12, tzinfo=UTC)


def context(name="Ethernet", subnet="192.168.1.0/24"):
    return NetworkContext(interface_id=name, interface_index=1, interface_name=name,
        interface_kind=NetworkInterfaceKind.ETHERNET,
        ipv4_address="192.168.1.10" if subnet.startswith("192") else "10.0.0.10",
        subnet=subnet, gateway=None, dns_servers=(), observed_at=AT)


def entry(ctx, mac="02:11:22:33:44:55", ip="192.168.1.40", at=AT, old=()):
    address = MacAddress(mac)
    device = DeviceIdentity(ctx.fingerprint, address, AT, at)
    bindings = (IdentityBinding(ctx.fingerprint, address, ip, at, at), *old)
    return DeviceInventoryEntry(device, bindings, ctx.interface_name, ctx.subnet)


def health(state=CaptureState.STOPPED, reason=CaptureCapabilityReason.NOT_PROBED):
    status = CapabilityStatus.AVAILABLE if reason is CaptureCapabilityReason.NONE else CapabilityStatus.UNAVAILABLE
    return CaptureHealthSnapshot(state, CaptureCapabilitySnapshot(status, reason, AT),
        0, 128, CaptureCounters(),
        selected_interface_id="Ethernet" if state is CaptureState.RUNNING else None,
        network_fingerprint=context().fingerprint if state is CaptureState.RUNNING else None,
        worker_alive=state is CaptureState.RUNNING)


def snapshot(ctx=None, entries=(), *, capability=None, problem=DeviceInventoryProblem.NONE, events=()):
    if ctx is None:
        return DeviceInventorySnapshot((), None, (), capability or health(), problem, events)
    return DeviceInventorySnapshot((ctx,), ctx.fingerprint, tuple(entries), capability or health(), problem, tuple(events))


def packet(ctx, mac="02:11:22:33:44:55", ip="192.168.1.40", at=AT):
    return PacketObservation(interface_id=ctx.interface_id, interface_index=ctx.interface_index,
        network_fingerprint=ctx.fingerprint, observed_at=at, captured_length=42,
        original_length=42, link_layer=LinkLayerProtocol.ETHERNET,
        network_layer=NetworkLayerProtocol.ARP,
        arp=ArpObservation(ArpOpcode.REPLY, MacAddress(mac), ip,
            MacAddress("ff:ff:ff:ff:ff:ff"), "192.168.1.10"))


class FakeRepository:
    def __init__(self):
        self.devices = {}
        self.bindings = {}
        self.fail = False

    def record_binding(self, device, binding):
        prior = self.devices.get(device.device_id)
        old_binding = self.bindings.get(binding.binding_id)
        if prior is not None:
            device = replace(prior, last_seen=max(prior.last_seen, device.last_seen))
        if old_binding is not None:
            binding = replace(old_binding, last_seen=max(old_binding.last_seen, binding.last_seen))
        self.devices[device.device_id] = device
        self.bindings[binding.binding_id] = binding
        return device, binding

    def list_devices(self, fingerprint):
        if self.fail:
            raise RuntimeError("SELECT secret FROM C:\\private\\devices.sqlite3")
        return tuple(device for device in self.devices.values() if device.network_fingerprint == fingerprint)

    def list_bindings(self, device_id, limit=None):
        return tuple(sorted((binding for binding in self.bindings.values() if binding.device_id == device_id),
            key=lambda binding: binding.last_seen, reverse=True))[:limit]

    def latest_binding_for_ip(self, fingerprint, ip):
        values = (binding for binding in self.bindings.values()
                  if binding.network_fingerprint == fingerprint and binding.ip_address == ip)
        return max(values, key=lambda binding: binding.last_seen, default=None)


class FakeContexts:
    def __init__(self, *contexts):
        self.contexts = contexts

    def get_contexts(self):
        return self.contexts


class FakeCapture:
    def __init__(self):
        self.state = health()
        self.observations = []
        self.start_calls = 0
        self.stop_calls = 0

    def health_snapshot(self):
        return self.state

    def probe(self, selected):
        self.state = replace(self.state, capability=CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT))
        return self.state.capability

    def start(self, request):
        self.start_calls += 1
        self.state = replace(self.state, state=CaptureState.RUNNING,
            selected_interface_id=request.context.interface_id,
            network_fingerprint=request.context.fingerprint, worker_alive=True)
        return True

    def stop(self, timeout=None):
        self.stop_calls += 1
        self.state = replace(self.state, state=CaptureState.STOPPED,
            selected_interface_id=None, network_fingerprint=None, worker_alive=False)
        return True

    def drain(self, limit):
        result = tuple(self.observations[:limit])
        del self.observations[:limit]
        return result


def test_placeholder_replaced_and_empty_capability_is_honest(qtbot: QtBot):
    window = MainWindow()
    qtbot.addWidget(window)
    view = window.page_widget(PageId.DEVICES)
    assert isinstance(view, DevicesView)
    assert view.table.accessibleName() == "Devices table"
    assert view.details.accessibleName() == "Device details"
    assert view.search_edit.accessibleName()
    assert view.network_selector.accessibleName()
    assert view.model.rowCount() == 0
    assert "capture is off" in view.status_label.text().lower()
    view.set_snapshot(snapshot(context(), capability=health(reason=CaptureCapabilityReason.PERMISSION_DENIED)))
    assert "permission" in view.status_label.text().lower()
    assert "Traceback" not in view.status_label.text()


def test_identity_bindings_selection_search_and_network_scope(qtbot: QtBot):
    view = DevicesView()
    qtbot.addWidget(view)
    view.show()
    a = context()
    b = context("VPN", "10.0.0.0/24")
    first = entry(a)
    second = entry(a, mac="02:11:22:33:44:66", ip="192.168.1.40")
    view.set_snapshot(snapshot(a, (first, second)))
    assert view.model.rowCount() == 2
    assert view.proxy_model.rowCount() == 2
    assert view.model.index(0, 0).data() == "02:11:22:33:44:55"
    assert view.model.index(0, 1).data() == "192.168.1.40"
    assert view.model.index(0, 2).data() == format_seen(AT)
    view.table.setCurrentIndex(view.proxy_model.index(0, 0))
    selected = view.selected_row_id
    assert selected == first.device.device_id
    assert view.details.values["local"].text() == "Yes"
    old = IdentityBinding(a.fingerprint, first.device.mac, "192.168.1.18", AT, AT)
    updated = entry(a, ip="192.168.1.41", at=AT + timedelta(seconds=5), old=(old,))
    view.set_snapshot(snapshot(a, (updated, second)))
    assert view.model.rowCount() == 2
    assert view.selected_row_id == selected
    assert view.details.values["ip"].text() == "192.168.1.41"
    assert "192.168.1.18" in view.details.values["bindings"].text()
    assert view.details.values["last"].text() == format_seen(AT + timedelta(seconds=5))
    view.set_snapshot(snapshot(a, (first, second)))
    assert view.details.values["last"].text() == format_seen(AT + timedelta(seconds=5))
    view.search_edit.setText("44:66")
    assert view.proxy_model.rowCount() == 1
    assert view.selected_row_id is None
    view.search_edit.clear()
    view.set_snapshot(snapshot(b, (entry(b, ip="10.0.0.40"),)))
    assert view.model.rowCount() == 1
    assert view.model.row_at(0).row_id != selected
    assert view.details.values["mac"].text() == "—"


def test_duplicate_and_out_of_order_rows_do_not_regress(qtbot: QtBot):
    view = DevicesView()
    qtbot.addWidget(view)
    ctx = context()
    newer = entry(ctx, ip="192.168.1.41", at=AT + timedelta(seconds=5))
    older = entry(ctx)
    view.set_snapshot(snapshot(ctx, (newer, older, newer)))
    assert view.model.rowCount() == 1
    assert view.model.row_at(0).ip_address == "192.168.1.41"
    assert view.model.row_at(0).first_seen == AT
    view.set_snapshot(snapshot(ctx, (older,)))
    assert view.model.row_at(0).last_seen == AT + timedelta(seconds=5)


def test_model_rejects_worker_thread_mutation(qtbot: QtBot):
    view = DevicesView()
    qtbot.addWidget(view)
    errors = []
    worker = Thread(target=lambda: _worker_apply(view, errors))
    worker.start()
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert errors == ["DevicesTableModel mutations must run in its Qt thread"]
    assert view.model.rowCount() == 0


def _worker_apply(view, errors):
    try:
        view.model.apply(context().fingerprint, (entry(context()),))
    except RuntimeError as error:
        errors.append(str(error))


def test_keyboard_selection_and_info_event(qtbot: QtBot):
    view = DevicesView()
    qtbot.addWidget(view)
    view.show()
    ctx = context()
    one, two = entry(ctx), entry(ctx, mac="02:11:22:33:44:66")
    event = NewDeviceDetected(one.device, one.bindings[0], AT)
    view.set_snapshot(snapshot(ctx, (one, two), events=(event,)))
    assert "New device observed" in view.event_label.text()
    assert "attack" not in view.event_label.text().lower()
    view.table.setFocus()
    view.table.setCurrentIndex(view.proxy_model.index(0, 0))
    qtbot.keyClick(view.table, Qt.Key.Key_Down)
    assert view.selected_row_id == two.device.device_id
    assert view.details.values["mac"].text() == str(two.device.mac)


def test_service_restart_live_observation_warmup_and_repository_error():
    ctx = context()
    repository = FakeRepository()
    capture = FakeCapture()
    service = DeviceInventoryService(FakeContexts(ctx), repository, capture)
    initial = service.refresh()
    assert initial.entries == ()
    assert capture.start_calls == 0
    assert service.refresh(start_capture=True).capture.state is CaptureState.RUNNING
    capture.observations.extend((packet(ctx), packet(ctx)))
    current = service.refresh()
    assert len(current.entries) == 1
    assert current.new_devices == ()  # detector owns the 60-second warm-up
    capture.observations.append(packet(ctx, ip="192.168.1.41", at=AT + timedelta(seconds=5)))
    assert len(service.refresh().entries[0].bindings) == 2
    service.close()
    restarted = DeviceInventoryService(FakeContexts(ctx), repository, FakeCapture())
    assert len(restarted.refresh().entries) == 1
    repository.fail = True
    unavailable = restarted.refresh()
    assert unavailable.problem is DeviceInventoryProblem.REPOSITORY_UNAVAILABLE
    view = DevicesView()
    view.set_snapshot(unavailable)
    assert "SELECT secret" not in view.status_label.text()
    assert "devices.sqlite3" not in view.status_label.text()


def test_service_context_switch_keeps_networks_separate_and_stops_old_capture():
    a = context()
    b = context("VPN", "10.0.0.0/24")
    repository = FakeRepository()
    registry = DeviceRegistryService(repository)
    registry.observe(a, packet(a))
    registry.observe(b, packet(b, ip="10.0.0.40"))
    capture = FakeCapture()
    service = DeviceInventoryService(FakeContexts(a, b), repository, capture)
    first = service.refresh(start_capture=True)
    assert first.selected_fingerprint == a.fingerprint
    assert len(first.entries) == 1
    assert first.entries[0].device.network_fingerprint == a.fingerprint
    switched = service.refresh(select=b.fingerprint)
    assert switched.selected_fingerprint == b.fingerprint
    assert len(switched.entries) == 1
    assert switched.entries[0].device.network_fingerprint == b.fingerprint
    assert switched.entries[0].bindings[0].ip_address == "10.0.0.40"
    assert capture.stop_calls == 1
    assert switched.capture.state is CaptureState.STOPPED


def test_worker_delivers_portable_snapshot_on_qt_thread_and_stops(qtbot: QtBot):
    ctx = context()
    repository = FakeRepository()
    DeviceRegistryService(repository).observe(ctx, packet(ctx))
    capture = FakeCapture()
    coordinator = DeviceInventoryCoordinator(lambda: DeviceInventoryService(FakeContexts(ctx), repository, capture))
    view = DevicesView(coordinator=coordinator)
    qtbot.addWidget(view)
    delivered = []
    coordinator.snapshot_ready.connect(lambda _value: delivered.append(QThread.currentThread() is view.thread()))
    assert coordinator.start()
    assert coordinator.request("refresh")
    qtbot.waitUntil(lambda: view.model.rowCount() == 1, timeout=3000)
    assert delivered and all(delivered)
    assert coordinator.stop()
    assert not coordinator.worker_alive
    before = view.model.rowCount()
    assert not coordinator.request("refresh")
    assert view.model.rowCount() == before


def test_desktop_composition_starts_loads_and_stops_inventory(qtbot: QtBot):
    ctx = context()
    repository = FakeRepository()
    DeviceRegistryService(repository).observe(ctx, packet(ctx))
    capture = FakeCapture()
    shell = create_application(FakeEngine(), argv=[],
        device_service_factory=lambda: DeviceInventoryService(FakeContexts(ctx), repository, capture))
    qtbot.addWidget(shell.window)
    assert shell.lifecycle.start()
    view = shell.window.page_widget(PageId.DEVICES)
    qtbot.waitUntil(lambda: view.model.rowCount() == 1, timeout=3000)
    assert shell.device_inventory.worker_alive
    shell.window.close()
    assert not shell.device_inventory.worker_alive
    assert capture.stop_calls == 1
    before = view.model.rowCount()
    shell.device_inventory.snapshot_ready.emit(snapshot(ctx, (entry(ctx, mac="02:11:22:33:44:66"),)))
    assert view.model.rowCount() == before


@pytest.mark.parametrize("problem,phrase", [
    (DeviceInventoryProblem.CONTEXT_PERMISSION, "access was denied"),
    (DeviceInventoryProblem.CONTEXT_UNAVAILABLE, "temporarily unavailable"),
    (DeviceInventoryProblem.REPOSITORY_UNAVAILABLE, "inventory is unavailable"),
    (DeviceInventoryProblem.ALERT_UNAVAILABLE, "alerts could not be saved"),
])
def test_typed_failure_messages(problem, phrase):
    view = DevicesView()
    view.set_snapshot(snapshot(problem=problem))
    assert phrase in view.status_label.text().lower()


@pytest.mark.parametrize("reason,phrase", [
    (CaptureCapabilityReason.PERMISSION_DENIED, "permission"),
    (CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE, "npcap"),
    (CaptureCapabilityReason.INTERFACE_UNAVAILABLE, "interface"),
    (CaptureCapabilityReason.NETWORK_CHANGED, "interface"),
    (CaptureCapabilityReason.TRANSIENT_FAILURE, "temporarily"),
])
def test_capture_capability_messages_are_sanitized(reason, phrase):
    view = DevicesView()
    view.set_snapshot(snapshot(context(), capability=health(reason=reason)))
    assert phrase in view.status_label.text().lower()
    assert "Traceback" not in view.status_label.text()


def test_device_presentation_and_core_dependency_boundaries():
    root = Path(__file__).resolve().parents[2] / "src" / "netsentinel"
    presentation_files = (
        root / "presentation" / "views" / "devices.py",
        root / "presentation" / "models" / "devices.py",
        root / "presentation" / "device_inventory.py",
    )
    for path in presentation_files:
        imported = _imports(path)
        assert not any(name == "netsentinel.infrastructure" or name.startswith("netsentinel.infrastructure.") for name in imported)
        assert not any(name.split(".")[0] in {"scapy", "sqlite3", "psutil"} for name in imported)
    for folder in (root / "application", root / "domain"):
        for path in folder.rglob("*.py"):
            assert not any(name.startswith("PyQt6") for name in _imports(path))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names
