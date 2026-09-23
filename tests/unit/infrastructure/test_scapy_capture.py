"""NS-020 fake-backend tests for safe bounded passive capture."""

from __future__ import annotations

import ast
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from time import monotonic

import pytest

from netsentinel.application.ports import (
    NetworkContextPermissionDenied,
    NetworkContextProvider,
    NetworkContextUnavailable,
    PacketCapture,
    PacketCaptureDependencyUnavailable,
    PacketCaptureInterfaceUnavailable,
    PacketCaptureNetworkChanged,
    PacketCapturePermissionDenied,
    PacketCaptureRequest,
    PacketCaptureTransientError,
)
from netsentinel.bootstrap import create_packet_capture
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    LinkLayerProtocol,
    NetworkLayerProtocol,
    ObservationSource,
)
from netsentinel.infrastructure.scapy_capture import (
    ScapyCaptureWorker,
    _resolve_scapy_interface,
)
from netsentinel.shared.diagnostics import (
    CapabilityStatus,
    CaptureCapabilityReason,
    CaptureState,
    DiagnosticCode,
)
from tests.fixtures.packets.dns import dns_query


NOW = datetime(2026, 9, 21, 13, 0, tzinfo=UTC)


def context(**overrides: object) -> NetworkContext:
    values: dict[str, object] = {
        "interface_id": "{WIFI-ADAPTER}",
        "interface_index": 12,
        "interface_name": "Wi-Fi",
        "interface_kind": NetworkInterfaceKind.WIFI,
        "ipv4_address": "192.168.50.25",
        "subnet": "192.168.50.0/24",
        "gateway": "192.168.50.1",
        "dns_servers": ("1.1.1.1",),
        "observed_at": NOW,
    }
    values.update(overrides)
    return NetworkContext(**values)  # type: ignore[arg-type]


class FakeContextProvider:
    def __init__(self, contexts: tuple[NetworkContext, ...]) -> None:
        self.contexts = contexts
        self.error: BaseException | None = None
        self.calls = 0

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.contexts


class FakePacket:
    def __init__(
        self,
        length: int = 64,
        *,
        wirelen: int | None = None,
        layers: tuple[str, ...] = ("Ether", "ARP"),
    ) -> None:
        self._length = length
        self.wirelen = wirelen
        self._layers = frozenset(layers)
        self.payload = b"secret payload that must never cross the adapter"
        self._ether = SimpleNamespace(
            type=0x0806,
            src="aa:bb:cc:dd:ee:ff",
            dst="ff:ff:ff:ff:ff:ff",
        )
        self._arp = SimpleNamespace(
            hwtype=1,
            ptype=0x0800,
            hwlen=6,
            plen=4,
            op=1,
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.50.20",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.50.1",
        )

    def __len__(self) -> int:
        return self._length

    def haslayer(self, name: str) -> bool:
        return name in self._layers

    def getlayer(self, name: str) -> object | None:
        if name in {"Ether", "Ethernet"} and name in self._layers:
            return self._ether
        if name == "ARP" and name in self._layers:
            return self._arp
        return None


class MalformedPacket:
    wirelen = None

    def __len__(self) -> int:
        raise ValueError("raw malformed packet detail")


class FakeSniffer:
    def __init__(
        self,
        callback: Callable[[object], None],
        *,
        start_packets: tuple[object, ...] = (),
        stubborn: bool = False,
    ) -> None:
        self.callback = callback
        self.start_packets = start_packets
        self.stubborn = stubborn
        self.alive = False
        self.closed = False
        self.start_calls = 0
        self.stop_calls = 0
        self.join_calls: list[float] = []
        self.start_error: BaseException | None = None
        self.join_error: BaseException | None = None

    def start(self, timeout: float) -> None:
        self.start_calls += 1
        if self.start_error is not None:
            raise self.start_error
        self.alive = True
        for packet in self.start_packets:
            self.callback(packet)

    def request_stop(self) -> None:
        self.stop_calls += 1
        if not self.stubborn:
            self.alive = False

    def join(self, timeout: float) -> None:
        self.join_calls.append(timeout)
        if self.join_error is not None:
            raise self.join_error

    def is_alive(self) -> bool:
        return self.alive

    def close(self) -> None:
        self.closed = True

    def emit(self, packet: object) -> None:
        self.callback(packet)


class FakeBackend:
    def __init__(self) -> None:
        self.probe_error: BaseException | None = None
        self.create_error: BaseException | None = None
        self.start_error: BaseException | None = None
        self.start_packets: tuple[object, ...] = ()
        self.stubborn = False
        self.probed: list[str] = []
        self.created: list[tuple[str, str]] = []
        self.handles: list[FakeSniffer] = []

    def probe(self, interface_id: str) -> None:
        self.probed.append(interface_id)
        if self.probe_error is not None:
            raise self.probe_error

    def create(
        self,
        *,
        interface_id: str,
        capture_filter: str,
        callback: Callable[[object], None],
    ) -> FakeSniffer:
        self.created.append((interface_id, capture_filter))
        if self.create_error is not None:
            raise self.create_error
        handle = FakeSniffer(
            callback,
            start_packets=self.start_packets,
            stubborn=self.stubborn,
        )
        handle.start_error = self.start_error
        self.handles.append(handle)
        return handle


def worker_for(
    provider: FakeContextProvider | None = None,
    backend: FakeBackend | None = None,
    **options: object,
) -> tuple[ScapyCaptureWorker, FakeContextProvider, FakeBackend]:
    provider = provider if provider is not None else FakeContextProvider((context(),))
    backend = backend if backend is not None else FakeBackend()
    defaults: dict[str, object] = {
        "queue_capacity": 4,
        "startup_timeout": 0.1,
        "shutdown_timeout": 0.1,
        "clock": lambda: NOW,
    }
    defaults.update(options)
    worker = ScapyCaptureWorker(provider, backend=backend, **defaults)
    return worker, provider, backend


def request(selected: NetworkContext | None = None) -> PacketCaptureRequest:
    return PacketCaptureRequest(
        context=context() if selected is None else selected,
        capture_filter="arp",
    )


def test_capture_can_be_constructed_without_network_probe_import_or_start() -> None:
    worker, provider, backend = worker_for()

    health = worker.health_snapshot()

    assert provider.calls == 0
    assert backend.probed == []
    assert backend.created == []
    assert health.state is CaptureState.STOPPED
    assert health.capability.reason is CaptureCapabilityReason.NOT_PROBED
    assert health.queue_depth == 0
    assert health.worker_alive is False


def test_adapter_satisfies_port_and_composition_is_dormant() -> None:
    provider = FakeContextProvider((context(),))
    capture: PacketCapture = create_packet_capture(context_provider=provider)

    assert isinstance(capture, ScapyCaptureWorker)
    assert provider.calls == 0


def test_probe_uses_current_ns019_context_without_starting_capture() -> None:
    worker, provider, backend = worker_for()

    capability = worker.probe(context())

    assert provider.calls == 1
    assert backend.probed == ["{WIFI-ADAPTER}"]
    assert backend.created == []
    assert capability.status is CapabilityStatus.AVAILABLE
    assert capability.reason is CaptureCapabilityReason.NONE


def test_scapy_interface_resolution_matches_ns019_windows_guid() -> None:
    class ScapyInterface:
        guid = "{WIFI-ADAPTER}"
        network_name = r"\Device\NPF_{WIFI-ADAPTER}"
        name = "Wi-Fi"

    class InterfaceTable:
        def values(self) -> tuple[ScapyInterface, ...]:
            return (ScapyInterface(),)

    class Conf:
        ifaces = InterfaceTable()

    def generic_resolver(value: str) -> object:
        raise ValueError(f"generic resolver did not match {value}")

    resolved = _resolve_scapy_interface(
        Conf(),
        generic_resolver,
        "{wifi-adapter}",
    )

    assert isinstance(resolved, ScapyInterface)


def test_start_requires_explicit_context_and_filter_and_uses_fresh_context() -> None:
    selected = context(ipv4_address="192.168.50.25")
    current = context(ipv4_address="192.168.50.99", interface_index=13)
    provider = FakeContextProvider((current,))
    backend = FakeBackend()
    backend.start_packets = (FakePacket(60, wirelen=64),)
    worker, _, _ = worker_for(provider, backend)

    assert worker.start(request(selected)) is True
    observations = worker.drain(4)

    assert provider.calls == 1
    assert backend.probed == [current.interface_id]
    assert backend.created == [(current.interface_id, "arp")]
    assert len(observations) == 1
    item = observations[0]
    assert item.interface_id == current.interface_id
    assert item.interface_index == 13
    assert item.network_fingerprint == current.fingerprint == selected.fingerprint
    assert item.captured_length == 60
    assert item.original_length == 64
    assert item.link_layer is LinkLayerProtocol.ETHERNET
    assert item.network_layer is NetworkLayerProtocol.ARP
    assert item.arp is not None
    assert item.arp.sender_ip == "192.168.50.20"
    assert str(item.arp.sender_mac) == "aa:bb:cc:dd:ee:ff"
    assert item.source is ObservationSource.PACKET_CAPTURE
    assert not hasattr(item, "payload")
    assert worker.stop() is True


def test_empty_capture_and_empty_drain_are_safe() -> None:
    worker, _, _ = worker_for()

    assert worker.start(request())
    assert worker.drain(4) == ()
    assert worker.stop()


def test_single_multiple_and_duplicate_packets_preserve_fifo_multiplicity() -> None:
    worker, _, backend = worker_for()
    assert worker.start(request())
    handle = backend.handles[0]
    packets = (
        FakePacket(60, layers=("Ether", "IP")),
        FakePacket(61, layers=("Ether", "IPv6")),
        FakePacket(61, layers=("Ether", "IPv6")),
    )
    for packet in packets:
        handle.emit(packet)

    observations = worker.drain(4)

    assert [item.captured_length for item in observations] == [60, 61, 61]
    assert [item.network_layer for item in observations] == [
        NetworkLayerProtocol.IPV4,
        NetworkLayerProtocol.IPV6,
        NetworkLayerProtocol.IPV6,
    ]
    assert observations[1] == observations[2]
    assert worker.health.counters.enqueued_observations == 3
    assert worker.stop()


def test_queue_overflow_drops_newest_without_blocking_and_is_measured() -> None:
    worker, _, backend = worker_for(queue_capacity=2)
    assert worker.start(request())
    handle = backend.handles[0]

    started = monotonic()
    handle.emit(FakePacket(60))
    handle.emit(FakePacket(61))
    handle.emit(FakePacket(62))
    elapsed = monotonic() - started

    health = worker.health
    assert elapsed < 0.1
    assert health.queue_depth == health.queue_capacity == 2
    assert health.counters.captured_packets == 3
    assert health.counters.enqueued_observations == 2
    assert health.counters.dropped_observations == 1
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.CAPTURE_QUEUE_OVERFLOW
    assert [item.captured_length for item in worker.drain(2)] == [60, 61]
    assert worker.stop()


def test_malformed_packet_is_isolated_and_later_packet_is_kept() -> None:
    worker, _, backend = worker_for()
    assert worker.start(request())
    handle = backend.handles[0]

    handle.emit(MalformedPacket())
    handle.emit(FakePacket(80, layers=()))

    observations = worker.drain(4)
    health = worker.health
    assert len(observations) == 1
    assert observations[0].captured_length == 80
    assert observations[0].link_layer is LinkLayerProtocol.OTHER
    assert observations[0].network_layer is NetworkLayerProtocol.OTHER
    assert health.counters.malformed_packets == 1
    assert health.counters.enqueued_observations == 1
    assert worker.stop()


def test_arp_parser_failure_is_isolated_and_later_packet_is_kept() -> None:
    calls = 0

    def failing_once(packet: object, metadata: object) -> object | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("private parser detail")
        return None

    worker, _, backend = worker_for(arp_parser=failing_once)
    assert worker.start(request())
    handle = backend.handles[0]

    handle.emit(FakePacket(70))
    handle.emit(FakePacket(71))

    observations = worker.drain(4)
    assert [item.captured_length for item in observations] == [71]
    assert worker.health.counters.malformed_packets == 1
    assert worker.health.last_error is not None
    assert worker.health.last_error.code is DiagnosticCode.CAPTURE_MALFORMED_PACKET
    assert worker.health.state is CaptureState.RUNNING
    assert worker.stop()


def test_malformed_arp_is_dropped_without_stopping_default_parser_pipeline() -> None:
    worker, _, backend = worker_for()
    assert worker.start(request())
    handle = backend.handles[0]
    malformed = FakePacket(72)
    malformed._arp.hwsrc = "invalid-mac"

    handle.emit(malformed)
    handle.emit(FakePacket(73))

    observations = worker.drain(4)
    assert [item.captured_length for item in observations] == [73]
    assert observations[0].arp is not None
    assert worker.health.counters.malformed_packets == 1
    assert worker.health.state is CaptureState.RUNNING
    assert worker.stop()


def test_dns_parser_uses_existing_bounded_capture_queue_and_isolates_bad_message() -> None:
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

    worker, _, backend = worker_for(queue_capacity=2)
    assert worker.start(PacketCaptureRequest(context(), "udp port 53"))
    handle = backend.handles[0]
    malformed = Ether() / IP() / UDP(sport=53000, dport=53) / DNS(
        qd=DNSQR(qname="example.com"),
        an=[DNSRR(rrname="example.com", type="A", rdata="192.0.2.1") for _ in range(17)],
    )
    handle.emit(malformed)
    handle.emit(dns_query())

    observations = worker.drain(2)
    assert len(observations) == 1
    assert observations[0].dns is not None
    assert observations[0].dns.questions[0].name == "example.com."
    assert observations[0].network_fingerprint == context().fingerprint
    assert worker.health.counters.malformed_packets == 1
    assert worker.health.state is CaptureState.RUNNING
    assert worker.stop()
    assert backend.handles[0].closed


def test_start_and_stop_are_idempotent_and_post_stop_callback_is_ignored() -> None:
    worker, _, backend = worker_for()

    assert worker.start(request()) is True
    assert worker.start(request()) is False
    handle = backend.handles[0]
    handle.emit(FakePacket(60))
    assert worker.stop() is True
    assert worker.stop() is True
    handle.emit(FakePacket(61))

    assert [item.captured_length for item in worker.drain(4)] == [60]
    assert handle.start_calls == 1
    assert handle.stop_calls == 1
    assert handle.closed is True
    assert worker.health.state is CaptureState.STOPPED
    assert worker.health.worker_alive is False


def test_stubborn_worker_shutdown_is_bounded_and_can_finish_later() -> None:
    backend = FakeBackend()
    backend.stubborn = True
    worker, _, _ = worker_for(backend=backend, shutdown_timeout=0.01)
    assert worker.start(request())
    handle = backend.handles[0]

    started = monotonic()
    assert worker.stop() is False
    elapsed = monotonic() - started

    assert elapsed < 0.2
    assert worker.health.state is CaptureState.STOPPING
    assert worker.health.worker_alive is True
    assert worker.health.last_error is not None
    assert worker.health.last_error.code is DiagnosticCode.CAPTURE_SHUTDOWN_TIMEOUT
    assert worker.start(request()) is False

    handle.alive = False
    assert worker.stop(timeout=0.1) is True
    assert handle.closed is True
    assert worker.health.worker_alive is False


@pytest.mark.parametrize(
    ("error", "status", "reason", "code"),
    [
        (
            PacketCapturePermissionDenied("private detail"),
            CapabilityStatus.UNAVAILABLE,
            CaptureCapabilityReason.PERMISSION_DENIED,
            DiagnosticCode.CAPTURE_PERMISSION_DENIED,
        ),
        (
            PacketCaptureDependencyUnavailable("private detail"),
            CapabilityStatus.UNAVAILABLE,
            CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE,
            DiagnosticCode.CAPTURE_DEPENDENCY_UNAVAILABLE,
        ),
        (
            PacketCaptureInterfaceUnavailable("private detail"),
            CapabilityStatus.UNAVAILABLE,
            CaptureCapabilityReason.INTERFACE_UNAVAILABLE,
            DiagnosticCode.CAPTURE_INTERFACE_UNAVAILABLE,
        ),
        (
            PacketCaptureTransientError("private detail"),
            CapabilityStatus.DEGRADED,
            CaptureCapabilityReason.TRANSIENT_FAILURE,
            DiagnosticCode.CAPTURE_TRANSIENT_FAILURE,
        ),
    ],
)
def test_backend_probe_failures_are_typed_sanitized_and_do_not_start(
    error: BaseException,
    status: CapabilityStatus,
    reason: CaptureCapabilityReason,
    code: DiagnosticCode,
) -> None:
    backend = FakeBackend()
    backend.probe_error = error
    worker, _, _ = worker_for(backend=backend)

    assert worker.start(request()) is False

    health = worker.health
    assert health.state is CaptureState.STOPPED
    assert health.capability.status is status
    assert health.capability.reason is reason
    assert health.last_error is not None
    assert health.last_error.code is code
    assert not hasattr(health.last_error, "message")
    assert backend.created == []


def test_socket_creation_failure_is_typed_and_creates_no_handle() -> None:
    backend = FakeBackend()
    backend.create_error = PacketCapturePermissionDenied("private driver text")
    worker, _, _ = worker_for(backend=backend)

    assert worker.start(request()) is False

    health = worker.health
    assert health.capability.reason is CaptureCapabilityReason.PERMISSION_DENIED
    assert health.counters.worker_failures == 1
    assert backend.handles == []


def test_worker_start_failure_closes_owned_capture_resource() -> None:
    backend = FakeBackend()
    backend.start_error = PacketCaptureTransientError("private worker text")
    worker, _, _ = worker_for(backend=backend)

    assert worker.start(request()) is False

    assert len(backend.handles) == 1
    assert backend.handles[0].closed is True
    assert worker.health.worker_alive is False
    assert worker.health.capability.reason is CaptureCapabilityReason.TRANSIENT_FAILURE


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (
            NetworkContextPermissionDenied("private platform text"),
            CaptureCapabilityReason.PERMISSION_DENIED,
        ),
        (
            NetworkContextUnavailable("private platform text"),
            CaptureCapabilityReason.TRANSIENT_FAILURE,
        ),
    ],
)
def test_context_provider_failure_is_classified_without_backend_access(
    error: BaseException,
    reason: CaptureCapabilityReason,
) -> None:
    provider = FakeContextProvider((context(),))
    provider.error = error
    worker, _, backend = worker_for(provider=provider)

    assert worker.start(request()) is False
    assert worker.health.capability.reason is reason
    assert backend.probed == []
    assert backend.created == []


def test_disconnected_or_disappeared_interface_is_unavailable() -> None:
    provider = FakeContextProvider(())
    worker, _, backend = worker_for(provider=provider)

    assert worker.start(request()) is False
    assert worker.health.capability.reason is CaptureCapabilityReason.INTERFACE_UNAVAILABLE
    assert backend.created == []


def test_network_fingerprint_change_rejects_stale_context() -> None:
    selected = context()
    changed = context(
        ipv4_address="10.0.0.25",
        subnet="10.0.0.0/8",
        gateway="10.0.0.1",
    )
    provider = FakeContextProvider((changed,))
    worker, _, backend = worker_for(provider=provider)

    assert worker.start(request(selected)) is False
    assert worker.health.capability.reason is CaptureCapabilityReason.NETWORK_CHANGED
    assert worker.health.last_error is not None
    assert worker.health.last_error.code is DiagnosticCode.CAPTURE_NETWORK_CHANGED
    assert backend.created == []


def test_loopback_is_rejected_while_explicit_vpn_and_virtual_contexts_are_allowed() -> None:
    loopback = context(
        interface_id="loopback",
        interface_index=1,
        interface_name="Loopback",
        interface_kind=NetworkInterfaceKind.LOOPBACK,
        ipv4_address="127.0.0.1",
        subnet="127.0.0.0/8",
        gateway=None,
        dns_servers=(),
    )
    loopback_worker, _, _ = worker_for(FakeContextProvider((loopback,)))
    assert loopback_worker.start(request(loopback)) is False
    assert (
        loopback_worker.health.capability.reason
        is CaptureCapabilityReason.INTERFACE_UNAVAILABLE
    )

    for kind in (NetworkInterfaceKind.VPN, NetworkInterfaceKind.VIRTUAL):
        selected = context(interface_kind=kind)
        worker, _, _ = worker_for(FakeContextProvider((selected,)))
        assert worker.start(request(selected)) is True
        assert worker.stop() is True


def test_runtime_interface_disappearance_is_visible_when_worker_dies() -> None:
    worker, _, backend = worker_for()
    assert worker.start(request())
    handle = backend.handles[0]
    handle.alive = False
    handle.join_error = PacketCaptureInterfaceUnavailable("private detail")

    health = worker.health_snapshot()

    assert health.state is CaptureState.STOPPED
    assert health.worker_alive is False
    assert health.capability.reason is CaptureCapabilityReason.INTERFACE_UNAVAILABLE
    assert health.counters.worker_failures == 1
    assert health.last_error is not None
    assert health.last_error.code is DiagnosticCode.CAPTURE_INTERFACE_UNAVAILABLE
    assert handle.closed is True


def test_restart_uses_fresh_context_and_drops_undrained_old_context_data() -> None:
    first = context()
    second = context(
        ipv4_address="10.0.0.25",
        subnet="10.0.0.0/8",
        gateway="10.0.0.1",
    )
    provider = FakeContextProvider((first,))
    worker, _, backend = worker_for(provider=provider)
    assert worker.start(request(first))
    backend.handles[0].emit(FakePacket(60))
    assert worker.stop()

    provider.contexts = (second,)
    assert worker.start(request(second))
    backend.handles[1].emit(FakePacket(61))

    observations = worker.drain(4)
    assert [item.captured_length for item in observations] == [61]
    assert observations[0].network_fingerprint == second.fingerprint
    assert worker.health.counters.dropped_observations == 1
    assert worker.stop()


@pytest.mark.parametrize(
    "values",
    [
        {"capture_filter": ""},
        {"capture_filter": "a" * 257},
        {"capture_filter": "arp\nsecret"},
        {"capture_filter": 123},
        {"context": object()},
    ],
)
def test_capture_request_rejects_unbounded_or_invalid_values(
    values: dict[str, object],
) -> None:
    options: dict[str, object] = {"context": context(), "capture_filter": "arp"}
    options.update(values)
    with pytest.raises((TypeError, ValueError)):
        PacketCaptureRequest(**options)  # type: ignore[arg-type]


def test_worker_configuration_and_drain_limits_are_bounded() -> None:
    provider = FakeContextProvider((context(),))
    for invalid in (0, -1, True):
        with pytest.raises((TypeError, ValueError)):
            ScapyCaptureWorker(provider, backend=FakeBackend(), queue_capacity=invalid)
    for invalid in (-1, float("inf"), float("nan"), True):
        with pytest.raises(ValueError):
            ScapyCaptureWorker(
                provider,
                backend=FakeBackend(),
                shutdown_timeout=invalid,
            )

    worker, _, _ = worker_for(queue_capacity=2)
    for invalid in (0, 3, -1, True):
        with pytest.raises((TypeError, ValueError)):
            worker.drain(invalid)


def test_capture_boundaries_keep_scapy_and_adapter_out_of_core_and_presentation() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    forbidden: dict[Path, set[str]] = {
        repository_root / "src" / "netsentinel" / "domain": {
            "scapy",
            "PyQt6",
            "sqlite3",
            "ctypes",
        },
        repository_root / "src" / "netsentinel" / "application": {
            "scapy",
            "PyQt6",
            "sqlite3",
            "ctypes",
        },
        repository_root / "src" / "netsentinel" / "presentation": {
            "scapy",
            "netsentinel.infrastructure.scapy_capture",
        },
    }
    violations: list[str] = []
    for root, blocked in forbidden.items():
        for source_path in root.rglob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    modules.append(node.module)
                if any(
                    name == item or name.startswith(f"{item}.")
                    for name in modules
                    for item in blocked
                ):
                    violations.append(str(source_path))

    assert violations == []


def test_scapy_import_is_lazy_and_module_contains_no_logging_or_payload_retention() -> None:
    source_path = (
        Path(__file__).parents[3]
        / "src"
        / "netsentinel"
        / "infrastructure"
        / "scapy_capture.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    top_level_scapy_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level_scapy_imports.extend(
                alias.name for alias in node.names if alias.name.startswith("scapy")
            )
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "scapy"
        ):
            top_level_scapy_imports.append(node.module or "")

    assert top_level_scapy_imports == []
    assert "logging" not in source
    assert "packet.payload" not in source
