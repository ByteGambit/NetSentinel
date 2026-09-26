"""NS-038 offline load: bounded capture, metric quality, and shutdown."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Event, Thread, enumerate as enumerate_threads

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.traffic_metrics import MeasurementConfidence, TrafficMetricsService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.infrastructure.scapy_capture import ScapyCaptureWorker
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.shared.diagnostics import CaptureState


AT = datetime(2026, 9, 26, tzinfo=UTC)
BURST_PACKETS = 2_048
QUEUE_CAPACITY = 32


class Contexts:
    def __init__(self, context: NetworkContext) -> None:
        self.context = context

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        return (self.context,)


class Handle:
    def __init__(self, callback) -> None:
        self.callback = callback
        self.alive = False
        self.closed = False

    def start(self, timeout: float) -> None:
        self.alive = True

    def request_stop(self) -> None:
        self.alive = False

    def join(self, timeout: float) -> None:
        pass

    def is_alive(self) -> bool:
        return self.alive

    def close(self) -> None:
        self.closed = True


class Backend:
    def __init__(self) -> None:
        self.handle = None

    def probe(self, interface_id: str) -> None:
        pass

    def create(self, *, interface_id: str, capture_filter: str, callback):
        self.handle = Handle(callback)
        return self.handle


def _emit_burst(handle: Handle, packet: object) -> None:
    for _ in range(BURST_PACKETS):
        handle.callback(packet)


@pytest.mark.performance
def test_synthetic_burst_preserves_queue_quality_bounds_and_bounded_stop(tmp_path) -> None:
    context = NetworkContext("adapter", 1, "Ethernet", NetworkInterfaceKind.ETHERNET,
                             "192.168.8.10", "192.168.8.0/24", None, (), AT)
    contexts = Contexts(context)
    backend = Backend()
    capture = ScapyCaptureWorker(contexts, backend=backend,
                                 queue_capacity=QUEUE_CAPACITY,
                                 startup_timeout=0.1, shutdown_timeout=1.0,
                                 clock=lambda: AT)
    ticks = [0.0]
    metrics = TrafficMetricsService(clock=lambda: ticks[0], window_seconds=10)
    service = DeviceInventoryService(
        contexts, SQLiteDeviceRepository(SQLiteDatabase(tmp_path / "burst.sqlite3")),
        capture, traffic_metrics=metrics,
    )
    before_threads = {thread.ident for thread in enumerate_threads()}
    packet = (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
              IP(src="192.168.8.2", dst="192.168.8.255"))
    assert service.refresh(start_capture=True).capture.state is CaptureState.RUNNING
    assert backend.handle is not None
    producer = Thread(target=_emit_burst, args=(backend.handle, packet),
                      name="netsentinel-ns038-producer")
    producer.start()
    producer.join(timeout=15)
    assert not producer.is_alive()  # producer never waits on a full capture queue

    health = capture.health_snapshot()
    assert health.queue_depth == QUEUE_CAPACITY
    assert health.counters.dropped_observations == BURST_PACKETS - QUEUE_CAPACITY
    snapshot = service.refresh()
    traffic = snapshot.traffic_metrics
    assert traffic is not None
    assert traffic.broadcast.packet_count == QUEUE_CAPACITY
    assert traffic.arp.packet_count == 0
    assert traffic.confidence is MeasurementConfidence.REDUCED
    assert traffic.dropped_observations == BURST_PACKETS - QUEUE_CAPACITY
    assert metrics.tracked_contexts == 1
    assert metrics.retained_buckets <= 10
    assert not hasattr(traffic, "payload")

    # Stop with a live producer paused at a controlled boundary. Its later
    # callbacks must be ignored by the capture generation guard.
    reached = Event()
    resume = Event()

    def still_producing() -> None:
        for index in range(BURST_PACKETS):
            if index == 64:
                reached.set()
                assert resume.wait(timeout=5)
            backend.handle.callback(packet)

    active_producer = Thread(target=still_producing, name="netsentinel-ns038-stop-producer")
    active_producer.start()
    assert reached.wait(timeout=5)
    counters_before_stop = capture.health_snapshot().counters
    assert service.close()
    resume.set()
    active_producer.join(timeout=15)
    assert not active_producer.is_alive()
    after_stop = capture.health_snapshot()
    assert after_stop.counters == counters_before_stop
    assert after_stop.queue_depth <= QUEUE_CAPACITY
    assert backend.handle.closed
    assert {thread.ident for thread in enumerate_threads()} == before_threads


@pytest.mark.performance
def test_offscreen_heartbeat_progresses_during_synthetic_capture_burst(
    qapp: QApplication, qtbot: QtBot,
) -> None:
    context = NetworkContext("adapter", 1, "Ethernet", NetworkInterfaceKind.ETHERNET,
                             "192.168.8.10", "192.168.8.0/24", None, (), AT)
    backend = Backend()
    capture = ScapyCaptureWorker(Contexts(context), backend=backend,
                                 queue_capacity=QUEUE_CAPACITY, clock=lambda: AT)
    from netsentinel.application.ports import PacketCaptureRequest
    assert capture.start(PacketCaptureRequest(context, "ether broadcast"))
    assert backend.handle is not None
    packet = (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
              IP(src="192.168.8.2", dst="192.168.8.255"))
    beats = []
    producer = Thread(target=_emit_burst, args=(backend.handle, packet),
                      name="netsentinel-ns038-ui-producer")
    heartbeat = QTimer()
    heartbeat.setInterval(0)
    heartbeat.timeout.connect(lambda: beats.append(producer.is_alive()))
    heartbeat.start()
    producer.start()
    qtbot.waitUntil(lambda: not producer.is_alive(), timeout=15_000)
    producer.join(timeout=1)
    heartbeat.stop()
    assert any(beats)
    assert capture.health_snapshot().queue_depth <= QUEUE_CAPACITY
    assert capture.stop(timeout=1.0)
    assert backend.handle.closed
