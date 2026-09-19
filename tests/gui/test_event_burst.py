"""NS-013 event-loop responsiveness smoke test for the bounded Qt bridge."""

from __future__ import annotations

from threading import Thread, enumerate as enumerate_threads

from PyQt6.QtCore import QElapsedTimer, QTimer
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.domain.connections import ConnectionOpened
from netsentinel.presentation.bridge import (
    BridgeHealthSnapshot,
    ConnectionEventBatch,
    QtEngineBridge,
)
from netsentinel.presentation.models.connections import ConnectionsTableModel
from tests.gui._ns013_support import FakeEngine, snapshot


def test_large_event_burst_keeps_heartbeat_and_bounded_batching_responsive(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    total_events = 2_048
    queue_capacity = 512
    batch_size = 16
    engine = FakeEngine(running=True)
    bridge = QtEngineBridge(
        engine,
        queue_capacity=queue_capacity,
        batch_size=batch_size,
        health_poll_interval_ms=1_000,
    )
    model = ConnectionsTableModel()
    bridge.connection_opened.connect(model.handle_connection_opened)

    batches: list[ConnectionEventBatch] = []
    health_updates: list[BridgeHealthSnapshot] = []
    processed = 0
    heartbeat_during_drain = 0

    def record_batch(batch: ConnectionEventBatch) -> None:
        nonlocal processed
        batches.append(batch)
        processed += len(batch.events)

    def heartbeat() -> None:
        nonlocal heartbeat_during_drain
        if 0 < processed < queue_capacity:
            heartbeat_during_drain += 1

    bridge.events_ready.connect(record_batch)
    bridge.health_changed.connect(health_updates.append)
    heartbeat_timer = QTimer()
    heartbeat_timer.setInterval(0)
    heartbeat_timer.timeout.connect(heartbeat)
    heartbeat_timer.start()
    bridge.start()

    threads_before = {thread.ident for thread in enumerate_threads()}
    publisher = Thread(
        target=lambda: [
            engine.dispatcher.publish(ConnectionOpened(snapshot(index)))
            for index in range(total_events)
        ],
        name="netsentinel-ns013-test-publisher",
    )
    elapsed = QElapsedTimer()
    elapsed.start()
    publisher.start()
    publisher.join(timeout=2.0)
    assert publisher.is_alive() is False

    qtbot.waitUntil(lambda: processed == queue_capacity, timeout=5_000)
    qtbot.waitUntil(
        lambda: any(update.dropped_events > 0 for update in health_updates),
        timeout=1_000,
    )
    heartbeat_timer.stop()

    # Five seconds is intentionally generous for shared/slow CI machines. It
    # catches event-loop starvation or a lost drain without claiming benchmark
    # precision; normal local execution is far below this ceiling.
    assert elapsed.elapsed() < 5_000
    assert heartbeat_during_drain > 0
    assert model.rowCount() == queue_capacity
    assert processed + bridge.dropped_events == total_events
    assert bridge.dropped_events == total_events - queue_capacity
    assert batches
    assert all(0 < len(batch.events) <= batch_size for batch in batches)
    assert len(batches) == queue_capacity // batch_size
    assert any(
        update.queue_capacity == queue_capacity
        and update.dropped_events == total_events - queue_capacity
        for update in health_updates
    )

    bridge.stop()
    QApplication.processEvents()
    threads_after = {thread.ident for thread in enumerate_threads()}
    assert threads_after == threads_before
    assert all(
        thread.name != "netsentinel-ns013-test-publisher"
        for thread in enumerate_threads()
    )

