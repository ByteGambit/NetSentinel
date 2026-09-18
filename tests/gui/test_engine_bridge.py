"""NS-009 offscreen tests for the bounded, thread-safe Qt engine bridge."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread, current_thread, get_ident

from PyQt6 import sip
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.application.events import EventDispatcher
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessInfo,
    TransportProtocol,
)
from netsentinel.presentation.bridge import (
    BridgeHealthSnapshot,
    ConnectionEventBatch,
    QtEngineBridge,
)
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


BASE_TIME = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


class FakeEngine:
    """Deterministic source with the same bridge-facing surface as the engine."""

    def __init__(self) -> None:
        self.dispatcher = EventDispatcher()
        self.health = EngineHealthSnapshot(
            state=EngineState.RUNNING,
            capabilities=CapabilitySnapshot(),
            counters=EngineCounters(),
            worker_alive=True,
        )

    def health_snapshot(self) -> EngineHealthSnapshot:
        return self.health


def _snapshot(
    *,
    port: int = 50_000,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    observed_at: datetime = BASE_TIME,
) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("127.0.0.1", port),
        remote_endpoint=Endpoint("127.0.0.1", 443),
        state=state,
        process=ProcessInfo.unavailable(),
        observed_at=observed_at,
    )


def _events() -> tuple[ConnectionOpened, ConnectionUpdated, ConnectionClosed]:
    initial = _snapshot()
    updated = _snapshot(
        state=ConnectionState.CLOSE_WAIT,
        observed_at=BASE_TIME + timedelta(seconds=1),
    )
    return (
        ConnectionOpened(initial),
        ConnectionUpdated(previous=initial, current=updated),
        ConnectionClosed(
            last_snapshot=updated,
            occurred_at=BASE_TIME + timedelta(seconds=2),
        ),
    )


def _publish_in_worker(engine: FakeEngine, *events: object) -> Thread:
    worker = Thread(
        target=lambda: [engine.dispatcher.publish(event) for event in events],
        name="netsentinel-ns009-test-publisher",
    )
    worker.start()
    worker.join(timeout=1.0)
    assert worker.is_alive() is False
    return worker


def test_bridge_can_be_created(qapp: QApplication) -> None:
    bridge = QtEngineBridge(FakeEngine())

    assert bridge.attached is False
    assert bridge.thread() == qapp.thread()
    assert bridge.dropped_events == 0


def test_start_subscribes_to_engine_dispatcher_and_is_idempotent(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    received: list[ConnectionOpened] = []
    bridge.connection_opened.connect(received.append)

    assert bridge.start() is True
    assert bridge.start() is False
    report = engine.dispatcher.publish(_events()[0])
    qtbot.waitUntil(lambda: len(received) == 1)

    assert report.delivered == 1
    assert report.failed == 0
    assert received == [_events()[0]]
    assert bridge.stop() is True


def test_connection_event_types_are_forwarded_by_specific_signals(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    opened: list[ConnectionOpened] = []
    updated: list[ConnectionUpdated] = []
    closed: list[ConnectionClosed] = []
    bridge.connection_opened.connect(opened.append)
    bridge.connection_updated.connect(updated.append)
    bridge.connection_closed.connect(closed.append)
    bridge.start()
    expected = _events()

    _publish_in_worker(engine, *expected)
    qtbot.waitUntil(lambda: len(opened) + len(updated) + len(closed) == 3)

    assert opened == [expected[0]]
    assert updated == [expected[1]]
    assert closed == [expected[2]]
    bridge.stop()


def test_worker_publish_is_consumed_in_qt_main_thread(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    main_python_thread = get_ident()
    deliveries: list[tuple[int, QThread, str]] = []
    bridge.connection_opened.connect(
        lambda _event: deliveries.append(
            (get_ident(), QThread.currentThread(), current_thread().name)
        )
    )
    bridge.start()

    worker = _publish_in_worker(engine, _events()[0])
    qtbot.waitUntil(lambda: bool(deliveries))

    assert worker.ident != main_python_thread
    assert deliveries[0][0] == main_python_thread
    assert deliveries[0][1] == qapp.thread()
    assert deliveries[0][2] == current_thread().name
    bridge.stop()


def test_burst_is_batched_once_and_preserves_cross_type_order(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine, batch_size=16)
    batches: list[ConnectionEventBatch] = []
    ordered: list[object] = []
    bridge.events_ready.connect(batches.append)
    bridge.connection_opened.connect(ordered.append)
    bridge.connection_updated.connect(ordered.append)
    bridge.connection_closed.connect(ordered.append)
    bridge.start()
    expected = _events()

    _publish_in_worker(engine, *expected)
    qtbot.waitUntil(lambda: len(ordered) == len(expected))

    assert len(batches) == 1
    assert batches[0].events == expected
    assert ordered == list(expected)
    bridge.stop()


def test_burst_larger_than_batch_size_uses_bounded_event_loop_turns(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine, batch_size=2)
    batches: list[ConnectionEventBatch] = []
    bridge.events_ready.connect(batches.append)
    bridge.start()
    events = tuple(ConnectionOpened(_snapshot(port=50_000 + index)) for index in range(5))

    _publish_in_worker(engine, *events)
    qtbot.waitUntil(lambda: sum(len(batch.events) for batch in batches) == 5)

    assert [len(batch.events) for batch in batches] == [2, 2, 1]
    assert tuple(event for batch in batches for event in batch.events) == events
    bridge.stop()


def test_queue_overflow_drops_newest_and_is_visible_in_health(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine, queue_capacity=2, batch_size=2)
    batches: list[ConnectionEventBatch] = []
    health_updates: list[BridgeHealthSnapshot] = []
    bridge.events_ready.connect(batches.append)
    bridge.health_changed.connect(health_updates.append)
    bridge.start()
    events = tuple(ConnectionOpened(_snapshot(port=51_000 + index)) for index in range(3))

    _publish_in_worker(engine, *events)
    qtbot.waitUntil(
        lambda: bool(batches)
        and any(health.dropped_events == 1 for health in health_updates)
    )

    assert batches[0].events == events[:2]
    overflow = next(health for health in health_updates if health.dropped_events == 1)
    assert overflow.engine is engine.health
    assert overflow.queue_capacity == 2
    assert overflow.overflowed is True
    assert bridge.dropped_events == 1
    bridge.stop()


def test_engine_health_changes_are_polled_with_existing_snapshot_api(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine, health_poll_interval_ms=10)
    health_updates: list[BridgeHealthSnapshot] = []
    bridge.health_changed.connect(health_updates.append)
    bridge.start()
    qtbot.waitUntil(lambda: bool(health_updates))

    engine.health = EngineHealthSnapshot(
        state=EngineState.STOPPING,
        capabilities=CapabilitySnapshot(),
        counters=EngineCounters(polling_rounds=3),
        worker_alive=True,
    )
    qtbot.waitUntil(
        lambda: any(update.engine.state is EngineState.STOPPING for update in health_updates)
    )

    assert health_updates[-1].engine.counters.polling_rounds == 3
    bridge.stop()


def test_stop_prevents_already_queued_and_later_events_from_reaching_gui(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    received: list[ConnectionOpened] = []
    bridge.connection_opened.connect(received.append)
    bridge.start()
    engine.dispatcher.publish(_events()[0])

    assert bridge.stop() is True
    assert bridge.stop() is False
    report = engine.dispatcher.publish(_events()[0])
    QApplication.processEvents()

    assert report.delivered == 0
    assert received == []
    assert bridge.attached is False


def test_bridge_can_reattach_without_duplicate_subscriptions(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    received: list[ConnectionOpened] = []
    bridge.connection_opened.connect(received.append)

    assert bridge.start() is True
    assert bridge.stop() is True
    assert bridge.start() is True
    assert bridge.start() is False
    report = engine.dispatcher.publish(_events()[0])
    qtbot.waitUntil(lambda: len(received) == 1)

    assert report.delivered == 1
    assert received == [_events()[0]]
    bridge.stop()


def test_qobject_destruction_removes_dispatcher_callbacks(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    bridge.start()
    bridge.deleteLater()
    qtbot.waitUntil(lambda: sip.isdeleted(bridge))

    report = engine.dispatcher.publish(_events()[0])

    assert report.delivered == 0
    assert report.failed == 0


def test_bridge_creates_no_worker_or_widget_and_leaves_no_visible_widget(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    bridge = QtEngineBridge(engine)
    before_widgets = tuple(QApplication.topLevelWidgets())
    bridge.start()

    _publish_in_worker(engine, _events()[0])
    qtbot.waitUntil(lambda: bridge.dropped_events == 0)
    bridge.stop()
    QApplication.processEvents()

    assert tuple(QApplication.topLevelWidgets()) == before_widgets
    assert all(
        thread.name != "netsentinel-ns009-test-publisher"
        for thread in __import__("threading").enumerate()
    )


def test_application_and_domain_layers_do_not_import_pyqt6() -> None:
    source_root = Path(__file__).resolve().parents[2] / "src" / "netsentinel"

    for layer in ("application", "domain"):
        for path in (source_root / layer).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imports.update(
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            assert not any(name == "PyQt6" or name.startswith("PyQt6.") for name in imports), path


def test_bridge_exposes_no_infrastructure_types_or_imports() -> None:
    bridge_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "netsentinel"
        / "presentation"
        / "bridge.py"
    )
    tree = ast.parse(bridge_path.read_text(encoding="utf-8"), filename=str(bridge_path))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert not any(name.split(".", 1)[0].lower() in {"psutil", "scapy", "sqlite3"} for name in imported)
    assert not any(
        name == "netsentinel.infrastructure"
        or name.startswith("netsentinel.infrastructure.")
        for name in imported
    )
