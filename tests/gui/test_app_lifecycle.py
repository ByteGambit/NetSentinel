"""NS-013 shutdown and QObject lifecycle regressions beyond NS-008/NS-009."""

from __future__ import annotations

from threading import enumerate as enumerate_threads

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QElapsedTimer
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.domain.connections import ConnectionOpened
from netsentinel.presentation.app import create_application
from tests.gui._ns013_support import BurstEngine, FakeEngine, snapshot


def test_qapplication_quit_signal_stops_engine_and_detaches_bridge(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    shell.window.show()
    assert shell.lifecycle.start() is True

    qapp.aboutToQuit.emit()

    assert shell.lifecycle.shutdown_requested
    assert engine.stop_calls == 1
    assert engine.running is False
    assert shell.bridge.attached is False
    shell.window.close()
    assert engine.stop_calls == 1


@pytest.mark.parametrize("detach_before_close", [False, True])
def test_window_close_is_safe_with_bridge_attached_or_detached(
    qtbot: QtBot,
    detach_before_close: bool,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    shell.window.show()
    shell.lifecycle.start()
    if detach_before_close:
        assert shell.bridge.detach() is True

    shell.window.close()
    report = engine.dispatcher.publish(ConnectionOpened(snapshot()))
    QApplication.processEvents()

    assert engine.stop_calls == 1
    assert engine.running is False
    assert shell.bridge.attached is False
    assert report.delivered == 0
    assert report.failed == 0


def test_shutdown_during_event_burst_is_bounded_and_leaves_no_worker(
    qtbot: QtBot,
) -> None:
    engine = BurstEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    shell.window.show()
    shell.lifecycle.start()
    assert engine.publisher_started.wait(timeout=1.0)
    qtbot.waitUntil(
        lambda: shell.bridge.dropped_events > 0
        or shell.window.connections_model.rowCount() > 0,
        timeout=2_000,
    )

    elapsed = QElapsedTimer()
    elapsed.start()
    shell.window.close()
    rows_after_close = shell.window.connections_model.rowCount()
    report = engine.dispatcher.publish(ConnectionOpened(snapshot(49_999)))
    QApplication.processEvents()

    # Three seconds is deliberately broad for a CI/offscreen smoke check. The
    # production worker join is bounded to one second; this is not a benchmark.
    assert elapsed.elapsed() < 3_000
    assert engine.stop_calls == 1
    assert engine.worker is not None
    assert engine.worker.is_alive() is False
    assert shell.bridge.attached is False
    assert report.delivered == 0
    assert shell.window.connections_model.rowCount() == rows_after_close
    assert all(
        thread.name != "netsentinel-ns013-burst-worker"
        for thread in enumerate_threads()
    )


def test_queued_events_cannot_mutate_widgets_after_window_destruction(
    qtbot: QtBot,
) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    window = shell.window
    qtbot.addWidget(window)
    insertions: list[bool] = []
    window.connections_model.rowsInserted.connect(
        lambda *_args: insertions.append(True)
    )
    shell.lifecycle.start()
    engine.dispatcher.publish(ConnectionOpened(snapshot()))

    window.close()
    window.deleteLater()
    qtbot.waitUntil(lambda: sip.isdeleted(window), timeout=2_000)
    report = engine.dispatcher.publish(ConnectionOpened(snapshot(1)))
    QApplication.processEvents()

    assert insertions == []
    assert report.delivered == 0
    assert report.failed == 0
    assert shell.bridge.attached is False
    assert engine.stop_calls == 1


def test_shutdown_remains_idempotent_after_manual_detach(qtbot: QtBot) -> None:
    engine = FakeEngine()
    shell = create_application(engine, argv=[])
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    shell.bridge.detach()

    assert shell.lifecycle.shutdown() is True
    assert shell.lifecycle.shutdown() is True
    assert engine.stop_calls == 1
    assert shell.bridge.detach() is False
    shell.window.close()

