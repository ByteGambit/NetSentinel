"""NS-038 portable M7 snapshot presentation on the Qt main thread."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from threading import Thread

from PyQt6.QtCore import QThread
from pytestqt.qtbot import QtBot

from netsentinel.application.services.device_inventory import DeviceInventorySnapshot
from netsentinel.application.services.traffic_metrics import (
    BaselineState, MeasurementConfidence, ProtocolRateSnapshot,
    TrafficBaselineSnapshot, TrafficMetricsSnapshot, TrafficProtocol,
)
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.shared.config import TrafficRateConfig
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState,
)


AT = datetime(2026, 9, 26, tzinfo=UTC)


def _context(name: str = "adapter") -> NetworkContext:
    return NetworkContext(name, 1, name, NetworkInterfaceKind.ETHERNET,
                          "192.168.8.10", "192.168.8.0/24", None, (), AT)


def _snapshot(*, context: NetworkContext | None = None,
              quality: MeasurementConfidence = MeasurementConfidence.COMPLETE,
              learned: bool = True, running: bool = True,
              broadcast_rate: float = 1.2, arp_rate: float = 0.4,
              dropped: int = 0) -> DeviceInventorySnapshot:
    context = context or _context()
    def baseline(value):
        return TrafficBaselineSnapshot(
            BaselineState.LEARNED if learned else BaselineState.LEARNING,
            value if learned else None, 3 if learned else 1, 12,
        )
    metric = TrafficMetricsSnapshot(
        context.fingerprint, context.interface_id, context.interface_index, 60, 1,
        ProtocolRateSnapshot(TrafficProtocol.ARP, 24, arp_rate, baseline(0.1)),
        ProtocolRateSnapshot(TrafficProtocol.BROADCAST, 72, broadcast_rate, baseline(0.3)),
        dropped, quality,
    )
    state = CaptureState.RUNNING if running else CaptureState.STOPPED
    capture = CaptureHealthSnapshot(
        state,
        CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
        0, 128, CaptureCounters(),
        selected_interface_id=context.interface_id if running else None,
        network_fingerprint=context.fingerprint if running else None,
        worker_alive=running,
    )
    return DeviceInventorySnapshot((context,), context.fingerprint, (), capture,
                                   traffic_metrics=metric, traffic_policy=TrafficRateConfig())


def test_rates_baselines_threshold_quality_and_accessibility(qtbot: QtBot) -> None:
    view = DashboardView()
    qtbot.addWidget(view)
    view.view_model.set_traffic_snapshot(_snapshot())
    assert view.broadcast_rate_label.text() == "1.2 pkt/s"
    assert view.arp_rate_label.text() == "0.4 pkt/s"
    assert view.broadcast_baseline_label.text() == "0.3 pkt/s"
    assert view.arp_baseline_label.text() == "0.1 pkt/s"
    assert view.traffic_window_label.text() == "Last 60 s rolling window"
    assert "Broadcast >5 pkt/s" in view.traffic_threshold_label.text()
    assert "ARP >2 pkt/s" in view.traffic_threshold_label.text()
    assert view.traffic_quality_label.text() == "Complete"
    for label in (view.broadcast_rate_label, view.arp_rate_label,
                  view.broadcast_baseline_label, view.arp_baseline_label,
                  view.traffic_quality_label, view.capture_drop_label):
        assert label.accessibleName()

    view.view_model.set_traffic_snapshot(_snapshot(learned=False,
        quality=MeasurementConfidence.UNKNOWN))
    assert view.broadcast_baseline_label.text() == "Learning baseline"
    assert "Unknown" in view.traffic_quality_label.text()
    view.view_model.set_traffic_snapshot(_snapshot(
        quality=MeasurementConfidence.REDUCED, dropped=7))
    assert "dropped observations" in view.traffic_quality_label.text()
    assert view.capture_drop_label.text() == "7"
    view.view_model.set_traffic_snapshot(_snapshot(running=False))
    assert "Capture off" in view.traffic_capture_label.text()
    assert "stale" in view.traffic_capture_label.text()


def test_network_change_bad_metric_and_duplicate_snapshot(qtbot: QtBot) -> None:
    view = DashboardView()
    qtbot.addWidget(view)
    original = _snapshot()
    emissions = []
    view.view_model.traffic_changed.connect(emissions.append)
    view.view_model.set_traffic_snapshot(original)
    view.view_model.set_traffic_snapshot(original)
    assert len(emissions) == 1
    other = _context("other")
    view.view_model.set_traffic_snapshot(replace(original, contexts=(other,),
                                                  selected_fingerprint=other.fingerprint))
    assert view.broadcast_rate_label.text() == "—"
    assert "Capture off" in view.traffic_capture_label.text()
    view.view_model.set_traffic_snapshot(_snapshot(context=other,
        broadcast_rate=float("nan"), arp_rate=float("inf")))
    assert view.broadcast_rate_label.text() == "—"
    assert view.arp_rate_label.text() == "—"


def test_worker_delivery_is_queued_and_mutation_stays_on_gui_thread(qtbot: QtBot) -> None:
    from PyQt6.QtCore import QObject, pyqtSignal

    class Source(QObject):
        ready = pyqtSignal(object)

    source = Source()
    view = DashboardView()
    qtbot.addWidget(view)
    source.ready.connect(view.view_model.set_traffic_snapshot)
    delivered_threads = []
    view.view_model.traffic_changed.connect(
        lambda _: delivered_threads.append(QThread.currentThread()))
    producer = Thread(target=lambda: source.ready.emit(_snapshot()))
    producer.start()
    producer.join(timeout=2)
    assert not producer.is_alive()
    qtbot.waitUntil(lambda: view.broadcast_rate_label.text() == "1.2 pkt/s")
    assert delivered_threads == [view.thread()]

    errors = []
    direct = Thread(target=lambda: _direct_mutation(view, errors))
    direct.start()
    direct.join(timeout=2)
    assert errors == ["Dashboard traffic mutations must run in its Qt thread"]


def _direct_mutation(view: DashboardView, errors: list[str]) -> None:
    try:
        view.view_model.set_traffic_snapshot(_snapshot())
    except RuntimeError as error:
        errors.append(str(error))


def test_alert_change_refreshes_existing_alerts_view_and_close_blocks_delivery(
    qtbot: QtBot,
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    alerts = window.page_widget(PageId.ALERTS)
    dashboard = window.page_widget(PageId.DASHBOARD)
    assert isinstance(alerts, AlertsView)
    assert isinstance(dashboard, DashboardView)
    refreshes = []
    alerts.refresh = lambda: refreshes.append(True)
    changed = replace(_snapshot(), traffic_alert_changed=True)
    window._on_device_snapshot_for_alerts(changed)
    assert refreshes
    window._on_device_snapshot_for_alerts(replace(_snapshot(), identity_alert_changed=True))
    assert len(refreshes) == 2
    assert dashboard.broadcast_rate_label.text() == "1.2 pkt/s"
    window.close()
    window._on_device_snapshot_for_alerts(_snapshot(broadcast_rate=9.0))
    assert dashboard.broadcast_rate_label.text() == "1.2 pkt/s"
