"""NS-048 offscreen capability, first-run, retry and lifecycle regressions."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import product
from threading import Event, current_thread

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.application.ports import NetworkContextPermissionDenied
from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.presentation.widgets.onboarding import OnboardingDialog
from netsentinel.presentation.app import run_application
from tests.gui.test_application_shell import FakeEngine
from netsentinel.shared.config import AppConfig, complete_onboarding, load_config_file, load_config_values
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot, CapabilityStatus, CaptureCapabilityReason,
    CaptureCapabilitySnapshot, CaptureCounters, CaptureHealthSnapshot,
    CaptureState, DatabaseDiagnostic, DatabaseStatus, DiagnosticsSnapshot,
    EngineCounters, EngineHealthSnapshot, EngineState,
)


class FakeContexts:
    def __init__(self, present: bool = True) -> None:
        self.present = present

    def get_contexts(self):
        return (type("Context", (), {"is_loopback": False})(),) if self.present else ()


class FakeCapture:
    def __init__(self, reason: CaptureCapabilityReason = CaptureCapabilityReason.NONE) -> None:
        self.reason = reason
        self.probes = 0
        self.starts = 0

    def probe(self, _context):
        self.probes += 1
        return self.health_snapshot().capability

    def health_snapshot(self):
        status = (
            CapabilityStatus.AVAILABLE if self.reason is CaptureCapabilityReason.NONE else
            CapabilityStatus.DEGRADED if self.reason is CaptureCapabilityReason.TRANSIENT_FAILURE else
            CapabilityStatus.UNAVAILABLE
        )
        return CaptureHealthSnapshot(
            CaptureState.STOPPED,
            CaptureCapabilitySnapshot(status, self.reason, datetime.now(UTC)),
            0, 8, CaptureCounters(),
        )


def diagnostics(capture: FakeCapture, database: DatabaseStatus = DatabaseStatus.AVAILABLE):
    return DiagnosticsSnapshot(
        EngineHealthSnapshot(EngineState.STOPPED, CapabilitySnapshot(), EngineCounters()),
        None, capture.health_snapshot(), DatabaseDiagnostic(database),
    )


@pytest.mark.parametrize(
    ("reason", "present", "db", "capture_status", "devices_status"),
    [
        (CaptureCapabilityReason.NONE, True, DatabaseStatus.AVAILABLE, "available", "available"),
        (CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE, True, DatabaseStatus.AVAILABLE, "unavailable", "degraded"),
        (CaptureCapabilityReason.PERMISSION_DENIED, True, DatabaseStatus.AVAILABLE, "unavailable", "degraded"),
        (CaptureCapabilityReason.NONE, False, DatabaseStatus.AVAILABLE, "unavailable", "degraded"),
        (CaptureCapabilityReason.NONE, True, DatabaseStatus.UNAVAILABLE, "available", "unavailable"),
    ],
)
def test_capability_matrix_keeps_connection_monitoring_and_saved_views_independent(
    reason, present, db, capture_status, devices_status,
):
    capture = FakeCapture(reason)
    matrix = CapabilityService(FakeContexts(present), capture, lambda: diagnostics(capture, db)).check()
    rows = {row.name: row for row in matrix.features}
    assert rows["Connections"].status.value == "available"
    assert rows["Packet capture"].status.value == capture_status
    assert rows["Devices"].status.value == devices_status
    assert rows["History"].status.value == db.value
    assert capture.starts == 0
    assert capture.probes == int(present)


@pytest.mark.parametrize(
    ("reason", "present", "db"),
    list(product(
        (CaptureCapabilityReason.NONE, CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE,
         CaptureCapabilityReason.PERMISSION_DENIED, CaptureCapabilityReason.INTERFACE_UNAVAILABLE,
         CaptureCapabilityReason.TRANSIENT_FAILURE),
        (True, False),
        (DatabaseStatus.AVAILABLE, DatabaseStatus.UNAVAILABLE),
    )),
)
def test_capability_matrix_all_dependency_interface_storage_combinations(reason, present, db):
    capture = FakeCapture(reason)
    matrix = CapabilityService(FakeContexts(present), capture, lambda: diagnostics(capture, db)).check()
    assert len(matrix.features) == 7
    for feature in matrix.features:
        assert feature.reason
        assert feature.status in CapabilityStatus
    packet = next(feature for feature in matrix.features if feature.name == "Packet capture")
    assert packet.reason == (reason.value if present else "interface_unavailable")
    assert packet.status is (
        CapabilityStatus.UNAVAILABLE if not present else
        CapabilityStatus.AVAILABLE if reason is CaptureCapabilityReason.NONE else
        CapabilityStatus.DEGRADED if reason is CaptureCapabilityReason.TRANSIENT_FAILURE else
        CapabilityStatus.UNAVAILABLE
    )


def test_context_permission_denial_is_not_reported_as_missing_driver():
    class DeniedContexts:
        def get_contexts(self):
            raise NetworkContextPermissionDenied("private adapter detail")

    capture = FakeCapture()
    matrix = CapabilityService(DeniedContexts(), capture, lambda: diagnostics(capture)).check()
    packet = next(feature for feature in matrix.features if feature.name == "Packet capture")
    assert packet.reason == "permission_denied"
    assert capture.probes == 0
    assert all("private adapter detail" not in feature.reason for feature in matrix.features)


def test_probe_failure_is_sanitized_while_database_and_connections_remain_visible(qtbot):
    class FailingCapture(FakeCapture):
        def probe(self, _context):
            raise RuntimeError("secret /private/path SELECT payload")

    capture = FailingCapture()
    matrix = CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)).check()
    rows = {feature.name: feature for feature in matrix.features}
    assert rows["Packet capture"].reason == "probe_unavailable"
    assert rows["History"].status is CapabilityStatus.AVAILABLE
    assert rows["Connections"].status is CapabilityStatus.AVAILABLE
    view = DiagnosticsView()
    qtbot.addWidget(view)
    view.set_matrix(matrix)
    assert "secret" not in view.rows["Packet capture"].text()


@pytest.mark.parametrize("reason, wording", [
    (CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE, "dependency or driver"),
    (CaptureCapabilityReason.PERMISSION_DENIED, "permission was denied"),
    (CaptureCapabilityReason.INTERFACE_UNAVAILABLE, "interface"),
])
def test_diagnostics_view_shows_distinct_sanitized_capture_reasons(reason, wording, qtbot):
    capture = FakeCapture(reason)
    matrix = CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)).check()
    view = DiagnosticsView()
    qtbot.addWidget(view)
    view.set_matrix(matrix)
    assert wording in view.rows["Packet capture"].text().lower()
    assert "packet capture: stopped" in view.health.text().lower()
    assert "database: available" in view.health.text().lower()


def test_first_run_requires_explicit_finish_and_survives_restart(tmp_path, qtbot):
    path = tmp_path / "config.json"
    assert not load_config_file(path).config.onboarding_completed
    capture = FakeCapture(CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE)
    coordinator = CapabilityCoordinator(lambda: CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)))
    assert coordinator.start()
    first = OnboardingDialog(coordinator, lambda: bool(complete_onboarding(path, AppConfig())))
    qtbot.addWidget(first)
    first.show()
    qtbot.waitUntil(lambda: "dependency" in first.diagnostics.rows["Packet capture"].text().lower())
    assert first.finish_button.isEnabled()
    first.close()
    assert not load_config_file(path).config.onboarding_completed
    second = OnboardingDialog(coordinator, lambda: bool(complete_onboarding(path, AppConfig())))
    qtbot.addWidget(second)
    second.show()
    qtbot.mouseClick(second.finish_button, Qt.MouseButton.LeftButton)
    assert second.completed
    assert load_config_file(path).config.onboarding_completed
    assert coordinator.stop()
    assert not coordinator.worker_alive
    assert capture.starts == 0


def test_malformed_config_fallback_keeps_onboarding_available(tmp_path, qtbot):
    path = tmp_path / "config.json"
    path.write_text("{bad", encoding="utf-8")
    loaded = load_config_file(path)
    assert loaded.issues and not loaded.config.onboarding_completed
    capture = FakeCapture()
    coordinator = CapabilityCoordinator(lambda: CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)))
    coordinator.start()
    dialog = OnboardingDialog(coordinator, lambda: bool(complete_onboarding(path, loaded.config)))
    qtbot.addWidget(dialog)
    dialog.show()
    qtbot.mouseClick(dialog.finish_button, Qt.MouseButton.LeftButton)
    assert load_config_file(path).config.onboarding_completed
    assert coordinator.stop()


def test_retry_discards_old_result_and_stops_one_worker(qtbot):
    entered = Event()
    release = Event()
    capture = FakeCapture()
    calls: list[str] = []

    class SlowService:
        def check(self):
            calls.append(current_thread().name)
            if len(calls) == 1:
                entered.set()
                release.wait(2)
                return CapabilityService(FakeContexts(), FakeCapture(CaptureCapabilityReason.PERMISSION_DENIED),
                                         lambda: diagnostics(FakeCapture(CaptureCapabilityReason.PERMISSION_DENIED))).check()
            return CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)).check()

    coordinator = CapabilityCoordinator(SlowService)
    view = DiagnosticsView(coordinator)
    qtbot.addWidget(view)
    coordinator.start()
    view.retry()
    assert entered.wait(1)
    view.retry()
    release.set()
    qtbot.waitUntil(lambda: "Available" in view.rows["Packet capture"].text(), timeout=2000)
    assert len(calls) == 2
    assert set(calls) == {"netsentinel-capabilities"}
    view.deactivate()
    assert coordinator.stop()
    assert not coordinator.worker_alive


def test_invalid_onboarding_field_falls_back_without_implicit_completion():
    result = load_config_values({"onboarding_completed": "true", "polling_interval": 0.2})
    assert result.config.onboarding_completed is False
    assert result.config.polling_interval == 0.2
    assert result.issues[0].field == "onboarding_completed"


@pytest.mark.parametrize("initial", ["first", "completed", "malformed"])
def test_production_startup_uses_one_application_and_one_engine(
    initial, tmp_path, monkeypatch, qapp,
):
    import netsentinel.bootstrap as bootstrap

    path = tmp_path / "NetSentinel" / "config.json"
    path.parent.mkdir()
    if initial == "completed":
        complete_onboarding(path, AppConfig())
    elif initial == "malformed":
        path.write_text("{bad", encoding="utf-8")
    engine = FakeEngine()
    capture = FakeCapture(CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE)
    monkeypatch.setattr(bootstrap, "runtime_config_path", lambda: path)
    monkeypatch.setattr(bootstrap, "initialize_runtime", lambda **_kw: load_config_file(path))
    monkeypatch.setattr(bootstrap, "create_desktop_engine", lambda **_kw: engine)
    monkeypatch.setattr(bootstrap, "create_capability_service_factory", lambda *_a, **_kw:
                        lambda: CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)))
    for name in (
        "create_history_query_service_factory", "create_device_inventory_service_factory",
        "create_device_profile_service_factory", "create_alert_query_service_factory",
        "create_dns_query_service_factory",
    ):
        monkeypatch.setattr(bootstrap, name, lambda **_kw: None)

    def inspect_and_exit(application):
        assert application is qapp
        assert QApplication.instance() is qapp
        dialogs = [widget for widget in QApplication.topLevelWidgets()
                   if isinstance(widget, OnboardingDialog) and widget.isVisible()]
        if initial == "completed":
            assert not dialogs
            assert engine.start_calls == 1
        else:
            assert len(dialogs) == 1
            assert engine.start_calls == 0
            if initial == "malformed":
                assert "safe defaults" in dialogs[0].error.text()
            dialogs[0]._complete()
            assert engine.start_calls == 1
            assert load_config_file(path).config.onboarding_completed
        return 0

    monkeypatch.setattr(QApplication, "exec", inspect_and_exit)
    assert run_application(argv=[]) == 0
    assert engine.start_calls == 1
    assert engine.stop_calls == 1
    assert capture.starts == 0
