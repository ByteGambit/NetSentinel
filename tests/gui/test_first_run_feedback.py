"""NS-098 offline usability, state, privacy and consent independence."""

from dataclasses import replace
import json
from threading import get_ident

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QDesktopServices, QFont
from PyQt6.QtWidgets import QApplication, QFileDialog

from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.bootstrap import ABUSEIPDB_DESCRIPTOR, create_storage_maintenance_worker
from netsentinel.domain.threat_intelligence import ThreatIntelConsent
from netsentinel.presentation.app import create_application
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.presentation.views.main_window import PageId
from netsentinel.presentation.widgets.onboarding import GUIDE_PAGES, OnboardingDialog
from netsentinel.presentation.widgets.storage_privacy import StoragePrivacyDialog
from netsentinel.shared.config import (
    AppConfig, CURRENT_ONBOARDING_VERSION, complete_onboarding, dismiss_onboarding,
    load_config_file, load_config_values, onboarding_pending, save_config_file,
    show_onboarding_at_startup,
)
from netsentinel.shared.diagnostics import CaptureState, CaptureCapabilityReason, DatabaseStatus
from tests.fixtures.storage_privacy import NOW, alert, connection, dns
from tests.gui.test_application_shell import FakeEngine
from tests.gui.test_capabilities import FakeCapture, FakeContexts, diagnostics
from uuid import UUID


def consent():
    return ThreatIntelConsent(UUID(int=1), ABUSEIPDB_DESCRIPTOR.provider,
                              next(iter(ABUSEIPDB_DESCRIPTOR.supported_data_types)))


@pytest.mark.parametrize("config,modal,pending", [
    (AppConfig(), True, True),
    (AppConfig(onboarding_completed=True), False, True),
    (AppConfig(onboarding_completed_version=1), False, False),
    (AppConfig(onboarding_dismissed_version=1), False, False),
    (AppConfig(onboarding_completed_version=2), False, False),
])
def test_version_trigger_legacy_upgrade_and_future_config(config, modal, pending):
    assert show_onboarding_at_startup(config) is modal
    assert onboarding_pending(config) is pending


def test_material_future_guide_version_uses_nonmodal_upgrade(monkeypatch):
    import netsentinel.shared.config as config_module
    monkeypatch.setattr(config_module, "CURRENT_ONBOARDING_VERSION", 2)
    previous = AppConfig(onboarding_completed_version=1)
    assert onboarding_pending(previous) and not show_onboarding_at_startup(previous)
    assert show_onboarding_at_startup(AppConfig())


@pytest.mark.parametrize("field", ["onboarding_completed_version", "onboarding_dismissed_version"])
@pytest.mark.parametrize("value", [-1, True, "1", None, 10001])
def test_malformed_version_preserves_unrelated_values_and_ti_fails_closed(tmp_path, field, value):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(threat_intel_consents=(consent(),)))
    original = json.loads(path.read_text())
    result = load_config_values({**original, field: value, "polling_interval": 0.5,
                                 "desktop_notifications_enabled": True})
    assert getattr(result.config, field) == 0
    assert result.config.polling_interval == 0.5
    assert result.config.desktop_notifications_enabled
    assert result.config.threat_intel_consents == ()
    assert any(issue.code == "disabled_due_to_config_issue" for issue in result.issues)
    assert any(issue.field == field for issue in result.issues)


@pytest.mark.parametrize("dismiss", [False, True])
def test_completion_and_skip_reload_current_settings_atomically(tmp_path, dismiss):
    path = tmp_path / "config.json"
    stale = AppConfig()
    actual = replace(stale, desktop_notifications_enabled=True, threat_intel_consents=(consent(),),
                     storage_retention_enabled=True, polling_interval=0.2)
    save_config_file(path, actual)
    result = (dismiss_onboarding if dismiss else complete_onboarding)(path, stale)
    assert result.threat_intel_consents == actual.threat_intel_consents
    assert result.desktop_notifications_enabled and result.storage_retention_enabled
    assert result.polling_interval == 0.2
    assert not show_onboarding_at_startup(load_config_file(path).config)
    assert result.onboarding_completed_version == (0 if dismiss else CURRENT_ONBOARDING_VERSION)
    assert result.onboarding_dismissed_version == (CURRENT_ONBOARDING_VERSION if dismiss else 0)
    assert not list(tmp_path.glob(".config-*"))


def test_atomic_save_failure_does_not_complete_or_reset(tmp_path, monkeypatch, qtbot):
    import netsentinel.shared.config as config_module
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(polling_interval=0.2))
    original = path.read_bytes()
    monkeypatch.setattr(config_module.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("secret")))
    dialog = OnboardingDialog(None, lambda: bool(complete_onboarding(path, AppConfig())))
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.finish_button.click()
    assert not dialog.completed and dialog.isVisible()
    assert "could not be saved" in dialog.error.text() and "secret" not in dialog.error.text()
    assert path.read_bytes() == original and not list(tmp_path.glob(".config-*"))


@pytest.mark.parametrize("running", [False, True])
@pytest.mark.parametrize("ti_enabled", [False, True])
@pytest.mark.parametrize("dismiss", [False, True])
def test_guide_never_changes_independent_capture_ti_or_notifications(qtbot, tmp_path, running, ti_enabled, dismiss):
    path = tmp_path / "config.json"
    config = AppConfig(threat_intel_consents=(consent(),) if ti_enabled else ())
    save_config_file(path, config)
    capture = FakeCapture()
    snapshot = diagnostics(capture)
    snapshot = replace(snapshot, capture=replace(snapshot.capture, state=CaptureState.RUNNING if running else CaptureState.STOPPED))
    matrix = CapabilityService(FakeContexts(), capture, lambda: snapshot).check()
    dialog = OnboardingDialog(None, lambda: bool(complete_onboarding(path, config)),
                              skip=lambda: bool(dismiss_onboarding(path, config)), config=config,
                              credential_available=False)
    qtbot.addWidget(dialog)
    dialog.diagnostics.set_matrix(matrix)
    dialog.show()
    assert ("Consent enabled" in dialog.diagnostics.preferences.text()) is ti_enabled
    assert ("Packet capture: Running" in dialog.diagnostics.summary.text()) is running
    assert "Disabled by user" in dialog.diagnostics.preferences.text()
    assert "Unavailable (this desktop" in dialog.diagnostics.preferences.text()
    for _ in range(5):
        dialog.next_button.click()
    dialog.back_button.click()
    assert load_config_file(path).config == config
    (dialog.skip_button if dismiss else dialog.finish_button).click()
    after = load_config_file(path).config
    assert after.threat_intel_consents == config.threat_intel_consents
    assert not after.desktop_notifications_enabled
    assert capture.starts == 0 and matrix.diagnostics.capture.state is snapshot.capture.state


@pytest.mark.parametrize("reason,database", [
    (CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE, DatabaseStatus.AVAILABLE),
    (CaptureCapabilityReason.NONE, DatabaseStatus.UNAVAILABLE),
    (CaptureCapabilityReason.TRANSIENT_FAILURE, DatabaseStatus.AVAILABLE),
])
def test_missing_optional_capabilities_do_not_block_guide(qtbot, reason, database):
    capture = FakeCapture(reason)
    dialog = OnboardingDialog(None, lambda: True, credential_available=False)
    qtbot.addWidget(dialog)
    dialog.diagnostics.set_matrix(CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture, database)).check())
    dialog.show()
    assert dialog.finish_button.isEnabled()
    assert database.value.capitalize() in dialog.diagnostics.summary.text()
    assert "No packet capture was started" in dialog.diagnostics.status.text()
    dialog.finish_button.click()
    assert dialog.completed and capture.starts == 0


def test_no_interface_is_unavailable_even_if_capture_probe_was_available(qtbot):
    capture = FakeCapture()
    view = DiagnosticsView()
    qtbot.addWidget(view)
    view.set_matrix(CapabilityService(FakeContexts(False), capture, lambda: diagnostics(capture)).check())
    assert "Packet capture: Unavailable" in view.summary.text()
    assert not view.details.isVisible()
    view.show()
    view.details_button.click()
    assert view.details.isVisible()


@pytest.mark.parametrize("size,font_size", [((740, 600), 9), ((780, 640), 12), ((920, 640), 16)])
def test_guide_layout_keyboard_and_accessibility(qtbot, size, font_size):
    saved = []
    dialog = OnboardingDialog(None, lambda: saved.append(True) or True, skip=lambda: True)
    qtbot.addWidget(dialog)
    dialog.setFont(QFont("Segoe UI", font_size))
    dialog.resize(*size)
    dialog.show()
    dialog.activateWindow()
    qtbot.waitUntil(dialog.isActiveWindow)
    for index in range(6):
        assert f"{index + 1} / 6" in dialog.progress.text()
        for button in (dialog.back_button, dialog.next_button, dialog.skip_button, dialog.cancel_button, dialog.finish_button):
            assert button.accessibleName() and dialog.rect().contains(button.mapTo(dialog, button.rect().bottomRight()))
        if index < 5:
            dialog.next_button.setFocus()
            qtbot.keyClick(dialog.next_button, Qt.Key.Key_Space)
    qtbot.keyClick(dialog, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is not None
    dialog.finish_button.setFocus()
    qtbot.keyClick(dialog.finish_button, Qt.Key.Key_Return)
    assert saved == [True]


def test_esc_cancel_does_not_save_and_back_is_read_only(qtbot):
    saved = []
    dialog = OnboardingDialog(None, lambda: saved.append(True) or True, skip=lambda: True)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.next_button.click()
    dialog.back_button.click()
    qtbot.keyClick(dialog, Qt.Key.Key_Escape)
    assert not dialog.completed and not dialog.skipped and saved == []


def test_help_reopen_current_settings_and_stable_navigation_preserves_engine(qtbot, tmp_path):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(onboarding_completed=True))
    engine = FakeEngine()
    shell = create_application(engine, config=load_config_file(path).config, config_path=path)
    qtbot.addWidget(shell.window)
    shell.window.show()
    assert "Privacy guide updated" in shell.window.statusBar().currentMessage()
    current = AppConfig(onboarding_completed=True, threat_intel_consents=(consent(),),
                        desktop_notifications_enabled=True, storage_retention_enabled=True)
    save_config_file(path, current)

    def inspect():
        dialogs = [item for item in QApplication.topLevelWidgets() if isinstance(item, OnboardingDialog) and item.isVisible()]
        assert len(dialogs) == 1
        dialog = dialogs[0]
        assert "Consent enabled" in dialog.diagnostics.preferences.text()
        assert "Notifications: Enabled" in dialog.diagnostics.preferences.text()
        dialog.links["Devices"].click()

    QTimer.singleShot(0, inspect)
    shell.window.onboarding_action.trigger()
    assert shell.window.current_page is PageId.DEVICES
    assert load_config_file(path).config == current
    assert engine.start_calls == 0
    shell.lifecycle.shutdown()


def test_all_limitation_wording_is_available_later():
    text = " ".join(paragraph for _, paragraphs in GUIDE_PAGES for paragraph in paragraphs)
    for wording in ("NetSentinel does not upload your network history by default.", "polling", "very short-lived",
                    "process creation/termination", "Per-flow", "DoH/DoT", "many-to-many", "ASN/country",
                    "disk", "memory integrity", "Signed does not mean safe", "unsigned does not mean malicious",
                    "HIT is not a malware", "NO_HIT is not a safety", "Novel/rare", "malware probability",
                    "Severity", "confidence", "measurement quality", "ordering is not causality", "expire",
                    "No automatic blocking", "AbuseIPDB", "source IP", "manual", "secret backend"):
        assert wording in text


def test_feedback_uses_existing_worker_full_preview_atomic_save_and_explicit_browser(qtbot, tmp_path, monkeypatch):
    from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
    from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
    database = SQLiteDatabase(tmp_path / "synthetic.db")
    connection(database, 1, NOW)
    dns(database, 2, NOW)
    for number in range(1, 13):
        alert(database, number, NOW)
    ui_thread = get_ident()
    readers = []
    original = SQLiteStorageMaintenanceRepository.export_page
    def tracked(self, *args):
        readers.append(get_ident())
        return original(self, *args)
    monkeypatch.setattr(SQLiteStorageMaintenanceRepository, "export_page", tracked)
    browser = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: browser.append(url.toString()) or True)
    worker = create_storage_maintenance_worker(database_path=database.path)
    worker.start()
    dialog = StoragePrivacyDialog(worker, feedback=True)
    qtbot.addWidget(dialog)
    dialog.show()
    try:
        assert dialog._future is None and dialog._export is None and browser == []
        assert not dialog.storage_controls.isVisible() and not dialog.export_save.isEnabled()
        dialog.export_preview.click()
        qtbot.waitUntil(lambda: dialog._future is None, timeout=5000)
        export = dialog._export
        assert export is not None
        assert dialog.preview.toPlainText().encode() == export.content
        parsed = json.loads(export.content)
        assert len(parsed["records"]) == 12  # full preview, beyond old sample of ten
        assert parsed["manifest"]["redaction_policy"] == "allowlist-v1"
        assert len(export.content) <= 65536 and export.record_count <= 100
        for raw in ("192.0.2.123", "203.0.113.123", "private.example", "connection_history(id", "api_key"):
            assert raw not in dialog.preview.toPlainText()
        destination = tmp_path / "netsentinel-support.json"
        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_: (str(destination), "JSON"))
        dialog.export_save.click()
        qtbot.waitUntil(lambda: dialog._future is None, timeout=5000)
        assert destination.read_bytes() == export.content and "No upload" in dialog.status.text()
        assert readers and all(thread != ui_thread for thread in readers) and browser == []
        dialog.project_button.click()
        assert browser == ["https://github.com/ByteGambit/NetSentinel"]
        assert "No dedicated feedback" in dialog.feedback_note.text()
        assert "No optional raw-data" in dialog.categories.text()
        assert not list(tmp_path.glob(".netsentinel-export-*"))
    finally:
        dialog.reject()
        assert worker.stop()


def test_feedback_failure_is_sanitized_and_no_save(qtbot, tmp_path):
    invalid = tmp_path / "invalid.db"
    invalid.write_bytes(b"not a database")
    worker = create_storage_maintenance_worker(database_path=invalid)
    worker.start()
    dialog = StoragePrivacyDialog(worker, feedback=True)
    qtbot.addWidget(dialog)
    dialog.show()
    try:
        dialog.export_preview.click()
        qtbot.waitUntil(lambda: dialog._future is None)
        assert not dialog.export_save.isEnabled() and dialog._export is None
        assert str(tmp_path) not in dialog.status.text()
    finally:
        dialog.reject()
        assert worker.stop()


@pytest.mark.parametrize("viewport", [(1280, 720), (1366, 768), (1600, 900), (1920, 1080)])
@pytest.mark.parametrize("font_size", [9, 16])
def test_supported_viewports_keep_essential_guide_and_feedback_controls(qtbot, tmp_path, viewport, font_size):
    shell = create_application(FakeEngine())
    qtbot.addWidget(shell.window)
    shell.window.resize(*viewport)
    shell.window.show()
    guide = OnboardingDialog(None, lambda: True, shell.window, skip=lambda: True)
    qtbot.addWidget(guide)
    guide.setFont(QFont("Segoe UI", font_size))
    guide.show()
    worker = create_storage_maintenance_worker(database_path=tmp_path / "synthetic.db")
    feedback = StoragePrivacyDialog(worker, shell.window, feedback=True)
    qtbot.addWidget(feedback)
    feedback.setFont(QFont("Segoe UI", font_size))
    feedback.show()
    for dialog, buttons in ((guide, (guide.finish_button, guide.skip_button, guide.cancel_button)),
                            (feedback, (feedback.export_preview, feedback.export_save, feedback.close_button))):
        assert dialog.width() <= viewport[0] and dialog.height() <= viewport[1]
        for button in buttons:
            assert dialog.rect().contains(button.mapTo(dialog, button.rect().bottomRight()))
            assert button.accessibleName() and button.toolTip()
    feedback.reject()
    guide.reject()
    shell.lifecycle.shutdown()


def test_help_completion_acknowledges_upgrade_without_engine_restart(qtbot, tmp_path):
    path = tmp_path / "config.json"
    config = AppConfig(onboarding_completed=True, desktop_notifications_enabled=True)
    save_config_file(path, config)
    engine = FakeEngine()
    shell = create_application(engine, config=config, config_path=path)
    qtbot.addWidget(shell.window)
    shell.window.show()
    def finish():
        dialog = next(item for item in QApplication.topLevelWidgets()
                      if isinstance(item, OnboardingDialog) and item.isVisible())
        dialog.finish_button.click()
    QTimer.singleShot(0, finish)
    shell.window.onboarding_action.trigger()
    assert not onboarding_pending(load_config_file(path).config)
    assert load_config_file(path).config.desktop_notifications_enabled
    assert not shell.window.statusBar().currentMessage()
    assert engine.start_calls == 0
    shell.lifecycle.shutdown()


def test_feedback_repreview_failure_clears_old_preview_and_save(qtbot, tmp_path, monkeypatch):
    from netsentinel.application.services.storage_privacy import StoragePrivacyService
    worker = create_storage_maintenance_worker(database_path=tmp_path / "synthetic.db")
    worker.start()
    dialog = StoragePrivacyDialog(worker, feedback=True)
    qtbot.addWidget(dialog)
    dialog.show()
    try:
        dialog.export_preview.click()
        qtbot.waitUntil(lambda: dialog._future is None)
        assert dialog.export_save.isEnabled()
        def fail(*_):
            raise RuntimeError("secret raw telemetry")
        monkeypatch.setattr(StoragePrivacyService, "preview_export", fail)
        dialog.export_preview.click()
        qtbot.waitUntil(lambda: dialog._future is None)
        assert not dialog.export_save.isEnabled() and not dialog.preview.toPlainText()
        assert "secret" not in dialog.status.text()
    finally:
        dialog.reject()
        assert worker.stop()
