"""NS-095 offscreen confirmation, Cancel, preview, settings and worker lifecycle."""

from datetime import timedelta
from threading import get_ident

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFileDialog

from netsentinel.application.services.storage_privacy import StoragePrivacyService
from netsentinel.application.services.storage_worker import StorageMaintenanceWorker
from netsentinel.bootstrap import create_storage_maintenance_worker
from netsentinel.domain.storage_privacy import StorageScope
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
from netsentinel.presentation.app import create_application
from netsentinel.presentation.widgets.storage_privacy import StoragePrivacyDialog
from netsentinel.shared.config import load_config_file, save_config_file, AppConfig
from tests.fixtures.storage_privacy import NOW, connection, count
from tests.gui.test_application_shell import FakeEngine


@pytest.fixture
def ui(qtbot, tmp_path):
    database = SQLiteDatabase(tmp_path / 'storage.db', busy_timeout_ms=100)
    connection(database, 1, NOW - timedelta(days=100))
    target = tmp_path / 'config.json'
    save_config_file(target, AppConfig())
    worker = create_storage_maintenance_worker(database_path=database.path, config_path=target)
    worker.start()
    dialog = StoragePrivacyDialog(worker)
    qtbot.addWidget(dialog)
    dialog.show()
    qtbot.waitUntil(lambda: dialog._future is None, timeout=5000)
    yield dialog, worker, database, target
    dialog.reject()
    assert worker.stop()


def click(qtbot, button, dialog):
    qtbot.mouseClick(button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: dialog._future is None, timeout=5000)


def test_settings_storage_summary_local_wording_and_counts(ui):
    dialog, worker, database, _ = ui
    assert 'Approximate DB' in dialog.summary.toPlainText()
    assert 'Scheduled retention disabled' in dialog.summary.toPlainText()
    assert 'protected' in dialog.summary.toPlainText()
    assert 'No cleanup this session' in dialog.summary.toPlainText()
    assert dialog.purge_button.isEnabled() and dialog.export_preview.isEnabled()
    assert not dialog.export_save.isEnabled()
    assert not worker.settings.enabled and count(database, 'connection_history') == 1


def test_close_cancel_settings_no_config_write(ui):
    dialog, _, _, target = ui
    original = target.read_bytes()
    dialog.enabled.setChecked(True)
    dialog.history_days.setValue(60)
    dialog.reject()
    assert target.read_bytes() == original


def test_settings_save_round_trip_deferred_schedule(ui, qtbot):
    dialog, worker, _, target = ui
    dialog.enabled.setChecked(True)
    dialog.history_days.setValue(60)
    click(qtbot, dialog.save_settings, dialog)
    loaded = load_config_file(target).config
    assert loaded.storage_retention_enabled and loaded.storage_history_days == 60
    assert worker.settings.enabled and worker.next_due_seconds > 50


@pytest.mark.parametrize('confirmed', [False, True])
def test_purge_confirmation_exact_scope_cancel_and_delete(ui, qtbot, monkeypatch, confirmed):
    dialog, _, database, _ = ui
    text = []
    def answer(message):
        text.append(message)
        return confirmed
    monkeypatch.setattr(dialog, '_ask_delete', answer)
    dialog.scope.setCurrentIndex(dialog.scope.findData(StorageScope.CONNECTIONS))
    click(qtbot, dialog.purge_button, dialog)
    assert 'Completed connection history' in text[0]
    assert 'Estimated eligible: 1' in text[0]
    for required in ('Protected', 'profiles/trust', 'preferences', 'expire', 'irreversible', 'Cancel'):
        assert required in text[0]
    assert count(database, 'connection_history') == (0 if confirmed else 1)


def test_export_preview_redacted_then_save_exact_bytes(ui, qtbot, tmp_path, monkeypatch):
    dialog, _, _, _ = ui
    click(qtbot, dialog.export_preview, dialog)
    assert dialog.export_save.isEnabled()
    assert 'support-export-v1' in dialog.preview.toPlainText()
    assert '192.0.2.123' not in dialog.preview.toPlainText()
    original = dialog._export.content
    destination = tmp_path / 'chosen.json'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *args: (str(destination), 'JSON'))
    click(qtbot, dialog.export_save, dialog)
    assert destination.read_bytes() == original
    assert 'No upload' in dialog.status.text()


def test_cancel_export_save_dialog_writes_no_file(ui, qtbot, tmp_path, monkeypatch):
    dialog, _, _, _ = ui
    click(qtbot, dialog.export_preview, dialog)
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *args: ('', ''))
    click(qtbot, dialog.export_save, dialog)
    assert not list(tmp_path.glob('*.json')) or list(tmp_path.glob('*.json')) == [tmp_path / 'config.json']
    assert not list(tmp_path.glob('.netsentinel-export-*'))


def test_off_qt_thread_summary_export_purge_and_config(qtbot, tmp_path, monkeypatch):
    database = SQLiteDatabase(tmp_path / 'thread.db', busy_timeout_ms=100)
    connection(database, 1, NOW - timedelta(days=100))
    caller = get_ident()
    identities = []
    class CheckedRepository(SQLiteStorageMaintenanceRepository):
        def summary(self, *args):
            identities.append(get_ident())
            return super().summary(*args)
        def cleanup_chunk(self, *args):
            identities.append(get_ident())
            return super().cleanup_chunk(*args)
        def export_page(self, *args):
            identities.append(get_ident())
            return super().export_page(*args)
    def save(settings):
        identities.append(get_ident())
    worker = StorageMaintenanceWorker(lambda: StoragePrivacyService(CheckedRepository(database), clock=lambda: NOW), save_settings=save)
    worker.start()
    dialog = StoragePrivacyDialog(worker)
    qtbot.addWidget(dialog)
    dialog.show()
    try:
        qtbot.waitUntil(lambda: dialog._future is None)
        click(qtbot, dialog.save_settings, dialog)
        click(qtbot, dialog.export_preview, dialog)
        monkeypatch.setattr(dialog, '_ask_delete', lambda text: True)
        click(qtbot, dialog.purge_button, dialog)
        assert len(identities) >= 5 and all(identity != caller for identity in identities)
        assert len(set(identities)) == 1
    finally:
        dialog.reject()
        assert worker.stop()


def test_shell_settings_action_and_bounded_idempotent_shutdown(qtbot, tmp_path):
    engine = FakeEngine()
    worker = create_storage_maintenance_worker(database_path=tmp_path / 'unused.db')
    shell = create_application(engine, storage_maintenance=worker)
    qtbot.addWidget(shell.window)
    assert shell.window.storage_privacy_action.isEnabled()
    assert shell.lifecycle.start()
    assert not (tmp_path / 'unused.db').exists()
    assert shell.lifecycle.shutdown() and shell.lifecycle.shutdown()
    assert engine.stop_calls == 1 and not worker.start()
