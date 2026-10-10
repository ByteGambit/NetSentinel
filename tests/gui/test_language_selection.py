"""NS-106 language bootstrap, accessible controls and whole-app restart."""

from dataclasses import replace
import json
from pathlib import Path

import pytest
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QApplication, QDialog

from netsentinel.presentation import app as app_module
from netsentinel.presentation.i18n import manager as manager_module
from netsentinel.presentation.i18n.manager import LocalizationManager, LocaleOutcome
from netsentinel.presentation.i18n.preferences import (
    LanguagePreferences, LanguageStartupCancelled, prepare_language,
)
from netsentinel.presentation.i18n.text import translate
from netsentinel.presentation.widgets.language_settings import LanguageSelectionDialog
from netsentinel.shared import config as config_module
from netsentinel.shared.config import AppConfig, load_config_file, save_config_file
from tests.fixtures.threat_intelligence import grant
from tests.gui._ns013_support import FakeEngine

PSEUDO = Path(__file__).parents[1] / 'fixtures/i18n/pseudo.qm'


@pytest.fixture
def manager(qapp):
    item = LocalizationManager(qapp)
    item.activate('en')
    yield item
    item.close()


def fixture_catalogs(monkeypatch):
    monkeypatch.setattr(manager_module, 'bundled_catalog',
                        lambda locale: PSEUDO.read_bytes() if locale in ('tr', 'ar') else None)


def test_planned_names_and_actual_availability(manager, tmp_path, qtbot):
    preferences = LanguagePreferences(manager, tmp_path / 'config.json')
    assert len(preferences.options) == 18
    assert manager.available_locales == ('en',)
    assert [item.metadata.id for item in preferences.options if item.selectable] == ['en']
    dialog = LanguageSelectionDialog(preferences, first_launch=True)
    qtbot.addWidget(dialog)
    dialog.show()
    assert dialog.isVisible()
    names = [dialog.languages.item(index).text() for index in range(18)]
    for name in ('Türkçe', 'Русский', 'العربية', '日本語', '한국어', '简体中文', '繁體中文'):
        assert any(name in text and 'unavailable' in text for text in names)
    assert preferences.options[11].metadata.rtl
    assert dialog.languages.accessibleName() == 'Languages'
    assert dialog.languages.accessibleDescription()
    assert dialog.confirm.accessibleName() == 'Continue'
    assert dialog.english.accessibleName() == 'Use English'
    assert not preferences.path.exists()


def test_keyboard_selection_tab_enter_and_layout(manager, monkeypatch, tmp_path, qtbot):
    fixture_catalogs(monkeypatch)
    preferences = LanguagePreferences(manager, tmp_path / 'config.json')
    dialog = LanguageSelectionDialog(preferences, first_launch=True)
    qtbot.addWidget(dialog)
    dialog.resize(380, 380)
    dialog.show()
    dialog.languages.setCurrentRow(0)
    dialog.activateWindow()
    QApplication.processEvents()
    dialog.languages.setFocus()
    qtbot.waitUntil(lambda: QApplication.focusWidget() is dialog.languages)
    qtbot.keyClick(dialog.languages, Qt.Key.Key_Down)
    assert dialog.languages.currentItem().data(Qt.ItemDataRole.UserRole) == 'tr'
    assert not preferences.path.exists()
    qtbot.keyClick(dialog.languages, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is dialog.confirm
    qtbot.keyClick(dialog.confirm, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is dialog.english
    qtbot.keyClick(dialog.english, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is dialog.cancel
    for control in (dialog.languages, dialog.confirm, dialog.english, dialog.cancel):
        assert dialog.rect().contains(control.geometry())
    dialog.confirm.setFocus()
    qtbot.keyClick(dialog.confirm, Qt.Key.Key_Return)
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert load_config_file(preferences.path).config.ui_language == 'tr'
    assert manager.current_locale == 'en'  # not installed while choosing


@pytest.mark.parametrize('action', ['escape', 'close', 'cancel'])
def test_bootstrap_cancel_never_writes(manager, tmp_path, qtbot, action):
    preferences = LanguagePreferences(manager, tmp_path / 'config.json')
    dialog = LanguageSelectionDialog(preferences, first_launch=True)
    qtbot.addWidget(dialog)
    dialog.show()
    if action == 'escape':
        qtbot.keyClick(dialog, Qt.Key.Key_Escape)
    elif action == 'close':
        dialog.close()
    else:
        qtbot.mouseClick(dialog.cancel, Qt.MouseButton.LeftButton)
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert not preferences.path.exists()
    assert preferences.needs_choice


def test_actual_modal_bootstrap_once_and_restart(manager, tmp_path, monkeypatch):
    path = tmp_path / 'config.json'
    original = LanguageSelectionDialog.exec
    calls = []
    def choose(dialog):
        calls.append(dialog)
        QTimer.singleShot(0, dialog.confirm.click)
        return original(dialog)
    monkeypatch.setattr(LanguageSelectionDialog, 'exec', choose)
    first = prepare_language(manager, path)
    assert first.saved
    assert first.config.ui_language_confirmed
    assert prepare_language(manager, path).needs_choice is False
    assert len(calls) == 1


def test_legacy_upgrade_preserves_all_settings_and_data(manager, tmp_path, monkeypatch):
    path = tmp_path / 'config.json'
    config = AppConfig(onboarding_completed=True, onboarding_completed_version=999,
                       onboarding_dismissed_version=500, desktop_notifications_enabled=True,
                       storage_retention_enabled=True, threat_intel_consents=(grant(),))
    save_config_file(path, config)
    raw = json.loads(path.read_text())
    raw.pop('ui_language')
    raw.pop('ui_language_confirmed')
    path.write_text(json.dumps(raw))
    database = tmp_path / 'netsentinel.sqlite3'
    database.write_bytes(b'untouched monitoring and firewall custody fixture')
    before = database.read_bytes()
    def choose(dialog):
        dialog.english.click()
        return dialog.result()
    monkeypatch.setattr(LanguageSelectionDialog, 'exec', choose)
    result = prepare_language(manager, path)
    assert result.config == replace(config, ui_language_confirmed=True)
    assert database.read_bytes() == before
    assert not config_module.show_onboarding_at_startup(result.config)
    assert prepare_language(manager, path).needs_choice is False


@pytest.mark.parametrize('locale,data,status', [('tr', None, LocaleOutcome.MISSING),
    ('tr', b'corrupt', LocaleOutcome.INVALID), ('removed', None, LocaleOutcome.ENGLISH)])
def test_confirmed_bad_preference_falls_back_without_repair_or_reprompt(
        manager, monkeypatch, tmp_path, locale, data, status):
    path = tmp_path / 'config.json'
    values = {'ui_language': locale, 'ui_language_confirmed': True, 'onboarding_completed': True}
    path.write_text(json.dumps(values))
    before = path.read_bytes()
    monkeypatch.setattr(manager_module, 'bundled_catalog', lambda _: data)
    def unexpected(dialog):
        pytest.fail('confirmed preference must not force another chooser')
    monkeypatch.setattr(LanguageSelectionDialog, 'exec', unexpected)
    preferences = prepare_language(manager, path)
    assert preferences.catalog_status is status
    assert preferences.diagnostics.fallback_active
    assert manager.current_locale == 'en'
    assert path.read_bytes() == before
    assert preferences.diagnostics.preference_invalid == (locale == 'removed')
    dialog = LanguageSelectionDialog(preferences)
    assert 'English' in dialog.notice.text()
    assert 'invalid or' in dialog.error.text()
    dialog.english.click()
    assert not preferences.diagnostics.fallback_active
    assert load_config_file(path).config.ui_language == 'en'
    dialog.close()


def test_save_failure_retry_and_explicit_unsaved_recovery(manager, tmp_path, monkeypatch, qtbot):
    path = tmp_path / 'config.json'
    preferences = LanguagePreferences(manager, path)
    def fail(*args, **kwargs):
        raise OSError('secret file path')
    monkeypatch.setattr(config_module.os, 'replace', fail)
    dialog = LanguageSelectionDialog(preferences, first_launch=True)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.confirm.click()
    assert dialog.isVisible()
    assert not path.exists()
    assert not preferences.saved
    assert not preferences.config.ui_language_confirmed
    assert 'could not be saved' in dialog.error.text()
    assert 'secret' not in dialog.error.text()
    assert dialog.recovery.isVisible()
    dialog.recovery.click()
    assert dialog.unsaved_english
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert not path.exists()


def test_unsaved_recovery_through_bootstrap(manager, monkeypatch, tmp_path):
    path = tmp_path / 'config.json'
    path.write_text('{')
    def recover(dialog):
        dialog.confirm.click()
        dialog.recovery.click()
        return dialog.result()
    monkeypatch.setattr(LanguageSelectionDialog, 'exec', recover)
    preferences = prepare_language(manager, path)
    assert not preferences.saved
    assert preferences.needs_choice
    assert manager.current_locale == 'en'
    assert path.read_text() == '{'


def test_apply_cancel_repeated_pending_changes_and_restart(manager, monkeypatch, tmp_path, qtbot):
    fixture_catalogs(monkeypatch)
    path = tmp_path / 'config.json'
    save_config_file(path, AppConfig(ui_language_confirmed=True))
    manager.seal()
    preferences = LanguagePreferences(manager, path)
    generation = manager.generation
    dialog = LanguageSelectionDialog(preferences)
    qtbot.addWidget(dialog)
    dialog.show()
    for locale in ('tr', 'en', 'ar', 'tr') * 3:
        row = next(index for index in range(18)
                   if dialog.languages.item(index).data(Qt.ItemDataRole.UserRole) == locale)
        dialog.languages.setCurrentRow(row)
        assert preferences.selected_locale == load_config_file(path).config.ui_language
        dialog.confirm.click()
        assert preferences.selected_locale == locale
        assert manager.current_locale == 'en'
        assert manager.generation == generation
        assert manager.application.layoutDirection() == Qt.LayoutDirection.LeftToRight
        assert translate('MainWindow', 'Dashboard') == 'Dashboard'
        assert preferences.diagnostics.restart_required == (locale != 'en')
        assert 'Restart' in dialog.error.text()
    before = path.read_bytes()
    dialog.languages.setCurrentRow(0)
    dialog.cancel.click()
    assert path.read_bytes() == before
    manager.close()
    next_manager = LocalizationManager(manager.application)
    try:
        restarted = prepare_language(next_manager, path)
        assert restarted.diagnostics.effective_locale == 'tr'
        assert not restarted.diagnostics.restart_required
        assert translate('MainWindow', 'Dashboard').startswith('[!!')
    finally:
        next_manager.close()


def test_failed_catalog_apply_or_save_does_not_change_current_pending(manager, monkeypatch, tmp_path):
    path = tmp_path / 'config.json'
    save_config_file(path, AppConfig(ui_language_confirmed=True))
    preferences = LanguagePreferences(manager, path)
    before = path.read_bytes()
    assert preferences.apply('tr') == 'catalog_unavailable'
    assert path.read_bytes() == before
    fixture_catalogs(monkeypatch)
    def fail(*args, **kwargs):
        raise OSError('private')
    monkeypatch.setattr(config_module.os, 'replace', fail)
    assert preferences.apply('tr') == 'save_failed'
    assert preferences.selected_locale == manager.current_locale == 'en'
    assert path.read_bytes() == before


def test_language_is_active_before_mainwindow_and_onboarding(qapp, monkeypatch, tmp_path, qtbot):
    fixture_catalogs(monkeypatch)
    path = tmp_path / 'config.json'
    save_config_file(path, AppConfig(ui_language='tr', ui_language_confirmed=True))
    original = app_module.MainWindow
    seen = []
    def construct(*args, **kwargs):
        seen.append(translate('MainWindow', 'Dashboard'))
        return original(*args, **kwargs)
    monkeypatch.setattr(app_module, 'MainWindow', construct)
    engine = FakeEngine()
    shell = app_module.create_application(engine, config_path=path, language_startup=True)
    qtbot.addWidget(shell.window)
    try:
        assert seen[0].startswith('[!!')
        assert engine.start_calls == 0
        assert shell.language_preferences.diagnostics.effective_locale == 'tr'
        assert shell.localization.activate('en') is LocaleOutcome.RESTART_REQUIRED
        from netsentinel.presentation.widgets.onboarding import OnboardingDialog
        guide = OnboardingDialog(None, lambda: True, config=shell.language_preferences.config)
        qtbot.addWidget(guide)
        assert translate('MainWindow', 'Dashboard').startswith('[!!')
        assert guide.accessibleName().startswith('[!!')
        assert guide.layoutDirection() == shell.application.layoutDirection()
    finally:
        shell.controller.shutdown()
        shell.localization.close()


def test_cancel_before_shell_construction(qapp, tmp_path, monkeypatch):
    def cancel(dialog):
        dialog.reject()
        return dialog.result()
    monkeypatch.setattr(LanguageSelectionDialog, 'exec', cancel)
    def unexpected(*args, **kwargs):
        pytest.fail('normal MainWindow was constructed on cancel')
    monkeypatch.setattr(app_module, 'MainWindow', unexpected)
    with pytest.raises(LanguageStartupCancelled):
        app_module.create_application(FakeEngine(), config_path=tmp_path / 'config.json', language_startup=True)
