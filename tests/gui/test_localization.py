"""NS-105 real offline QM, restart gate, source descriptors and feasibility."""

from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from PyQt6.QtCore import QLocale, Qt
from PyQt6.QtWidgets import QDialogButtonBox, QMessageBox

from netsentinel.application.services.notifications import DesktopNotificationRequest, preview_body
from netsentinel.application.services.risk_explanation import RiskExplanationRequest, RiskExplanationViewModel
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.connections import ConnectionOpened
from netsentinel.domain.risk_assessment import AssessmentReadStatus
from netsentinel.domain.risk_scoring import RiskSeverity
from netsentinel.presentation.app import create_application
from netsentinel.presentation.i18n import manager as manager_module
from netsentinel.presentation.i18n.manager import LocalizationManager, LocaleOutcome, PLANNED_LOCALES
from netsentinel.presentation.i18n.notifications import notification_text
from netsentinel.presentation.i18n.text import (
    display_enum, display_number, display_timestamp, placeholders, render_text, translate,
)
from netsentinel.presentation.models.connections import ConnectionRole, ConnectionsTableModel
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.tray import QtTrayAdapter
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.presentation.widgets.application_behavior import ApplicationBehaviorDialog
from netsentinel.presentation.widgets.onboarding import OnboardingDialog
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget
from netsentinel.shared.config import WindowCloseBehavior
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP, join_text
from tests.gui._ns013_support import FakeEngine, snapshot
from tests.gui.test_tray_lifecycle import FakeTray

PSEUDO = Path(__file__).parents[1] / 'fixtures/i18n/pseudo.qm'


def opened(index: int) -> ConnectionOpened:
    return ConnectionOpened(snapshot(index))


@pytest.fixture
def localization(qapp, monkeypatch):
    monkeypatch.setattr(manager_module, 'bundled_catalog', lambda _: PSEUDO.read_bytes())
    manager = LocalizationManager(qapp)
    manager.activate('en')
    yield manager
    manager.close()


def test_manager_initialization_and_planned_identity(localization):
    assert localization.current_locale == 'en'
    assert localization.generation == 1
    # This fixture supplies a valid real QM for every planned target.
    assert localization.available_locales == tuple(item.id for item in PLANNED_LOCALES)
    assert [item.id for item in PLANNED_LOCALES] == [
        'en', 'tr', 'de', 'fr', 'es', 'it', 'pt-BR', 'nl', 'pl', 'ru', 'uk', 'ar',
        'ja', 'ko', 'zh-Hans', 'zh-Hant', 'id', 'cs',
    ]
    assert not LocalizationManager.RUNTIME_SWITCHING
    assert translate('MainWindow', 'Dashboard') == 'Dashboard'


@pytest.mark.parametrize('locale, expected', [('en', LocaleOutcome.ENGLISH),
    ('xx', LocaleOutcome.UNSUPPORTED), ('../../ar', LocaleOutcome.UNSUPPORTED)])
def test_english_and_unsupported_fallback(localization, locale, expected):
    assert localization.activate(locale) is expected
    assert localization.current_locale == 'en'
    assert translate('MainWindow', 'Dashboard') == 'Dashboard'


@pytest.mark.parametrize('data, expected', [(None, LocaleOutcome.MISSING), (b'invalid', LocaleOutcome.INVALID)])
def test_missing_invalid_catalog_falls_back_after_installed_translator(localization, monkeypatch, data, expected):
    assert localization.activate('tr') is LocaleOutcome.APPLIED
    assert translate('MainWindow', 'Dashboard').startswith('[!!')
    monkeypatch.setattr(manager_module, 'bundled_catalog', lambda _: data)
    assert localization.activate('tr') is expected
    assert translate('MainWindow', 'Dashboard') == 'Dashboard'


def test_load_exception_is_sanitized(localization, monkeypatch, capsys):
    def failure(_):
        raise OSError('private path / API-key must never appear')
    monkeypatch.setattr(manager_module, 'bundled_catalog', failure)
    assert localization.activate('tr') is LocaleOutcome.INVALID
    assert not capsys.readouterr().out
    assert not capsys.readouterr().err


def test_real_qm_install_remove_missing_key_and_repeated_switches(localization):
    for _ in range(6):
        assert localization.activate('tr') is LocaleOutcome.APPLIED
        assert translate('MainWindow', 'Dashboard').startswith('[!!')
        assert translate('MissingContext', 'Still readable English') == 'Still readable English'
        assert localization.activate('en') is LocaleOutcome.ENGLISH
        assert translate('MainWindow', 'Dashboard') == 'Dashboard'
    assert localization.generation == 13


def test_startup_static_navigation_headers_accessibility_and_onboarding(localization, qtbot):
    localization.activate('tr')
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.navigation.item(0).text().startswith('[!!')
    assert window.navigation.accessibleName().startswith('[!!')
    assert window.accessibleName().startswith('[!!')
    assert window.navigation.item(0).data(Qt.ItemDataRole.UserRole) == 'dashboard'
    assert window.connections_model.headerData(0, Qt.Orientation.Horizontal).startswith('[!!')
    assert window.page_widget(PageId.DASHBOARD).title_label.text().startswith('[!!')
    guide = OnboardingDialog(None, lambda: True, window, actions={'Devices': lambda: None})
    qtbot.addWidget(guide)
    assert guide.accessibleName().startswith('[!!')
    assert guide.next_button.text().startswith('[!!')
    assert guide.links['Devices'].text().startswith('[!!')
    assert guide.links['Devices'].accessibleName().startswith('[!!')


def test_dialog_standard_buttons_and_unsaved_input_survive_restart_request(localization, qtbot):
    localization.activate('tr')
    localization.seal()
    saved = []
    dialog = ApplicationBehaviorDialog(WindowCloseBehavior.QUIT_APPLICATION, True, saved.append)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.close_behavior.setCurrentIndex(1)
    assert dialog.windowTitle().startswith('[!!')
    assert dialog.buttons.button(QDialogButtonBox.StandardButton.Save).text().startswith('[!!')
    before = (dialog.windowTitle(), dialog.close_behavior.currentData(), dialog.accessibleName())
    generation = localization.generation
    for locale in ('ar', 'en', 'tr'):
        assert localization.activate(locale) is LocaleOutcome.RESTART_REQUIRED
        assert localization.generation == generation
        assert (dialog.windowTitle(), dialog.close_behavior.currentData(), dialog.accessibleName()) == before
    assert dialog.isVisible() and not saved


def test_destructive_confirmation_language_and_target_do_not_change(localization, qtbot):
    localization.seal()
    dialog = QMessageBox()
    dialog.setText('Delete this exact selected target?')
    dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
    dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
    qtbot.addWidget(dialog)
    dialog.show()
    before = (dialog.text(), dialog.defaultButton())
    assert localization.activate('ar') is LocaleOutcome.RESTART_REQUIRED
    assert (dialog.text(), dialog.defaultButton()) == before
    assert dialog.isVisible()


def test_explicit_runtime_probe_fails_static_retranslation_and_preserves_state(localization, qtbot, qapp):
    """Evidence for NO_GO; an unsealed isolated probe is never composed UX."""
    model = ConnectionsTableModel()
    model.handle_connection_opened(opened(0))
    window = MainWindow(connections_model=model)
    qtbot.addWidget(window)
    window.navigate_to(PageId.CONNECTIONS)
    view = window.page_widget(PageId.CONNECTIONS)
    view.search_edit.setText('198.51.100.7')
    window.show()
    view.table.selectRow(0)
    view.search_edit.setFocus()
    qapp.processEvents()
    row_id = model.index(0, 0).data(int(ConnectionRole.ROW_ID))
    focused = qapp.focusWidget()
    old_label = window.navigation.item(0).text()
    for locale, direction in [('ar', Qt.LayoutDirection.RightToLeft), ('en', Qt.LayoutDirection.LeftToRight)]:
        localization.activate(locale)
        qapp.processEvents()
        assert window.layoutDirection() == direction
        assert window.current_page is PageId.CONNECTIONS
        assert view.search_edit.text() == '198.51.100.7'
        assert qapp.focusWidget() is focused
        assert model.index(0, 0).data(int(ConnectionRole.ROW_ID)) == row_id
        assert view.table.selectionModel().selectedRows()[0].row() == 0
        if locale == 'ar':
            assert model.headerData(0, Qt.Orientation.Horizontal).startswith('[!!')
            assert window.navigation.item(0).text() == old_label == 'Dashboard'
            # Old constructor text plus new on-demand header is a mixed UI.
            assert not LocalizationManager.RUNTIME_SWITCHING


def test_composition_seals_before_widget_creation(qtbot, qapp, monkeypatch):
    monkeypatch.setattr(manager_module, 'bundled_catalog', lambda _: PSEUDO.read_bytes())
    engine = FakeEngine()
    shell = create_application(engine, tray_adapter=FakeTray(False), initial_locale='tr')
    qtbot.addWidget(shell.window)
    try:
        assert shell.localization.current_locale == 'tr'
        assert shell.window.navigation.item(0).text().startswith('[!!')
        assert shell.localization.activate('ar') is LocaleOutcome.RESTART_REQUIRED
        assert engine.start_calls == engine.stop_calls == 0
    finally:
        shell.controller.shutdown()
        shell.localization.close()


def test_enum_display_changes_while_internal_identity_stays_fixed(localization):
    from netsentinel.domain.response import ResponseOutcome
    assert AlertStatus.OPEN.value == 'open'
    localization.activate('tr')
    assert display_enum(AlertStatus.OPEN).startswith('[!!')
    assert display_enum(ResponseOutcome.PARTIAL).startswith('[!!')
    assert ResponseOutcome.PARTIAL.value == 'partial'
    assert AlertStatus.OPEN.value == 'open'
    assert snapshot().state.value == 'established'


@pytest.mark.parametrize('count', [0, 1, 2, 19])
def test_numerus_real_qt_catalog_and_english_fallback(localization, count):
    source = 'Passive capture active · %n observed device(s).'
    english = translate('Devices', source, None, count)
    assert '%n' not in english and str(count) in english and 'device(s)' in english
    localization.activate('tr')
    result = translate('Devices', source, None, count)
    assert result.startswith('[!!') and '%n' not in result and str(count) in result


def test_parameters_and_raw_evidence_are_not_translated(localization):
    value = QT_TRANSLATE_NOOP('MainWindow', '{value1} page').format(value1='example.com.')
    localization.activate('tr')
    assert render_text(value).startswith('[!!')
    assert 'example.com.' in render_text(value)
    for raw in ('192.0.2.10', '00:11:22:33:44:55', 'browser.exe', 'Dashboard', 'schema_020'):
        assert render_text(raw) == raw
    assert placeholders('{count:03d} {count:03d} {{literal}}') == {('count', '03d', None): 2}
    assert render_text(join_text('\n', [value, '192.0.2.10'])).endswith('192.0.2.10')


def test_tray_and_future_notification_text_without_replay(localization, qapp, qtbot, monkeypatch):
    window = MainWindow()
    qtbot.addWidget(window)
    adapter = QtTrayAdapter(qapp, window)
    monkeypatch.setattr(adapter, 'available', lambda: True)
    localization.activate('tr')
    try:
        adapter.start(lambda: None, lambda: None, lambda: None)
        assert adapter.menu.actions()[0].text().startswith('[!!')
        request = DesktopNotificationRequest(uuid4(), RiskSeverity.LOW,
            'NetSentinel security alert', preview_body(RiskSeverity.LOW))
        title, body = notification_text(request)
        assert title.startswith('[!!') and body.startswith('[!!')
        assert request.title == 'NetSentinel security alert'
        assert request.body == preview_body(RiskSeverity.LOW)
        localization.seal()
        assert localization.activate('en') is LocaleOutcome.RESTART_REQUIRED
        # A locale request has no notification service dispatch/replay hook.
        assert notification_text(request) == (title, body)
    finally:
        adapter.cleanup()


def test_late_worker_source_is_rendered_at_completion_locale(localization, qtbot):
    from uuid import uuid4
    entered, release = Event(), Event()
    source = QT_TRANSLATE_NOOP('RiskExplanation', 'Risk details unavailable. Try Refresh.')
    class Service:
        def lookup(self, request, *, now):
            entered.set()
            assert release.wait(2)
            return RiskExplanationViewModel(AssessmentReadStatus.UNAVAILABLE, source)
    coordinator = RiskQueryCoordinator(Service)
    coordinator.start()
    widget = RiskExplanationWidget(coordinator)
    qtbot.addWidget(widget)
    try:
        widget.select(RiskExplanationRequest(lifecycle_id=uuid4()))
        qtbot.waitUntil(entered.is_set)
        query_generation = widget._generation
        # Isolated feasibility probe: only the typed completion is retranslatable.
        localization.activate('tr')
        release.set()
        qtbot.waitUntil(lambda: widget.status.text().startswith('[!!'))
        assert widget._generation == query_generation
        assert source == 'Risk details unavailable. Try Refresh.'
    finally:
        release.set()
        assert coordinator.stop()


def test_sealed_locale_request_during_worker_preserves_session(localization, qtbot):
    from uuid import uuid4
    entered, release = Event(), Event()
    class Service:
        def lookup(self, request, *, now):
            entered.set()
            assert release.wait(2)
            return RiskExplanationViewModel(AssessmentReadStatus.UNAVAILABLE,
                QT_TRANSLATE_NOOP('RiskExplanation', 'Risk details unavailable. Try Refresh.'))
    localization.seal()
    coordinator = RiskQueryCoordinator(Service)
    widget = RiskExplanationWidget(coordinator)
    qtbot.addWidget(widget)
    coordinator.start()
    try:
        widget.select(RiskExplanationRequest(lifecycle_id=uuid4()))
        qtbot.waitUntil(entered.is_set)
        generation = widget._generation
        assert localization.activate('ar') is LocaleOutcome.RESTART_REQUIRED
        release.set()
        qtbot.waitUntil(lambda: widget.status.text() == 'Risk details unavailable. Try Refresh.')
        assert widget._generation == generation
    finally:
        release.set()
        assert coordinator.stop()


def test_locale_number_and_display_date_do_not_change_raw_utc(localization):
    stamp = datetime(2026, 10, 9, 12, 30, tzinfo=UTC)
    raw = stamp.isoformat()
    assert display_number(1234) == QLocale('en_US').toString(1234)
    english = display_timestamp(stamp)
    localization.activate('ar')
    assert display_number(1234) == QLocale('ar_EG').toString(1234)
    assert display_timestamp(stamp) != english
    assert stamp.isoformat() == raw
    with pytest.raises(ValueError):
        display_timestamp(stamp.replace(tzinfo=None))


def test_invalid_translated_parameters_fall_back_to_readable_source(qapp, monkeypatch):
    from PyQt6.QtCore import QCoreApplication
    monkeypatch.setattr(QCoreApplication, 'translate', lambda *args: 'Dropped required field')
    assert translate('Fixture', 'Value {count:03d}').format(count=4) == 'Value 004'
    monkeypatch.setattr(QCoreApplication, 'translate', lambda *args: '{count.attribute}')
    assert translate('Fixture', 'Value {count}') == 'Value {count}'


def test_failed_install_retains_english_and_no_translator(localization, qapp, monkeypatch):
    monkeypatch.setattr(type(qapp), 'installTranslator', lambda *args: False)
    assert localization.activate('tr') is LocaleOutcome.INVALID
    assert localization.current_locale == 'en'
    assert localization._translator is None
    assert translate('MainWindow', 'Dashboard') == 'Dashboard'


def test_timeline_cursor_and_sort_are_canonical_across_probe_locales(localization, tmp_path):
    from tests.fixtures.incident_timeline import story
    from netsentinel.application.services.incident_timeline import TimelineRequest
    _, _, record, _, service = story(tmp_path)
    request = TimelineRequest(record.incident_id, limit=1)
    english = service.lookup(request)
    localization.activate('tr')
    pseudo = service.lookup(request)
    assert english.next_cursor == pseudo.next_cursor
    assert english.entries[0].sort_key == pseudo.entries[0].sort_key
    assert english.entries[0].entry_id == pseudo.entries[0].entry_id
    assert str(english.entries[0].title) == str(pseudo.entries[0].title)


def test_actual_qt_notification_submission_translates_future_messages_without_replay(localization, qapp, qtbot, monkeypatch):
    from netsentinel.presentation import notifications
    from netsentinel.presentation.notifications import QtDesktopNotificationSink
    from tests.gui.test_desktop_notifications import FakeIcon, request
    FakeIcon.instances, FakeIcon.available, FakeIcon.messages, FakeIcon.failure = [], True, True, False
    monkeypatch.setattr(notifications, 'QSystemTrayIcon', FakeIcon)
    window = MainWindow()
    qtbot.addWidget(window)
    sink = QtDesktopNotificationSink(qapp, window)
    try:
        sink.submit(request(1))
        assert FakeIcon.instances[0].requests[0][0] == 'NetSentinel security alert'
        localization.activate('tr')  # Isolated pre-seal feasibility probe.
        assert len(FakeIcon.instances) == 1 and sink.submission_attempts == 1
        sink.submit(request(2))
        assert FakeIcon.instances[1].requests[0][0].startswith('[!!')
        assert FakeIcon.instances[1].requests[0][1].startswith('[!!')
        assert len(FakeIcon.instances[0].requests) == 1
        localization.seal()
        assert localization.activate('en') is LocaleOutcome.RESTART_REQUIRED
        assert sink.submission_attempts == 2
    finally:
        sink.close()
