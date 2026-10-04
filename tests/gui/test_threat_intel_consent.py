"""NS-084 offscreen disclosure, independent choices and explicit persistence."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialogButtonBox, QLabel
import pytest

from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService, ThreatIntelLookupService
from netsentinel.bootstrap import create_threat_intel_consent_service
from netsentinel.domain.threat_intelligence import ThreatIntelDataType, ThreatIntelDenial
from netsentinel.domain.connections import (
    ConnectionOpened, ConnectionSnapshot, ConnectionState, Endpoint, ProcessInfo, TransportProtocol,
)
from netsentinel.presentation.app import create_application
from netsentinel.presentation.views.main_window import PageId
from netsentinel.presentation.widgets.threat_intel_consent import ThreatIntelConsentDialog
from netsentinel.shared.config import AppConfig, load_config_file, save_config_file
from tests.fixtures.threat_intelligence import A, B, DESCRIPTORS, NOW, FakeProviderA, FakeProviderB, query
from tests.gui.test_application_shell import FakeEngine


def texts(widget):
    return "\n".join(item.text() for item in widget.findChildren(QLabel))


def click(qtbot, dialog, button):
    qtbot.mouseClick(dialog.buttons.button(button), Qt.MouseButton.LeftButton)


def test_default_off_and_all_disclosures_precede_separate_choices(qtbot):
    saves = []
    service = ThreatIntelConsentService(DESCRIPTORS, lambda: (), saves.append)
    dialog = ThreatIntelConsentDialog(service)
    qtbot.addWidget(dialog)
    dialog.show()
    assert len(dialog.checkboxes) == 6
    assert all(not checkbox.isChecked() for checkbox in dialog.checkboxes.values())
    message = texts(dialog)
    for required in ("manual selected-subject", "public source IP", "retention is unknown",
                     "connection or DNS history", "file and file path", "Selected public IPv4/IPv6",
                     "Selected canonical ASCII domain", "Selected SHA-256 digest"):
        assert required in message
    assert "Cloud protection" not in message
    assert "cloud features" not in message.lower()
    for provider in (A, B):
        for data_type in ThreatIntelDataType:
            assert provider.value in dialog.checkboxes[provider, data_type].accessibleName()
            assert data_type.value in dialog.checkboxes[provider, data_type].accessibleName()
    qtbot.mouseClick(dialog.checkboxes[A, ThreatIntelDataType.IP_REPUTATION], Qt.MouseButton.LeftButton)
    assert sum(c.isChecked() for c in dialog.checkboxes.values()) == 1
    assert not dialog.checkboxes[B, ThreatIntelDataType.IP_REPUTATION].isChecked()
    assert saves == []
    click(qtbot, dialog, QDialogButtonBox.StandardButton.Cancel)
    assert saves == []


def test_cancel_save_restart_and_revoke_exact_choices(tmp_path, qtbot):
    path = tmp_path / "config.json"
    service = create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS)
    canceled = ThreatIntelConsentDialog(service)
    qtbot.addWidget(canceled)
    canceled.show()
    canceled.checkboxes[A, ThreatIntelDataType.IP_REPUTATION].setChecked(True)
    click(qtbot, canceled, QDialogButtonBox.StandardButton.Cancel)
    assert not path.exists()

    saved = ThreatIntelConsentDialog(service)
    qtbot.addWidget(saved)
    saved.show()
    saved.checkboxes[A, ThreatIntelDataType.IP_REPUTATION].setChecked(True)
    saved.checkboxes[B, ThreatIntelDataType.HASH_REPUTATION].setChecked(True)
    click(qtbot, saved, QDialogButtonBox.StandardButton.Save)
    consents = load_config_file(path).config.threat_intel_consents
    assert {(c.provider, c.data_type) for c in consents} == {
        (A, ThreatIntelDataType.IP_REPUTATION), (B, ThreatIntelDataType.HASH_REPUTATION),
    }
    restarted = ThreatIntelConsentDialog(create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS))
    qtbot.addWidget(restarted)
    restarted.show()
    assert {(p, t) for (p, t), c in restarted.checkboxes.items() if c.isChecked()} == {
        (A, ThreatIntelDataType.IP_REPUTATION), (B, ThreatIntelDataType.HASH_REPUTATION),
    }
    # Saving unchanged choices preserves the consent reference.
    click(qtbot, restarted, QDialogButtonBox.StandardButton.Save)
    assert load_config_file(path).config.threat_intel_consents == consents
    revoked = ThreatIntelConsentDialog(service)
    qtbot.addWidget(revoked)
    revoked.show()
    for checkbox in revoked.checkboxes.values():
        checkbox.setChecked(False)
    click(qtbot, revoked, QDialogButtonBox.StandardButton.Save)
    assert service.current() == ()


@pytest.mark.parametrize("content", ["{bad", '{"threat_intel_consents":true}', "null"])
def test_corrupt_config_dialog_has_all_choices_off(tmp_path, qtbot, content):
    path = tmp_path / "config.json"
    path.write_text(content, encoding="utf-8")
    service = create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS)
    dialog = ThreatIntelConsentDialog(service)
    qtbot.addWidget(dialog)
    assert all(not c.isChecked() for c in dialog.checkboxes.values())
    dialog.reject()
    assert path.read_text(encoding="utf-8") == content


def test_save_failure_shows_sanitized_status_without_grant(qtbot):
    def fail(_):
        raise OSError("API_KEY_SENTINEL private path")
    service = ThreatIntelConsentService(DESCRIPTORS, lambda: (), fail)
    dialog = ThreatIntelConsentDialog(service)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.checkboxes[A, ThreatIntelDataType.IP_REPUTATION].setChecked(True)
    click(qtbot, dialog, QDialogButtonBox.StandardButton.Save)
    assert "could not be saved" in dialog.error.text()
    assert "API_KEY_SENTINEL" not in texts(dialog)
    assert service.current() == ()
    assert dialog.isVisible()


def test_production_registry_empty_no_save_or_provider_selection(tmp_path, qtbot):
    service = create_threat_intel_consent_service(config_path=tmp_path / "config.json")
    dialog = ThreatIntelConsentDialog(service)
    qtbot.addWidget(dialog)
    assert dialog.checkboxes == {}
    assert "No providers configured" in texts(dialog)
    assert not dialog.buttons.button(QDialogButtonBox.StandardButton.Save).isEnabled()


def test_startup_settings_save_and_connection_selection_make_zero_provider_calls(tmp_path, qtbot):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(onboarding_completed=True))
    a, b = FakeProviderA(), FakeProviderB()
    service = create_threat_intel_consent_service(config_path=path, descriptors=(a.descriptor, b.descriptor))
    lookup = ThreatIntelLookupService((a, b), service.current)
    shell = create_application(FakeEngine(), argv=[], threat_intel_consent_service=service)
    qtbot.addWidget(shell.window)
    shell.window.show()
    assert a.calls == b.calls == []
    shell.window.threat_intel_consent_action.trigger()
    dialog = shell.window.findChild(ThreatIntelConsentDialog)
    assert dialog is not None and dialog.isVisible()
    dialog.checkboxes[A, ThreatIntelDataType.IP_REPUTATION].setChecked(True)
    click(qtbot, dialog, QDialogButtonBox.StandardButton.Save)
    shell.window.navigate_to(PageId.CONNECTIONS)
    connection = ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint("192.0.2.10", 41001), Endpoint("8.8.8.8", 443),
        ConnectionState.ESTABLISHED, ProcessInfo.unavailable(), NOW,
    )
    shell.window.connections_model.handle_connection_opened(ConnectionOpened(connection))
    view = shell.window.page_widget(PageId.CONNECTIONS)
    view.table.selectRow(0)
    assert a.calls == b.calls == []
    # Manual consent still denies a request lacking its exact reference.
    assert lookup.lookup_selected(query()).denial is ThreatIntelDenial.NO_CONSENT
    assert a.calls == b.calls == []
    shell.window.close()
