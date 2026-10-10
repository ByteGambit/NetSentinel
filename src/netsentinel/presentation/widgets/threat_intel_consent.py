"""Explicit provider/data-type consent preview; contains no lookup action."""

from netsentinel.presentation.i18n.buttons import localize_buttons

from netsentinel.presentation.i18n.text import format_text

from netsentinel.presentation.i18n.text import TranslationMapping, translate

from uuid import uuid4

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QGroupBox, QLabel, QScrollArea,
    QVBoxLayout, QWidget,
)

from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.domain.threat_intelligence import (
    ThreatIntelConsent, ThreatIntelDataType, ThreatIntelProviderId,
)


DATA_DISCLOSURES = TranslationMapping(lambda: {
    ThreatIntelDataType.IP_REPUTATION:
        translate('ThreatIntelConsent', 'Selected public IPv4/IPv6 address only (example: 8.8.8.8). Private/local, multicast, unspecified and reserved addresses are ineligible.'),
    ThreatIntelDataType.DOMAIN_REPUTATION:
        translate('ThreatIntelConsent', 'Selected canonical ASCII domain only (example: example.com.). Localhost, .local and single-label hostnames are ineligible.'),
    ThreatIntelDataType.HASH_REPUTATION:
        translate('ThreatIntelConsent', 'Selected SHA-256 digest only (64 hexadecimal characters). The file, file contents, filename and file path are not uploaded.'),
})

CONSENT_LABELS = TranslationMapping(lambda: {
    ThreatIntelDataType.IP_REPUTATION: translate('ThreatIntelConsent', 'Allow selected public IP addresses (manual lookup)'),
    ThreatIntelDataType.DOMAIN_REPUTATION: translate('ThreatIntelConsent', 'Allow selected public domains (manual lookup)'),
    ThreatIntelDataType.HASH_REPUTATION: translate('ThreatIntelConsent', 'Allow selected SHA-256 digests (manual lookup)'),
})


class ThreatIntelConsentDialog(QDialog):
    def __init__(self, service: ThreatIntelConsentService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._service = service
        self._original = service.current()
        self.checkboxes: dict[tuple[ThreatIntelProviderId, ThreatIntelDataType], QCheckBox] = {}
        self.setWindowTitle(translate('ThreatIntelConsent', 'Threat intelligence / reputation consent'))
        self.setAccessibleName(translate('ThreatIntelConsent', 'Threat intelligence consent settings'))
        self.resize(650, 620)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget(scroll)
        content = QVBoxLayout(body)

        def label(message: str, layout: QVBoxLayout) -> QLabel:
            item = QLabel(message, body)
            item.setWordWrap(True)
            item.setTextFormat(Qt.TextFormat.PlainText)
            layout.addWidget(item)
            return item

        label(translate('ThreatIntelConsent', 'Default: disabled. Consent permits a manual selected-subject lookup only. Saving consent does not request a lookup. Automatic lookup is unavailable.'), content)
        label(translate('ThreatIntelConsent', 'Before enabling a choice, review the provider and data below. A future external request can also reveal your public source IP to the provider and network path. Provider retention is unknown; no promise of non-retention is made.'), content)
        label(translate('ThreatIntelConsent', 'NetSentinel will not upload your connection or DNS history by enabling these options. Process paths, command lines, raw packets, evidence bundles and user notes are not sent.'), content)
        label(translate('ThreatIntelConsent', 'Only a selected SHA-256 digest is eligible for hash lookup; the file and file path are not uploaded. Hash permission is separate from IP/domain permission.'), content)
        label(translate('ThreatIntelConsent', 'This screen manages consent only. Saving consent never submits a lookup request.'), content)
        if not service.descriptors:
            label(translate('ThreatIntelConsent', 'No providers configured. All reputation lookups remain disabled.'), content)
        for descriptor in service.descriptors:
            group = QGroupBox(f"{descriptor.display_name} ({descriptor.provider.value})", body)
            group.setAccessibleName(format_text(translate('ThreatIntelConsent', 'Provider {value1}'), value1=descriptor.provider.value))
            group_layout = QVBoxLayout(group)
            label(format_text(translate('ThreatIntelConsent', 'Provider retention: {value1}'), value1=descriptor.retention), group_layout)
            for data_type in ThreatIntelDataType:
                if data_type not in descriptor.supported_data_types:
                    continue
                label(f"{data_type.value}: {DATA_DISCLOSURES[data_type]}", group_layout)
                checkbox = QCheckBox(
                    CONSENT_LABELS[data_type], group,
                )
                checkbox.setAccessibleName(format_text(translate('ThreatIntelConsent', '{value1} {value2} consent'), value1=descriptor.provider.value, value2=data_type.value))
                checkbox.setChecked(any(c.provider == descriptor.provider and c.data_type is data_type
                                        for c in self._original))
                self.checkboxes[descriptor.provider, data_type] = checkbox
                group_layout.addWidget(checkbox)
            content.addWidget(group)
        content.addStretch()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        self.error = label("", outer)
        self.error.setAccessibleName(translate('ThreatIntelConsent', 'Consent save status'))
        self.buttons = localize_buttons(QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self,
        ))
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        save_button = self.buttons.button(QDialogButtonBox.StandardButton.Save)
        assert save_button is not None
        save_button.setEnabled(bool(self.checkboxes))
        outer.addWidget(self.buttons)

    def _save(self) -> None:
        consents = []
        for (provider, data_type), checkbox in self.checkboxes.items():
            if checkbox.isChecked():
                previous = next((c for c in self._original
                                 if c.provider == provider and c.data_type is data_type), None)
                consents.append(previous or ThreatIntelConsent(uuid4(), provider, data_type))
        try:
            self._service.save(tuple(consents))
        except (OSError, TypeError, ValueError):
            self.error.setText(translate('ThreatIntelConsent', 'Consent could not be saved. No new permission has been applied.'))
            return
        self.accept()
