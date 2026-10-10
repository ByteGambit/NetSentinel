"""Selected-connection detail panel for the Connections page."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import translate
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import TranslationSequence
from uuid import UUID

from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtWidgets import QFormLayout, QGroupBox, QLabel, QPushButton, QVBoxLayout, QWidget

from netsentinel.domain.connections import ProcessInfo
from netsentinel.domain.executable_signer import ExecutableSigner, SignerAvailability
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
)
from netsentinel.presentation.widgets.page_flow import FlowTabWidget
from netsentinel.presentation.theme import SECONDARY_TEXT
from netsentinel.presentation.process_context import (
    PROCESS_CONTEXT_FIELDS,
    process_context_text,
)
from netsentinel.presentation.viewmodels import MISSING_VALUE
from netsentinel.presentation.destination_context import DestinationEvidenceWidget
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator
from netsentinel.presentation.widgets.baseline_detail import BaselineDetailWidget
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget
from netsentinel.application.services.risk_explanation import RiskExplanationRequest
from netsentinel.presentation.widgets.threat_intel_lookup import ThreatIntelLookupWidget
from netsentinel.presentation.widgets.manual_response import ManualResponseWidget
from netsentinel.presentation.response_commands import ResponseCommandCoordinator
from netsentinel.application.services.response_ui import ResponseSelection


_DETAIL_FIELDS = TranslationSequence(lambda: (
    ("process", translate('ConnectionDetails', 'Process name')),
    ("pid", translate('ConnectionDetails', 'PID')),
    *PROCESS_CONTEXT_FIELDS,
    ("protocol", translate('ConnectionDetails', 'Protocol')),
    ("state", translate('ConnectionDetails', 'State')),
    ("local_address", translate('ConnectionDetails', 'Local address')),
    ("local_port", translate('ConnectionDetails', 'Local port')),
    ("remote_address", translate('ConnectionDetails', 'Remote address')),
    ("remote_port", translate('ConnectionDetails', 'Remote port')),
    ("duration", translate('ConnectionDetails', 'Duration')),
))


class ConnectionDetailsWidget(QGroupBox):
    """Render one proxy row without exposing Python/internal values."""

    def __init__(self, parent: QWidget | None = None, *, baseline_queries: BaselineQueryCoordinator | None = None,
                 preference_commands: PreferenceCommandCoordinator | None = None,
                 risk_queries: RiskQueryCoordinator | None = None,
                 response_commands: ResponseCommandCoordinator | None = None,
                 threat_intel: ThreatIntelLookupWidget | None = None) -> None:
        super().__init__(translate('ConnectionDetails', 'Selected connection'), parent)
        self.setObjectName("connectionDetails")
        self.setAccessibleName(translate('ConnectionDetails', 'Connection details'))
        self.status_label = QLabel(self)
        self.status_label.setObjectName("connectionDetailsStatus")
        self.status_label.setAccessibleName(translate('ConnectionDetails', 'Connection details status'))
        self.status_label.setStyleSheet(SECONDARY_TEXT)

        self.value_labels: dict[str, QLabel] = {}
        content = QWidget(self)
        form = QFormLayout(content)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(5)
        for key, title in _DETAIL_FIELDS:
            value = QLabel(MISSING_VALUE, self)
            value.setObjectName(f"connectionDetail_{key}")
            value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setWordWrap(key.endswith("address") or key == "executable")
            value.setAccessibleName(format_text(translate('ConnectionDetails', '{value1} value'), value1=title))
            self.value_labels[key] = value
            form.addRow(f"{title}:", value)

        connection_content = QWidget(self)
        layout = QVBoxLayout(connection_content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self.status_label)
        layout.addWidget(content)
        self.destination = DestinationEvidenceWidget(self)
        layout.addWidget(self.destination)
        signer_group = QGroupBox(translate('ConnectionDetails', 'Local executable signature'), self)
        signer_layout = QVBoxLayout(signer_group)
        self.signer_button = QPushButton(translate('ConnectionDetails', 'Check disk file signature'), signer_group)
        self.signer_button.setObjectName("checkExecutableSignature")
        self.signer_text = QLabel(translate('ConnectionDetails', 'On-demand local evidence; no file has been checked.'), signer_group)
        self.signer_text.setObjectName("executableSignatureEvidence")
        self.signer_text.setTextFormat(Qt.TextFormat.PlainText)
        self.signer_text.setWordWrap(True)
        self.signer_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        signer_layout.addWidget(self.signer_button)
        signer_layout.addWidget(self.signer_text)
        layout.addWidget(signer_group)
        self.baseline = BaselineDetailWidget(baseline_queries, self, preference_commands=preference_commands)
        self.tabs = FlowTabWidget(self)
        self.tabs.setAccessibleName(translate('ConnectionDetails', 'Selected connection detail sections'))
        self.tabs.setAccessibleDescription(translate('ConnectionDetails', 'Connection context and observed behavior baseline'))
        self.tabs.addTab(connection_content, translate('ConnectionDetails', 'Connection'))
        self.tabs.addTab(self.baseline, translate('ConnectionDetails', 'Behavior baseline'))
        self.risk = RiskExplanationWidget(risk_queries, self, page_flow=True)
        self.tabs.addTab(self.risk, translate('ConnectionDetails', 'Risk explanation'))
        self.threat_intel = threat_intel or ThreatIntelLookupWidget(parent=self)
        self.tabs.addTab(self.threat_intel, translate('ConnectionDetails', 'External reputation'))
        self.response = ManualResponseWidget(response_commands, self)
        self.tabs.addTab(self.response, translate('ConnectionDetails', 'Manual firewall response'))
        self.risk.evidence_changed.connect(self.response.invalidate_evidence)
        self.threat_intel.assessment_updated.connect(self.response.invalidate_evidence)
        self.threat_intel.assessment_updated.connect(self.risk.refresh_after_commit)
        if risk_queries is not None:
            risk_queries.stopped.connect(self.threat_intel.stop)
        outer = QVBoxLayout(self)
        outer.addWidget(self.tabs)
        self.clear()

    def value_text(self, field: str) -> str:
        """Return a displayed field value for assertions/accessibility helpers."""

        return self.value_labels[field].text()

    def clear(self, message: str = QT_TRANSLATE_NOOP('ConnectionDetails', 'No connection selected.')) -> None:
        self.status_label.setText(render_text(message))
        self.status_label.show()
        for label in self.value_labels.values():
            label.setText(render_text(MISSING_VALUE))
        self.destination.clear()
        self.baseline.clear()
        self.risk.clear(translate('ConnectionDetails', 'No connection selected.'))
        self.threat_intel.clear()
        self.response.select(None)
        self.signer_text.setText(translate('ConnectionDetails', 'On-demand local evidence; no file has been checked.'))

    def set_connection(self, index: QModelIndex) -> None:
        model = index.model()
        if not index.isValid() or model is None:
            self.clear()
            return

        row = index.row()
        first = model.index(row, 0)
        lifecycle = model.data(first, int(ConnectionRole.LIFECYCLE_ID))
        response_source = model.data(first, int(ConnectionRole.RESPONSE_SOURCE))
        self.response.select(response_source if isinstance(response_source, ResponseSelection) else None)
        self.threat_intel.select(lifecycle if isinstance(lifecycle, UUID) else None,
            str(model.data(first, int(ConnectionRole.RAW_REMOTE_ADDRESS))))
        self.risk.select(RiskExplanationRequest(lifecycle_id=lifecycle) if isinstance(lifecycle, UUID) else None)

        self.status_label.clear()
        self.status_label.hide()
        self.value_labels['process'].setText(render_text(_safe_display(model.data(model.index(row, int(ConnectionColumn.PROCESS))))))
        self.value_labels['pid'].setText(render_text(_safe_display(model.data(model.index(row, int(ConnectionColumn.PID))))))
        self.value_labels['protocol'].setText(render_text(_safe_display(model.data(model.index(row, int(ConnectionColumn.PROTOCOL))))))
        self.value_labels['state'].setText(render_text(_safe_display(model.data(model.index(row, int(ConnectionColumn.STATE))))))
        self.value_labels['local_address'].setText(render_text(_safe_raw(model.data(first, int(ConnectionRole.RAW_LOCAL_ADDRESS)))))
        self.value_labels['local_port'].setText(render_text(_safe_raw(model.data(first, int(ConnectionRole.RAW_LOCAL_PORT)))))
        self.value_labels['remote_address'].setText(render_text(_safe_raw(model.data(first, int(ConnectionRole.RAW_REMOTE_ADDRESS)))))
        self.value_labels['remote_port'].setText(render_text(_safe_raw(model.data(first, int(ConnectionRole.RAW_REMOTE_PORT)))))
        self.value_labels['duration'].setText(render_text(_safe_display(model.data(model.index(row, int(ConnectionColumn.DURATION))))))
        process = model.data(first, int(ConnectionRole.PROCESS_INFO))
        if isinstance(process, ProcessInfo):
            for key, value in process_context_text(process).items():
                self.value_labels[key].setText(render_text(value))

    def set_signer_result(self, result: ExecutableSigner) -> None:
        self.response.invalidate_evidence()
        if result.availability is not SignerAvailability.AVAILABLE:
            self.signer_text.setText(format_text(translate('ConnectionDetails', 'Verification: {value1}'), value1=display_enum(result.availability, 'words')))
            return
        signer = result.signer
        self.signer_text.setText(render_join('\n', (format_text(translate('ConnectionDetails', 'Signature source: {value1}'), value1=display_enum(result.kind)), format_text(translate('ConnectionDetails', 'Signature validation: {value1}'), value1=display_enum(result.validation, 'words')), format_text(translate('ConnectionDetails', 'Local Windows trust: {value1}'), value1=display_enum(result.local_trust, 'words')), format_text(translate('ConnectionDetails', 'Revocation: {value1}'), value1=display_enum(result.revocation, 'words')), format_text(translate('ConnectionDetails', 'Signer subject: {value1}'), value1=signer.subject if signer and signer.subject else translate('ConnectionDetails', 'Unknown')), format_text(translate('ConnectionDetails', 'Issuer: {value1}'), value1=signer.issuer if signer and signer.issuer else translate('ConnectionDetails', 'Unknown')), format_text(translate('ConnectionDetails', 'Certificate SHA-256: {value1}'), value1=signer.certificate_sha256 if signer and signer.certificate_sha256 else translate('ConnectionDetails', 'Unknown')), format_text(translate('ConnectionDetails', 'Timestamp countersigner present: {value1}'), value1=(translate('ConnectionDetails', 'yes') if result.timestamp_present else translate('ConnectionDetails', 'no')) if result.timestamp_present is not None else translate('ConnectionDetails', 'unknown')), translate('ConnectionDetails', 'Evidence is for the current disk file, not the loaded process image or application safety.'))))


def _safe_raw(value: object | None) -> str:
    return MISSING_VALUE if value is None else str(value)


def _safe_display(value: object | None) -> str:
    if value is None:
        return MISSING_VALUE
    text = str(value)
    return text if text else MISSING_VALUE


__all__ = ("ConnectionDetailsWidget",)
