"""Selected-connection detail panel for the Connections page."""

from __future__ import annotations
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


_DETAIL_FIELDS: tuple[tuple[str, str], ...] = (
    ("process", "Process name"),
    ("pid", "PID"),
    *PROCESS_CONTEXT_FIELDS,
    ("protocol", "Protocol"),
    ("state", "State"),
    ("local_address", "Local address"),
    ("local_port", "Local port"),
    ("remote_address", "Remote address"),
    ("remote_port", "Remote port"),
    ("duration", "Duration"),
)


class ConnectionDetailsWidget(QGroupBox):
    """Render one proxy row without exposing Python/internal values."""

    def __init__(self, parent: QWidget | None = None, *, baseline_queries: BaselineQueryCoordinator | None = None,
                 preference_commands: PreferenceCommandCoordinator | None = None,
                 risk_queries: RiskQueryCoordinator | None = None,
                 response_commands: ResponseCommandCoordinator | None = None,
                 threat_intel: ThreatIntelLookupWidget | None = None) -> None:
        super().__init__("Selected connection", parent)
        self.setObjectName("connectionDetails")
        self.setAccessibleName("Connection details")
        self.status_label = QLabel(self)
        self.status_label.setObjectName("connectionDetailsStatus")
        self.status_label.setAccessibleName("Connection details status")
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
            value.setAccessibleName(f"{title} value")
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
        signer_group = QGroupBox("Local executable signature", self)
        signer_layout = QVBoxLayout(signer_group)
        self.signer_button = QPushButton("Check disk file signature", signer_group)
        self.signer_button.setObjectName("checkExecutableSignature")
        self.signer_text = QLabel("On-demand local evidence; no file has been checked.", signer_group)
        self.signer_text.setObjectName("executableSignatureEvidence")
        self.signer_text.setTextFormat(Qt.TextFormat.PlainText)
        self.signer_text.setWordWrap(True)
        self.signer_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        signer_layout.addWidget(self.signer_button)
        signer_layout.addWidget(self.signer_text)
        layout.addWidget(signer_group)
        self.baseline = BaselineDetailWidget(baseline_queries, self, preference_commands=preference_commands)
        self.tabs = FlowTabWidget(self)
        self.tabs.setAccessibleName("Selected connection detail sections")
        self.tabs.setAccessibleDescription("Connection context and observed behavior baseline")
        self.tabs.addTab(connection_content, "Connection")
        self.tabs.addTab(self.baseline, "Behavior baseline")
        self.risk = RiskExplanationWidget(risk_queries, self, page_flow=True)
        self.tabs.addTab(self.risk, "Risk explanation")
        self.threat_intel = threat_intel or ThreatIntelLookupWidget(parent=self)
        self.tabs.addTab(self.threat_intel, "External reputation")
        self.response = ManualResponseWidget(response_commands, self)
        self.tabs.addTab(self.response, "Manual firewall response")
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

    def clear(self, message: str = "No connection selected.") -> None:
        self.status_label.setText(message)
        self.status_label.show()
        for label in self.value_labels.values():
            label.setText(MISSING_VALUE)
        self.destination.clear()
        self.baseline.clear()
        self.risk.clear("No connection selected.")
        self.threat_intel.clear()
        self.response.select(None)
        self.signer_text.setText("On-demand local evidence; no file has been checked.")

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
        self.value_labels["process"].setText(
            _safe_display(model.data(model.index(row, int(ConnectionColumn.PROCESS))))
        )
        self.value_labels["pid"].setText(
            _safe_display(model.data(model.index(row, int(ConnectionColumn.PID))))
        )
        self.value_labels["protocol"].setText(
            _safe_display(model.data(model.index(row, int(ConnectionColumn.PROTOCOL))))
        )
        self.value_labels["state"].setText(
            _safe_display(model.data(model.index(row, int(ConnectionColumn.STATE))))
        )
        self.value_labels["local_address"].setText(
            _safe_raw(model.data(first, int(ConnectionRole.RAW_LOCAL_ADDRESS)))
        )
        self.value_labels["local_port"].setText(
            _safe_raw(model.data(first, int(ConnectionRole.RAW_LOCAL_PORT)))
        )
        self.value_labels["remote_address"].setText(
            _safe_raw(model.data(first, int(ConnectionRole.RAW_REMOTE_ADDRESS)))
        )
        self.value_labels["remote_port"].setText(
            _safe_raw(model.data(first, int(ConnectionRole.RAW_REMOTE_PORT)))
        )
        self.value_labels["duration"].setText(
            _safe_display(model.data(model.index(row, int(ConnectionColumn.DURATION))))
        )
        process = model.data(first, int(ConnectionRole.PROCESS_INFO))
        if isinstance(process, ProcessInfo):
            for key, value in process_context_text(process).items():
                self.value_labels[key].setText(value)

    def set_signer_result(self, result: ExecutableSigner) -> None:
        self.response.invalidate_evidence()
        if result.availability is not SignerAvailability.AVAILABLE:
            self.signer_text.setText(f"Verification: {result.availability.value.replace('_', ' ')}")
            return
        signer = result.signer
        self.signer_text.setText("\n".join((
            f"Signature source: {result.kind.value}",
            f"Signature validation: {result.validation.value.replace('_', ' ')}",
            f"Local Windows trust: {result.local_trust.value.replace('_', ' ')}",
            f"Revocation: {result.revocation.value.replace('_', ' ')}",
            f"Signer subject: {signer.subject if signer and signer.subject else 'Unknown'}",
            f"Issuer: {signer.issuer if signer and signer.issuer else 'Unknown'}",
            f"Certificate SHA-256: {signer.certificate_sha256 if signer and signer.certificate_sha256 else 'Unknown'}",
            f"Timestamp countersigner present: {('yes' if result.timestamp_present else 'no') if result.timestamp_present is not None else 'unknown'}",
            "Evidence is for the current disk file, not the loaded process image or application safety.",
        )))


def _safe_raw(value: object | None) -> str:
    return MISSING_VALUE if value is None else str(value)


def _safe_display(value: object | None) -> str:
    if value is None:
        return MISSING_VALUE
    text = str(value)
    return text if text else MISSING_VALUE


__all__ = ("ConnectionDetailsWidget",)
