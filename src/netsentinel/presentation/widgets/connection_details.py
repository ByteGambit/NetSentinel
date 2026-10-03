"""Selected-connection detail panel for the Connections page."""

from __future__ import annotations

from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtWidgets import QFormLayout, QGroupBox, QLabel, QPushButton, QScrollArea, QTabWidget, QVBoxLayout, QWidget

from netsentinel.domain.connections import ProcessInfo
from netsentinel.domain.executable_signer import ExecutableSigner, SignerAvailability
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
)
from netsentinel.presentation.process_context import (
    PROCESS_CONTEXT_FIELDS,
    process_context_text,
)
from netsentinel.presentation.viewmodels import MISSING_VALUE
from netsentinel.presentation.destination_context import DestinationEvidenceWidget
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator
from netsentinel.presentation.widgets.baseline_detail import BaselineDetailWidget


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

    def __init__(self, parent: QWidget | None = None, *, baseline_queries: BaselineQueryCoordinator | None = None) -> None:
        super().__init__("Selected connection", parent)
        self.setObjectName("connectionDetails")
        self.setAccessibleName("Connection details")
        self.status_label = QLabel(self)
        self.status_label.setObjectName("connectionDetailsStatus")
        self.status_label.setAccessibleName("Connection details status")
        self.status_label.setStyleSheet("color: #627d98;")

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
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.destination = DestinationEvidenceWidget(self)
        destination_scroll = QScrollArea(self)
        destination_scroll.setWidgetResizable(True)
        destination_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        destination_scroll.setMaximumHeight(240)
        destination_scroll.setWidget(self.destination)
        layout.addWidget(destination_scroll)
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
        self.baseline = BaselineDetailWidget(baseline_queries, self)
        self.tabs = QTabWidget(self)
        self.tabs.setAccessibleName("Selected connection detail sections")
        self.tabs.setAccessibleDescription("Connection context and observed behavior baseline")
        self.tabs.addTab(connection_content, "Connection")
        self.tabs.addTab(self.baseline, "Behavior baseline")
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
        self.signer_text.setText("On-demand local evidence; no file has been checked.")

    def set_connection(self, index: QModelIndex) -> None:
        if not index.isValid() or index.model() is None:
            self.clear()
            return

        model = index.model()
        row = index.row()
        first = model.index(row, 0)

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
