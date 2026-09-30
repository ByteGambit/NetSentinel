"""Selected-connection detail panel for the Connections page."""

from __future__ import annotations

from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtWidgets import QFormLayout, QGroupBox, QLabel, QScrollArea, QVBoxLayout, QWidget

from netsentinel.domain.connections import ProcessInfo
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
)
from netsentinel.presentation.process_context import (
    PROCESS_CONTEXT_FIELDS,
    process_context_text,
)
from netsentinel.presentation.viewmodels import MISSING_VALUE


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

    def __init__(self, parent: QWidget | None = None) -> None:
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

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self.status_label)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.clear()

    def value_text(self, field: str) -> str:
        """Return a displayed field value for assertions/accessibility helpers."""

        return self.value_labels[field].text()

    def clear(self, message: str = "No connection selected.") -> None:
        self.status_label.setText(message)
        self.status_label.show()
        for label in self.value_labels.values():
            label.setText(MISSING_VALUE)

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


def _safe_raw(value: object | None) -> str:
    return MISSING_VALUE if value is None else str(value)


def _safe_display(value: object | None) -> str:
    if value is None:
        return MISSING_VALUE
    text = str(value)
    return text if text else MISSING_VALUE


__all__ = ("ConnectionDetailsWidget",)
