"""User-facing NS-048 capability matrix; all I/O is owned by the coordinator."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from netsentinel.application.services.capabilities import CapabilityMatrix
from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureHealthSnapshot


_REASONS = {
    "connection_monitoring": "Connection visibility depends on what Windows permits this user to read.",
    "process_metadata": "Some process details may be restricted by Windows permissions.",
    "local_storage_available": "Saved metadata can be read locally.",
    "local_storage_unavailable": "Local storage is unavailable. Saved views may be limited.",
    "none": "The capture dependency and checked interface are available. Access is confirmed only when you explicitly start capture.",
    "not_probed": "Packet capture has not been checked.",
    "dependency_unavailable": "Packet capture dependency or driver is unavailable. Npcap may need installation outside this app.",
    "permission_denied": "Packet capture or network context permission was denied. Review interface access or, if authorized, restart manually with the required rights. This app never elevates automatically.",
    "interface_unavailable": "No eligible local interface is available for packet capture.",
    "network_changed": "The checked network changed. Retry after selecting the current network in Devices.",
    "transient_failure": "Packet capture could not be checked right now. Retry later.",
    "context_unavailable": "Network interface information is temporarily unavailable.",
    "probe_unavailable": "Packet capture readiness could not be checked.",
    "passive_capture_available": "Passive features can be started explicitly in Devices; no capture is running from this check.",
    "saved_data_only": "Saved data remains available; live passive capture is limited.",
}


class DiagnosticsView(QWidget):
    def __init__(self, coordinator: CapabilityCoordinator | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Capability diagnostics")
        self._coordinator = coordinator
        self._active = True
        self._live_capture: CaptureHealthSnapshot | None = None
        self._last_matrix: CapabilityMatrix | None = None
        title = QLabel("Capabilities and health", self)
        title.setAccessibleName("Capability diagnostics title")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        explanation = QLabel(
            "Availability describes features on this system. Running health describes current workers. Neither is a security verdict.", self,
        )
        explanation.setWordWrap(True)
        explanation.setAccessibleName("Capability diagnostics explanation")
        self.status = QLabel("Not checked", self)
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setAccessibleName("Capability check status")
        self.privilege = QLabel("Privilege context: Not checked", self)
        self.privilege.setWordWrap(True)
        self.privilege.setAccessibleName("Process privilege context")
        self.rows: dict[str, QLabel] = {}
        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(explanation)
        layout.addWidget(self.status)
        layout.addWidget(self.privilege)
        for name in ("Connections", "Process details", "History", "Packet capture", "Devices", "DNS", "Alerts"):
            row = QLabel(f"{name}: Not checked", self)
            row.setWordWrap(True)
            row.setTextFormat(Qt.TextFormat.PlainText)
            row.setAccessibleName(f"{name} capability")
            self.rows[name] = row
            layout.addWidget(row)
        self.health = QLabel("Worker health: Not checked", self)
        self.health.setWordWrap(True)
        self.health.setAccessibleName("Worker and database health")
        layout.addWidget(self.health)
        self.retry_button = QPushButton("Retry check", self)
        self.retry_button.setAccessibleName("Retry capability check")
        self.retry_button.setEnabled(coordinator is not None)
        layout.addWidget(self.retry_button)
        layout.addStretch()
        self.retry_button.clicked.connect(self.retry)
        if coordinator is not None:
            coordinator.ready.connect(self._receive_matrix)
            coordinator.failed.connect(self._receive_failure)

    def deactivate(self) -> None:
        self._active = False

    def _receive_matrix(self, generation: int, matrix: CapabilityMatrix) -> None:
        if self._active and self._coordinator is not None and generation == self._coordinator.generation:
            self.set_matrix(matrix)

    def _receive_failure(self, generation: int) -> None:
        if self._active and self._coordinator is not None and generation == self._coordinator.generation:
            self.set_failure()

    def retry(self) -> None:
        if self._active and self._coordinator is not None and self._coordinator.request():
            self.status.setText("Checking capabilities…")

    def set_failure(self) -> None:
        self.status.setText("Capability check unavailable. Retry later; saved views may still work.")

    def set_matrix(self, matrix: CapabilityMatrix) -> None:
        self._last_matrix = matrix
        if matrix.is_elevated is True:
            self.privilege.setText("Running elevated. Capture access still depends on the driver and interface.")
        elif matrix.is_elevated is False:
            self.privilege.setText("Running as a standard user. Capture may need additional access; this app never elevates automatically.")
        else:
            self.privilege.setText("Privilege context not checked. Capture access is confirmed only when started explicitly.")
        self.status.setText("Check complete. No packet capture was started.")
        for item in matrix.features:
            reason = _REASONS.get(item.reason, "Capability status is unavailable.")
            self.rows[item.name].setText(f"{item.name}: {item.status.value.capitalize()} — {reason}")
        self._render_health()
        self._show_live_capture()

    def _render_health(self) -> None:
        if self._last_matrix is None:
            return
        diagnostics = self._last_matrix.diagnostics
        capture = self._live_capture or diagnostics.capture
        writer = diagnostics.persistence
        history = (
            f"history writer: {writer.state.value}, queue {writer.queue_depth}/{writer.queue_capacity}"
            if writer is not None else "history writer: not checked"
        )
        dns = (
            f"DNS writer: {'running' if diagnostics.dns_writer_running else 'stopped'}, "
            f"queue {diagnostics.dns_queue_depth}/{diagnostics.dns_queue_capacity}"
            if diagnostics.dns_writer_running is not None else "DNS writer: not checked"
        )
        self.health.setText(
            f"Engine: {diagnostics.engine.state.value}; "
            f"packet capture: {capture.state.value if capture else 'not checked'}; "
            f"database: {diagnostics.database.status.value}; {history}; {dns}."
        )

    def set_live_capture(self, capture: CaptureHealthSnapshot | None) -> None:
        self._live_capture = capture
        self._show_live_capture()

    def _show_live_capture(self) -> None:
        capture = self._live_capture
        if capture is None:
            return
        if capture.capability.reason is not CaptureCapabilityReason.NOT_PROBED:
            self.rows["Packet capture"].setText(
                f"Packet capture: {capture.capability.status.value.capitalize()} — "
                f"{_REASONS.get(capture.capability.reason.value, 'Capability status is unavailable.')}"
            )
        self._render_health()


__all__ = ("DiagnosticsView",)
