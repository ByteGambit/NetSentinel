"""User-facing NS-048 capability matrix; all I/O is owned by the coordinator."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import translate

from netsentinel.presentation.i18n.text import format_text, render_text

from netsentinel.presentation.i18n.text import TranslationMapping
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP
from dataclasses import replace

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from netsentinel.application.services.capabilities import CapabilityMatrix
from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureHealthSnapshot
from netsentinel.application.services.notifications import NotificationDiagnostics
from netsentinel.presentation.widgets.notification_settings import notification_state_text
from netsentinel.shared.config import AppConfig


_REASONS = TranslationMapping(lambda: {
    "connection_monitoring": translate('Diagnostics', 'Connection visibility depends on what Windows permits this user to read.'),
    "process_metadata": translate('Diagnostics', 'Some process details may be restricted by Windows permissions.'),
    "local_storage_available": translate('Diagnostics', 'Saved metadata can be read locally.'),
    "local_storage_unavailable": translate('Diagnostics', 'Local storage is unavailable. Saved views may be limited.'),
    "none": translate('Diagnostics', 'The capture dependency and checked interface are available. Access is confirmed only when you explicitly start capture.'),
    "not_probed": translate('Diagnostics', 'Packet capture has not been checked.'),
    "dependency_unavailable": translate('Diagnostics', 'Packet capture dependency or driver is unavailable. Npcap may need installation outside this app.'),
    "permission_denied": translate('Diagnostics', 'Packet capture or network context permission was denied. Review interface access or, if authorized, restart manually with the required rights. This app never elevates automatically.'),
    "interface_unavailable": translate('Diagnostics', 'No eligible local interface is available for packet capture.'),
    "network_changed": translate('Diagnostics', 'The checked network changed. Retry after selecting the current network in Devices.'),
    "transient_failure": translate('Diagnostics', 'Packet capture could not be checked right now. Retry later.'),
    "context_unavailable": translate('Diagnostics', 'Network interface information is temporarily unavailable.'),
    "probe_unavailable": translate('Diagnostics', 'Packet capture readiness could not be checked.'),
    "passive_capture_available": translate('Diagnostics', 'Passive features can be started explicitly in Devices; no capture is running from this check.'),
    "saved_data_only": translate('Diagnostics', 'Saved data remains available; live passive capture is limited.'),
})

# Capability service names are stable lookup identities, not translated keys.
_FEATURE_NAMES = {
    'Connections': QT_TRANSLATE_NOOP('Diagnostics', 'Connections'),
    'Process details': QT_TRANSLATE_NOOP('Diagnostics', 'Process details'),
    'History': QT_TRANSLATE_NOOP('Diagnostics', 'History'),
    'Packet capture': QT_TRANSLATE_NOOP('Diagnostics', 'Packet capture'),
    'Devices': QT_TRANSLATE_NOOP('Diagnostics', 'Devices'),
    'DNS': QT_TRANSLATE_NOOP('Diagnostics', 'DNS'),
    'Alerts': QT_TRANSLATE_NOOP('Diagnostics', 'Alerts'),
}


class DiagnosticsView(QWidget):
    def __init__(self, coordinator: CapabilityCoordinator | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName(translate('Diagnostics', 'Capability diagnostics'))
        self._coordinator = coordinator
        self._active = True
        self._live_capture: CaptureHealthSnapshot | None = None
        self._last_matrix: CapabilityMatrix | None = None
        title = QLabel(translate('Diagnostics', 'Capabilities and health'), self)
        title.setAccessibleName(translate('Diagnostics', 'Capability diagnostics title'))
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        explanation = QLabel(
            translate('Diagnostics', 'Availability describes features on this system. Running health describes current workers. Neither is a security verdict.'), self,
        )
        explanation.setWordWrap(True)
        explanation.setAccessibleName(translate('Diagnostics', 'Capability diagnostics explanation'))
        self.status = QLabel(translate('Diagnostics', 'Not checked'), self)
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setAccessibleName(translate('Diagnostics', 'Capability check status'))
        self.privilege = QLabel(translate('Diagnostics', 'Privilege context: Not checked'), self)
        self.privilege.setWordWrap(True)
        self.privilege.setAccessibleName(translate('Diagnostics', 'Process privilege context'))
        self.rows: dict[str, QLabel] = {}
        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(explanation)
        layout.addWidget(self.status)
        self.summary = QLabel(translate('Diagnostics', 'Current activity: Not checked'), self)
        self.summary.setWordWrap(True)
        self.summary.setAccessibleName(translate('Diagnostics', 'Current monitoring activity summary'))
        layout.addWidget(self.summary)
        self.preferences = QLabel(self)
        self.preferences.setWordWrap(True)
        self.preferences.setAccessibleName(translate('Diagnostics', 'Optional feature preferences'))
        layout.addWidget(self.preferences)
        self.details_button = QPushButton(translate('Diagnostics', 'Show technical details'), self)
        self.details_button.setCheckable(True)
        self.details_button.setAccessibleName(translate('Diagnostics', 'Expand technical diagnostics'))
        layout.addWidget(self.details_button)
        self.details = QWidget(self)
        detail_layout = QVBoxLayout(self.details)
        detail_layout.addWidget(self.privilege)
        for name in _FEATURE_NAMES.values():
            row = QLabel(format_text(translate('Diagnostics', '{value1}: Not checked'), value1=name), self)
            row.setWordWrap(True)
            row.setTextFormat(Qt.TextFormat.PlainText)
            row.setAccessibleName(format_text(translate('Diagnostics', '{value1} capability'), value1=name))
            self.rows[name] = row
            detail_layout.addWidget(row)
        self.health = QLabel(translate('Diagnostics', 'Worker health: Not checked'), self)
        self.health.setWordWrap(True)
        self.health.setAccessibleName(translate('Diagnostics', 'Worker and database health'))
        detail_layout.addWidget(self.health)
        self.notifications = QLabel(translate('Diagnostics', 'Desktop notifications: Not checked'), self)
        self.notifications.setWordWrap(True)
        self.notifications.setTextFormat(Qt.TextFormat.PlainText)
        self.notifications.setAccessibleName(translate('Diagnostics', 'Desktop notification delivery diagnostics'))
        detail_layout.addWidget(self.notifications)
        layout.addWidget(self.details)
        self.details.hide()
        self.details_button.toggled.connect(self.details.setVisible)
        self.details_button.toggled.connect(lambda expanded: self.details_button.setText(render_text(translate('Diagnostics', 'Hide technical details') if expanded else translate('Diagnostics', 'Show technical details'))))
        self.set_preferences(AppConfig())
        self.retry_button = QPushButton(translate('Diagnostics', 'Retry check'), self)
        self.retry_button.setAccessibleName(translate('Diagnostics', 'Retry capability check'))
        self.retry_button.setEnabled(coordinator is not None)
        layout.addWidget(self.retry_button)
        layout.addStretch()
        self.retry_button.clicked.connect(self.retry)
        if coordinator is not None:
            coordinator.ready.connect(self._receive_matrix)
            coordinator.failed.connect(self._receive_failure)

    def deactivate(self) -> None:
        self._active = False

    def set_preferences(self, config: AppConfig, *, credential_available: bool | None = None) -> None:
        self._config = config
        self._credential_available = credential_available
        credential = (translate('Diagnostics', 'Unavailable (this desktop has no usable secret backend)') if credential_available is False else
                      translate('Diagnostics', 'Available') if credential_available is True else translate('Diagnostics', 'Not checked here'))
        ti = (translate('Diagnostics', 'Consent enabled; manual lookup only')
              if config.threat_intel_consents else translate('Diagnostics', 'Disabled by user (default: zero requests)'))
        self.preferences.setText(format_text(translate('Diagnostics', 'Threat intelligence (AbuseIPDB): {value1}.\nProvider credential: {value2}.\nNotifications: {value3}.\nStorage: local; scheduled retention {value4}.'), value1=ti, value2=credential, value3=translate('Diagnostics', 'Enabled; delivery capability checked separately') if config.desktop_notifications_enabled else translate('Diagnostics', 'Disabled by user'), value4=translate('Diagnostics', 'enabled') if config.storage_retention_enabled else translate('Diagnostics', 'disabled by user')))

    def set_storage_preferences(self, enabled: bool, history_days: int, security_days: int) -> None:
        self.set_preferences(replace(self._config, storage_retention_enabled=enabled,
                                     storage_history_days=history_days, storage_security_days=security_days),
                             credential_available=self._credential_available)

    def set_notification_diagnostics(self, snapshot: NotificationDiagnostics, *, enabled: bool) -> None:
        if self._active:
            self.set_preferences(replace(self._config, desktop_notifications_enabled=enabled),
                                 credential_available=self._credential_available)
            self.notifications.setText(format_text(translate('Diagnostics', 'Desktop notifications: {value1} intents {value2}; eligible {value3}; adapter attempts {value4}; OS/session skipped {value5}; submitted {value6} (display unconfirmed); visible delivery UNKNOWN (Qt supplies no display confirmation); last adapter outcome {value7}; unavailable {value8}; failed {value9}; queue coalesced {value10}, dropped {value11}; session capacity skipped {value12}; navigation succeeded {value13}, failed {value14}.'), value1=notification_state_text(enabled, snapshot.platform_state), value2=snapshot.intents_seen, value3=snapshot.eligible_for_delivery, value4=snapshot.submission_attempts, value5=snapshot.os_policy_skipped, value6=snapshot.submitted_to_sink, value7=snapshot.last_submission_outcome.value if snapshot.last_submission_outcome else 'none', value8=snapshot.sink_unavailable, value9=snapshot.sink_failure, value10=snapshot.queue_coalesced, value11=snapshot.queue_dropped, value12=snapshot.capacity_skipped, value13=snapshot.navigation_success, value14=snapshot.navigation_failure))

    def _receive_matrix(self, generation: int, matrix: CapabilityMatrix) -> None:
        if self._active and self._coordinator is not None and generation == self._coordinator.generation:
            self.set_matrix(matrix)

    def _receive_failure(self, generation: int) -> None:
        if self._active and self._coordinator is not None and generation == self._coordinator.generation:
            self.set_failure()

    def retry(self) -> None:
        if self._active and self._coordinator is not None and self._coordinator.request():
            self.status.setText(translate('Diagnostics', 'Checking capabilities…'))

    def set_failure(self) -> None:
        self.status.setText(translate('Diagnostics', 'Capability check unavailable. Retry later; saved views may still work.'))
        self.summary.setText(translate('Diagnostics', 'Current activity: Unavailable for this check. Optional features and saved data are independent.'))

    def set_matrix(self, matrix: CapabilityMatrix) -> None:
        self._last_matrix = matrix
        if matrix.is_elevated is True:
            self.privilege.setText(translate('Diagnostics', 'Running elevated. Capture access still depends on the driver and interface.'))
        elif matrix.is_elevated is False:
            self.privilege.setText(translate('Diagnostics', 'Running as a standard user. Capture may need additional access; this app never elevates automatically.'))
        else:
            self.privilege.setText(translate('Diagnostics', 'Privilege context not checked. Capture access is confirmed only when started explicitly.'))
        self.status.setText(translate('Diagnostics', 'Check complete. No packet capture was started.'))
        for item in matrix.features:
            reason = _REASONS.get(item.reason, translate('Diagnostics', 'Capability status is unavailable.'))
            self.rows[item.name].setText(format_text(translate('Diagnostics', '{feature}: {status} — {reason}'),
                feature=_FEATURE_NAMES.get(item.name, item.name), status=display_enum(item.status, 'human'), reason=reason))
        self._render_health()
        self._show_live_capture()

    def _render_health(self) -> None:
        if self._last_matrix is None:
            return
        diagnostics = self._last_matrix.diagnostics
        capture = self._live_capture or diagnostics.capture
        writer = diagnostics.persistence
        history = (
            format_text(translate('Diagnostics', 'history writer: {value1}, queue {value2}/{value3}'), value1=writer.state.value, value2=writer.queue_depth, value3=writer.queue_capacity)
            if writer is not None else translate('Diagnostics', 'history writer: not checked')
        )
        dns = (
            format_text(translate('Diagnostics', 'DNS writer: {value1}, queue {value2}/{value3}'), value1='running' if diagnostics.dns_writer_running else 'stopped', value2=diagnostics.dns_queue_depth, value3=diagnostics.dns_queue_capacity)
            if diagnostics.dns_writer_running is not None else translate('Diagnostics', 'DNS writer: not checked')
        )
        self.health.setText(format_text(translate('Diagnostics', 'Engine: {value1}; packet capture: {value2}; database: {value3}; {value4}; {value5}.'), value1=diagnostics.engine.state.value, value2=capture.state.value if capture else translate('Diagnostics', 'not checked'), value3=diagnostics.database.status.value, value4=history, value5=dns))
        features = {item.name: item for item in self._last_matrix.features}
        connection = features.get(QT_TRANSLATE_NOOP('Diagnostics', 'Connections'))
        capture_feature = features.get(QT_TRANSLATE_NOOP('Diagnostics', 'Packet capture'))
        capture_status = (self._live_capture.capability.status.value if self._live_capture is not None else
                          capture_feature.status.value if capture_feature else translate('Diagnostics', 'not checked'))
        capture_activity = capture.state.value if capture else translate('Diagnostics', 'not checked')
        if capture_status != "available":
            capture_activity = capture_status
        dns_feature = features.get(QT_TRANSLATE_NOOP('Diagnostics', 'DNS'))
        dns_activity = (translate('Diagnostics', 'Unavailable') if dns_feature is not None and dns_feature.status.value == "unavailable" else
                        translate('Diagnostics', 'Capture running; observations only where capture sees classic DNS') if capture_activity == "running" else
                        translate('Diagnostics', 'Limited while capture is stopped or unavailable'))
        self.summary.setText(format_text(translate('Diagnostics', 'Monitoring engine: {value1}\nConnection visibility: {value2}\nPacket capture: {value3} (capability: {value4})\nDNS observation: {value5}\nLocal storage: {value6}'), value1=display_enum(diagnostics.engine.state, 'human'), value2=display_enum(connection.status, 'human') if connection else translate('Diagnostics', 'Not checked'), value3=capture_activity.capitalize(), value4=capture_status, value5=dns_activity, value6=display_enum(diagnostics.database.status, 'human')))

    def set_live_capture(self, capture: CaptureHealthSnapshot | None) -> None:
        self._live_capture = capture
        self._show_live_capture()

    def _show_live_capture(self) -> None:
        capture = self._live_capture
        if capture is None:
            return
        if capture.capability.reason is not CaptureCapabilityReason.NOT_PROBED:
            self.rows['Packet capture'].setText(format_text(translate('Diagnostics', 'Packet capture: {value1} — {value2}'), value1=display_enum(capture.capability.status, 'human'), value2=_REASONS.get(capture.capability.reason.value, translate('Diagnostics', 'Capability status is unavailable.'))))
        self._render_health()


__all__ = ("DiagnosticsView",)
