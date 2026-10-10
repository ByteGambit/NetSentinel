"""Settings → Storage & Privacy. All storage/file/config work stays off Qt."""

from netsentinel.presentation.i18n.buttons import localize_buttons

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import translate

from concurrent.futures import Future
from pathlib import Path

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget, QScrollArea,
)

from netsentinel.application.services.storage_worker import (
    MaintenanceOperation as Op, MaintenanceRequest, MaintenanceValue,
    StorageMaintenanceWorker, StorageSettings,
)
from netsentinel.domain.storage_privacy import (
    PurgePreview, RetentionRunResult, SanitizedExport, StorageRetentionPolicy,
    StorageScope, StorageSummary,
)


class StoragePrivacyDialog(QDialog):
    retention_settings_saved = pyqtSignal(bool, int, int)

    def __init__(self, worker: StorageMaintenanceWorker, parent: QWidget | None = None, *, feedback: bool = False) -> None:
        super().__init__(parent)
        self.worker = worker
        self._future: Future[MaintenanceValue] | None = None
        self._operation = Op.SUMMARY
        self._export: SanitizedExport | None = None
        self.setWindowTitle(translate('StoragePrivacy', 'Feedback & Support') if feedback else translate('StoragePrivacy', 'Storage & Privacy'))
        self.setAccessibleName(render_text(self.windowTitle()))
        self.resize(780, 640)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget(scroll)
        scroll.setWidget(body)
        outer.addWidget(scroll)
        layout = QVBoxLayout(body)
        local = QLabel(translate('StoragePrivacy', 'NetSentinel stores monitoring history locally by default. Local metadata may contain personal and activity data.'), self)
        local.setWordWrap(True)
        layout.addWidget(local)
        self.feedback_note = QLabel(
            translate('StoragePrivacy', 'Review categories → Preview → Save locally → manually share. No dedicated feedback or private vulnerability contact is defined in this checkout. The project page is the starting point for finding a maintainer-approved channel; issue availability is not assumed. Never post secrets, raw telemetry or vulnerability details publicly. Opening the project page reveals browser/source-IP metadata to GitHub; no support data is attached.'), self)
        self.feedback_note.setWordWrap(True)
        self.feedback_note.setVisible(feedback)
        layout.addWidget(self.feedback_note)
        self.project_button = QPushButton(translate('StoragePrivacy', 'Open project page (browser)…'), self)
        self.project_button.setAccessibleName(translate('StoragePrivacy', 'Open canonical project page without attaching support data'))
        self.project_button.setToolTip(translate('StoragePrivacy', 'User-initiated browser navigation to GitHub. No query, attachment or upload.'))
        self.project_button.setVisible(feedback)
        self.project_button.clicked.connect(self._open_project)
        layout.addWidget(self.project_button)
        main_layout = layout
        self.storage_controls = QWidget(body)
        layout = QVBoxLayout(self.storage_controls)
        main_layout.addWidget(self.storage_controls)
        self.storage_controls.setVisible(not feedback)
        self.summary = QPlainTextEdit(self)
        self.summary.setReadOnly(True)
        self.summary.setMaximumHeight(170)
        layout.addWidget(self.summary)
        form = QFormLayout()
        settings = worker.settings
        self.enabled = QCheckBox(translate('StoragePrivacy', 'Enable scheduled retention (hourly, bounded)'), self)
        self.enabled.setChecked(settings.enabled)
        self.history_days = QSpinBox(self)
        self.history_days.setRange(30, 365)
        self.history_days.setValue(settings.policy.history_days)
        self.security_days = QSpinBox(self)
        self.security_days.setRange(30, 365)
        self.security_days.setValue(settings.policy.security_days)
        form.addRow(self.enabled)
        form.addRow(translate('StoragePrivacy', 'Connection / DNS history days'), self.history_days)
        form.addRow(translate('StoragePrivacy', 'Resolved alert / incident days'), self.security_days)
        layout.addLayout(form)
        self.policy_note = QLabel(translate('StoragePrivacy', 'Save enables future maintenance; first check after 60 seconds. Current state, trust and preferences remain protected. Expired baselines: 90 days; assessment snapshots: 30 days when unreferenced; cache: existing TTL.'), self)
        self.policy_note.setWordWrap(True)
        layout.addWidget(self.policy_note)
        row = QHBoxLayout()
        self.save_settings = QPushButton(translate('StoragePrivacy', 'Save retention settings'), self)
        self.refresh = QPushButton(translate('StoragePrivacy', 'Refresh storage summary'), self)
        row.addWidget(self.save_settings)
        row.addWidget(self.refresh)
        layout.addLayout(row)
        self.scope = QComboBox(self)
        for scope in StorageScope:
            self.scope.addItem(scope.value, scope)
        layout.addWidget(self.scope)
        self.purge_button = QPushButton(translate('StoragePrivacy', 'Preview deletion…'), self)
        layout.addWidget(self.purge_button)
        deletion = QLabel(translate('StoragePrivacy', 'Deletion is local and irreversible from NetSentinel, but secure erasure is not guaranteed. SQLite/WAL files may not shrink immediately. DB encryption is not guaranteed.'), self)
        deletion.setWordWrap(True)
        layout.addWidget(deletion)
        layout = main_layout
        self.categories = QLabel(
            translate('StoragePrivacy', 'Included (fixed allowlist-v1): app/schema/export version, aggregate local storage counts, retention policy, bounded sanitized alert and incident summaries. No optional raw-data categories are offered. Excluded: raw history, IP/domain/path/MAC/hash, evidence, notes, provider responses, full config and secrets. Counts are estimates; records are bounded. This is not anonymous or a forensic log. No automatic upload.'), self)
        self.categories.setWordWrap(True)
        self.categories.setAccessibleName(translate('StoragePrivacy', 'Support export included and excluded categories and limitations'))
        layout.addWidget(self.categories)
        row = QHBoxLayout()
        self.export_preview = QPushButton(translate('StoragePrivacy', 'Preview sanitized support export'), self)
        self.export_save = QPushButton(translate('StoragePrivacy', 'Save sanitized export…'), self)
        self.export_save.setEnabled(False)
        row.addWidget(self.export_preview)
        row.addWidget(self.export_save)
        outer.addLayout(row)
        self.preview = QPlainTextEdit(self)
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(160)
        self.preview.setAccessibleName(translate('StoragePrivacy', 'Full sanitized support export preview'))
        self.preview.setToolTip(translate('StoragePrivacy', 'Exact bounded bytes that Save will write; never raw telemetry.'))
        layout.addWidget(self.preview)
        export_note = QLabel(translate('StoragePrivacy', 'Exporting creates a file on your computer. NetSentinel does not upload it automatically. Maximum 100 records / 64 KiB. Preview shows the full sanitized export, including category counts and limitations.'), self)
        export_note.setWordWrap(True)
        layout.addWidget(export_note)
        self.status = QLabel("", self)
        self.status.setWordWrap(True)
        outer.addWidget(self.status)
        row = QHBoxLayout()
        self.cancel_operation = QPushButton(translate('StoragePrivacy', 'Cancel current operation'), self)
        self.close_button = QPushButton(translate('StoragePrivacy', 'Close'), self)
        row.addWidget(self.cancel_operation)
        row.addWidget(self.close_button)
        outer.addLayout(row)
        for button in (self.export_preview, self.export_save, self.cancel_operation, self.close_button):
            button.setAccessibleName(render_text(button.text()))
            button.setToolTip(render_text(button.text() + translate('StoragePrivacy', ' — local action; no upload.')))
        self._buttons = (self.refresh, self.save_settings, self.purge_button, self.export_preview)
        self._controls = (self.enabled, self.history_days, self.security_days, self.scope)
        self.refresh.clicked.connect(lambda: self._submit(MaintenanceRequest(Op.SUMMARY)))
        self.save_settings.clicked.connect(self._save_settings)
        self.purge_button.clicked.connect(lambda: self._submit(MaintenanceRequest(Op.PURGE_PREVIEW, scope=self.scope.currentData())))
        self.export_preview.clicked.connect(lambda: self._submit(MaintenanceRequest(Op.EXPORT_PREVIEW)))
        self.export_save.clicked.connect(self._save_export)
        self.cancel_operation.clicked.connect(worker.cancel)
        self.close_button.clicked.connect(self.reject)
        self.finished.connect(self._closed)
        self.timer = QTimer(self)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self._poll)
        self.timer.start()
        if not feedback:
            self._submit(MaintenanceRequest(Op.SUMMARY))
        else:
            self.status.setText(translate('StoragePrivacy', 'Review the fixed sanitized categories, then request a preview. Nothing is exported or sent on opening.'))
            self._set_busy(worker.busy)

    def _open_project(self) -> None:
        # Canonical remote, no invented issue/contact endpoint or URL prefill.
        if not QDesktopServices.openUrl(QUrl("https://github.com/ByteGambit/NetSentinel")):
            self.status.setText(translate('StoragePrivacy', 'Project page could not be opened. No data was sent by NetSentinel.'))

    def _save_settings(self) -> None:
        settings = StorageSettings(self.enabled.isChecked(), StorageRetentionPolicy(
            self.history_days.value(), self.security_days.value()))
        self._submit(MaintenanceRequest(Op.SETTINGS, settings=settings))

    def _submit(self, request: MaintenanceRequest) -> None:
        if self._future is not None:
            return
        if request.operation is Op.EXPORT_PREVIEW:
            self._export = None
            self.preview.clear()
        self._operation = request.operation
        self._future = self.worker.submit(request)
        self.status.setText(translate('StoragePrivacy', 'Working locally…'))
        self._set_busy(True)

    def _set_busy(self, busy: bool) -> None:
        for button in self._buttons:
            button.setEnabled(not busy)
        for control in self._controls:
            control.setEnabled(not busy)
        self.export_save.setEnabled(not busy and self._export is not None)
        self.cancel_operation.setEnabled(busy)

    def _poll(self) -> None:
        if self._future is None:
            # Scheduled work may begin while the dialog is open.
            self._set_busy(self.worker.busy)
            return
        if not self._future.done():
            return
        future, self._future = self._future, None
        self._set_busy(False)
        try:
            result = future.result()
        except Exception:
            self.status.setText(render_text(translate('StoragePrivacy', 'Export cancelled, busy or unavailable. No new final file written; retry later.') if self._operation in (Op.EXPORT_PREVIEW, Op.EXPORT_SAVE) else translate('StoragePrivacy', 'Operation cancelled, busy or unavailable. Previous committed chunks may remain; retry after monitoring writes finish.')))
            return
        if isinstance(result, StorageSummary):
            lines = [format_text(translate('StoragePrivacy', 'Approximate DB: {value1:,} bytes; WAL: {value2:,} bytes; schema {value3:03d}'), value1=result.database_bytes, value2=result.wal_bytes, value3=result.schema_version)]
            lines.extend((format_text(translate('StoragePrivacy', '{value1}: {value2:,} rows; {value3:,} protected; quota {value4:,}'), value1=s.store.value, value2=s.rows, value3=s.protected, value4=s.quota) + (translate('StoragePrivacy', ' — capacity pressure') if s.pressure else '') for s in result.stores))
            due = self.worker.next_due_seconds
            lines.append(translate('StoragePrivacy', 'Scheduled retention disabled') if due is None else format_text(translate('StoragePrivacy', 'Next scheduled check in approximately {value1} seconds'), value1=int(due)))
            previous = self.worker.last_cleanup
            lines.append(translate('StoragePrivacy', 'No cleanup this session') if previous is None else format_text(translate('StoragePrivacy', 'Last cleanup: {value1}, {value2} physical rows'), value1=previous.status.value, value2=previous.deleted_rows))
            lines.append(format_text(translate('StoragePrivacy', 'Maintenance failures: {value1}; conflicting requests rejected: {value2}'), value1=self.worker.failures, value2=self.worker.rejected))
            self.summary.setPlainText(render_join('\n', lines))
            self.status.setText(translate('StoragePrivacy', 'Local storage summary loaded. Protected-only pressure never triggers destructive fallback.'))
        elif isinstance(result, PurgePreview):
            self._confirm_purge(result)
        elif isinstance(result, RetentionRunResult):
            failed = sum(s.failed for s in result.stores)
            self.status.setText(format_text(translate('StoragePrivacy', '{value1}: {value2} physical rows deleted in {value3} bounded chunks; failed stores/chunks: {value4}. Large scopes may need another confirmed run. References are evaluated lazily on read.'), value1=result.status.value, value2=result.deleted_rows, value3=result.chunks, value4=failed))
            if result.capacity_pressure:
                self.status.setText(render_text(self.status.text() + translate('StoragePrivacy', ' Capacity pressure: ') + render_join(', ', (item.store.value for item in result.capacity_pressure)) + translate('StoragePrivacy', '. Protected rows remain.')))
            if result.summary_unavailable:
                self.status.setText(render_text(self.status.text() + translate('StoragePrivacy', ' Final protection/pressure counts unavailable within this run budget; refresh summary.')))
            self._export = None
            self.export_save.setEnabled(False)
        elif isinstance(result, SanitizedExport):
            self._export = result
            self.preview.setPlainText(render_text(result.content.decode('utf-8')))
            self.export_save.setEnabled(True)
            self.status.setText(format_text(translate('StoragePrivacy', 'Sanitized preview ready: {value1} records, {value2} bytes. Save writes these exact previewed export bytes locally.'), value1=result.record_count, value2=len(result.content)))
        elif isinstance(result, StorageSettings):
            self.retention_settings_saved.emit(result.enabled, result.policy.history_days, result.policy.security_days)
            self.status.setText(translate('StoragePrivacy', 'Retention settings saved. Unrelated consent, notification and user preferences are unchanged.'))
            self._export = None
            self.export_save.setEnabled(False)
        elif isinstance(result, bool):
            self.status.setText(render_text(translate('StoragePrivacy', 'Sanitized export saved locally. No upload was performed.') if result else translate('StoragePrivacy', 'Export cancelled; no final file written.')))
            if result:
                self._export = None
                self.export_save.setEnabled(False)

    def _confirm_purge(self, preview: PurgePreview) -> None:
        text = (format_text(translate('StoragePrivacy', 'Scope: {value1}\nEstimated eligible: {value2:,} parent/source records\nProtected records across local stores: {value3:,}\n\nDelete eligible records locally. Execution rechecks protection; counts can change. OPEN/ACK alerts/incidents, current connections, unexpired baselines, profiles/trust, preferences and current gateway/VLAN state remain. Consent and notification settings remain. Incident/source links may become expired or unavailable while retained explanation remains. At most 2048 physical rows per run; Cancel stops future chunks, earlier commits remain. Deletion is irreversible from NetSentinel; secure erasure is not guaranteed.'), value1=preview.scope.value, value2=preview.eligible, value3=preview.protected))
        if self._ask_delete(text):
            self._submit(MaintenanceRequest(Op.PURGE, confirmation=preview))
        else:
            self.status.setText(translate('StoragePrivacy', 'Deletion cancelled; no records deleted.'))

    def _ask_delete(self, text: str) -> bool:
        dialog = localize_buttons(QMessageBox(QMessageBox.Icon.Warning, translate('StoragePrivacy', 'Confirm local deletion'), text,
                             QMessageBox.StandardButton.Cancel, self))
        delete = dialog.addButton(translate('StoragePrivacy', 'Delete local eligible records'), QMessageBox.ButtonRole.DestructiveRole)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        return dialog.clickedButton() is delete

    def _save_export(self) -> None:
        if self._export is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, translate('StoragePrivacy', 'Save sanitized local support export'), "netsentinel-support.json", translate('StoragePrivacy', 'JSON (*.json)'))
        if path:
            self._submit(MaintenanceRequest(Op.EXPORT_SAVE, export=self._export, destination=Path(path)))

    def _closed(self, _result: int) -> None:
        self.timer.stop()
        if self._future is not None:
            self.worker.cancel()
        self._future = None
        self._export = None
