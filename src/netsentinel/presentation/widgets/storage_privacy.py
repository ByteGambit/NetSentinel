"""Settings → Storage & Privacy. All storage/file/config work stays off Qt."""

from concurrent.futures import Future
from pathlib import Path

from PyQt6.QtCore import QTimer
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
    def __init__(self, worker: StorageMaintenanceWorker, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.worker = worker
        self._future: Future[MaintenanceValue] | None = None
        self._operation = Op.SUMMARY
        self._export: SanitizedExport | None = None
        self.setWindowTitle("Storage & Privacy")
        self.resize(780, 740)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget(scroll)
        scroll.setWidget(body)
        outer.addWidget(scroll)
        layout = QVBoxLayout(body)
        local = QLabel("NetSentinel stores monitoring history locally by default. Local metadata may contain personal and activity data.", self)
        local.setWordWrap(True)
        layout.addWidget(local)
        self.summary = QPlainTextEdit(self)
        self.summary.setReadOnly(True)
        self.summary.setMaximumHeight(170)
        layout.addWidget(self.summary)
        form = QFormLayout()
        settings = worker.settings
        self.enabled = QCheckBox("Enable scheduled retention (hourly, bounded)", self)
        self.enabled.setChecked(settings.enabled)
        self.history_days = QSpinBox(self)
        self.history_days.setRange(30, 365)
        self.history_days.setValue(settings.policy.history_days)
        self.security_days = QSpinBox(self)
        self.security_days.setRange(30, 365)
        self.security_days.setValue(settings.policy.security_days)
        form.addRow(self.enabled)
        form.addRow("Connection / DNS history days", self.history_days)
        form.addRow("Resolved alert / incident days", self.security_days)
        layout.addLayout(form)
        self.policy_note = QLabel("Save enables future maintenance; first check after 60 seconds. Current state, trust and preferences remain protected. Expired baselines: 90 days; assessment snapshots: 30 days when unreferenced; cache: existing TTL.", self)
        self.policy_note.setWordWrap(True)
        layout.addWidget(self.policy_note)
        row = QHBoxLayout()
        self.save_settings = QPushButton("Save retention settings", self)
        self.refresh = QPushButton("Refresh storage summary", self)
        row.addWidget(self.save_settings)
        row.addWidget(self.refresh)
        layout.addLayout(row)
        self.scope = QComboBox(self)
        for scope in StorageScope:
            self.scope.addItem(scope.value, scope)
        layout.addWidget(self.scope)
        self.purge_button = QPushButton("Preview deletion…", self)
        layout.addWidget(self.purge_button)
        deletion = QLabel("Deletion is local and irreversible from NetSentinel, but secure erasure is not guaranteed. SQLite/WAL files may not shrink immediately. DB encryption is not guaranteed.", self)
        deletion.setWordWrap(True)
        layout.addWidget(deletion)
        row = QHBoxLayout()
        self.export_preview = QPushButton("Preview sanitized support export", self)
        self.export_save = QPushButton("Save sanitized export…", self)
        self.export_save.setEnabled(False)
        row.addWidget(self.export_preview)
        row.addWidget(self.export_save)
        layout.addLayout(row)
        self.preview = QPlainTextEdit(self)
        self.preview.setReadOnly(True)
        layout.addWidget(self.preview)
        export_note = QLabel("Exporting creates a file on your computer. NetSentinel does not upload it automatically. Raw IP/domain/path/MAC/hash, user notes, evidence, provider responses, config and secrets are excluded. Maximum 100 records / 64 KiB; preview samples at most 10 per category.", self)
        export_note.setWordWrap(True)
        layout.addWidget(export_note)
        self.status = QLabel("", self)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.cancel_operation = QPushButton("Cancel current operation", self)
        self.close_button = QPushButton("Close", self)
        row.addWidget(self.cancel_operation)
        row.addWidget(self.close_button)
        layout.addLayout(row)
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
        self._submit(MaintenanceRequest(Op.SUMMARY))

    def _save_settings(self) -> None:
        settings = StorageSettings(self.enabled.isChecked(), StorageRetentionPolicy(
            self.history_days.value(), self.security_days.value()))
        self._submit(MaintenanceRequest(Op.SETTINGS, settings=settings))

    def _submit(self, request: MaintenanceRequest) -> None:
        if self._future is not None:
            return
        self._operation = request.operation
        self._future = self.worker.submit(request)
        self.status.setText("Working locally…")
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
            self.status.setText("Operation cancelled, busy or unavailable. Previous committed chunks may remain; retry after monitoring writes finish.")
            return
        if isinstance(result, StorageSummary):
            lines = [f"Approximate DB: {result.database_bytes:,} bytes; WAL: {result.wal_bytes:,} bytes; schema {result.schema_version:03d}"]
            lines.extend(f"{s.store.value}: {s.rows:,} rows; {s.protected:,} protected; quota {s.quota:,}" + (" — capacity pressure" if s.pressure else "") for s in result.stores)
            due = self.worker.next_due_seconds
            lines.append("Scheduled retention disabled" if due is None else f"Next scheduled check in approximately {int(due)} seconds")
            previous = self.worker.last_cleanup
            lines.append("No cleanup this session" if previous is None else f"Last cleanup: {previous.status.value}, {previous.deleted_rows} physical rows")
            lines.append(f"Maintenance failures: {self.worker.failures}; conflicting requests rejected: {self.worker.rejected}")
            self.summary.setPlainText("\n".join(lines))
            self.status.setText("Local storage summary loaded. Protected-only pressure never triggers destructive fallback.")
        elif isinstance(result, PurgePreview):
            self._confirm_purge(result)
        elif isinstance(result, RetentionRunResult):
            failed = sum(s.failed for s in result.stores)
            self.status.setText(f"{result.status.value}: {result.deleted_rows} physical rows deleted in {result.chunks} bounded chunks; failed stores/chunks: {failed}. Large scopes may need another confirmed run. References are evaluated lazily on read.")
            if result.capacity_pressure:
                self.status.setText(self.status.text() + " Capacity pressure: " + ", ".join(item.store.value for item in result.capacity_pressure) + ". Protected rows remain.")
            if result.summary_unavailable:
                self.status.setText(self.status.text() + " Final protection/pressure counts unavailable within this run budget; refresh summary.")
            self._export = None
            self.export_save.setEnabled(False)
        elif isinstance(result, SanitizedExport):
            self._export = result
            self.preview.setPlainText(result.sample)
            self.export_save.setEnabled(True)
            self.status.setText(f"Sanitized preview ready: {result.record_count} records, {len(result.content)} bytes. Save writes these exact previewed export bytes locally.")
        elif isinstance(result, StorageSettings):
            self.status.setText("Retention settings saved. Unrelated consent, notification and user preferences are unchanged.")
            self._export = None
            self.export_save.setEnabled(False)
        elif isinstance(result, bool):
            self.status.setText("Sanitized export saved locally. No upload was performed." if result else "Export cancelled; no final file written.")
            if result:
                self._export = None
                self.export_save.setEnabled(False)

    def _confirm_purge(self, preview: PurgePreview) -> None:
        text = (f"Scope: {preview.scope.value}\nEstimated eligible: {preview.eligible:,} parent/source records\n"
                f"Protected records across local stores: {preview.protected:,}\n\n"
                "Delete eligible records locally. Execution rechecks protection; counts can change. "
                "OPEN/ACK alerts/incidents, current connections, unexpired baselines, profiles/trust, "
                "preferences and current gateway/VLAN state remain. Consent and notification settings remain. "
                "Incident/source links may become expired or unavailable while retained explanation remains. "
                "At most 2048 physical rows per run; Cancel stops future chunks, earlier commits remain. "
                "Deletion is irreversible from NetSentinel; secure erasure is not guaranteed.")
        if self._ask_delete(text):
            self._submit(MaintenanceRequest(Op.PURGE, confirmation=preview))
        else:
            self.status.setText("Deletion cancelled; no records deleted.")

    def _ask_delete(self, text: str) -> bool:
        dialog = QMessageBox(QMessageBox.Icon.Warning, "Confirm local deletion", text,
                             QMessageBox.StandardButton.Cancel, self)
        delete = dialog.addButton("Delete local eligible records", QMessageBox.ButtonRole.DestructiveRole)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        return dialog.clickedButton() is delete

    def _save_export(self) -> None:
        if self._export is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save sanitized local support export", "netsentinel-support.json", "JSON (*.json)")
        if path:
            self._submit(MaintenanceRequest(Op.EXPORT_SAVE, export=self._export, destination=Path(path)))

    def _closed(self, _result: int) -> None:
        self.timer.stop()
        if self._future is not None:
            self.worker.cancel()
        self._future = None
        self._export = None
