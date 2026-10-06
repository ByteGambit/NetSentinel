"""Settings → Storage & Privacy. All storage/file/config work stays off Qt."""

from concurrent.futures import Future
from pathlib import Path

from PyQt6.QtCore import QTimer
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
    def __init__(self, worker: StorageMaintenanceWorker, parent: QWidget | None = None, *, feedback: bool = False) -> None:
        super().__init__(parent)
        self.worker = worker
        self._future: Future[MaintenanceValue] | None = None
        self._operation = Op.SUMMARY
        self._export: SanitizedExport | None = None
        self.setWindowTitle("Feedback & Support" if feedback else "Storage & Privacy")
        self.setAccessibleName(self.windowTitle())
        self.resize(780, 640)
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
        self.feedback_note = QLabel(
            "Review categories → Preview → Save locally → manually share. No dedicated feedback or private vulnerability contact is defined in this checkout. "
            "The project page is the starting point for finding a maintainer-approved channel; issue availability is not assumed. "
            "Never post secrets, raw telemetry or vulnerability details publicly. Opening the project page reveals browser/source-IP metadata to GitHub; no support data is attached.", self)
        self.feedback_note.setWordWrap(True)
        self.feedback_note.setVisible(feedback)
        layout.addWidget(self.feedback_note)
        self.project_button = QPushButton("Open project page (browser)…", self)
        self.project_button.setAccessibleName("Open canonical project page without attaching support data")
        self.project_button.setToolTip("User-initiated browser navigation to GitHub. No query, attachment or upload.")
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
        layout = main_layout
        self.categories = QLabel(
            "Included (fixed allowlist-v1): app/schema/export version, aggregate local storage counts, retention policy, bounded sanitized alert and incident summaries. "
            "No optional raw-data categories are offered. Excluded: raw history, IP/domain/path/MAC/hash, evidence, notes, provider responses, full config and secrets. "
            "Counts are estimates; records are bounded. This is not anonymous or a forensic log. No automatic upload.", self)
        self.categories.setWordWrap(True)
        self.categories.setAccessibleName("Support export included and excluded categories and limitations")
        layout.addWidget(self.categories)
        row = QHBoxLayout()
        self.export_preview = QPushButton("Preview sanitized support export", self)
        self.export_save = QPushButton("Save sanitized export…", self)
        self.export_save.setEnabled(False)
        row.addWidget(self.export_preview)
        row.addWidget(self.export_save)
        outer.addLayout(row)
        self.preview = QPlainTextEdit(self)
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(160)
        self.preview.setAccessibleName("Full sanitized support export preview")
        self.preview.setToolTip("Exact bounded bytes that Save will write; never raw telemetry.")
        layout.addWidget(self.preview)
        export_note = QLabel("Exporting creates a file on your computer. NetSentinel does not upload it automatically. Maximum 100 records / 64 KiB. Preview shows the full sanitized export, including category counts and limitations.", self)
        export_note.setWordWrap(True)
        layout.addWidget(export_note)
        self.status = QLabel("", self)
        self.status.setWordWrap(True)
        outer.addWidget(self.status)
        row = QHBoxLayout()
        self.cancel_operation = QPushButton("Cancel current operation", self)
        self.close_button = QPushButton("Close", self)
        row.addWidget(self.cancel_operation)
        row.addWidget(self.close_button)
        outer.addLayout(row)
        for button in (self.export_preview, self.export_save, self.cancel_operation, self.close_button):
            button.setAccessibleName(button.text())
            button.setToolTip(button.text() + " — local action; no upload.")
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
            self.status.setText("Review the fixed sanitized categories, then request a preview. Nothing is exported or sent on opening.")
            self._set_busy(worker.busy)

    def _open_project(self) -> None:
        # Canonical remote, no invented issue/contact endpoint or URL prefill.
        if not QDesktopServices.openUrl(QUrl("https://github.com/ByteGambit/NetSentinel")):
            self.status.setText("Project page could not be opened. No data was sent by NetSentinel.")

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
            self.status.setText(
                "Export cancelled, busy or unavailable. No new final file written; retry later."
                if self._operation in (Op.EXPORT_PREVIEW, Op.EXPORT_SAVE) else
                "Operation cancelled, busy or unavailable. Previous committed chunks may remain; retry after monitoring writes finish.")
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
            self.preview.setPlainText(result.content.decode("utf-8"))
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
