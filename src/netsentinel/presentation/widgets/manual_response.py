"""Thin explicit manual firewall review and bounded local audit browser."""

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import translate

from datetime import UTC, datetime
from collections.abc import Callable
from uuid import UUID

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QListWidget, QPushButton,
    QTextEdit, QVBoxLayout, QWidget,
)

from netsentinel.application.services.response_ui import (
    ResponseHistory, ResponsePreview, ResponseSelection, ResponseUiReply, WARNINGS,
)
from netsentinel.domain.response import ResponseAction, ResponseProfile
from netsentinel.presentation.response_commands import ResponseCommandCoordinator


def label(text: str, name: str, parent: QWidget) -> QLabel:
    value = QLabel(render_text(text), parent)
    value.setTextFormat(Qt.TextFormat.PlainText)
    value.setWordWrap(True)
    value.setAccessibleName(render_text(name))
    return value


class ResponseConfirmationDialog(QDialog):
    def __init__(self, preview: ResponsePreview, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate('ManualResponse', 'Confirm exact Windows Firewall rule'))
        self.setAccessibleName(translate('ManualResponse', 'Exact firewall rule confirmation'))
        self.resize(720, 620)
        self.text = QTextEdit(self)
        self.text.setReadOnly(True)
        self.text.setPlainText(render_text(preview.text))
        self.text.setAccessibleName(translate('ManualResponse', 'Complete firewall preview and collateral warnings'))
        self.cancel = QPushButton(translate('ManualResponse', '&Cancel — no firewall write'), self)
        self.cancel.setAccessibleName(translate('ManualResponse', 'Cancel firewall rule without writing'))
        self.cancel.setDefault(True)
        self.confirm = QPushButton(translate('ManualResponse', 'Confirm &Undo firewall rule') if preview.command.action is ResponseAction.REMOVE
                                   else translate('ManualResponse', 'Confirm &Create firewall rule'), self)
        self.confirm.setAccessibleName(render_text(self.confirm.text().replace('&', '')))
        self.confirm.setAutoDefault(False)
        self.confirm.clicked.connect(self.accept)
        self.cancel.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addWidget(self.cancel)
        buttons.addWidget(self.confirm)
        layout = QVBoxLayout(self)
        layout.addWidget(self.text, 1)
        layout.addLayout(buttons)
        QWidget.setTabOrder(self.text, self.cancel)
        QWidget.setTabOrder(self.cancel, self.confirm)
        self.cancel.setFocus()


class ManualResponseWidget(QWidget):
    def __init__(self, coordinator: ResponseCommandCoordinator | None = None, parent: QWidget | None = None,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        super().__init__(parent)
        self.setAccessibleName(translate('ManualResponse', 'Manual Windows Firewall response'))
        self.coordinator = coordinator
        self._clock = clock
        self._selection: ResponseSelection | None = None
        self._epoch = 0
        self._job: int | None = None
        self._preview: ResponsePreview | None = None
        self._history = ResponseHistory()
        self.dialog: ResponseConfirmationDialog | None = None
        self._pending = False
        self._stopped = False
        self.status = label(translate('ManualResponse', 'Select one connection. No automatic response.'), translate('ManualResponse', 'Manual response status'), self)
        self.context = label("", translate('ManualResponse', 'Selected firewall target and source'), self)
        self.profile = QComboBox(self)
        self.profile.setAccessibleName(translate('ManualResponse', 'Explicit Windows Firewall profile'))
        self.profile.addItem(translate('ManualResponse', 'Select one profile…'), None)
        for profile in ResponseProfile:
            self.profile.addItem(display_enum(profile, 'title'), profile)
        self.lifetime = label(translate('ManualResponse', 'Lifetime: until manually removed. Persists after exit/crash/restart; no timed expiry.'),
                              translate('ManualResponse', 'Firewall rule lifetime'), self)
        self.review = QPushButton(translate('ManualResponse', 'Review &firewall rule…'), self)
        self.review.setAccessibleName(translate('ManualResponse', 'Review firewall rule for selected connection'))
        self.refresh = QPushButton(translate('ManualResponse', 'Read local response &history'), self)
        self.refresh.setAccessibleName(translate('ManualResponse', 'Read local firewall response ownership and audit history'))
        self.next = QPushButton(translate('ManualResponse', 'Next ownership page'), self)
        self.next.setAccessibleName(translate('ManualResponse', 'Next response ownership page'))
        self.next_audit = QPushButton(translate('ManualResponse', 'Next audit page'), self)
        self.next_audit.setAccessibleName(translate('ManualResponse', 'Next response audit page'))
        self.records = QListWidget(self)
        self.records.setAccessibleName(translate('ManualResponse', 'Retained response operations'))
        self.record_text = QTextEdit(self)
        self.record_text.setReadOnly(True)
        self.record_text.setAccessibleName(translate('ManualResponse', 'Response target verified result and current lifecycle'))
        self.record_text.setMinimumHeight(200)
        self.audit = QTextEdit(self)
        self.audit.setReadOnly(True)
        self.audit.setAccessibleName(translate('ManualResponse', 'Bounded local response audit events'))
        self.audit.setMinimumHeight(120)
        self.undo = QPushButton(translate('ManualResponse', 'Review &Undo firewall rule…'), self)
        self.undo.setAccessibleName(translate('ManualResponse', 'Review Undo of exact finalized owned firewall rule'))
        self.warning = label(WARNINGS, translate('ManualResponse', 'Firewall scope attribution and collateral limitations'), self)
        layout = QVBoxLayout(self)
        for widget in (self.status, self.context, self.profile, self.lifetime, self.review, self.warning):
            layout.addWidget(widget)
        controls = QHBoxLayout()
        for widget in (self.refresh, self.next, self.next_audit):
            controls.addWidget(widget)
        layout.addLayout(controls)
        for history_widget in (self.records, self.record_text, self.undo, self.audit):
            layout.addWidget(history_widget)
        self.profile.currentIndexChanged.connect(self._invalidate_profile)
        self.review.clicked.connect(self._review)
        self.undo.clicked.connect(self._undo)
        self.refresh.clicked.connect(lambda: self._read())
        self.next.clicked.connect(lambda: self._read(self._history.next_operation))
        self.next_audit.clicked.connect(lambda: self._read(sequence=self._history.next_sequence or 0))
        self.records.currentRowChanged.connect(self._record_selected)
        if coordinator:
            coordinator.completed.connect(self._completed)
            coordinator.stopped.connect(self.stop)
        order = (self.profile, self.review, self.refresh, self.next, self.next_audit,
                 self.records, self.record_text, self.undo, self.audit)
        for first, second in zip(order, order[1:]):
            QWidget.setTabOrder(first, second)
        self._controls()

    def select(self, selection: ResponseSelection | None) -> None:
        if selection == self._selection:
            return
        self._selection = selection
        self._invalidate()
        if selection:
            source = selection.source
            self.context.setText(format_text(translate('ManualResponse', 'Executable: {value1}\nRemote IP: {value2}; protocol: {value3}; remote port: {value4}\nSource: connection; observed UTC: {value5}'), value1=selection.program_path or translate('ManualResponse', 'unavailable'), value2=selection.remote_ip or translate('ManualResponse', 'unavailable'), value3=selection.protocol.upper(), value4=selection.remote_port, value5=source.observed_at.isoformat() if source else translate('ManualResponse', 'unavailable')))
        else:
            self.context.clear()
        self._controls()

    def _invalidate(self) -> None:
        self._epoch = self.coordinator.invalidate() if self.coordinator else self._epoch + 1
        self._preview = None
        if self.dialog:
            self.dialog.reject()
        self.status.setText(render_text(translate('ManualResponse', 'Selection/preview changed. New review required.') if not self._pending else translate('ManualResponse', 'Previously confirmed operation pending for its original target; read history after completion. Closing does not cancel dispatch.')))

    def _invalidate_profile(self) -> None:
        self._invalidate()
        self._controls()

    def invalidate_evidence(self) -> None:
        """Optional surrounding evidence changed; a fresh review is required."""
        self._invalidate()
        self._controls()

    def _controls(self) -> None:
        idle = not self._pending and not self._stopped and self.coordinator is not None
        reason = self._selection.unavailable() if self._selection else translate('ManualResponse', 'Unavailable: select one exact connection.')
        self.review.setEnabled(idle and reason is None and self.profile.currentData() is not None)
        self.profile.setEnabled(not self._pending and not self._stopped)
        self.refresh.setEnabled(idle)
        self.next.setEnabled(idle and self._history.next_operation is not None)
        self.next_audit.setEnabled(idle and self._history.next_sequence is not None)
        row = self.records.currentRow()
        owned = 0 <= row < len(self._history.rows) and self._history.rows[row].undo_available
        self.undo.setEnabled(idle and owned)
        if not self._pending and self._preview is None:
            if reason:
                self.status.setText(render_text(reason))
            elif self.coordinator is None:
                self.status.setText(translate('ManualResponse', 'BOUNDARY_UNAVAILABLE: response service unavailable. Local monitoring/trust remain available.'))
            elif self.profile.currentData() is None:
                self.status.setText(translate('ManualResponse', 'Select one Windows Firewall profile explicitly; no response has been requested.'))

    def _submit(self, job: int | None) -> None:
        if job is None:
            self.status.setText(translate('ManualResponse', 'Response worker busy/unavailable. Wait, then review again; no duplicate operation submitted.'))
            return
        self._job, self._pending = job, True
        self.status.setText(translate('ManualResponse', 'Pending response work for the exact requested target. No automatic elevation.'))
        self._controls()

    def _review(self) -> None:
        if self.coordinator and self.review.isEnabled():
            self._submit(self.coordinator.preview(self._selection, self.profile.currentData()))

    def _undo(self) -> None:
        if self.coordinator and self.undo.isEnabled():
            self._submit(self.coordinator.preview(None, None, self._history.rows[self.records.currentRow()].operation_id))

    def _read(self, after: UUID | None = None, sequence: int = 0) -> None:
        if self.coordinator and not self._pending:
            self._submit(self.coordinator.history(after, sequence))

    def _record_selected(self) -> None:
        self._invalidate()
        row = self.records.currentRow()
        self.record_text.setPlainText(render_text(self._history.rows[row].text if 0 <= row < len(self._history.rows) else ''))
        self._controls()

    def _completed(self, serial: int, generation: int, kind: str, reply: object) -> None:
        if serial != self._job or self._stopped:
            return
        self._job, self._pending = None, False
        if generation != self._epoch:
            self._controls()
            self.status.setText(translate('ManualResponse', 'Earlier operation completed for a different selection. Read local history for its retained outcome.'))
            return
        if isinstance(reply, ResponseHistory):
            self._history = reply
            self.records.blockSignals(True)
            self.records.clear()
            for row in reply.rows:
                self.records.addItem(format_text(translate('ManualResponse', '{value1} — rule {value2}'), value1=row.operation_id, value2=row.rule_id))
            self.records.blockSignals(False)
            self.record_text.clear()
            self.audit.setPlainText(render_text(render_join('\n', reply.audit) or translate('ManualResponse', 'No retained audit events. Selection/Cancel are not attempts.')))
            self.status.setText(translate('ManualResponse', 'Local historical custody read. Current OS state may have changed; Undo fresh-checks equality. Audit is finite, not tamper-proof.'))
        elif isinstance(reply, ResponseUiReply):
            self._preview = reply.preview
            self.status.setText(render_text(reply.message))
            if reply.preview:
                self.dialog = ResponseConfirmationDialog(reply.preview, self)
                self.dialog.finished.connect(self._confirmation_finished)
                self.dialog.open()
        self._controls()

    def _confirmation_finished(self, result: int) -> None:
        preview, self._preview = self._preview, None
        dialog, self.dialog = self.dialog, None
        if dialog:
            dialog.deleteLater()
        if result == QDialog.DialogCode.Accepted and preview and self.coordinator and not self._pending:
            self._submit(self.coordinator.confirm(preview, self._clock()))
        else:
            if self.coordinator:
                self._epoch = self.coordinator.invalidate()
            self.status.setText(translate('ManualResponse', 'Cancelled before dispatch: no firewall write, owned rule, intent or ATTEMPT audit.'))
            self._controls()
        self.review.setFocus() if self.review.isEnabled() else self.refresh.setFocus()

    def stop(self) -> None:
        self._stopped = True
        self._invalidate()
        self._controls()
