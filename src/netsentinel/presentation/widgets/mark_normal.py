"""Selected behavior feedback, separate from observed baseline and device trust."""

from netsentinel.presentation.i18n.buttons import localize_buttons

from netsentinel.presentation.i18n.text import display_enum, format_text, render_text

from netsentinel.presentation.i18n.text import TranslationMapping, translate

from concurrent.futures import Future
from datetime import UTC, datetime, timedelta

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from netsentinel.application.services.baseline_detail import BaselineDetailRequest
from netsentinel.application.services.mark_normal import (
    BEHAVIOR_RULES, BehaviorPreferenceContext, MarkNormalPreview, behavior_context,
    preview_mark_normal, scope_choices, selector_text,
)
from netsentinel.domain.preferences import (
    PreferenceLifetime, PreferenceLifetimeKind, PreferencePage, PreferenceResult,
    PreferenceResultStatus, PreferenceStatus, ScopedPreference,
)
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator


def plain_label(parent: QWidget, name: str) -> QLabel:
    label = QLabel(parent)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setAccessibleName(render_text(name))
    return label


class MarkNormalDialog(QDialog):
    def __init__(self, context: BehaviorPreferenceContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate('MarkNormal', 'Mark this behavior as normal'))
        self.setAccessibleName(translate('MarkNormal', 'Selected behavior preference options'))
        self.context = context
        self.preview: MarkNormalPreview | None = None
        self.scope = QComboBox(self)
        self.scope.setAccessibleName(translate('MarkNormal', 'Selected behavior scope'))
        self.scope.setAccessibleDescription(translate('MarkNormal', 'Narrow default; explicitly select a broader scope if desired'))
        for i, selector in enumerate(scope_choices(context)):
            label = (translate('MarkNormal', 'Exact available scope') if i == 0 else translate('MarkNormal', 'Broader scope'))
            label += "; " + (translate('MarkNormal', 'exact revision') if selector.application_revision else translate('MarkNormal', 'any revision'))
            label += "; " + (translate('MarkNormal', 'this network') if selector.network_fingerprint else translate('MarkNormal', 'any network'))
            label += "; " + (translate('MarkNormal', 'this destination') if selector.destination else translate('MarkNormal', 'any destination'))
            self.scope.addItem(label, selector)
        self.lifetime = QComboBox(self)
        self.lifetime.setAccessibleName(translate('MarkNormal', 'Preference lifetime'))
        self.lifetime.addItem(translate('MarkNormal', 'Choose lifetime…'), None)
        self.lifetime.addItem(translate('MarkNormal', '24 hours from preview'), "timed")
        self.lifetime.addItem(translate('MarkNormal', 'Permanent (explicit choice)'), "permanent")
        self.reason = QLineEdit(self)
        self.reason.setMaxLength(512)
        self.reason.setAccessibleName(translate('MarkNormal', 'Preference reason (required, up to 512 characters)'))
        self.reason.setPlaceholderText(translate('MarkNormal', 'Why is this selected behavior expected?'))
        self.summary = plain_label(self, translate('MarkNormal', 'Selected scope and current network'))
        self.error = plain_label(self, translate('MarkNormal', 'Preference validation'))
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Scope:", self.scope)
        form.addRow("Lifetime:", self.lifetime)
        form.addRow("Reason:", self.reason)
        layout.addLayout(form)
        layout.addWidget(self.summary)
        layout.addWidget(self.error)
        self.buttons = localize_buttons(QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self))
        preview_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        assert preview_button is not None
        self.preview_button: QPushButton = preview_button
        self.preview_button.setText(translate('MarkNormal', 'Preview…'))
        self.preview_button.setAccessibleName(translate('MarkNormal', 'Preview selected behavior preference'))
        cancel = self.buttons.button(QDialogButtonBox.StandardButton.Cancel)
        assert cancel is not None
        cancel.setAccessibleName(translate('MarkNormal', 'Cancel preference without saving'))
        layout.addWidget(self.buttons)
        self.buttons.accepted.connect(self._preview)
        self.buttons.rejected.connect(self.reject)
        self.scope.currentIndexChanged.connect(self._changed)
        self.lifetime.currentIndexChanged.connect(self._changed)
        self.reason.textChanged.connect(self._changed)
        self._changed()

    def _changed(self) -> None:
        selector = self.scope.currentData()
        self.summary.setText(render_text(selector_text(selector) + format_text(translate('MarkNormal', '\nCurrent network scope: {value1}'), value1=self.context.network_text) + translate('MarkNormal', '\nDisplay name/PID are not persistent identity. Pattern selection does not assert observed evidence.')))
        self.preview_button.setEnabled(self.lifetime.currentData() is not None and bool(self.reason.text().strip()))
        self.error.setText(format_text(translate('MarkNormal', 'Reason: {value1}/512 characters (single line).'), value1=len(self.reason.text())))

    def _preview(self) -> None:
        now = datetime.now(UTC)
        choice = self.lifetime.currentData()
        if choice is None:
            return
        lifetime = (PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, now + timedelta(hours=24))
                    if choice == "timed" else PreferenceLifetime(PreferenceLifetimeKind.PERMANENT))
        try:
            preview = preview_mark_normal(self.context, self.scope.currentData(), lifetime,
                                          self.reason.text(), now=now)
        except (ValueError, TypeError):
            self.error.setText(translate('MarkNormal', 'Invalid scope or reason. Use nonempty single-line text up to 512 characters.'))
            return
        dialog = localize_buttons(QMessageBox(self))
        dialog.setWindowTitle(translate('MarkNormal', 'Preview selected behavior preference'))
        dialog.setAccessibleName(translate('MarkNormal', 'Confirm scoped preference save'))
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(render_text(preview.text))
        dialog.setStandardButtons(QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel)
        localize_buttons(dialog)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.setEscapeButton(QMessageBox.StandardButton.Cancel)
        save, cancel = dialog.button(QMessageBox.StandardButton.Save), dialog.button(QMessageBox.StandardButton.Cancel)
        assert save is not None and cancel is not None
        save.setAccessibleName(translate('MarkNormal', 'Save previewed preference'))
        cancel.setAccessibleName(translate('MarkNormal', 'Cancel preview without saving'))
        if dialog.exec() == QMessageBox.StandardButton.Save:
            self.preview = preview
            self.accept()


RESULT_TEXT = TranslationMapping(lambda: {
    PreferenceResultStatus.CREATED: translate('MarkNormal', 'Preference saved for future matching signals.'),
    PreferenceResultStatus.NO_CHANGE: translate('MarkNormal', 'An equivalent preference already exists; no change.'),
    PreferenceResultStatus.REVOKED: translate('MarkNormal', 'Preference revoked; past alerts and suppressed signals remain unchanged.'),
    PreferenceResultStatus.ALREADY_REVOKED: translate('MarkNormal', 'Preference already revoked; no change.'),
    PreferenceResultStatus.CONFLICT: translate('MarkNormal', 'Preference changed since preview; refreshed current state. Nothing was overwritten.'),
    PreferenceResultStatus.CAPACITY_REACHED: translate('MarkNormal', 'Preference storage capacity reached; no change was saved.'),
    PreferenceResultStatus.INVALID: translate('MarkNormal', 'Invalid or expired preview; open a new preview.'),
})


class MarkNormalWidget(QGroupBox):
    def __init__(self, coordinator: PreferenceCommandCoordinator | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(translate('MarkNormal', 'User preference — future matching behavior'), parent)
        self._coordinator = coordinator
        self._request: BaselineDetailRequest | None = None
        self._context: BehaviorPreferenceContext | None = None
        self._generation: int | None = None
        self._epoch = 0
        self._pending: tuple[int, Future[PreferenceResult]] | None = None
        self.setAccessibleName(translate('MarkNormal', 'Selected behavior user preferences'))
        layout = QVBoxLayout(self)
        self.rule = QComboBox(self)
        self.rule.setAccessibleName(translate('MarkNormal', 'Selected behavior rule'))
        self.rule.addItem(translate('MarkNormal', 'Select a behavior pattern…'), None)
        for rule_id, label in BEHAVIOR_RULES:
            self.rule.addItem(f"{label} ({rule_id})", rule_id)
        self.action = QPushButton(translate('MarkNormal', 'Mark this behavior as normal…'), self)
        self.action.setAccessibleName(translate('MarkNormal', 'Mark this behavior as normal'))
        self.action.setAccessibleDescription(translate('MarkNormal', 'Preview a scoped preference for future matching signals; not application trust or baseline reset'))
        self.refresh_button = QPushButton(translate('MarkNormal', 'Refresh preferences'), self)
        self.refresh_button.setAccessibleName(translate('MarkNormal', 'Refresh selected behavior preferences'))
        self.list = QListWidget(self)
        self.list.setAccessibleName(translate('MarkNormal', 'Relevant preferences (up to 32)'))
        self.list.setMaximumHeight(95)
        self.detail = plain_label(self, translate('MarkNormal', 'Preference scope, lifetime, reason and revision'))
        self.status = plain_label(self, translate('MarkNormal', 'Preference command status'))
        self.revoke = QPushButton(translate('MarkNormal', 'Revoke selected preference…'), self)
        self.revoke.setAccessibleName(translate('MarkNormal', 'Revoke selected behavior preference'))
        self.revoke.setAccessibleDescription(translate('MarkNormal', 'Confirm stopping future suppression; no historical replay'))
        for widget in (self.rule, self.action, self.refresh_button, self.list, self.detail, self.status, self.revoke):
            layout.addWidget(widget)
        self.rule.currentIndexChanged.connect(self._changed)
        self.action.clicked.connect(self._create)
        self.refresh_button.clicked.connect(self.refresh)
        self.list.currentRowChanged.connect(self._selected_preference)
        self.revoke.clicked.connect(self._revoke)
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        if coordinator:
            coordinator.result_ready.connect(self._ready)
            coordinator.stopped.connect(self._shutdown)
        self.clear()

    def _shutdown(self) -> None:
        self._timer.stop()
        self._pending = None
        self.clear()

    def clear(self) -> None:
        self._request = None
        self._changed()

    def select(self, request: BaselineDetailRequest) -> None:
        if request != self._request:
            self._request = request
            self._changed()

    def _changed(self) -> None:
        self._epoch += 1
        self._generation = None
        self._context = None
        self.list.clear()
        self.detail.clear()
        self.revoke.setEnabled(False)
        if self._coordinator:
            self._coordinator.invalidate()
        message = translate('MarkNormal', 'Select a connection and behavior pattern. No application trust is created.')
        if self._request and self.rule.currentData():
            try:
                self._context = behavior_context(self._request, self.rule.currentData())
            except (ValueError, TypeError):
                message = translate('MarkNormal', 'Unavailable: stable application identity required; PID/name/provisional identity cannot persist.')
        available = self._context is not None and self._coordinator is not None
        self.action.setEnabled(available and self._pending is None)
        self.refresh_button.setEnabled(available)
        self.status.setText(render_text(message if not available else translate('MarkNormal', 'Selected rule/application preference affects future matching signals only.')))
        self.refresh()

    def refresh(self) -> None:
        if self._context is None or self._coordinator is None:
            return
        try:
            self._generation = self._coordinator.request(self._context)
        except RuntimeError:
            self.action.setEnabled(False)
            self.status.setText(translate('MarkNormal', 'Preference storage unavailable.'))

    def _ready(self, generation: int, page: object) -> None:
        if generation != self._generation:
            return
        self._generation = None
        self.list.clear()
        if not isinstance(page, PreferencePage) or page.status is not PreferenceResultStatus.FOUND:
            self.status.setText(translate('MarkNormal', 'Preference query unavailable; no policy state could be confirmed.'))
            return
        for entry in page.entries:
            pref = entry.preference
            if pref is None:
                continue
            state = display_enum(pref.status_at(datetime.now(UTC)), 'upper')
            life = pref.definition.lifetime.expires_at
            item = QListWidgetItem(format_text(translate('MarkNormal', '{value1} — revision {value2} — '), value1=state, value2=pref.revision) + (format_text(translate('MarkNormal', 'expires {value1}'), value1=life.isoformat()) if life else translate('MarkNormal', 'permanent')))
            item.setData(Qt.ItemDataRole.UserRole, pref)
            self.list.addItem(item)
        if page.truncated:
            self.status.setText(translate('MarkNormal', 'Showing first 32 relevant preferences; additional entries exist.'))
        if any(entry.preference is None for entry in page.entries):
            self.status.setText(translate('MarkNormal', 'Some relevant preferences are corrupt or unsupported; their state is unavailable.'))
        if self.list.count():
            self.list.setCurrentRow(0)
        else:
            self.detail.setText(translate('MarkNormal', 'No relevant preferences stored.'))

    def _selected_preference(self) -> None:
        item = self.list.currentItem()
        pref = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.revoke.setEnabled(isinstance(pref, ScopedPreference) and pref.status is not PreferenceStatus.REVOKED
                               and self._pending is None)
        self.detail.setText(render_text(selector_text(pref.definition.selector) + format_text(translate('MarkNormal', '\nReason: {value1}'), value1=pref.definition.reason) if isinstance(pref, ScopedPreference) else ''))

    def _submit(self, command: MarkNormalPreview | ScopedPreference, epoch: int) -> None:
        if self._coordinator is None or self._pending is not None:
            return
        self._pending = (epoch, self._coordinator.submit(command))
        self.action.setEnabled(False)
        self.revoke.setEnabled(False)
        self._timer.start()

    def _create(self) -> None:
        if self._context is None or self._pending is not None:
            return
        epoch = self._epoch
        dialog = MarkNormalDialog(self._context, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.preview is not None:
            self._submit(dialog.preview, epoch)

    def _revoke(self) -> None:
        item = self.list.currentItem()
        pref = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(pref, ScopedPreference) or pref.status is PreferenceStatus.REVOKED or self._pending:
            return
        epoch = self._epoch
        dialog = localize_buttons(QMessageBox(self))
        dialog.setWindowTitle(translate('MarkNormal', 'Revoke selected preference'))
        dialog.setAccessibleName(translate('MarkNormal', 'Confirm preference revocation'))
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(render_text(selector_text(pref.definition.selector) + format_text(translate('MarkNormal', '\nRevision: {value1}\n'), value1=pref.revision) + (format_text(translate('MarkNormal', 'Expires: {value1} (UTC)\n'), value1=pref.definition.lifetime.expires_at.isoformat()) if pref.definition.lifetime.expires_at else translate('MarkNormal', 'Lifetime: Permanent\n')) + format_text(translate('MarkNormal', 'Reason: {value1}\n'), value1=pref.definition.reason) + translate('MarkNormal', 'This stops this preference from suppressing future matching signals. It does not recreate past alerts or reopen existing alerts.')))
        dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        localize_buttons(dialog)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.setEscapeButton(QMessageBox.StandardButton.Cancel)
        if dialog.exec() == QMessageBox.StandardButton.Yes:
            self._submit(pref, epoch)

    def _poll(self) -> None:
        if self._pending is None or not self._pending[1].done():
            return
        epoch, future = self._pending
        self._pending = None
        self._timer.stop()
        if epoch == self._epoch:
            result = future.result()
            self.status.setText(render_text(RESULT_TEXT.get(result.status, translate('MarkNormal', 'Preference operation unavailable; no durable change confirmed.'))))
        self.action.setEnabled(self._context is not None and self._coordinator is not None)
        self._selected_preference()
        self.refresh()
