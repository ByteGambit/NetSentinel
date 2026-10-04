"""Selected behavior feedback, separate from observed baseline and device trust."""

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
    label.setAccessibleName(name)
    return label


class MarkNormalDialog(QDialog):
    def __init__(self, context: BehaviorPreferenceContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Mark this behavior as normal")
        self.setAccessibleName("Selected behavior preference options")
        self.context = context
        self.preview: MarkNormalPreview | None = None
        self.scope = QComboBox(self)
        self.scope.setAccessibleName("Selected behavior scope")
        self.scope.setAccessibleDescription("Narrow default; explicitly select a broader scope if desired")
        for i, selector in enumerate(scope_choices(context)):
            label = ("Exact available scope" if i == 0 else "Broader scope")
            label += "; " + ("exact revision" if selector.application_revision else "any revision")
            label += "; " + ("this network" if selector.network_fingerprint else "any network")
            label += "; " + ("this destination" if selector.destination else "any destination")
            self.scope.addItem(label, selector)
        self.lifetime = QComboBox(self)
        self.lifetime.setAccessibleName("Preference lifetime")
        self.lifetime.addItem("Choose lifetime…", None)
        self.lifetime.addItem("24 hours from preview", "timed")
        self.lifetime.addItem("Permanent (explicit choice)", "permanent")
        self.reason = QLineEdit(self)
        self.reason.setMaxLength(512)
        self.reason.setAccessibleName("Preference reason (required, up to 512 characters)")
        self.reason.setPlaceholderText("Why is this selected behavior expected?")
        self.summary = plain_label(self, "Selected scope and current network")
        self.error = plain_label(self, "Preference validation")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Scope:", self.scope)
        form.addRow("Lifetime:", self.lifetime)
        form.addRow("Reason:", self.reason)
        layout.addLayout(form)
        layout.addWidget(self.summary)
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        preview_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        assert preview_button is not None
        self.preview_button: QPushButton = preview_button
        self.preview_button.setText("Preview…")
        self.preview_button.setAccessibleName("Preview selected behavior preference")
        cancel = self.buttons.button(QDialogButtonBox.StandardButton.Cancel)
        assert cancel is not None
        cancel.setAccessibleName("Cancel preference without saving")
        layout.addWidget(self.buttons)
        self.buttons.accepted.connect(self._preview)
        self.buttons.rejected.connect(self.reject)
        self.scope.currentIndexChanged.connect(self._changed)
        self.lifetime.currentIndexChanged.connect(self._changed)
        self.reason.textChanged.connect(self._changed)
        self._changed()

    def _changed(self) -> None:
        selector = self.scope.currentData()
        self.summary.setText(selector_text(selector) + f"\nCurrent network scope: {self.context.network_text}"
                             + "\nDisplay name/PID are not persistent identity. Pattern selection does not assert observed evidence.")
        self.preview_button.setEnabled(self.lifetime.currentData() is not None and bool(self.reason.text().strip()))
        self.error.setText(f"Reason: {len(self.reason.text())}/512 characters (single line).")

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
            self.error.setText("Invalid scope or reason. Use nonempty single-line text up to 512 characters.")
            return
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Preview selected behavior preference")
        dialog.setAccessibleName("Confirm scoped preference save")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(preview.text)
        dialog.setStandardButtons(QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.setEscapeButton(QMessageBox.StandardButton.Cancel)
        save, cancel = dialog.button(QMessageBox.StandardButton.Save), dialog.button(QMessageBox.StandardButton.Cancel)
        assert save is not None and cancel is not None
        save.setAccessibleName("Save previewed preference")
        cancel.setAccessibleName("Cancel preview without saving")
        if dialog.exec() == QMessageBox.StandardButton.Save:
            self.preview = preview
            self.accept()


RESULT_TEXT = {
    PreferenceResultStatus.CREATED: "Preference saved for future matching signals.",
    PreferenceResultStatus.NO_CHANGE: "An equivalent preference already exists; no change.",
    PreferenceResultStatus.REVOKED: "Preference revoked; past alerts and suppressed signals remain unchanged.",
    PreferenceResultStatus.ALREADY_REVOKED: "Preference already revoked; no change.",
    PreferenceResultStatus.CONFLICT: "Preference changed since preview; refreshed current state. Nothing was overwritten.",
    PreferenceResultStatus.CAPACITY_REACHED: "Preference storage capacity reached; no change was saved.",
    PreferenceResultStatus.INVALID: "Invalid or expired preview; open a new preview.",
}


class MarkNormalWidget(QGroupBox):
    def __init__(self, coordinator: PreferenceCommandCoordinator | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__("User preference — future matching behavior", parent)
        self._coordinator = coordinator
        self._request: BaselineDetailRequest | None = None
        self._context: BehaviorPreferenceContext | None = None
        self._generation: int | None = None
        self._epoch = 0
        self._pending: tuple[int, Future[PreferenceResult]] | None = None
        self.setAccessibleName("Selected behavior user preferences")
        layout = QVBoxLayout(self)
        self.rule = QComboBox(self)
        self.rule.setAccessibleName("Selected behavior rule")
        self.rule.addItem("Select a behavior pattern…", None)
        for rule_id, label in BEHAVIOR_RULES:
            self.rule.addItem(f"{label} ({rule_id})", rule_id)
        self.action = QPushButton("Mark this behavior as normal…", self)
        self.action.setAccessibleName("Mark this behavior as normal")
        self.action.setAccessibleDescription("Preview a scoped preference for future matching signals; not application trust or baseline reset")
        self.refresh_button = QPushButton("Refresh preferences", self)
        self.refresh_button.setAccessibleName("Refresh selected behavior preferences")
        self.list = QListWidget(self)
        self.list.setAccessibleName("Relevant preferences (up to 32)")
        self.list.setMaximumHeight(95)
        self.detail = plain_label(self, "Preference scope, lifetime, reason and revision")
        self.status = plain_label(self, "Preference command status")
        self.revoke = QPushButton("Revoke selected preference…", self)
        self.revoke.setAccessibleName("Revoke selected behavior preference")
        self.revoke.setAccessibleDescription("Confirm stopping future suppression; no historical replay")
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
        message = "Select a connection and behavior pattern. No application trust is created."
        if self._request and self.rule.currentData():
            try:
                self._context = behavior_context(self._request, self.rule.currentData())
            except (ValueError, TypeError):
                message = "Unavailable: stable application identity required; PID/name/provisional identity cannot persist."
        available = self._context is not None and self._coordinator is not None
        self.action.setEnabled(available and self._pending is None)
        self.refresh_button.setEnabled(available)
        self.status.setText(message if not available else "Selected rule/application preference affects future matching signals only.")
        self.refresh()

    def refresh(self) -> None:
        if self._context is None or self._coordinator is None:
            return
        try:
            self._generation = self._coordinator.request(self._context)
        except RuntimeError:
            self.action.setEnabled(False)
            self.status.setText("Preference storage unavailable.")

    def _ready(self, generation: int, page: object) -> None:
        if generation != self._generation:
            return
        self._generation = None
        self.list.clear()
        if not isinstance(page, PreferencePage) or page.status is not PreferenceResultStatus.FOUND:
            self.status.setText("Preference query unavailable; no policy state could be confirmed.")
            return
        for entry in page.entries:
            pref = entry.preference
            if pref is None:
                continue
            state = pref.status_at(datetime.now(UTC)).value
            life = pref.definition.lifetime.expires_at
            item = QListWidgetItem(f"{state.upper()} — revision {pref.revision} — " + (f"expires {life.isoformat()}" if life else "permanent"))
            item.setData(Qt.ItemDataRole.UserRole, pref)
            self.list.addItem(item)
        if page.truncated:
            self.status.setText("Showing first 32 relevant preferences; additional entries exist.")
        if any(entry.preference is None for entry in page.entries):
            self.status.setText("Some relevant preferences are corrupt or unsupported; their state is unavailable.")
        if self.list.count():
            self.list.setCurrentRow(0)
        else:
            self.detail.setText("No relevant preferences stored.")

    def _selected_preference(self) -> None:
        item = self.list.currentItem()
        pref = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.revoke.setEnabled(isinstance(pref, ScopedPreference) and pref.status is not PreferenceStatus.REVOKED
                               and self._pending is None)
        self.detail.setText(selector_text(pref.definition.selector) + f"\nReason: {pref.definition.reason}"
                            if isinstance(pref, ScopedPreference) else "")

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
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Revoke selected preference")
        dialog.setAccessibleName("Confirm preference revocation")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(selector_text(pref.definition.selector) + f"\nRevision: {pref.revision}\n"
                       + (f"Expires: {pref.definition.lifetime.expires_at.isoformat()} (UTC)\n"
                          if pref.definition.lifetime.expires_at else "Lifetime: Permanent\n")
                       + f"Reason: {pref.definition.reason}\n"
                       + "This stops this preference from suppressing future matching signals. "
                       "It does not recreate past alerts or reopen existing alerts.")
        dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
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
            self.status.setText(RESULT_TEXT.get(result.status, "Preference operation unavailable; no durable change confirmed."))
        self.action.setEnabled(self._context is not None and self._coordinator is not None)
        self._selected_preference()
        self.refresh()
