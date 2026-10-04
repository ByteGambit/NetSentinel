"""Observed behavior and explicitly confirmed exact-scope reset."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QGroupBox, QLabel, QMessageBox, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget

from netsentinel.application.services.baseline_detail import BaselineDetail, BaselineDetailRequest
from netsentinel.application.services.behavior_baseline import BaselineResetResult, BaselineResetSubmission
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator
from netsentinel.presentation.widgets.mark_normal import MarkNormalWidget


class BaselineDetailWidget(QGroupBox):
    def __init__(self, coordinator: BaselineQueryCoordinator | None = None, parent: QWidget | None = None,
                 *, preference_commands: PreferenceCommandCoordinator | None = None) -> None:
        super().__init__("Behavior baseline — observed behavior", parent)
        self.setAccessibleName("Behavior baseline")
        self.setAccessibleDescription("Observed learning and scoped reset, separate from user trust preferences")
        self._coordinator = coordinator
        self._request: BaselineDetailRequest | None = None
        self._selection_id: object = None
        self._generation: int | None = None
        self._detail: BaselineDetail | None = None
        self._pending: tuple[BaselineDetailRequest, BaselineResetSubmission] | None = None
        layout = QVBoxLayout(self)
        self.text = QLabel("No connection selected.", self)
        self.text.setObjectName("behaviorBaselineText")
        self.text.setAccessibleName("Observed behavior baseline detail")
        self.text.setAccessibleDescription("Scope, lifecycle, progress, coverage, retained features and limitations")
        self.text.setTextFormat(Qt.TextFormat.PlainText)
        self.text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.text.setWordWrap(True)
        self.text.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        scroll = QScrollArea(self)
        scroll.setAccessibleName("Scrollable observed baseline explanation")
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.text)
        scroll.setMinimumHeight(100)
        layout.addWidget(scroll, 1)
        self.status = QLabel(self)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setAccessibleName("Baseline reset status")
        self.refresh_button = QPushButton("Refresh baseline", self)
        self.refresh_button.setAccessibleName("Refresh observed baseline")
        self.refresh_button.setAccessibleDescription("Read a fresh local snapshot for the selected scope")
        self.reset_button = QPushButton("Reset learned baseline…", self)
        self.reset_button.setObjectName("resetBehaviorBaseline")
        self.reset_button.setAccessibleName("Reset learned baseline")
        self.reset_button.setAccessibleDescription("Confirm removal of observed baseline data for this application, revision and network only")
        for widget in (self.status, self.refresh_button, self.reset_button):
            layout.addWidget(widget)
        self.preferences = MarkNormalWidget(preference_commands, self)
        preferences_scroll = QScrollArea(self)
        preferences_scroll.setWidgetResizable(True)
        preferences_scroll.setWidget(self.preferences)
        preferences_scroll.setMinimumHeight(160)
        layout.addWidget(preferences_scroll, 1)
        QWidget.setTabOrder(self.text, self.refresh_button)
        QWidget.setTabOrder(self.refresh_button, self.reset_button)
        self.refresh_button.clicked.connect(self.refresh)
        self.reset_button.clicked.connect(self._confirm_reset)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._refresh_visible)
        self._completion_timer = QTimer(self)
        self._completion_timer.setInterval(100)
        self._completion_timer.timeout.connect(self._poll_reset)
        if coordinator is not None:
            coordinator.result_ready.connect(self._ready)
            coordinator.query_failed.connect(self._failed)
            coordinator.stopped.connect(self._shutdown)
        self.clear()

    def _shutdown(self) -> None:
        self.clear()
        self._pending = None
        self._completion_timer.stop()

    def clear(self) -> None:
        self.preferences.clear()
        if self._coordinator is not None and self._request is not None:
            self._coordinator.invalidate()
        self._request = None
        self._selection_id = None
        self._generation = None
        self._detail = None
        self._refresh_timer.stop()
        self.text.setText("No connection selected.")
        self.status.clear()
        self.reset_button.setEnabled(False)
        self.refresh_button.setEnabled(False)

    def select(self, request: BaselineDetailRequest, selection_id: object = None) -> None:
        self.preferences.select(request)
        if request == self._request and selection_id == self._selection_id:
            return  # Model refreshes do not submit a query for every polling round.
        self._request = request
        self._selection_id = selection_id
        self._detail = None
        self._generation = None
        self.status.clear()
        self.reset_button.setEnabled(False)
        self.refresh_button.setEnabled(self._coordinator is not None)
        self.text.setText("Loading observed behavior baseline…")
        self.refresh()
        self._refresh_timer.start()

    def _refresh_visible(self) -> None:
        if self.isVisible():
            self.refresh()

    def refresh(self) -> None:
        if self._request is None or self._coordinator is None:
            self.text.setText("Baseline unavailable.")
            return
        if self._generation is not None:
            return
        try:
            self._generation = self._coordinator.request(self._request)
        except RuntimeError:
            self._failed(self._generation)

    def _ready(self, generation: int, detail: object) -> None:
        if generation != self._generation or not isinstance(detail, BaselineDetail) or detail.request != self._request:
            return
        self._generation = None
        self._detail = detail
        lines = detail.text.splitlines()
        self.text.setText("\n".join(lines[:2]) + "\n\n" + detail.context + "\n\n" + "\n".join(lines[2:]))
        self.reset_button.setEnabled(detail.reset_available and self._pending is None)

    def _failed(self, generation: int | None) -> None:
        if generation != self._generation:
            return
        self._generation = None
        self._detail = None
        self.text.setText("UNAVAILABLE: baseline detail could not be loaded. No behavior verdict is available.")
        self.reset_button.setEnabled(False)

    def _confirm_reset(self) -> None:
        detail = self._detail
        if detail is None or not detail.reset_available or detail.scope is None or self._coordinator is None:
            return
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Reset learned baseline")
        dialog.setAccessibleName("Confirm scoped baseline reset")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText("Remove the learned baseline for this exact scope?\n\n" + detail.context +
                       "\n\nThis removes learned behavioral baseline data only. It does not block the application, "
                       "change trust/preferences, or delete connection history. Current runtime observations remain separate.")
        dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.setEscapeButton(QMessageBox.StandardButton.Cancel)
        if dialog.exec() != QMessageBox.StandardButton.Yes:
            return
        # A modal dialog can process selection/refresh events; use its captured scope.
        try:
            submission = self._coordinator.reset(detail.scope)
        except Exception:
            if detail.request == self._request:
                self.status.setText("Reset unavailable; no durable completion was confirmed.")
            return
        self._pending = (detail.request, submission)
        if detail.request == self._request:
            self.status.setText("Reset accepted; waiting for durable storage completion." if submission.accepted
                                else "Reset unavailable; no reset was accepted.")
            self.reset_button.setEnabled(False)
        self._completion_timer.start()
        self._poll_reset()

    def _poll_reset(self) -> None:
        if self._pending is None or not self._pending[1].completion.done():
            return
        request, submission = self._pending
        self._pending = None
        self._completion_timer.stop()
        if request != self._request:
            if self._detail is not None:
                self.reset_button.setEnabled(self._detail.reset_available)
            return
        result = submission.completion.result()
        if result is BaselineResetResult.COMPLETED:
            self.status.setText("Learned baseline reset completed in local storage (also valid if already absent).")
        else:
            self.status.setText("Reset failed or unavailable; durable completion was not confirmed. Storage may retry an accepted reset.")
        if self._coordinator is not None:
            self._coordinator.invalidate()
        self._generation = None
        self._detail = None
        self.reset_button.setEnabled(False)
        self.text.setText("Refreshing observed baseline after reset…")
        self.refresh()
