"""Explicit opt-in and limited-preview explanation; Cancel performs no write."""

from collections.abc import Callable
from PyQt6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget
from netsentinel.application.services.notifications import NotificationPlatformState, NotificationDeliveryOutcome


def notification_state_text(enabled: bool, state: NotificationPlatformState) -> str:
    if not enabled:
        return "Disabled in NetSentinel (optional feature; not an application failure)."
    return {
        NotificationPlatformState.DISABLED_BY_APP: "Enabled in NetSentinel; Windows delivery state not checked yet.",
        NotificationPlatformState.DISABLED_BY_OS: "Enabled in NetSentinel; Windows balloon notification policy is configured off. No submission.",
        NotificationPlatformState.SESSION_RESTRICTED: "Enabled in NetSentinel; Windows session currently restricts notifications. No submission.",
        NotificationPlatformState.UNAVAILABLE: "Enabled in NetSentinel; notification platform unavailable. Local alerts remain available.",
        NotificationPlatformState.DELIVERY_UNKNOWN: "Enabled in NetSentinel; Windows permission/display unverified. Submission is not proof of visible delivery.",
        NotificationPlatformState.FAILED: "Enabled in NetSentinel; notification submission/status failed. Local alerts remain available.",
    }[state]


class NotificationSettingsDialog(QDialog):
    def __init__(self, enabled: bool, save: Callable[[bool], None], parent: QWidget, *,
                 policy_state: Callable[[], NotificationPlatformState] | None = None,
                 submission_outcome: Callable[[], NotificationDeliveryOutcome | None] | None = None) -> None:
        super().__init__(parent)
        self._save_preference = save
        self.setWindowTitle("Desktop notifications")
        layout = QVBoxLayout(self)
        self.enabled = QCheckBox("Enable desktop notifications", self)
        self.enabled.setChecked(enabled)
        self._policy_state = policy_state or (lambda: NotificationPlatformState.DELIVERY_UNKNOWN)
        self._submission_outcome = submission_outcome or (lambda: None)
        self.delivery_state = QLabel("", self)
        self.delivery_state.setWordWrap(True)
        self.delivery_state.setAccessibleName("Windows notification delivery state")
        self.enabled.toggled.connect(self.refresh_delivery_state)
        explanation = QLabel(
            "Notifications show only a generic severity preview. Other people may see them, "
            "including on the lock screen depending on Windows settings. "
            "Enabling applies to future alerts. Notifications may be hidden by the operating system.", self)
        explanation.setWordWrap(True)
        self.error = QLabel("", self)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                       QDialogButtonBox.StandardButton.Cancel, self)
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        for widget in (self.enabled, explanation, self.delivery_state, self.error, self.buttons):
            layout.addWidget(widget)
        self.refresh_delivery_state()

    def refresh_delivery_state(self) -> None:
        text = notification_state_text(self.enabled.isChecked(), self._policy_state())
        outcome = self._submission_outcome()
        if self.enabled.isChecked() and outcome is not None:
            text += " " + {
                NotificationDeliveryOutcome.SINK_FAILED: "Last submission attempt failed.",
                NotificationDeliveryOutcome.SINK_UNAVAILABLE: "Last submission attempt found no available notification platform.",
                NotificationDeliveryOutcome.PLATFORM_RESTRICTED: "Last request skipped because Windows restricted notifications.",
                NotificationDeliveryOutcome.SUBMITTED_TO_SINK: "Last request submitted; visible delivery unconfirmed.",
            }.get(outcome, "Last delivery result unknown.")
        self.delivery_state.setText(text)

    def _save(self) -> None:
        try:
            self._save_preference(self.enabled.isChecked())
        except (OSError, ValueError, TypeError):
            self.error.setText("Notification preference could not be saved. Preference unchanged.")
            return
        self.accept()
