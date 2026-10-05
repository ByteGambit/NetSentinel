"""Explicit opt-in and limited-preview explanation; Cancel performs no write."""

from collections.abc import Callable
from PyQt6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget


class NotificationSettingsDialog(QDialog):
    def __init__(self, enabled: bool, save: Callable[[bool], None], parent: QWidget) -> None:
        super().__init__(parent)
        self._save_preference = save
        self.setWindowTitle("Desktop notifications")
        layout = QVBoxLayout(self)
        self.enabled = QCheckBox("Enable desktop notifications", self)
        self.enabled.setChecked(enabled)
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
        for widget in (self.enabled, explanation, self.error, self.buttons):
            layout.addWidget(widget)

    def _save(self) -> None:
        try:
            self._save_preference(self.enabled.isChecked())
        except (OSError, ValueError, TypeError):
            self.error.setText("Notification preference could not be saved. Preference unchanged.")
            return
        self.accept()
