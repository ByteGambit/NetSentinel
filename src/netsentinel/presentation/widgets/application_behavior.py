"""Narrow NS-093 close preference dialog; only Save applies a preference."""

from collections.abc import Callable
from PyQt6.QtGui import QStandardItemModel

from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget,
)

from netsentinel.shared.config import WindowCloseBehavior


class ApplicationBehaviorDialog(QDialog):
    def __init__(
        self, behavior: WindowCloseBehavior, tray_available: bool,
        save: Callable[[WindowCloseBehavior], None], parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._save_preference = save
        self.setWindowTitle("Application behavior")
        self.setAccessibleName("Application behavior settings")
        layout = QVBoxLayout(self)
        label = QLabel("When I close the window:", self)
        self.close_behavior = QComboBox(self)
        self.close_behavior.setAccessibleName("When I close the window")
        self.close_behavior.addItem("Quit NetSentinel", WindowCloseBehavior.QUIT_APPLICATION)
        self.close_behavior.addItem("Hide to system tray", WindowCloseBehavior.HIDE_TO_TRAY)
        label.setBuddy(self.close_behavior)
        self.close_behavior.setCurrentIndex(self.close_behavior.findData(behavior))
        if not tray_available:
            # Preserve the stored choice even while it is disabled this session.
            model = self.close_behavior.model()
            assert isinstance(model, QStandardItemModel)
            item = model.item(1)
            assert item is not None
            item.setEnabled(False)
        self.explanation = QLabel(
            "Hiding keeps monitoring running. Quit stops monitoring and exits."
            if tray_available else
            "System tray unavailable; closing the window will quit NetSentinel. "
            "Your saved preference is preserved.", self,
        )
        self.explanation.setWordWrap(True)
        self.error = QLabel("", self)
        self.error.setAccessibleName("Application behavior save status")
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self,
        )
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        for widget in (label, self.close_behavior, self.explanation, self.error, self.buttons):
            layout.addWidget(widget)

    def _save(self) -> None:
        try:
            self._save_preference(self.close_behavior.currentData())
        except (OSError, ValueError, TypeError):
            self.error.setText("Application behavior could not be saved. Preference unchanged.")
            return
        self.accept()
