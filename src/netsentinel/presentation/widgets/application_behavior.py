"""Narrow NS-093 close preference dialog; only Save applies a preference."""

from netsentinel.presentation.i18n.buttons import localize_buttons

from netsentinel.presentation.i18n.text import translate

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
        self.setWindowTitle(translate('ApplicationBehavior', 'Application behavior'))
        self.setAccessibleName(translate('ApplicationBehavior', 'Application behavior settings'))
        layout = QVBoxLayout(self)
        label = QLabel(translate('ApplicationBehavior', 'When I close the window:'), self)
        self.close_behavior = QComboBox(self)
        self.close_behavior.setAccessibleName(translate('ApplicationBehavior', 'When I close the window'))
        self.close_behavior.addItem(translate('ApplicationBehavior', 'Quit NetSentinel'), WindowCloseBehavior.QUIT_APPLICATION)
        self.close_behavior.addItem(translate('ApplicationBehavior', 'Hide to system tray'), WindowCloseBehavior.HIDE_TO_TRAY)
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
            translate('ApplicationBehavior', 'Hiding keeps monitoring running. Quit stops monitoring and exits.')
            if tray_available else
            translate('ApplicationBehavior', 'System tray unavailable; closing the window will quit NetSentinel. Your saved preference is preserved.'), self,
        )
        self.explanation.setWordWrap(True)
        self.error = QLabel("", self)
        self.error.setAccessibleName(translate('ApplicationBehavior', 'Application behavior save status'))
        self.buttons = localize_buttons(QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self,
        ))
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        for widget in (label, self.close_behavior, self.explanation, self.error, self.buttons):
            layout.addWidget(widget)

    def _save(self) -> None:
        try:
            self._save_preference(self.close_behavior.currentData())
        except (OSError, ValueError, TypeError):
            self.error.setText(translate('ApplicationBehavior', 'Application behavior could not be saved. Preference unchanged.'))
            return
        self.accept()
