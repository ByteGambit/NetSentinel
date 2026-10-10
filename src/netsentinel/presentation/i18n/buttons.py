"""Application-owned standard button labels; native OS dialogs stay OS-owned."""

from typing import TypeVar
from PyQt6.QtWidgets import QDialogButtonBox, QMessageBox
from netsentinel.presentation.i18n.text import translate

Box = TypeVar('Box', QDialogButtonBox, QMessageBox)


def localize_buttons(box: Box) -> Box:
    labels = {
        'Ok': translate('StandardButtons', 'OK'),
        'Save': translate('StandardButtons', 'Save'),
        'Cancel': translate('StandardButtons', 'Cancel'),
        'Close': translate('StandardButtons', 'Close'),
        'Yes': translate('StandardButtons', '&Yes'),
        'No': translate('StandardButtons', '&No'),
    }
    for name, label in labels.items():
        enum = QDialogButtonBox.StandardButton if isinstance(box, QDialogButtonBox) else QMessageBox.StandardButton
        button = box.button(getattr(enum, name))
        if button is not None:
            button.setText(label)
            button.setAccessibleName(label.replace('&', ''))
    return box
