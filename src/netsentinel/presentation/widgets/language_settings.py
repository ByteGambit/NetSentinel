"""Language-only bootstrap chooser and reusable Apply/Cancel foundation."""

from PyQt6.QtCore import QLocale, Qt
from PyQt6.QtWidgets import (
    QDialog, QLabel, QListWidget, QListWidgetItem, QPushButton, QVBoxLayout, QHBoxLayout, QWidget,
)

from netsentinel.presentation.i18n.preferences import LanguagePreferences
from netsentinel.presentation.i18n.text import format_text, translate
from netsentinel.shared.locales import PLANNED_LOCALES


class LanguageSelectionDialog(QDialog):
    def __init__(self, preferences: LanguagePreferences, parent: QWidget | None = None,
                 *, first_launch: bool = False) -> None:
        super().__init__(parent)
        self.preferences = preferences
        self.first_launch = first_launch
        self.unsaved_english = False
        self.setWindowTitle(translate('LanguageSelection', 'Choose your language'))
        self.setAccessibleName(translate('LanguageSelection', 'Application language'))
        self.setMinimumSize(360, 320)
        self.resize(560, 520)
        layout = QVBoxLayout(self)
        description = QLabel(translate('LanguageSelection',
            'Choose a language and confirm. Unavailable languages need a reviewed offline translation pack.'))
        description.setWordWrap(True)
        layout.addWidget(description)
        self.notice = QLabel()
        self.notice.setWordWrap(True)
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.setAccessibleName(translate('LanguageSelection', 'Current and pending language'))
        layout.addWidget(self.notice)
        self.languages = QListWidget()
        self.languages.setAccessibleName(translate('LanguageSelection', 'Languages'))
        self.languages.setAccessibleDescription(translate('LanguageSelection',
            'Use arrow keys to select an available language, then confirm.'))
        self.languages.setMinimumHeight(100)
        self.languages.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.languages, 1)
        options = preferences.options
        suggested = preferences.selected_locale
        if first_launch and not preferences.path.exists():
            # Exact Qt mapping only; an OS suggestion never grants confirmation.
            qt_name = QLocale.system().name()
            suggested = next((item.metadata.id for item in options
                              if item.metadata.qt_locale == qt_name and item.selectable), 'en')
        for option in options:
            name = option.metadata.display_name
            if not option.selectable:
                name = format_text(translate('LanguageSelection', '{language} — unavailable'), language=name)
            item = QListWidgetItem(name, self.languages)
            item.setData(Qt.ItemDataRole.UserRole, option.metadata.id)
            if not option.selectable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled & ~Qt.ItemFlag.ItemIsSelectable)
            if option.metadata.id == suggested and option.selectable:
                self.languages.setCurrentItem(item)
        if self.languages.currentItem() is None:
            self.languages.setCurrentRow(0)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setAccessibleName(translate('LanguageSelection', 'Language selection status'))
        layout.addWidget(self.error)
        buttons = QHBoxLayout()
        self.confirm = QPushButton(translate('LanguageSelection', 'Continue') if first_launch
                                   else translate('LanguageSelection', 'Apply'))
        self.confirm.setDefault(True)
        self.english = QPushButton(translate('LanguageSelection', 'Use English'))
        self.cancel = QPushButton(translate('LanguageSelection', 'Cancel'))
        for button in (self.confirm, self.english, self.cancel):
            button.setAccessibleName(button.text())
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.recovery = QPushButton(translate('LanguageSelection', 'Continue in English without saving'))
        self.recovery.setAccessibleName(self.recovery.text())
        self.recovery.hide()
        layout.addWidget(self.recovery)
        self.confirm.clicked.connect(self._confirm)
        self.english.clicked.connect(lambda: self._apply('en'))
        self.cancel.clicked.connect(self.reject)
        self.recovery.clicked.connect(self._recover)
        QWidget.setTabOrder(self.languages, self.confirm)
        QWidget.setTabOrder(self.confirm, self.english)
        QWidget.setTabOrder(self.english, self.cancel)
        QWidget.setTabOrder(self.cancel, self.recovery)
        self.languages.setFocus()
        self._notice()

    def _notice(self) -> None:
        names = {item.id: item.display_name for item in PLANNED_LOCALES}
        state = self.preferences.diagnostics
        self.notice.setText(format_text(translate('LanguageSelection',
            'Current: {current}. Selected for next launch: {selected}. Language changes require an application restart.'),
            current=names[state.effective_locale], selected=names[state.selected_locale]))
        if state.fallback_active:
            self.error.setText(translate('LanguageSelection',
                'The saved language is invalid or its translation pack is unavailable. English is active; choose an available language to replace the preference.'))

    def _confirm(self) -> None:
        item = self.languages.currentItem()
        if item is not None:
            self._apply(item.data(Qt.ItemDataRole.UserRole))

    def _apply(self, locale: str) -> None:
        outcome = self.preferences.apply(locale)
        if outcome == 'catalog_unavailable':
            self.error.setText(translate('LanguageSelection',
                'This translation pack could not be loaded. Choose an available language or Use English.'))
        elif outcome == 'save_failed':
            self.error.setText(translate('LanguageSelection',
                'The language preference could not be saved. Retry or continue in English without saving.'))
            if self.first_launch:
                self.recovery.show()
        elif self.first_launch:
            self.accept()
        else:
            self._notice()
            self.error.setText(translate('LanguageSelection',
                'Language preference saved. Restart the application to use the selected language.'))

    def _recover(self) -> None:
        self.unsaved_english = True
        self.accept()
