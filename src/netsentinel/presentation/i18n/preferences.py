"""NS-106 durable selection; effective UI remains sealed for this launch."""

from dataclasses import dataclass
from pathlib import Path

from netsentinel.presentation.i18n.manager import LocalizationManager, LocaleOutcome
from netsentinel.shared.config import ConfigLoadResult, load_config_file, save_ui_language
from netsentinel.shared.locales import LocaleMetadata, PLANNED_LOCALES


@dataclass(frozen=True, slots=True)
class LanguageOption:
    metadata: LocaleMetadata
    catalog_status: LocaleOutcome

    @property
    def selectable(self) -> bool:
        return self.catalog_status in (LocaleOutcome.APPLIED, LocaleOutcome.ENGLISH)


@dataclass(frozen=True, slots=True)
class LanguageDiagnostics:
    selected_locale: str
    effective_locale: str
    fallback_active: bool
    catalog_status: str
    restart_required: bool
    preference_invalid: bool


class LanguagePreferences:
    def __init__(self, manager: LocalizationManager, path: Path,
                 loaded: ConfigLoadResult | None = None) -> None:
        self.manager = manager
        self.path = path
        self.loaded = loaded if loaded is not None else load_config_file(path)
        self.config = self.loaded.config
        self.selected_locale = self.config.ui_language
        self.preference_invalid = any(item.field in ('ui_language', 'ui_language_confirmed', 'config')
                                      for item in self.loaded.issues)
        self.catalog_status = self.manager.validate_catalog(self.selected_locale)
        self.saved = False

    @property
    def needs_choice(self) -> bool:
        return not self.config.ui_language_confirmed

    @property
    def options(self) -> tuple[LanguageOption, ...]:
        return tuple(LanguageOption(item, self.manager.validate_catalog(item.id)) for item in PLANNED_LOCALES)

    @property
    def diagnostics(self) -> LanguageDiagnostics:
        effective = self.manager.current_locale
        return LanguageDiagnostics(self.selected_locale, effective,
                                   self.preference_invalid or self.catalog_status not in (
                                       LocaleOutcome.ENGLISH, LocaleOutcome.APPLIED),
                                   self.catalog_status.value, self.selected_locale != effective,
                                   self.preference_invalid)

    def apply(self, locale: str) -> str:
        """Stage, reload/merge, atomic save, then publish pending choice only.

        No live activation, Qt generation change or process restart. Failed
        staging/save never publishes a new selection. Caller translates codes.
        """
        outcome, candidate, data = self.manager.stage(locale)
        try:
            if outcome not in (LocaleOutcome.ENGLISH, LocaleOutcome.APPLIED):
                return 'catalog_unavailable'
            try:
                config = save_ui_language(self.path, locale)
            except (OSError, ValueError, TypeError):
                return 'save_failed'
            self.config = config
            self.selected_locale = locale
            self.catalog_status = outcome
            self.preference_invalid = False
            self.saved = True
            return 'saved'
        finally:
            if candidate is not None:
                candidate.deleteLater()

    def activate_startup(self) -> LocaleOutcome:
        self.catalog_status = self.manager.activate(self.selected_locale)
        return self.catalog_status

    def continue_unsaved_english(self) -> None:
        # Explicit recovery never claims or writes acknowledgement.
        self.catalog_status = self.manager.activate('en')


class LanguageStartupCancelled(Exception):
    """Bootstrap X/Esc exits before the normal shell and lifecycle start."""


def prepare_language(manager: LocalizationManager, path: Path) -> LanguagePreferences:
    from netsentinel.presentation.widgets.language_settings import LanguageSelectionDialog
    manager.activate('en')
    preferences = LanguagePreferences(manager, path)
    if preferences.needs_choice:
        dialog = LanguageSelectionDialog(preferences, first_launch=True)
        accepted = dialog.exec()
        unsaved = dialog.unsaved_english
        dialog.deleteLater()
        if not accepted:
            raise LanguageStartupCancelled()
        if unsaved:
            preferences.continue_unsaved_english()
            return preferences
    preferences.activate_startup()
    return preferences
