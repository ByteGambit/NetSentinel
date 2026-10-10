"""Qt localization boundary; no locale is persisted here (NS-105)."""

from netsentinel.presentation.i18n.manager import LocalizationManager, LocaleOutcome
from netsentinel.presentation.i18n.text import translate

__all__ = ("LocalizationManager", "LocaleOutcome", "translate")
