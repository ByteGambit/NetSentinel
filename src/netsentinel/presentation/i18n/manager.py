"""One GUI-owned QTranslator, offline catalog staging and sealed session locale."""

from enum import Enum
from hashlib import sha256
from importlib import resources
import json
from typing import Any, cast

from PyQt6.QtCore import QObject, QThread, QTranslator, QLocale, Qt, pyqtSignal
from PyQt6.QtWidgets import QApplication
from netsentinel.shared.locales import PLANNED_LOCALES


class LocaleOutcome(str, Enum):
    APPLIED = 'applied'
    ENGLISH = 'english'
    UNSUPPORTED = 'unsupported'
    MISSING = 'missing_catalog'
    INVALID = 'invalid_catalog'
    RESTART_REQUIRED = 'restart_required'


MAX_CATALOG_BYTES = 4 * 1024 * 1024


def bundled_catalog(locale: str) -> bytes | None:
    """Fixed bundled allowlist, size/digest checked before Qt parses bytes."""
    root = resources.files('netsentinel.assets').joinpath('i18n')
    with root.joinpath('manifest.json').open('rb') as stream:
        manifest_bytes = stream.read(16385)
    if len(manifest_bytes) > 16384:
        raise ValueError('invalid catalog manifest')
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get('version') != 1 or not isinstance(manifest.get('catalogs'), dict):
        raise ValueError('invalid catalog manifest')
    entry = manifest['catalogs'].get(locale)
    if entry is None:
        return None
    # No filename from the manifest can redirect the resource resolver.
    if not isinstance(entry, dict) or not isinstance(entry.get('sha256'), str):
        raise ValueError('invalid catalog entry')
    with root.joinpath(f'netsentinel_{locale}.qm').open('rb') as stream:
        data = stream.read(MAX_CATALOG_BYTES + 1)
    if not 0 < len(data) <= MAX_CATALOG_BYTES or sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('invalid catalog resource')
    return data


class LocalizationManager(QObject):
    locale_changed = pyqtSignal(str, int)
    RUNTIME_SWITCHING = False

    def __init__(self, application: QApplication) -> None:
        super().__init__(application)
        self.application = application
        self.current_locale = 'en'
        self.requested_locale = 'en'
        self.generation = 0
        self._translator: QTranslator | None = None
        self._catalog_data: bytes | None = None
        self._sealed = False
        self._closed = False

    @property
    def available_locales(self) -> tuple[str, ...]:
        return tuple(item.id for item in PLANNED_LOCALES
                     if self.validate_catalog(item.id) in (LocaleOutcome.ENGLISH, LocaleOutcome.APPLIED))

    def stage(self, locale: str) -> tuple[LocaleOutcome, QTranslator | None, bytes | None]:
        """Validate without changing translator, Qt locale or direction."""
        self._require_gui()
        if not any(item.id == locale for item in PLANNED_LOCALES):
            return LocaleOutcome.UNSUPPORTED, None, None
        if locale == 'en':
            return LocaleOutcome.ENGLISH, None, None
        candidate = None
        try:
            data = bundled_catalog(locale)
            if data is None:
                return LocaleOutcome.MISSING, None, None
            if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CATALOG_BYTES:
                return LocaleOutcome.INVALID, None, None
            candidate = QTranslator(self)
            if not candidate.loadFromData(cast(Any, data)) or candidate.isEmpty():
                candidate.deleteLater()
                return LocaleOutcome.INVALID, None, None
            return LocaleOutcome.APPLIED, candidate, data
        except (OSError, ValueError, KeyError, TypeError):
            if candidate is not None:
                candidate.deleteLater()
            return LocaleOutcome.INVALID, None, None

    def validate_catalog(self, locale: str) -> LocaleOutcome:
        outcome, candidate, data = self.stage(locale)
        if candidate is not None:
            candidate.deleteLater()
        return outcome

    def seal(self) -> None:
        """Composition seals before constructing any widgets or starting workers."""
        self._require_gui()
        self._sealed = True

    def _require_gui(self) -> None:
        if QThread.currentThread() != self.thread():
            raise RuntimeError('localization requires the GUI thread')

    def activate(self, locale: str) -> LocaleOutcome:
        self._require_gui()
        if self._closed:
            raise RuntimeError('localization manager closed')
        if self._sealed:
            return LocaleOutcome.RESTART_REQUIRED
        self.requested_locale = locale
        metadata = next((item for item in PLANNED_LOCALES if item.id == locale), None)
        outcome, candidate, data = self.stage(locale)
        if candidate is not None and not self.application.installTranslator(candidate):
            outcome = LocaleOutcome.INVALID
            candidate.deleteLater()
            candidate = None
        previous = self._translator
        if previous is not None:
            self.application.removeTranslator(previous)
            previous.deleteLater()
        self._translator = candidate
        # Qt's memory loader can retain the buffer; keep it with the translator.
        self._catalog_data = data if candidate is not None else None
        self.current_locale = locale if candidate is not None else 'en'
        effective = metadata if candidate is not None else PLANNED_LOCALES[0]
        assert effective is not None
        QLocale.setDefault(QLocale(effective.qt_locale))
        self.application.setLayoutDirection(Qt.LayoutDirection.RightToLeft if effective.rtl
                                            else Qt.LayoutDirection.LeftToRight)
        self.generation += 1
        self.locale_changed.emit(self.current_locale, self.generation)
        return outcome

    def close(self) -> None:
        """Remove the owned translator at shutdown; never persist a preference."""
        self._require_gui()
        if self._closed:
            return
        if self._translator is not None:
            self.application.removeTranslator(self._translator)
            self._translator.deleteLater()
            self._translator = None
            self._catalog_data = None
        self._closed = True
        QLocale.setDefault(QLocale('en_US'))
        self.application.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
