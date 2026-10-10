"""One GUI-owned QTranslator. Whole-app restart contract, no language UX."""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from importlib import resources
import json
from typing import Any, cast

from PyQt6.QtCore import QObject, QThread, QTranslator, QLocale, Qt, pyqtSignal
from PyQt6.QtWidgets import QApplication


class LocaleOutcome(str, Enum):
    APPLIED = 'applied'
    ENGLISH = 'english'
    UNSUPPORTED = 'unsupported'
    MISSING = 'missing_catalog'
    INVALID = 'invalid_catalog'
    RESTART_REQUIRED = 'restart_required'


@dataclass(frozen=True)
class LocaleMetadata:
    id: str
    english_name: str
    qt_locale: str
    rtl: bool = False


PLANNED_LOCALES = (
    LocaleMetadata('en', 'English', 'en_US'),
    LocaleMetadata('tr', 'Turkish', 'tr_TR'),
    LocaleMetadata('de', 'German', 'de_DE'),
    LocaleMetadata('fr', 'French', 'fr_FR'),
    LocaleMetadata('es', 'Spanish', 'es_ES'),
    LocaleMetadata('it', 'Italian', 'it_IT'),
    LocaleMetadata('pt-BR', 'Portuguese (Brazil)', 'pt_BR'),
    LocaleMetadata('nl', 'Dutch', 'nl_NL'),
    LocaleMetadata('pl', 'Polish', 'pl_PL'),
    LocaleMetadata('ru', 'Russian', 'ru_RU'),
    LocaleMetadata('uk', 'Ukrainian', 'uk_UA'),
    LocaleMetadata('ar', 'Arabic', 'ar_EG', True),
    LocaleMetadata('ja', 'Japanese', 'ja_JP'),
    LocaleMetadata('ko', 'Korean', 'ko_KR'),
    LocaleMetadata('zh-Hans', 'Simplified Chinese', 'zh_CN'),
    LocaleMetadata('zh-Hant', 'Traditional Chinese', 'zh_TW'),
    LocaleMetadata('id', 'Indonesian', 'id_ID'),
    LocaleMetadata('cs', 'Czech', 'cs_CZ'),
)

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
        # Planned metadata is deliberately separate from shippable languages.
        return ('en',)

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
        outcome = LocaleOutcome.APPLIED
        candidate = None
        data = None
        if metadata is None:
            outcome = LocaleOutcome.UNSUPPORTED
        elif locale == 'en':
            outcome = LocaleOutcome.ENGLISH
        else:
            try:
                data = bundled_catalog(locale)
                if data is None:
                    outcome = LocaleOutcome.MISSING
                else:
                    candidate = QTranslator(self)
                    # PyQt6's buffer overload accepts bytes at runtime; its
                    # generated stub advertises only array[bytes]. Real QM tests
                    # exercise this exact offline API and retained buffer lifetime.
                    if not candidate.loadFromData(cast(Any, data)):
                        outcome = LocaleOutcome.INVALID
                        candidate.deleteLater()
                        candidate = None
            except (OSError, ValueError, KeyError, TypeError):
                outcome = LocaleOutcome.INVALID
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
