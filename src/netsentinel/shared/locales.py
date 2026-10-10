"""Frozen NS-106 locale identities; no Qt, catalogs or user preferences."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LocaleMetadata:
    id: str
    english_name: str
    qt_locale: str
    rtl: bool = False
    native_name: str = ''

    @property
    def display_name(self) -> str:
        return (self.native_name if self.native_name == self.english_name
                else f'{self.native_name} ({self.english_name})')


PLANNED_LOCALES = (
    LocaleMetadata('en', 'English', 'en_US', native_name='English'),
    LocaleMetadata('tr', 'Turkish', 'tr_TR', native_name='Türkçe'),
    LocaleMetadata('de', 'German', 'de_DE', native_name='Deutsch'),
    LocaleMetadata('fr', 'French', 'fr_FR', native_name='Français'),
    LocaleMetadata('es', 'Spanish', 'es_ES', native_name='Español'),
    LocaleMetadata('it', 'Italian', 'it_IT', native_name='Italiano'),
    LocaleMetadata('pt-BR', 'Portuguese (Brazil)', 'pt_BR', native_name='Português (Brasil)'),
    LocaleMetadata('nl', 'Dutch', 'nl_NL', native_name='Nederlands'),
    LocaleMetadata('pl', 'Polish', 'pl_PL', native_name='Polski'),
    LocaleMetadata('ru', 'Russian', 'ru_RU', native_name='Русский'),
    LocaleMetadata('uk', 'Ukrainian', 'uk_UA', native_name='Українська'),
    LocaleMetadata('ar', 'Arabic', 'ar_EG', True, 'العربية'),
    LocaleMetadata('ja', 'Japanese', 'ja_JP', native_name='日本語'),
    LocaleMetadata('ko', 'Korean', 'ko_KR', native_name='한국어'),
    LocaleMetadata('zh-Hans', 'Simplified Chinese', 'zh_CN', native_name='简体中文'),
    LocaleMetadata('zh-Hant', 'Traditional Chinese', 'zh_TW', native_name='繁體中文'),
    LocaleMetadata('id', 'Indonesian', 'id_ID', native_name='Bahasa Indonesia'),
    LocaleMetadata('cs', 'Czech', 'cs_CZ', native_name='Čeština'),
)
LOCALE_IDS = frozenset(item.id for item in PLANNED_LOCALES)
