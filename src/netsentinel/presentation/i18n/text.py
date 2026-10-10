"""Extractable Qt calls and deferred source containers for hand-built widgets."""

from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import datetime
from enum import Enum
from string import Formatter
from typing import Any, TypeVar, overload

from PyQt6.QtCore import QCoreApplication, QDateTime, QLocale
from netsentinel.shared.source_text import SourceMessage, SourceText
from netsentinel.shared.enum_sources import enum_source


def placeholders(text: str) -> Counter[tuple[str, str, str | None]]:
    """Exact named fields, format specifications and conversions, never eval."""
    fields = Counter((name, spec or '', conversion) for _, name, spec, conversion
                     in Formatter().parse(text) if name is not None)
    if any(not name.isidentifier() or '{' in spec or '}' in spec
           for name, spec, _ in fields):
        raise ValueError("named simple translation placeholders required")
    return fields


def translate(context: str, source: str, disambiguation: str | None = None,
              n: int = -1) -> str:
    """Use Qt lookup; invalid placeholders safely retain canonical English."""
    result = QCoreApplication.translate(context, source, disambiguation or '', n)
    try:
        valid = placeholders(source) == placeholders(result)
    except ValueError:
        valid = False
    if not result or not valid:
        result = source.replace('%n', QLocale().toString(n)) if n >= 0 else source
    return result


def render_text(value: Any) -> Any:
    """Render only typed sources; historical text and raw evidence stay verbatim."""
    if not isinstance(value, SourceText):
        return value
    pieces = []
    for part in value.parts:
        if isinstance(part, SourceMessage):
            values = {key: render_text(item) if isinstance(item, SourceText) else item
                      for key, item in part.values}
            pieces.append(translate(part.context, part.source).format(**values)
                          if values else translate(part.context, part.source))
        else:
            pieces.append(render_text(part) if isinstance(part, SourceText) else part)
    result = ''.join(pieces)
    if value.maximum is not None and len(result) > value.maximum:
        result = result[:value.maximum] + translate('SourceText', '… [display truncated]')
    return result


def display_enum(value: Enum, style: str = 'raw') -> str:
    return render_text(enum_source(value, style))


def render_join(separator: str, values: Iterable[str]) -> str:
    return separator.join(render_text(value) for value in values)


def format_text(source: str, **values: Any) -> str:
    return source.format(**{key: render_text(value) for key, value in values.items()})


K = TypeVar('K')
V = TypeVar('V')


class TranslationMapping(Mapping[K, V]):
    """Defer literal Qt calls until lookup; never cache translated identity."""

    def __init__(self, factory: Callable[[], dict[K, V]]) -> None:
        self._factory = factory

    def __getitem__(self, key: K) -> V:
        return self._factory()[key]

    def __iter__(self) -> Iterator[K]:
        return iter(self._factory())

    def __len__(self) -> int:
        return len(self._factory())


class TranslationSequence(Sequence[V]):
    """Headers/guide source descriptors, resolved after startup activation."""

    def __init__(self, factory: Callable[[], tuple[V, ...]]) -> None:
        self._factory = factory

    @overload
    def __getitem__(self, index: int) -> V: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[V, ...]: ...

    def __getitem__(self, index: int | slice) -> V | tuple[V, ...]:
        return self._factory()[index]

    def __len__(self) -> int:
        return len(self._factory())

    def __iter__(self) -> Iterator[V]:
        return iter(self._factory())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (tuple, TranslationSequence)):
            return tuple(self) == tuple(other)
        return NotImplemented


def display_number(value: int | float, precision: int = 1) -> str:
    locale = QLocale()
    return locale.toString(value) if isinstance(value, int) else locale.toString(value, 'f', precision)


def display_timestamp(value: datetime) -> str:
    """Local presentation only. Explicit UTC offset; source/storage unchanged."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('timestamp must be timezone-aware')
    local = value.astimezone()
    stamp = QDateTime(local)
    return QLocale().toString(stamp, QLocale.FormatType.ShortFormat) + local.strftime(' %z')
