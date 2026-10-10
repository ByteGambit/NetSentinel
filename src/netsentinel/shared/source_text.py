"""Language-neutral UI source descriptors, with canonical string compatibility.

No Qt and no translation lookup. Read projections can cross a worker boundary
without selecting a language. Raw evidence strings are never descriptors.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SourceMessage:
    context: str
    source: str
    values: tuple[tuple[str, Any], ...] = ()


class SourceText(str):
    """Canonical str for existing pure contracts; immutable render recipe."""

    parts: tuple[SourceMessage | str, ...]
    maximum: int | None

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError('source text is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError('source text is immutable')

    def __new__(cls, canonical: str, parts: tuple[SourceMessage | str, ...],
                maximum: int | None = None) -> 'SourceText':
        value = super().__new__(cls, canonical)
        object.__setattr__(value, 'parts', parts)
        object.__setattr__(value, 'maximum', maximum)
        return value

    def __reduce__(self) -> tuple[object, tuple[str, tuple[SourceMessage | str, ...], int | None]]:
        return type(self), (str(self), self.parts, self.maximum)

    def __add__(self, other: str) -> 'SourceText':
        return SourceText(str(self) + str(other), _parts(self) + _parts(other))

    def __radd__(self, other: str) -> 'SourceText':
        return SourceText(str(other) + str(self), _parts(other) + _parts(self))

    def format(self, *args: Any, **kwargs: Any) -> 'SourceText':
        if args or len(self.parts) != 1 or not isinstance(self.parts[0], SourceMessage):
            raise ValueError('source messages require named parameters')
        part = self.parts[0]
        return SourceText(str(self).format(**kwargs),
                          (SourceMessage(part.context, part.source, tuple(kwargs.items())),))

    def bounded(self, maximum: int) -> 'SourceText':
        canonical = str(self) if len(self) <= maximum else str(self)[:maximum] + '… [display truncated]'
        return SourceText(canonical, self.parts, maximum)


def _parts(value: str) -> tuple[SourceMessage | str, ...]:
    return value.parts if isinstance(value, SourceText) and value.maximum is None else (value,)


def QT_TRANSLATE_NOOP(context: str, source: str) -> SourceText:  # noqa: N802
    """Qt Linguist extraction marker; rendering belongs to presentation."""
    return SourceText(source, (SourceMessage(context, source),))


def join_text(separator: str, values: Iterable[str]) -> SourceText:
    pieces = tuple(values)
    parts: list[SourceMessage | str] = []
    for index, piece in enumerate(pieces):
        if index:
            parts.extend(_parts(separator))
        parts.extend(_parts(piece))
    return SourceText(separator.join(pieces), tuple(parts))
