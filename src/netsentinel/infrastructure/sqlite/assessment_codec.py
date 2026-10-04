"""Closed, strict format-1 codec; never replays the current scoring policy."""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime
from enum import Enum
import json
from types import UnionType
from typing import Any, get_args, get_origin, get_type_hints
from uuid import UUID

from netsentinel.domain.risk_assessment import ASSESSMENT_VALUE_TYPES, AssessmentSnapshot, utc_time


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate snapshot key")
        result[key] = value
    return result


def _decode(value: Any, expected: Any) -> Any:
    """Types come exclusively from our closed dataclass vocabulary."""
    if get_origin(expected) is UnionType:
        for candidate in get_args(expected):
            try:
                return _decode(value, candidate)
            except (ValueError, TypeError, AttributeError):
                pass
        raise ValueError("invalid optional snapshot field")
    if expected is type(None):
        if value is not None:
            raise ValueError("expected absent value")
        return None
    if get_origin(expected) is tuple:
        # Largest format-1 collection is the 64 score contributors. Dataclass
        # validators subsequently enforce the smaller field-specific quotas.
        if type(value) is not list or len(value) > 64:
            raise ValueError("snapshot collection exceeds quota")
        return tuple(_decode(v, get_args(expected)[0]) for v in value)
    if expected in (str, int, bool):
        if type(value) is not expected:
            raise ValueError("invalid snapshot primitive")
        return value
    if expected is datetime:
        if type(value) is not str or len(value) > 32:
            raise ValueError("invalid snapshot time")
        return utc_time(datetime.fromisoformat(value))
    if expected is UUID:
        if type(value) is not str or len(value) != 36 or str(UUID(value)) != value:
            raise ValueError("invalid snapshot UUID")
        return UUID(value)
    if isinstance(expected, type) and issubclass(expected, Enum):
        if type(value) is not str:
            raise ValueError("invalid snapshot enum")
        return expected(value)
    if expected in ASSESSMENT_VALUE_TYPES:
        names = {f.name for f in fields(expected) if f.init}
        if expected is AssessmentSnapshot and type(value) is dict and "threat_intelligence" not in value:
            names.remove("threat_intelligence")  # Exact legacy v1 vocabulary; hashes unchanged.
        if type(value) is not dict or set(value) != names:
            raise ValueError("unknown/missing snapshot fields")
        hints = get_type_hints(expected)
        return expected(**{name: _decode(value[name], hints[name]) for name in names})
    raise TypeError("unsupported snapshot type")


def decode_value(payload: str, expected: Any, maximum_bytes: int, *, format_version: int = 1) -> Any:
    if type(payload) is not str or len(payload.encode("utf-8")) > maximum_bytes:
        raise ValueError("snapshot payload exceeds quota")
    value = json.loads(payload, object_pairs_hook=_unique_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if expected is AssessmentSnapshot:
        if format_version not in (1, 2) or type(value) is not dict or ("threat_intelligence" in value) != (format_version == 2):
            raise ValueError("snapshot vocabulary does not match format")
    return _decode(value, expected)
