"""Strict bounded format-1 incident vocabulary, isolated from assessment formats."""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
from types import UnionType
from typing import Any, get_args, get_origin, get_type_hints
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import ProcessIdentity
from netsentinel.domain.incidents import (
    CorrelatedIncident, IncidentConnectionRef, IncidentCorrelationKey,
    IncidentDestination, IncidentObservationRef, IncidentPolicy,
    IncidentProcessDestination, IncidentProcessRef, IncidentRelation, incident_time,
)
from netsentinel.domain.incident_persistence import (
    MAX_INCIDENT_BYTES, MAX_LINK_BYTES, IncidentRecord, IncidentRevision,
    IncidentSourceLink, canonical_incident_json,
)
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceScope

VALUE_TYPES = (CorrelatedIncident, IncidentConnectionRef, IncidentCorrelationKey,
    IncidentDestination, IncidentObservationRef, IncidentPolicy, IncidentProcessDestination,
    IncidentProcessRef, IncidentRelation, ProcessIdentity, AlertAssessmentReference,
    EvidenceReference, EvidenceScope, IncidentRecord, IncidentRevision)
LINK_TYPES = {"process": IncidentProcessRef, "connection": IncidentConnectionRef,
    "destination": IncidentDestination, "evidence": EvidenceReference,
    "assessment": AlertAssessmentReference, "alert": UUID, "scope": EvidenceScope,
    "relation": IncidentRelation}


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate incident field")
        value[key] = item
    return value


def _decode(value: Any, expected: Any) -> Any:
    if get_origin(expected) is UnionType:
        for candidate in get_args(expected):
            try:
                return _decode(value, candidate)
            except (ValueError, TypeError, AttributeError):
                pass
        raise ValueError("invalid incident union")
    if expected is type(None):
        if value is not None:
            raise ValueError("invalid null")
        return None
    if get_origin(expected) is tuple:
        if type(value) is not list or len(value) > 128:
            raise ValueError("incident tuple exceeds bound")
        return tuple(_decode(v, get_args(expected)[0]) for v in value)
    if expected in (str, int, bool):
        if type(value) is not expected:
            raise ValueError("invalid incident primitive")
        return value
    if expected is datetime:
        if type(value) is not str or len(value) > 32:
            raise ValueError("invalid incident time")
        return incident_time(datetime.fromisoformat(value))
    if expected is timedelta:
        if type(value) is not int or not 0 <= value <= 600_000_000:
            raise ValueError("invalid incident duration")
        return timedelta(microseconds=value)
    if expected is UUID:
        if type(value) is not str or len(value) != 36 or str(UUID(value)) != value:
            raise ValueError("invalid incident UUID")
        return UUID(value)
    if isinstance(expected, type) and issubclass(expected, Enum):
        if type(value) is not str:
            raise ValueError("invalid incident enum")
        return expected(value)
    if expected in VALUE_TYPES:
        names = {f.name for f in fields(expected) if f.init}
        if type(value) is not dict or set(value) != names:
            raise ValueError("unknown/missing incident fields")
        hints = get_type_hints(expected)
        return expected(**{name: _decode(value[name], hints[name]) for name in names})
    raise TypeError("unsupported incident type")


def decode_incident(payload: str, expected: Any = IncidentRecord, maximum: int = MAX_INCIDENT_BYTES) -> Any:
    if type(payload) is not str or len(payload.encode("utf-8")) > maximum:
        raise ValueError("incident payload exceeds bound")
    value = json.loads(payload, object_pairs_hook=_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite incident value")))
    return _decode(value, expected)


def source_links(snapshot: CorrelatedIncident) -> tuple[IncidentSourceLink, ...]:
    links = []
    for kind, name in (("process", "processes"), ("connection", "connections"),
                       ("destination", "destinations"), ("evidence", "evidence"),
                       ("assessment", "assessments"), ("alert", "alerts"),
                       ("scope", "scopes"), ("relation", "relations")):
        for value in getattr(snapshot, name):
            payload = canonical_incident_json(value)
            # Decode on admission as well: arbitrary dataclasses cannot enter.
            decode_incident(payload, LINK_TYPES[kind], MAX_LINK_BYTES)
            links.append(IncidentSourceLink(kind, sha256(payload.encode("ascii")).hexdigest(), payload))
    return tuple(sorted(links, key=lambda r: (r.kind, r.identity)))
