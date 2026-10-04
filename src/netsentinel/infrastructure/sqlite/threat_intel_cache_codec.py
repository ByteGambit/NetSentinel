"""Strict version-2 normalized TI snapshot codec, never arbitrary provider JSON."""

from datetime import UTC, datetime, timedelta
import json
from uuid import UUID

from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheEntry, ThreatIntelCacheKey, ThreatIntelCachedResult,
)
from netsentinel.domain.threat_intelligence import ThreatIntelIpFacts, ThreatIntelResultStatus, ThreatIntelTrigger, _utc


TI_CACHE_FORMAT_VERSION = 2
_FIELDS = frozenset(("status", "request_id", "queried_at", "received_at", "trigger", "query_policy_version"))
_FACT_FIELDS = frozenset(("mapping_version", "lookback_days", "abuse_confidence_score",
                          "total_reports", "distinct_users", "last_reported_at", "is_whitelisted"))
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def utc_microseconds(value: datetime) -> int:
    _utc(value)
    delta = value - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def from_microseconds(value: int) -> datetime:
    if type(value) is not int:
        raise ValueError("invalid persisted time")
    return _EPOCH + timedelta(microseconds=value)


def encode_entry(entry: ThreatIntelCacheEntry, max_bytes: int) -> str:
    result = entry.result
    data: dict[str, object] = {
        "status": result.status.value, "request_id": str(result.request_id),
        "queried_at": result.queried_at.isoformat(), "received_at": result.received_at.isoformat(),
        "trigger": result.trigger.value, "query_policy_version": result.query_policy_version,
    }
    if result.ip_facts is not None:
        facts = result.ip_facts
        data["ip_facts"] = {
            "mapping_version": facts.mapping_version, "lookback_days": facts.lookback_days,
            "abuse_confidence_score": facts.abuse_confidence_score,
            "total_reports": facts.total_reports, "distinct_users": facts.distinct_users,
            "last_reported_at": facts.last_reported_at.isoformat() if facts.last_reported_at else None,
            "is_whitelisted": facts.is_whitelisted,
        }
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(payload.encode("utf-8")) > max_bytes:
        raise ValueError("cache snapshot exceeds byte bound")
    return payload


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cache field")
        result[key] = value
    return result


def decode_entry(key: ThreatIntelCacheKey, payload: str, received: int, fresh: int,
                 stale: int, max_bytes: int) -> ThreatIntelCacheEntry:
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > max_bytes:
        raise ValueError("invalid snapshot size")
    data = json.loads(payload, object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or data.keys() not in (_FIELDS, _FIELDS | {"ip_facts"}):
        raise ValueError("invalid cache fields")
    if (any(type(data[name]) is not str for name in _FIELDS - {"query_policy_version"})
            or type(data["query_policy_version"]) is not int):
        raise ValueError("invalid cache field types")
    facts = None
    if "ip_facts" in data:
        values = data["ip_facts"]
        if not isinstance(values, dict) or values.keys() != _FACT_FIELDS:
            raise ValueError("invalid cached fact fields")
        timestamp = values["last_reported_at"]
        if timestamp is not None and type(timestamp) is not str:
            raise ValueError("invalid cached report time")
        facts = ThreatIntelIpFacts(
            values["mapping_version"], values["lookback_days"], values["abuse_confidence_score"],
            values["total_reports"], values["distinct_users"],
            datetime.fromisoformat(timestamp) if timestamp is not None else None,
            values["is_whitelisted"],
        )
    result = ThreatIntelCachedResult(
        ThreatIntelResultStatus(data["status"]), UUID(data["request_id"]),
        datetime.fromisoformat(data["queried_at"]), datetime.fromisoformat(data["received_at"]),
        ThreatIntelTrigger(data["trigger"]), data["query_policy_version"], facts,
    )
    if result.received_at != from_microseconds(received):
        raise ValueError("snapshot timestamp mismatch")
    entry = ThreatIntelCacheEntry(key, result, from_microseconds(fresh), from_microseconds(stale))
    # Reject alternate representations, whitespace, NaN and unnormalized payloads.
    if encode_entry(entry, max_bytes) != payload:
        raise ValueError("noncanonical cache snapshot")
    return entry
