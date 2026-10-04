"""NS-085 lazy, bounded, atomic local TI cache with scoped connections."""

from datetime import datetime
import sqlite3

from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheEntry, ThreatIntelCacheFreshness as Freshness, ThreatIntelCacheKey,
    ThreatIntelCacheLookup, ThreatIntelCacheMutation, ThreatIntelCacheMutationStatus as Status,
    ThreatIntelCachePolicy, classify_entry,
)
from netsentinel.domain.threat_intelligence import TI_RESULT_CONTRACT_VERSION, ThreatIntelProviderId, _utc
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.threat_intel_cache_codec import (
    TI_CACHE_FORMAT_VERSION, decode_entry, encode_entry, utc_microseconds,
)


_KEY_COLUMNS = "provider_id, data_type, subject_kind, canonical_subject, hash_algorithm, result_version"
_KEY_WHERE = " AND ".join(f"{name.strip()} = ?" for name in _KEY_COLUMNS.split(","))
_ORDER_KEY = _KEY_COLUMNS
_TIMES_SELECT = ", ".join(
    f"CASE WHEN typeof({name}) = 'integer' THEN {name} END"
    for name in ("received_at_utc_us", "fresh_until_utc_us", "stale_until_utc_us")
)


def _key_values(key: ThreatIntelCacheKey) -> tuple[str | int, ...]:
    return (key.provider.value, key.data_type.value, key.subject.kind.value, key.subject.value,
            key.subject.algorithm.value if key.subject.algorithm else "", key.result_version)


class SQLiteThreatIntelCacheRepository:
    """No RAM front cache, no preload, no touch-on-read write amplification.

    Every call opens a component-scoped connection. Invoke from an owning worker.
    Global quota may evict another provider, but exact-key replacement and scoped
    purge never cross providers. Policy can tighten, never raise schema budgets.
    """

    def __init__(self, database: SQLiteDatabase,
                 policy: ThreatIntelCachePolicy = ThreatIntelCachePolicy()) -> None:
        self._database = database
        self._policy = policy

    @property
    def policy(self) -> ThreatIntelCachePolicy:
        return self._policy

    def get(self, key: ThreatIntelCacheKey, now: datetime) -> ThreatIntelCacheLookup:
        _utc(now)
        if key.result_version != TI_RESULT_CONTRACT_VERSION:
            return ThreatIntelCacheLookup(Freshness.UNSUPPORTED)
        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    "SELECT CASE WHEN typeof(format_version) = 'integer' THEN format_version END, "
                    "CASE WHEN typeof(normalized_result) = 'text' "
                    "AND length(CAST(normalized_result AS BLOB)) <= ? THEN normalized_result END, "
                    f"{_TIMES_SELECT} "
                    f"FROM threat_intel_cache WHERE {_KEY_WHERE}",
                    (self.policy.max_payload_bytes, *_key_values(key)),
                ).fetchone()
            if row is None:
                return ThreatIntelCacheLookup(Freshness.MISS)
            if type(row[0]) is not int or row[0] < 1:
                return ThreatIntelCacheLookup(Freshness.CORRUPT)
            if row[0] != TI_CACHE_FORMAT_VERSION:
                return ThreatIntelCacheLookup(Freshness.UNSUPPORTED)
            try:
                entry = decode_entry(key, row[1], row[2], row[3], row[4], self.policy.max_payload_bytes)
                return classify_entry(entry, now, self.policy)
            except (ValueError, TypeError, OverflowError, RecursionError):
                return ThreatIntelCacheLookup(Freshness.CORRUPT)
        except (sqlite3.Error, SQLiteAdapterError, OSError):
            return ThreatIntelCacheLookup(Freshness.UNAVAILABLE)

    def put(self, entry: ThreatIntelCacheEntry, now: datetime) -> ThreatIntelCacheMutation:
        _utc(now)
        if entry.key.result_version != TI_RESULT_CONTRACT_VERSION:
            return ThreatIntelCacheMutation(Status.UNSUPPORTED)
        if entry.result.received_at > now:
            return ThreatIntelCacheMutation(Status.INVALID)
        try:
            payload = encode_entry(entry, self.policy.max_payload_bytes)
            times = tuple(utc_microseconds(t) for t in
                          (entry.result.received_at, entry.fresh_until, entry.stale_until))
        except (ValueError, TypeError, OverflowError):
            return ThreatIntelCacheMutation(Status.INVALID)
        try:
            with self._database.connection() as connection, transaction(connection):
                changed = connection.execute(
                    f"INSERT INTO threat_intel_cache ({_KEY_COLUMNS}, format_version, normalized_result, "
                    "received_at_utc_us, fresh_until_utc_us, stale_until_utc_us) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    f"ON CONFLICT ({_KEY_COLUMNS}) DO UPDATE SET "
                    "format_version = excluded.format_version, normalized_result = excluded.normalized_result, "
                    "received_at_utc_us = excluded.received_at_utc_us, "
                    "fresh_until_utc_us = excluded.fresh_until_utc_us, stale_until_utc_us = excluded.stale_until_utc_us "
                    "WHERE excluded.received_at_utc_us > threat_intel_cache.received_at_utc_us "
                    "OR (excluded.received_at_utc_us = threat_intel_cache.received_at_utc_us "
                    "AND excluded.normalized_result > threat_intel_cache.normalized_result)",
                    (*_key_values(entry.key), TI_CACHE_FORMAT_VERSION, payload, *times),
                ).rowcount
                # At most max_disk_entries + one rows in normal operation. A
                # lower policy on reopen trims at most one bounded chunk/call.
                count = connection.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0]
                overflow = max(0, count - self.policy.max_disk_entries)
                if overflow > self.policy.cleanup_chunk:
                    # Roll back rather than commit an over-capacity store.
                    raise ValueError("cache requires explicit chunk cleanup")
                evicted = self._delete(connection, "1", (), overflow, now) if overflow else 0
            return ThreatIntelCacheMutation(Status.STORED if changed else Status.NO_CHANGE,
                                             changed, evicted)
        except ValueError:
            return ThreatIntelCacheMutation(Status.INVALID)
        except (sqlite3.Error, SQLiteAdapterError, OSError):
            return ThreatIntelCacheMutation(Status.UNAVAILABLE)

    def _delete(self, connection: sqlite3.Connection, where: str,
                values: tuple[str | int, ...], limit: int, now: datetime | None = None) -> int:
        order = _ORDER_KEY
        order_values: tuple[int, ...] = ()
        if now is not None:
            stamp = utc_microseconds(now)
            order = ("CASE WHEN stale_until_utc_us <= ? THEN 0 "
                     "WHEN fresh_until_utc_us <= ? THEN 1 ELSE 2 END, "
                     f"received_at_utc_us, {_ORDER_KEY}")
            order_values = (stamp, stamp)
        return connection.execute(
            f"DELETE FROM threat_intel_cache WHERE ({_KEY_COLUMNS}) IN "
            f"(SELECT {_KEY_COLUMNS} FROM threat_intel_cache WHERE {where} ORDER BY {order} LIMIT ?)",
            (*values, *order_values, limit),
        ).rowcount

    def purge(self, *, key: ThreatIntelCacheKey | None = None,
              provider: ThreatIntelProviderId | None = None) -> ThreatIntelCacheMutation:
        if key is not None and provider is not None:
            raise ValueError("choose one purge scope")
        if key is not None and not isinstance(key, ThreatIntelCacheKey):
            raise TypeError("purge requires a typed key")
        if provider is not None and not isinstance(provider, ThreatIntelProviderId):
            raise TypeError("purge requires a typed provider")
        where = "1"
        values: tuple[str | int, ...] = ()
        if key is not None:
            where, values = _KEY_WHERE, _key_values(key)
        elif provider is not None:
            where, values = "provider_id = ?", (provider.value,)
        return self._purge_chunk(where, values)

    def _purge_chunk(self, where: str, values: tuple[str | int, ...]) -> ThreatIntelCacheMutation:
        try:
            with self._database.connection() as connection, transaction(connection):
                count = self._delete(connection, where, values, self.policy.cleanup_chunk)
                remaining = connection.execute(
                    f"SELECT 1 FROM threat_intel_cache WHERE {where} LIMIT 1", values,
                ).fetchone() is not None
            return ThreatIntelCacheMutation(Status.PURGED, count, remaining=remaining)
        except (sqlite3.Error, SQLiteAdapterError, OSError):
            return ThreatIntelCacheMutation(Status.UNAVAILABLE)

    def cleanup(self, now: datetime) -> ThreatIntelCacheMutation:
        _utc(now)
        # Explicit bounded maintenance: expired rows first, then quota overflow.
        try:
            with self._database.connection() as connection, transaction(connection):
                expired = self._delete(connection, "stale_until_utc_us <= ?",
                                       (utc_microseconds(now),), self.policy.cleanup_chunk, now)
                count = connection.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0]
                overflow = max(0, count - self.policy.max_disk_entries)
                evicted = self._delete(connection, "1", (),
                                       min(overflow, self.policy.cleanup_chunk - expired), now)
                remaining = overflow > evicted or connection.execute(
                    "SELECT 1 FROM threat_intel_cache WHERE stale_until_utc_us <= ? LIMIT 1",
                    (utc_microseconds(now),),
                ).fetchone() is not None
            return ThreatIntelCacheMutation(Status.PURGED, expired + evicted, evicted, remaining)
        except (sqlite3.Error, SQLiteAdapterError, OSError):
            return ThreatIntelCacheMutation(Status.UNAVAILABLE)
