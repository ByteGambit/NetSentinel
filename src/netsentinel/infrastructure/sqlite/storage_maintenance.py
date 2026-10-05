"""NS-095 fixed-table plans, bounded physical deletes, worker-owned connections."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import sqlite3

from netsentinel.domain.storage_privacy import (
    Store, StoreRetentionRule, StorageSummary, StoreSummary, SupportRecord, utc_now,
    PROFILE_ROW_QUOTA, DEVICE_ROW_QUOTA, GATEWAY_ROW_QUOTA,
)
from netsentinel.domain.threat_intel_cache import ThreatIntelCachePolicy, ThreatIntelCacheMutationStatus
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
from netsentinel.infrastructure.sqlite.retention_guards import ASSESSMENT_UNPROTECTED


# Conservative substring checks use canonical fixed-size IDs, not user SQL.
# All retained alerts protect their explanation, even when resolved. Corrupt
# alert payloads protect all assessments until explicitly addressed by the user.
@dataclass(frozen=True, slots=True)
class _Plan:
    key: str
    order: str
    protected_filter: str = "1"
    children: tuple[tuple[str, str], ...] = ()
    minimum_age_days: int = 0


_PLANS = {
    Store.ASSOCIATIONS: _Plan("rowid", "expires_at_utc_us, evidence_id, association_index"),
    Store.CONNECTIONS: _Plan("id", "COALESCE(closed_at_utc_us, last_seen_utc_us), id",
                            "(closed_at_utc_us IS NOT NULL OR observation_gap = 1)"),
    Store.DNS: _Plan("id", "event_at_utc_us, id"),
    Store.BINDINGS: _Plan("id", "last_seen_utc_us, id",
                         "NOT EXISTS (SELECT 1 FROM device_profile_members m WHERE m.device_id = device_bindings.device_id)", minimum_age_days=90),
    Store.DEVICES: _Plan("id", "last_seen_utc_us, id",
                        "NOT EXISTS (SELECT 1 FROM device_profile_members m WHERE m.device_id = devices.id) "
                        "AND NOT EXISTS (SELECT 1 FROM device_bindings b WHERE b.device_id = devices.id)", minimum_age_days=90),
    Store.GATEWAY_CHANGES: _Plan("id", "changed_at_utc_us, id"),
    Store.ALERTS: _Plan("id", "updated_at_utc_us, id", "status = 'resolved'"),
    Store.INCIDENTS: _Plan("incident_id", "resolved_at, incident_id", "state = 'resolved'",
                          (("incident_revisions", "incident_id"), ("incident_references", "incident_id"))),
    Store.ASSESSMENTS: _Plan("assessment_id", "original_observed_at, assessment_id",
                            ASSESSMENT_UNPROTECTED, (("risk_assessment_revisions", "assessment_id"),)),
    Store.BASELINES: _Plan("(application_key, revision_digest, network_fingerprint)",
                          "last_observed_at, application_key, revision_digest, network_fingerprint",
                          minimum_age_days=90),
}

# Preserved stores have an explicit admission or structural quota, not retention.
_PRESERVED = (
    (Store.PROFILES, PROFILE_ROW_QUOTA), (Store.PROFILE_MEMBERS, DEVICE_ROW_QUOTA), (Store.GATEWAYS, GATEWAY_ROW_QUOTA),
    (Store.VLANS, 64), (Store.VLAN_IDS, 64 * 128),
    (Store.ASSESSMENT_REVISIONS, 512 * 8), (Store.INCIDENT_REVISIONS, 1024 * 32),
    (Store.INCIDENT_REFERENCES, 1024 * 320), (Store.PREFERENCES, 1024),
    (Store.PREFERENCE_REVISIONS, 16384),
)


class StorageUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Local storage maintenance is busy or unavailable.")


class SQLiteStorageMaintenanceRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @contextmanager
    def _connection(self, stop: Callable[[], bool]) -> Iterator[sqlite3.Connection]:
        with self.database.connection() as connection:
            connection.set_progress_handler(lambda: int(stop()), 1000)
            try:
                yield connection
            finally:
                connection.set_progress_handler(None, 0)

    @staticmethod
    def _eligible(store: Store, now: datetime) -> tuple[str, tuple[object, ...]]:
        if store is Store.CACHE:
            return "1", ()
        plan = _PLANS[store]
        predicate = plan.protected_filter
        args: tuple[object, ...] = ()
        if plan.minimum_age_days:
            column = "last_observed_at" if store is Store.BASELINES else "last_seen_utc_us"
            predicate += f" AND {column} < ?"
            cutoff = now - timedelta(days=plan.minimum_age_days)
            args = (cutoff.isoformat() if store is Store.BASELINES else _us(cutoff),)
        if store in (Store.INCIDENTS, Store.ALERTS):
            # Re-evaluate reopen safety inside the same write transaction.
            column = "resolved_at" if store is Store.INCIDENTS else "updated_at_utc_us"
            predicate += f" AND {column} < ?"
            horizon = now - timedelta(minutes=5)
            args += (horizon.isoformat() if store is Store.INCIDENTS else _us(horizon),)
        return predicate, args

    def summary(self, rules: tuple[StoreRetentionRule, ...], now: datetime,
                stop: Callable[[], bool]) -> StorageSummary:
        utc_now(now)
        summaries = []
        with self._connection(stop) as c:
            c.execute("BEGIN")
            try:
                for rule in rules:
                    predicate, args = self._eligible(rule.store, now)
                    row = c.execute(f"SELECT COUNT(*), COALESCE(SUM(CASE WHEN {predicate} THEN 1 ELSE 0 END),0) FROM {rule.store.value}", args).fetchone()
                    summaries.append(StoreSummary(rule.store, row[0], row[1], row[0] - row[1], rule.max_rows))
                for store, quota in _PRESERVED:
                    count = c.execute(f"SELECT COUNT(*) FROM {store.value}").fetchone()[0]
                    summaries.append(StoreSummary(store, count, 0, count, quota))
                schema = c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            finally:
                c.execute("ROLLBACK")
        db = self.database.path
        wal = db.with_name(db.name + "-wal")
        return StorageSummary(tuple(summaries), db.stat().st_size,
                              wal.stat().st_size if wal.exists() else 0, schema)

    def cleanup_chunk(self, rule: StoreRetentionRule, now: datetime, limit: int,
                      purge: bool, stop: Callable[[], bool]) -> int:
        utc_now(now)
        if type(limit) is not int or not 1 <= limit <= rule.chunk_rows or type(purge) is not bool:
            raise ValueError("invalid cleanup bound")
        if stop():
            return 0
        if rule.store is Store.CACHE:
            # Reuse NS-085 TTL, stale priority and explicit purge semantics.
            policy = replace(ThreatIntelCachePolicy(), cleanup_chunk=min(limit, 128))
            repo = SQLiteThreatIntelCacheRepository(self.database, policy)
            receipt = repo.purge() if purge else repo.cleanup(now)
            if receipt.status is not ThreatIntelCacheMutationStatus.PURGED:
                raise StorageUnavailable()
            return receipt.affected
        plan = _PLANS[rule.store]
        predicate, args = self._eligible(rule.store, now)
        with self._connection(stop) as c, transaction(c):
            excess = max(0, c.execute(f"SELECT COUNT(*) FROM {rule.store.value}").fetchone()[0] - rule.max_rows)
            if not purge:
                column = plan.order.split(",")[0]
                if rule.store is Store.CONNECTIONS:
                    column = "COALESCE(closed_at_utc_us, last_seen_utc_us)"
                if rule.store is Store.ASSOCIATIONS:
                    age_arg: object = _us(now)
                    comparison = "<="
                elif rule.age_days is not None:
                    cutoff = now - timedelta(days=rule.age_days)
                    age_arg = cutoff.isoformat(timespec="microseconds") if rule.store is Store.ASSESSMENTS else cutoff.isoformat() if rule.store in (Store.BASELINES, Store.INCIDENTS) else _us(cutoff)
                    comparison = "<"
                else:
                    raise ValueError("age policy missing")
                # UNION-like ordering without unbounded Python candidates: old
                # age candidates first, or oldest eligible rows above quota.
                predicate += f" AND ({column} {comparison} ? OR ? > 0)"
                args += (age_arg, excess)
            candidate_limit = min(limit, 16) if plan.children else limit
            projection = plan.key.strip("()")
            rows = c.execute(f"SELECT {projection} FROM {rule.store.value} WHERE {predicate} ORDER BY {plan.order} LIMIT ?",
                             (*args, candidate_limit)).fetchall()
            deleted = 0
            for index, row in enumerate(rows):
                if stop():
                    # Interrupting inside a transaction rolls back this chunk.
                    raise StorageUnavailable()
                key = tuple(row)
                placeholders = "(" + ",".join("?" for _ in key) + ")" if len(key) > 1 else "?"
                owned = 1
                for table, fk in plan.children:
                    owned += c.execute(f"SELECT COUNT(*) FROM {table} WHERE {fk} = ?", key).fetchone()[0]
                if deleted + owned > limit:
                    # A corrupt oversized parent stays protected; no cascade
                    # can silently exceed the physical deletion budget.
                    continue
                if not purge and index >= excess:
                    # Above-quota eligibility is limited to the actual excess.
                    age_column = "COALESCE(closed_at_utc_us, last_seen_utc_us)" if rule.store is Store.CONNECTIONS else plan.order.split(",")[0]
                    age = c.execute(f"SELECT {age_column} {comparison} ? FROM {rule.store.value} WHERE {plan.key} = {placeholders}",
                                    (age_arg, *key)).fetchone()[0]
                    if not age:
                        continue
                c.execute(f"DELETE FROM {rule.store.value} WHERE {plan.key} = {placeholders}", key)
                deleted += owned
            if deleted and rule.store is Store.BASELINES:
                c.execute("UPDATE behavior_baseline_storage SET capacity_loss = 1 WHERE singleton = 1")
            return deleted

    def export_page(self, category: Store, offset: int, limit: int,
                    stop: Callable[[], bool]) -> tuple[SupportRecord, ...]:
        if category not in (Store.ALERTS, Store.INCIDENTS) or type(offset) is not int or not 0 <= offset <= 50 or type(limit) is not int or not 1 <= limit <= 25:
            raise ValueError("export page outside bounds")
        projection = "status, severity" if category is Store.ALERTS else "state, revision"
        key = "id" if category is Store.ALERTS else "incident_id"
        with self._connection(stop) as c:
            rows = c.execute(f"SELECT {projection} FROM {category.value} ORDER BY {key} LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        result = []
        for row in rows:
            try:
                result.append(SupportRecord(category, row[0], severity=row[1]) if category is Store.ALERTS
                              else SupportRecord(category, row[0], revision=row[1]))
            except (TypeError, ValueError):
                # Corrupt/unrecognized enum data never leaks through projection.
                continue
        return tuple(result)


def _us(value: datetime) -> int:
    return int(value.timestamp()) * 1_000_000 + value.microsecond
