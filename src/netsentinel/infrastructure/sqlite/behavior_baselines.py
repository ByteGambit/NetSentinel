"""NS-071 parameterized, bounded summaries on a worker-owned connection."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, fields
from datetime import datetime, timedelta
import json
import sqlite3

from netsentinel.application.ports import BaselineRepository
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.behavior_baseline import (
    BaselineLoad, BaselineRead, BaselineState, BaselineSummary,
    FEATURE_POLICY_VERSION, SUMMARY_VERSION, MAX_BASELINE_PAYLOAD_BYTES,
    validate_baseline_scope, validate_baseline_summary,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import NetworkScopeStatus, TransportProtocol
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, transaction
from netsentinel.shared.config import BehaviorBaselineConfig


def encode_summary(summary: BaselineSummary) -> str:
    validate_baseline_summary(summary)
    data = asdict(summary.features)
    del data["scope"]
    for name in ("destinations", "ports", "protocols"):
        data[name] = sorted(data[name], key=lambda item: str(item["value"]))
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(payload.encode("utf-8")) > MAX_BASELINE_PAYLOAD_BYTES:
        raise ValueError("baseline payload exceeds quota")
    return payload


def decode_summary(row: sqlite3.Row) -> BaselineRead:
    scope = None
    try:
        scope = BehaviorScopeKey(row["application_key"], ApplicationIdentityQuality.STABLE,
                                 row["revision_digest"] or None, NetworkScopeStatus.RESOLVED,
                                 row["network_fingerprint"])
        try:
            validate_baseline_scope(scope)
        except (ValueError, TypeError):
            return BaselineRead(None, BaselineState.CORRUPT)
        if type(row["summary_version"]) is not int or row["summary_version"] != SUMMARY_VERSION:
            return BaselineRead(scope, BaselineState.UNSUPPORTED_VERSION)
        if type(row["feature_policy_version"]) is not int or row["feature_policy_version"] != FEATURE_POLICY_VERSION:
            return BaselineRead(scope, BaselineState.POLICY_MISMATCH)
        payload = row["payload"]
        if not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_BASELINE_PAYLOAD_BYTES:
            raise ValueError("oversized payload")
        data = json.loads(payload, object_pairs_hook=_unique_object)
        expected = {item.name for item in fields(BehaviorFeatureSnapshot)} - {"scope"}
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError("invalid summary fields")
        for name, cap in (("destinations", 64), ("ports", 32), ("protocols", 2)):
            items = data[name]
            if not isinstance(items, list) or len(items) > cap:
                raise ValueError("feature map exceeds quota")
            parsed = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {"value", "observed_appearances"}:
                    raise ValueError("invalid feature fields")
                value = TransportProtocol(item["value"]) if name == "protocols" else item["value"]
                parsed.append(FeatureCount(value, item["observed_appearances"]))
            data[name] = tuple(parsed)
        summary = BaselineSummary(
            BehaviorFeatureSnapshot(scope=scope, **data),
            datetime.fromisoformat(row["last_observed_at"]),
            datetime.fromisoformat(row["persisted_at"]), row["policy_key"],
            row["summary_version"], row["feature_policy_version"],
        )
        validate_baseline_summary(summary)
        return BaselineRead(scope, BaselineState.LEARNING, summary)
    except (ValueError, TypeError, OverflowError, RecursionError, KeyError, AttributeError):
        return BaselineRead(scope, BaselineState.CORRUPT)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate JSON field")
        data[key] = value
    return data


class SQLiteBaselineRepository:
    """No domain lifecycle heuristics; each mutation has a short transaction."""

    def __init__(self, connection: sqlite3.Connection, config: BehaviorBaselineConfig | None = None) -> None:
        self._connection = connection
        self.config = config or BehaviorBaselineConfig()

    def load(self, limit: int) -> BaselineLoad:
        if type(limit) is not int or not 1 <= limit <= self.config.load_limit:
            raise ValueError("baseline load limit outside quota")
        rows = self._connection.execute(
            """SELECT application_key, revision_digest, network_fingerprint,
                      summary_version, feature_policy_version, policy_key,
                      CASE WHEN length(last_observed_at) <= 32 THEN last_observed_at ELSE NULL END AS last_observed_at,
                      CASE WHEN length(persisted_at) <= 32 THEN persisted_at ELSE NULL END AS persisted_at,
                      CASE WHEN length(CAST(payload AS BLOB)) <= 16384 THEN payload ELSE NULL END AS payload
               FROM behavior_baselines
               ORDER BY last_observed_at DESC, application_key, revision_digest, network_fingerprint
               LIMIT ?""", (limit + 1,),
        ).fetchall()
        storage = self._connection.execute(
            "SELECT capacity_loss FROM behavior_baseline_storage WHERE singleton = 1"
        ).fetchone()
        # Missing/corrupt metadata is conservatively a loss, never empty knowledge.
        loss = storage is None or type(storage[0]) is not int or storage[0] != 0
        return BaselineLoad(tuple(decode_summary(row) for row in rows[:limit]), loss or len(rows) > limit)

    def write(self, summary: BaselineSummary | None, scope: BehaviorScopeKey, *, reset: bool = False) -> int:
        validate_baseline_scope(scope)
        params = (scope.application_key, scope.revision_digest or "", scope.network_token)
        payload = None if summary is None else encode_summary(summary)
        if summary is not None and summary.features.scope != scope:
            raise ValueError("summary scope mismatch")
        deleted = 0
        with transaction(self._connection):
            if reset:
                self._connection.execute(
                    "DELETE FROM behavior_baselines WHERE application_key = ? AND revision_digest = ? AND network_fingerprint = ?", params,
                )
            if summary is not None:
                existing = self._connection.execute(
                    "SELECT 1 FROM behavior_baselines WHERE application_key = ? AND revision_digest = ? AND network_fingerprint = ?", params,
                ).fetchone()
                count = self._connection.execute("SELECT COUNT(*) FROM behavior_baselines").fetchone()[0]
                if existing is None and count >= self.config.max_rows:
                    # One new scope displaces at most one row in the normal path.
                    deleted = self._delete_oldest(min(count - self.config.max_rows + 1, self.config.cleanup_chunk_size))
                    if count - deleted >= self.config.max_rows:
                        raise ValueError("baseline quota requires cleanup")
                self._connection.execute(
                    """INSERT INTO behavior_baselines
                       (application_key, revision_digest, network_fingerprint, summary_version,
                        feature_policy_version, policy_key, last_observed_at, persisted_at, payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(application_key, revision_digest, network_fingerprint) DO UPDATE SET
                       summary_version = excluded.summary_version,
                       feature_policy_version = excluded.feature_policy_version,
                       policy_key = excluded.policy_key, last_observed_at = excluded.last_observed_at,
                       persisted_at = excluded.persisted_at, payload = excluded.payload""",
                    (*params, summary.summary_version, summary.feature_policy_version, summary.policy_key,
                     summary.last_observed_at.isoformat(), summary.persisted_at.isoformat(), payload),
                )
        return deleted

    def _delete_oldest(self, limit: int) -> int:
        deleted = self._connection.execute(
            """DELETE FROM behavior_baselines WHERE (application_key, revision_digest, network_fingerprint) IN
               (SELECT application_key, revision_digest, network_fingerprint FROM behavior_baselines
                ORDER BY last_observed_at, application_key, revision_digest, network_fingerprint LIMIT ?)""", (limit,),
        ).rowcount
        if deleted:
            self._mark_loss()
        return deleted

    def _mark_loss(self) -> None:
        self._connection.execute("UPDATE behavior_baseline_storage SET capacity_loss = 1 WHERE singleton = 1")

    def cleanup(self, now: datetime) -> int:
        offset = now.utcoffset()
        if now.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("cleanup clock must be UTC")
        cutoff = (now - timedelta(days=self.config.retention_days)).isoformat()
        with transaction(self._connection):
            deleted = self._connection.execute(
                """DELETE FROM behavior_baselines WHERE (application_key, revision_digest, network_fingerprint) IN
                   (SELECT application_key, revision_digest, network_fingerprint FROM behavior_baselines
                    WHERE last_observed_at <= ?
                    ORDER BY last_observed_at, application_key, revision_digest, network_fingerprint LIMIT ?)""",
                (cutoff, self.config.cleanup_chunk_size),
            ).rowcount
            count = self._connection.execute("SELECT COUNT(*) FROM behavior_baselines").fetchone()[0]
            if deleted:
                self._mark_loss()
            remaining = self.config.cleanup_chunk_size - deleted
            if remaining > 0 and count > self.config.max_rows:
                deleted += self._delete_oldest(min(remaining, count - self.config.max_rows))
            return deleted


@contextmanager
def baseline_repository_session(database: SQLiteDatabase, config: BehaviorBaselineConfig) -> Iterator[BaselineRepository]:
    with database.connection() as connection:
        yield SQLiteBaselineRepository(connection, config)
