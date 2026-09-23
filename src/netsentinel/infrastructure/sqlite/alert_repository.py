"""Transactional, bounded SQLite storage for portable NS-028 alerts."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import sqlite3
from uuid import UUID

from netsentinel.application.ports import AlertDataCorrupt, AlertQuery, AlertRepositoryError
from netsentinel.domain.alerts import (
    Alert, AlertCandidate, AlertEvidence, AlertStatus, ArpScoreComponent,
    ArpScoreRule, MAX_ALERT_EVIDENCE, alert_id,
)
from netsentinel.domain.devices import GatewayBaselineStatus
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.repositories import datetime_to_epoch_microseconds as to_us, epoch_microseconds_to_datetime as from_us


_COLUMNS = "id, fingerprint, rule_id, network_fingerprint, entity_id, severity, confidence, status, first_seen_utc_us, last_seen_utc_us, occurrence_count, evidence_json, created_at_utc_us, updated_at_utc_us, last_notified_at_utc_us"


def _encode(items: tuple[AlertEvidence, ...]) -> str:
    value = json.dumps([{
        "observed_at": to_us(item.observed_at),
        "ip_address": item.ip_address,
        "observed_mac": str(item.observed_mac) if item.observed_mac is not None else None,
        "expected_mac": str(item.expected_mac) if item.expected_mac is not None else None,
        "expected_last_seen_at": to_us(item.expected_last_seen_at) if item.expected_last_seen_at is not None else None,
        "baseline_status": item.baseline_status.value if item.baseline_status is not None else None,
        "score": item.score,
        "breakdown": [[part.rule.value, part.points] for part in item.breakdown],
        "observation_count": item.observation_count,
        "details": item.details,
    } for item in items], separators=(",", ":"), sort_keys=True)
    if len(value) > 8192:
        raise ValueError("alert evidence exceeds storage bound")
    return value


def _decode(value: str) -> tuple[AlertEvidence, ...]:
    data = json.loads(value)
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_ALERT_EVIDENCE:
        raise ValueError("invalid evidence list")
    return tuple(AlertEvidence(
        from_us(item["observed_at"]), item["ip_address"],
        MacAddress(item["observed_mac"]) if item["observed_mac"] is not None else None,
        MacAddress(item["expected_mac"]) if item["expected_mac"] is not None else None,
        from_us(item["expected_last_seen_at"]) if item["expected_last_seen_at"] is not None else None,
        GatewayBaselineStatus(item["baseline_status"]) if item["baseline_status"] is not None else None,
        item["score"], tuple(ArpScoreComponent(ArpScoreRule(rule), points) for rule, points in item["breakdown"]),
        item["observation_count"], tuple(tuple(pair) for pair in item.get("details", ())),
    ) for item in data)


def _map(row: sqlite3.Row) -> Alert:
    try:
        return Alert(
            UUID(row["id"]), row["fingerprint"], row["rule_id"], row["network_fingerprint"],
            row["entity_id"], row["severity"], row["confidence"], AlertStatus(row["status"]),
            from_us(row["first_seen_utc_us"]), from_us(row["last_seen_utc_us"]),
            row["occurrence_count"], _decode(row["evidence_json"]),
            from_us(row["created_at_utc_us"]), from_us(row["updated_at_utc_us"]),
            from_us(row["last_notified_at_utc_us"]),
        )
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, json.JSONDecodeError) as error:
        raise AlertDataCorrupt("Persisted alert contains unsupported data.") from error


class SQLiteAlertRepository:
    """Each call owns its connection; BEGIN IMMEDIATE serializes duplicate writes."""

    def __init__(self, database: SQLiteDatabase) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be SQLiteDatabase")
        self._database = database

    def record(self, candidate: AlertCandidate, now: datetime, rate_window: timedelta) -> tuple[Alert, bool]:
        if not isinstance(candidate, AlertCandidate) or not isinstance(rate_window, timedelta) or rate_window <= timedelta(0):
            raise ValueError("invalid alert write")
        now_us = to_us(now)
        seen_us = to_us(candidate.evidence.observed_at)
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    row = connection.execute(f"SELECT {_COLUMNS} FROM alerts WHERE fingerprint = ?", (candidate.fingerprint,)).fetchone()
                    if row is None:
                        connection.execute("""INSERT INTO alerts (id, fingerprint, rule_id, network_fingerprint, entity_id, severity, confidence, status, first_seen_utc_us, last_seen_utc_us, occurrence_count, evidence_json, created_at_utc_us, updated_at_utc_us, last_notified_at_utc_us)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (str(alert_id(candidate.fingerprint)), candidate.fingerprint, candidate.rule_id,
                             candidate.network_fingerprint, candidate.entity_id, candidate.severity, candidate.confidence,
                             AlertStatus.OPEN.value, seen_us, seen_us, 1, _encode((candidate.evidence,)), now_us, now_us, now_us))
                        notify = True
                    else:
                        old = _map(row)
                        if (old.rule_id, old.network_fingerprint, old.entity_id) != (candidate.rule_id, candidate.network_fingerprint, candidate.entity_id):
                            raise AlertDataCorrupt("Alert fingerprint identity is inconsistent.")
                        if candidate.evidence.observed_at <= old.last_seen:
                            return old, False
                        evidence = (old.evidence + (candidate.evidence,))[-MAX_ALERT_EVIDENCE:]
                        notify = (old.status is AlertStatus.RESOLVED or candidate.severity != old.severity
                                  or candidate.confidence != old.confidence
                                  or now >= old.last_notified_at + rate_window)
                        connection.execute("""UPDATE alerts SET severity = ?, confidence = ?, status = ?,
                            last_seen_utc_us = ?, occurrence_count = occurrence_count + 1,
                            evidence_json = ?, updated_at_utc_us = ?, last_notified_at_utc_us = ?
                            WHERE fingerprint = ?""",
                            (candidate.severity, candidate.confidence,
                             AlertStatus.OPEN.value if old.status is AlertStatus.RESOLVED else old.status.value,
                             seen_us, _encode(evidence), max(now_us, to_us(old.updated_at)),
                             max(now_us, to_us(old.last_notified_at)) if notify else to_us(old.last_notified_at),
                             candidate.fingerprint))
                    updated = connection.execute(f"SELECT {_COLUMNS} FROM alerts WHERE fingerprint = ?", (candidate.fingerprint,)).fetchone()
                    return _map(updated), notify
        except AlertRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, ValueError, TypeError) as error:
            raise AlertRepositoryError("Alert persistence failed.") from error

    def set_status(self, alert_id_value: UUID, status: AlertStatus, now: datetime) -> Alert | None:
        if not isinstance(alert_id_value, UUID) or not isinstance(status, AlertStatus):
            raise TypeError("alert id and status must be typed")
        now_us = to_us(now)
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    row = connection.execute(f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (str(alert_id_value),)).fetchone()
                    if row is None:
                        return None
                    old = _map(row)
                    if old.status is status:
                        return old
                    connection.execute("UPDATE alerts SET status = ?, updated_at_utc_us = ? WHERE id = ?",
                                       (status.value, max(now_us, to_us(old.updated_at)), str(alert_id_value)))
                    return _map(connection.execute(f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (str(alert_id_value),)).fetchone())
        except AlertRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, ValueError, TypeError) as error:
            raise AlertRepositoryError("Alert status update failed.") from error

    def get(self, alert_id_value: UUID) -> Alert | None:
        if not isinstance(alert_id_value, UUID):
            raise TypeError("alert id must be UUID")
        try:
            with self._database.connection() as connection:
                row = connection.execute(f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (str(alert_id_value),)).fetchone()
                return _map(row) if row is not None else None
        except AlertRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise AlertRepositoryError("Alert read failed.") from error

    def query(self, query: AlertQuery) -> tuple[Alert, ...]:
        if not isinstance(query, AlertQuery):
            raise TypeError("query must be AlertQuery")
        clauses: list[str] = []
        values: list[object] = []
        for column, value in (("rule_id", query.rule_id), ("network_fingerprint", query.network_fingerprint),
                              ("severity", query.severity), ("confidence", query.confidence),
                              ("status", query.status.value if query.status is not None else None)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    f"SELECT {_COLUMNS} FROM alerts{where} ORDER BY last_seen_utc_us DESC, id LIMIT ? OFFSET ?",
                    (*values, query.limit, query.offset),
                ).fetchall()
                return tuple(_map(row) for row in rows)
        except AlertRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise AlertRepositoryError("Alert query failed.") from error


__all__ = ("SQLiteAlertRepository",)
