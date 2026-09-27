"""SQLite mapping for bounded, portable DNS transaction history."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Callable
from datetime import datetime
import json
from math import isfinite
import sqlite3
from typing import Iterator
from uuid import UUID

from netsentinel.application.ports import (
    DnsHistoryDataCorrupt, DnsHistoryQuery, DnsHistoryQueryCancelled, DnsHistoryRepositoryError,
)
from netsentinel.domain.dns import (
    DnsAnswer, DnsHistoryRecord, DnsQuestion, DnsRecordType, DnsTransaction,
    DnsTransactionStatus, DnsTransport,
)
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.repositories import (
    datetime_to_epoch_microseconds as to_us, epoch_microseconds_to_datetime as from_us,
)

_COLUMNS = (
    "id, status, network_fingerprint, transport, client_ip, client_port, "
    "server_ip, server_port, transaction_id, qname, questions_json, "
    "query_at_utc_us, response_at_utc_us, event_at_utc_us, latency_us, "
    "response_code, truncated, answers_json, retry_count"
)


def _encode(record: DnsHistoryRecord) -> tuple[object, ...]:
    tx = record.transaction
    if tx.latency_seconds is not None and (
        not isfinite(tx.latency_seconds) or tx.latency_seconds > 9_223_372_036_854
    ):
        raise ValueError("DNS latency is outside the storage bound")
    questions = json.dumps([[q.name, q.record_type] for q in tx.questions], separators=(",", ":"))
    answers = json.dumps(
        [[a.name, a.record_type.value, a.value, a.ttl] for a in tx.answers],
        separators=(",", ":"),
    )
    if len(questions) > 1200 or len(answers) > 10000:
        raise ValueError("DNS metadata exceeds the storage bound")
    event_at = tx.query_at or tx.response_at
    assert event_at is not None
    return (
        str(record.id), tx.status.value, tx.network_fingerprint, tx.transport.value,
        tx.client_ip, tx.client_port, tx.server_ip, tx.server_port, tx.transaction_id,
        tx.questions[0].name if tx.questions else None, questions,
        to_us(tx.query_at) if tx.query_at else None,
        to_us(tx.response_at) if tx.response_at else None,
        to_us(event_at),
        round(tx.latency_seconds * 1_000_000) if tx.latency_seconds is not None else None,
        tx.response_code, int(tx.truncated), answers, tx.retry_count,
    )


def _decode(row: sqlite3.Row) -> DnsHistoryRecord:
    try:
        questions_raw = json.loads(row["questions_json"])
        answers_raw = json.loads(row["answers_json"])
        questions = tuple(DnsQuestion(*item) for item in questions_raw)
        answers = tuple(DnsAnswer(item[0], DnsRecordType(item[1]), item[2], item[3]) for item in answers_raw)
        tx = DnsTransaction(
            status=DnsTransactionStatus(row["status"]),
            network_fingerprint=row["network_fingerprint"],
            transport=DnsTransport(row["transport"]),
            client_ip=row["client_ip"], client_port=row["client_port"],
            server_ip=row["server_ip"], server_port=row["server_port"],
            transaction_id=row["transaction_id"], questions=questions,
            query_at=from_us(row["query_at_utc_us"]) if row["query_at_utc_us"] is not None else None,
            response_at=from_us(row["response_at_utc_us"]) if row["response_at_utc_us"] is not None else None,
            latency_seconds=row["latency_us"] / 1_000_000 if row["latency_us"] is not None else None,
            response_code=row["response_code"], truncated=bool(row["truncated"]),
            answers=answers, retry_count=row["retry_count"],
        )
        if row["qname"] != (questions[0].name if questions else None):
            raise ValueError("inconsistent qname")
        if row["event_at_utc_us"] != to_us(tx.query_at or tx.response_at):
            raise ValueError("inconsistent event time")
        return DnsHistoryRecord(UUID(row["id"]), tx)
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, json.JSONDecodeError):
        raise DnsHistoryDataCorrupt("Persisted DNS history is invalid.") from None


class SQLiteDnsHistoryRepository:
    """Each public call owns its connection; the writer uses write_batch on one owned session."""

    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database

    def record(self, record: DnsHistoryRecord) -> None:
        self.write_batch((record,))

    def write_batch(self, records: tuple[DnsHistoryRecord, ...]) -> None:
        try:
            with self._database.connection() as connection:
                self._insert_batch(connection, records)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsHistoryRepositoryError("DNS history could not be written.") from None

    @staticmethod
    def _insert_batch(connection: sqlite3.Connection, records: tuple[DnsHistoryRecord, ...]) -> None:
        if not 1 <= len(records) <= 500:
            raise ValueError("batch size must be between 1 and 500")
        values = tuple(_encode(record) for record in records)
        with transaction(connection):
            for value in values:
                cursor = connection.execute(
                    f"INSERT INTO dns_history ({_COLUMNS}) VALUES ({','.join('?' for _ in value)}) "
                    "ON CONFLICT(id) DO NOTHING",
                    value,
                )
                if cursor.rowcount == 0:
                    existing = connection.execute(
                        f"SELECT {_COLUMNS} FROM dns_history WHERE id = ?", (value[0],)
                    ).fetchone()
                    if existing is None or tuple(existing) != value:
                        raise ValueError("record identity conflict")

    def get(self, record_id: UUID) -> DnsHistoryRecord | None:
        if not isinstance(record_id, UUID):
            raise TypeError("record_id must be a UUID")
        try:
            with self._database.connection() as connection:
                row = connection.execute(f"SELECT {_COLUMNS} FROM dns_history WHERE id = ?", (str(record_id),)).fetchone()
            return _decode(row) if row is not None else None
        except DnsHistoryDataCorrupt:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsHistoryRepositoryError("DNS history could not be read.") from None

    def query(self, query: DnsHistoryQuery, *, is_cancelled: Callable[[], bool] | None = None) -> tuple[DnsHistoryRecord, ...]:
        if not isinstance(query, DnsHistoryQuery):
            raise TypeError("query must be a DnsHistoryQuery")
        filters: list[str] = []
        parameters: list[object] = []
        for field, value in (
            ("event_at_utc_us >= ?", to_us(query.event_from) if query.event_from else None),
            ("event_at_utc_us <= ?", to_us(query.event_to) if query.event_to else None),
            ("network_fingerprint = ?", query.network_fingerprint),
            ("qname = ?", query.qname),
            ("CAST(json_extract(questions_json, '$[0][1]') AS INTEGER) = ?", query.qtype),
            ("server_ip = ?", query.server_ip),
            ("status = ?", query.status.value if query.status else None),
            ("transport = ?", query.transport.value if query.transport else None),
        ):
            if value is not None:
                filters.append(field)
                parameters.append(value)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        parameters.extend((query.limit, query.offset))
        try:
            with self._database.connection() as connection:
                if is_cancelled is not None:
                    connection.set_progress_handler(lambda: 1 if is_cancelled() else 0, 1000)
                rows = connection.execute(
                    f"SELECT {_COLUMNS} FROM dns_history{where} "
                    "ORDER BY event_at_utc_us DESC, id DESC LIMIT ? OFFSET ?",
                    parameters,
                ).fetchall()
            if is_cancelled is not None and is_cancelled():
                raise DnsHistoryQueryCancelled("DNS history query was cancelled.")
            return tuple(_decode(row) for row in rows)
        except DnsHistoryQueryCancelled:
            raise
        except DnsHistoryDataCorrupt:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            if is_cancelled is not None and is_cancelled():
                raise DnsHistoryQueryCancelled("DNS history query was cancelled.") from None
            raise DnsHistoryRepositoryError("DNS history could not be read.") from None

    def delete_before(self, cutoff: datetime, limit: int) -> int:
        cutoff_us = to_us(cutoff)
        _positive(limit)
        if limit > 500:
            raise ValueError("limit cannot exceed 500")
        try:
            with self._database.connection() as connection, transaction(connection):
                cursor = connection.execute(
                    "DELETE FROM dns_history WHERE id IN (SELECT id FROM dns_history "
                    "WHERE event_at_utc_us < ? ORDER BY event_at_utc_us ASC, id ASC LIMIT ?)",
                    (cutoff_us, limit),
                )
                return cursor.rowcount
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsHistoryRepositoryError("DNS history cleanup failed.") from None

    def delete_oldest_over_limit(self, max_rows: int, limit: int) -> int:
        _positive(max_rows)
        _positive(limit)
        if limit > 500:
            raise ValueError("limit cannot exceed 500")
        try:
            with self._database.connection() as connection, transaction(connection):
                excess = max(0, connection.execute("SELECT COUNT(*) FROM dns_history").fetchone()[0] - max_rows)
                if not excess:
                    return 0
                cursor = connection.execute(
                    "DELETE FROM dns_history WHERE id IN (SELECT id FROM dns_history "
                    "ORDER BY event_at_utc_us ASC, id ASC LIMIT ?)",
                    (min(excess, limit),),
                )
                return cursor.rowcount
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsHistoryRepositoryError("DNS history cleanup failed.") from None


def _positive(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("limit must be a positive integer")


class SQLiteDnsHistoryWriteSession:
    """Reusable writer-thread connection with atomic batches."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def write_batch(self, records: tuple[DnsHistoryRecord, ...]) -> None:
        try:
            SQLiteDnsHistoryRepository._insert_batch(self._connection, records)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsHistoryRepositoryError("DNS history batch could not be written.") from None


class SQLiteDnsHistorySessionFactory:
    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database

    @contextmanager
    def __call__(self) -> Iterator[SQLiteDnsHistoryWriteSession]:
        with self._database.connection() as connection:
            yield SQLiteDnsHistoryWriteSession(connection)
