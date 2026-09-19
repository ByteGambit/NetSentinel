"""SQLite adapters for portable application repository ports."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import sqlite3
from uuid import UUID, uuid4

from netsentinel.application.ports import (
    ConnectionHistoryQuery,
    HistoryDataCorrupt,
    HistoryRecordNotFound,
    HistoryRepositoryError,
)
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
    ConnectionHistoryRecord,
    ConnectionKey,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.infrastructure.sqlite.database import (
    SQLiteAdapterError,
    SQLiteDatabase,
    transaction,
)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_HISTORY_COLUMNS = """
    id, protocol, local_address, local_port, remote_address, remote_port,
    pid, process_create_time_utc_us, process_name, process_status,
    connection_state, first_seen_utc_us, last_seen_utc_us,
    closed_at_utc_us, close_reason
"""


def datetime_to_epoch_microseconds(value: datetime) -> int:
    """Map a UTC-aware datetime to an exact integer Unix microsecond value."""

    if not isinstance(value, datetime):
        raise TypeError("timestamp must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use a UTC offset")
    delta = value.astimezone(UTC) - _EPOCH
    result = (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )
    if result < 0:
        raise ValueError("timestamp cannot precede the Unix epoch")
    return result


def epoch_microseconds_to_datetime(value: int) -> datetime:
    """Map an integer Unix microsecond value to an aware UTC datetime."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("persisted timestamp must be an integer")
    if value < 0:
        raise ValueError("persisted timestamp cannot be negative")
    try:
        return _EPOCH + timedelta(microseconds=value)
    except OverflowError as error:
        raise ValueError("persisted timestamp is outside the datetime range") from error


class SQLiteConnectionHistoryRepository:
    """Synchronous SQLite implementation of ``ConnectionHistoryRepository``.

    Every public operation owns one short-lived, migrated connection.  Writes
    use NS-014's transaction helper and never create workers, queues, or
    background threads; NS-016 can safely coordinate calls from its writer.
    """

    def __init__(
        self,
        database: SQLiteDatabase,
        *,
        record_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be a SQLiteDatabase")
        if not callable(record_id_factory):
            raise TypeError("record_id_factory must be callable")
        self._database = database
        self._record_id_factory = record_id_factory

    def record_opened(self, event: ConnectionOpened) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionOpened):
            raise TypeError("event must be a ConnectionOpened")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    existing_row = self._find_by_key_and_first_seen(
                        connection,
                        event.key,
                        datetime_to_epoch_microseconds(event.occurred_at),
                    )
                    if existing_row is None:
                        existing_row = self._find_active(connection, event.key)
                    if existing_row is not None:
                        existing = _row_to_record(existing_row)
                        if existing.is_closed:
                            return existing
                        if event.occurred_at >= existing.last_seen:
                            self._update_snapshot(
                                connection,
                                existing.record_id,
                                event.snapshot,
                            )
                            return self._get_required(connection, existing.record_id)
                        return existing

                    record_id = self._new_record_id()
                    self._insert_open(connection, record_id, event.snapshot)
                    return self._get_required(connection, record_id)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def record_updated(self, event: ConnectionUpdated) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionUpdated):
            raise TypeError("event must be a ConnectionUpdated")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    row = self._find_active(connection, event.key)
                    if row is None:
                        raise HistoryRecordNotFound(
                            "The active connection history record was not found."
                        )
                    existing = _row_to_record(row)
                    if event.current.observed_at < existing.last_seen:
                        raise HistoryRepositoryError(
                            "Connection history cannot move backwards in time."
                        )
                    self._update_snapshot(
                        connection,
                        existing.record_id,
                        event.current,
                    )
                    return self._get_required(connection, existing.record_id)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def record_closed(self, event: ConnectionClosed) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionClosed):
            raise TypeError("event must be a ConnectionClosed")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    row = self._find_active(connection, event.key)
                    if row is None:
                        return self._get_duplicate_close(connection, event)

                    existing = _row_to_record(row)
                    if event.occurred_at < existing.first_seen:
                        return self._get_duplicate_close(connection, event)
                    if event.last_snapshot.observed_at < existing.last_seen:
                        raise HistoryRepositoryError(
                            "Connection history cannot move backwards in time."
                        )
                    if event.occurred_at < existing.last_seen:
                        raise HistoryRepositoryError(
                            "Connection close time precedes the last observation."
                        )
                    self._close_record(
                        connection,
                        existing.record_id,
                        event,
                    )
                    return self._get_required(connection, existing.record_id)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def get(self, record_id: UUID) -> ConnectionHistoryRecord | None:
        if not isinstance(record_id, UUID):
            raise TypeError("record_id must be a UUID")
        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    f"SELECT {_HISTORY_COLUMNS} FROM connection_history WHERE id = ?",
                    (str(record_id),),
                ).fetchone()
                return None if row is None else _row_to_record(row)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise HistoryRepositoryError(
                "Connection history could not be read."
            ) from error

    def query(
        self, query: ConnectionHistoryQuery
    ) -> tuple[ConnectionHistoryRecord, ...]:
        if not isinstance(query, ConnectionHistoryQuery):
            raise TypeError("query must be a ConnectionHistoryQuery")
        try:
            clauses: list[str] = []
            parameters: list[object] = []
            if query.first_seen_from is not None:
                clauses.append("first_seen_utc_us >= ?")
                parameters.append(
                    datetime_to_epoch_microseconds(query.first_seen_from)
                )
            if query.first_seen_to is not None:
                clauses.append("first_seen_utc_us <= ?")
                parameters.append(datetime_to_epoch_microseconds(query.first_seen_to))
            if query.protocol is not None:
                clauses.append("protocol = ?")
                parameters.append(query.protocol.value)
            if query.process_name is not None:
                clauses.append("process_name = ? COLLATE NOCASE")
                parameters.append(query.process_name)
            if query.pid is not None:
                clauses.append("pid = ?")
                parameters.append(query.pid)
            if query.endpoint_address is not None:
                clauses.append("(local_address = ? OR remote_address = ?)")
                parameters.extend((query.endpoint_address, query.endpoint_address))

            where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
            parameters.extend((query.limit, query.offset))
            statement = (
                f"SELECT {_HISTORY_COLUMNS} FROM connection_history{where} "
                "ORDER BY first_seen_utc_us DESC, id DESC LIMIT ? OFFSET ?"
            )
            with self._database.connection() as connection:
                rows = connection.execute(statement, parameters).fetchall()
                return tuple(_row_to_record(row) for row in rows)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be read."
            ) from error

    def _new_record_id(self) -> UUID:
        record_id = self._record_id_factory()
        if not isinstance(record_id, UUID):
            raise TypeError("record_id_factory must return a UUID")
        return record_id

    @staticmethod
    def _insert_open(
        connection: sqlite3.Connection,
        record_id: UUID,
        snapshot: ConnectionSnapshot,
    ) -> None:
        values = _snapshot_values(snapshot)
        observed_at = datetime_to_epoch_microseconds(snapshot.observed_at)
        connection.execute(
            """
            INSERT INTO connection_history (
                id, protocol, local_address, local_port, remote_address,
                remote_port, pid, process_create_time_utc_us, process_name,
                process_status, connection_state, first_seen_utc_us,
                last_seen_utc_us, closed_at_utc_us, close_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (str(record_id), *values, observed_at, observed_at),
        )

    @staticmethod
    def _update_snapshot(
        connection: sqlite3.Connection,
        record_id: UUID,
        snapshot: ConnectionSnapshot,
    ) -> None:
        values = _snapshot_values(snapshot)
        connection.execute(
            """
            UPDATE connection_history
            SET protocol = ?, local_address = ?, local_port = ?,
                remote_address = ?, remote_port = ?, pid = ?,
                process_create_time_utc_us = ?, process_name = ?,
                process_status = ?, connection_state = ?, last_seen_utc_us = ?
            WHERE id = ? AND closed_at_utc_us IS NULL
            """,
            (*values, datetime_to_epoch_microseconds(snapshot.observed_at), str(record_id)),
        )

    @staticmethod
    def _close_record(
        connection: sqlite3.Connection,
        record_id: UUID,
        event: ConnectionClosed,
    ) -> None:
        values = _snapshot_values(event.last_snapshot)
        connection.execute(
            """
            UPDATE connection_history
            SET protocol = ?, local_address = ?, local_port = ?,
                remote_address = ?, remote_port = ?, pid = ?,
                process_create_time_utc_us = ?, process_name = ?,
                process_status = ?, connection_state = ?, last_seen_utc_us = ?,
                closed_at_utc_us = ?, close_reason = ?
            WHERE id = ? AND closed_at_utc_us IS NULL
            """,
            (
                *values,
                datetime_to_epoch_microseconds(event.last_snapshot.observed_at),
                datetime_to_epoch_microseconds(event.occurred_at),
                event.reason.value,
                str(record_id),
            ),
        )

    @staticmethod
    def _find_active(
        connection: sqlite3.Connection, key: ConnectionKey
    ) -> sqlite3.Row | None:
        return connection.execute(
            f"""
            SELECT {_HISTORY_COLUMNS}
            FROM connection_history
            WHERE protocol = ? AND local_address = ? AND local_port = ?
              AND remote_address IS ? AND remote_port IS ?
              AND pid IS ? AND process_create_time_utc_us IS ?
              AND closed_at_utc_us IS NULL
            ORDER BY first_seen_utc_us DESC, id DESC
            LIMIT 1
            """,
            _key_values(key),
        ).fetchone()

    @staticmethod
    def _find_by_key_and_first_seen(
        connection: sqlite3.Connection,
        key: ConnectionKey,
        first_seen_utc_us: int,
    ) -> sqlite3.Row | None:
        return connection.execute(
            f"""
            SELECT {_HISTORY_COLUMNS}
            FROM connection_history
            WHERE protocol = ? AND local_address = ? AND local_port = ?
              AND remote_address IS ? AND remote_port IS ?
              AND pid IS ? AND process_create_time_utc_us IS ?
              AND first_seen_utc_us = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (*_key_values(key), first_seen_utc_us),
        ).fetchone()

    @staticmethod
    def _find_duplicate_close(
        connection: sqlite3.Connection,
        event: ConnectionClosed,
    ) -> sqlite3.Row | None:
        return connection.execute(
            f"""
            SELECT {_HISTORY_COLUMNS}
            FROM connection_history
            WHERE protocol = ? AND local_address = ? AND local_port = ?
              AND remote_address IS ? AND remote_port IS ?
              AND pid IS ? AND process_create_time_utc_us IS ?
              AND closed_at_utc_us = ? AND close_reason = ?
            ORDER BY first_seen_utc_us DESC, id DESC
            LIMIT 1
            """,
            (
                *_key_values(event.key),
                datetime_to_epoch_microseconds(event.occurred_at),
                event.reason.value,
            ),
        ).fetchone()

    def _get_duplicate_close(
        self,
        connection: sqlite3.Connection,
        event: ConnectionClosed,
    ) -> ConnectionHistoryRecord:
        row = self._find_duplicate_close(connection, event)
        if row is None:
            raise HistoryRecordNotFound(
                "The active connection history record was not found."
            )
        return _row_to_record(row)

    @staticmethod
    def _get_required(
        connection: sqlite3.Connection, record_id: UUID
    ) -> ConnectionHistoryRecord:
        row = connection.execute(
            f"SELECT {_HISTORY_COLUMNS} FROM connection_history WHERE id = ?",
            (str(record_id),),
        ).fetchone()
        if row is None:
            raise HistoryRecordNotFound("The connection history record was not found.")
        return _row_to_record(row)


def _snapshot_values(snapshot: ConnectionSnapshot) -> tuple[object, ...]:
    remote = snapshot.remote_endpoint
    identity = snapshot.process.identity
    return (
        snapshot.protocol.value,
        snapshot.local_endpoint.address,
        snapshot.local_endpoint.port,
        remote.address if remote is not None else None,
        remote.port if remote is not None else None,
        identity.pid if identity is not None else None,
        (
            datetime_to_epoch_microseconds(identity.create_time)
            if identity is not None and identity.create_time is not None
            else None
        ),
        snapshot.process.name,
        snapshot.process.status.value,
        snapshot.state.value,
    )


def _key_values(key: ConnectionKey) -> tuple[object, ...]:
    remote = key.remote_endpoint
    identity = key.process_identity
    return (
        key.protocol.value,
        key.local_endpoint.address,
        key.local_endpoint.port,
        remote.address if remote is not None else None,
        remote.port if remote is not None else None,
        identity.pid if identity is not None else None,
        (
            datetime_to_epoch_microseconds(identity.create_time)
            if identity is not None and identity.create_time is not None
            else None
        ),
    )


def _row_to_record(row: sqlite3.Row) -> ConnectionHistoryRecord:
    try:
        raw_id = row["id"]
        record_id = UUID(raw_id)
        if str(record_id) != raw_id:
            raise ValueError("record ID is not canonical")

        pid = row["pid"]
        create_time_value = row["process_create_time_utc_us"]
        identity = (
            ProcessIdentity(
                pid=pid,
                create_time=(
                    epoch_microseconds_to_datetime(create_time_value)
                    if create_time_value is not None
                    else None
                ),
            )
            if pid is not None
            else None
        )
        process = ProcessInfo(
            status=ProcessInfoStatus(row["process_status"]),
            identity=identity,
            name=row["process_name"],
        )
        remote_address = row["remote_address"]
        remote_endpoint = (
            Endpoint(remote_address, row["remote_port"])
            if remote_address is not None
            else None
        )
        last_seen = epoch_microseconds_to_datetime(row["last_seen_utc_us"])
        snapshot = ConnectionSnapshot(
            protocol=TransportProtocol(row["protocol"]),
            local_endpoint=Endpoint(row["local_address"], row["local_port"]),
            remote_endpoint=remote_endpoint,
            state=ConnectionState(row["connection_state"]),
            process=process,
            observed_at=last_seen,
        )
        raw_closed_at = row["closed_at_utc_us"]
        raw_reason = row["close_reason"]
        return ConnectionHistoryRecord(
            record_id=record_id,
            first_seen=epoch_microseconds_to_datetime(row["first_seen_utc_us"]),
            last_seen=last_seen,
            snapshot=snapshot,
            closed_at=(
                epoch_microseconds_to_datetime(raw_closed_at)
                if raw_closed_at is not None
                else None
            ),
            close_reason=(
                ConnectionClosureReason(raw_reason)
                if raw_reason is not None
                else None
            ),
        )
    except HistoryDataCorrupt:
        raise
    except (
        AttributeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        OverflowError,
    ) as error:
        raise HistoryDataCorrupt(
            "Persisted connection history contains unsupported data."
        ) from error


__all__ = (
    "SQLiteConnectionHistoryRepository",
    "datetime_to_epoch_microseconds",
    "epoch_microseconds_to_datetime",
)
