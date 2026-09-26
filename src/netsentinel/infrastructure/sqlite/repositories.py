"""SQLite adapters for portable application repository ports."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
import json
import sqlite3
from uuid import UUID, uuid4

from netsentinel.application.ports import (
    ConnectionHistoryQuery,
    DeviceDataCorrupt,
    DeviceProfileDataCorrupt,
    DeviceProfileMergeConflict,
    DeviceProfileRepositoryError,
    DeviceRepositoryError,
    GatewayBaselineDataCorrupt,
    GatewayBaselineRepositoryError,
    HistoryDataCorrupt,
    HistoryRecordNotFound,
    HistoryQueryCancelled,
    HistoryRepositoryError,
    HistoryRetentionRepositoryError,
    HistoryStorageDiagnostics,
)
from netsentinel.domain.devices import (
    DeviceIdentity, DeviceProfile, DeviceTrust, GatewayBaseline, GatewayBaselineChange, GatewayBaselineStatus,
    IdentityBinding,
)
from netsentinel.domain.observations import MacAddress
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
                    return self._record_opened_in_transaction(connection, event)
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
                    return self._record_updated_in_transaction(connection, event)
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
                    return self._record_closed_in_transaction(connection, event)
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def _record_opened_in_transaction(
        self,
        connection: sqlite3.Connection,
        event: ConnectionOpened,
    ) -> ConnectionHistoryRecord:
        """Map OPENED using a caller-owned active transaction."""

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
                self._update_snapshot(connection, existing.record_id, event.snapshot)
                return self._get_required(connection, existing.record_id)
            return existing

        record_id = self._new_record_id()
        self._insert_open(connection, record_id, event.snapshot)
        return self._get_required(connection, record_id)

    def _record_updated_in_transaction(
        self,
        connection: sqlite3.Connection,
        event: ConnectionUpdated,
    ) -> ConnectionHistoryRecord:
        """Map UPDATED using a caller-owned active transaction."""

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
        self._update_snapshot(connection, existing.record_id, event.current)
        return self._get_required(connection, existing.record_id)

    def _record_closed_in_transaction(
        self,
        connection: sqlite3.Connection,
        event: ConnectionClosed,
    ) -> ConnectionHistoryRecord:
        """Map CLOSED using a caller-owned active transaction."""

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
        self._close_record(connection, existing.record_id, event)
        return self._get_required(connection, existing.record_id)

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
        self,
        query: ConnectionHistoryQuery,
        *,
        is_cancelled: Callable[[], bool] | None = None,
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
            if is_cancelled is not None and is_cancelled():
                raise HistoryQueryCancelled("Connection history query was cancelled.")
            with self._database.connection() as connection:
                if is_cancelled is not None:
                    connection.set_progress_handler(
                        lambda: 1 if is_cancelled() else 0,
                        1_000,
                    )
                try:
                    rows = connection.execute(statement, parameters).fetchall()
                except sqlite3.OperationalError as error:
                    if is_cancelled is not None and is_cancelled():
                        raise HistoryQueryCancelled(
                            "Connection history query was cancelled."
                        ) from error
                    raise
                finally:
                    if is_cancelled is not None:
                        connection.set_progress_handler(None, 0)
                if is_cancelled is not None and is_cancelled():
                    raise HistoryQueryCancelled(
                        "Connection history query was cancelled."
                    )
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


class SQLiteHistoryRetentionRepository:
    """SQLite adapter for bounded, completed-only history cleanup.

    Every delete call owns a separate migrated connection and one short
    transaction. A caller can stop safely between calls without undoing chunks
    which have already committed.
    """

    def __init__(self, database: SQLiteDatabase) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be a SQLiteDatabase")
        self._database = database

    def delete_completed_before(self, cutoff: datetime, limit: int) -> int:
        """Delete a deterministic chunk whose close time is strictly older."""

        cutoff_utc_us = datetime_to_epoch_microseconds(cutoff)
        _require_positive_limit(limit, "limit")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    cursor = connection.execute(
                        """
                        DELETE FROM connection_history
                        WHERE closed_at_utc_us IS NOT NULL
                          AND closed_at_utc_us < ?
                          AND id IN (
                              SELECT id
                              FROM connection_history
                              WHERE closed_at_utc_us IS NOT NULL
                                AND closed_at_utc_us < ?
                              ORDER BY first_seen_utc_us ASC,
                                       closed_at_utc_us ASC,
                                       id ASC
                              LIMIT ?
                          )
                        """,
                        (cutoff_utc_us, cutoff_utc_us, limit),
                    )
                    return _deleted_row_count(cursor)
        except HistoryRetentionRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRetentionRepositoryError(
                "Connection history cleanup could not be completed."
            ) from error

    def delete_oldest_completed_over_total_limit(
        self,
        max_rows: int,
        limit: int,
    ) -> int:
        """Trim oldest completed rows until the all-row ceiling can be met.

        Active rows count toward ``max_rows`` but can never be selected. If
        active rows alone exceed the ceiling, every completed row is eligible
        and the remaining total may necessarily stay above the configured
        value.
        """

        _require_positive_limit(max_rows, "max_rows")
        _require_positive_limit(limit, "limit")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    row = connection.execute(
                        "SELECT COUNT(*) FROM connection_history"
                    ).fetchone()
                    if row is None:
                        raise HistoryRetentionRepositoryError(
                            "Connection history row count could not be read."
                        )
                    excess = max(0, int(row[0]) - max_rows)
                    if excess == 0:
                        return 0
                    delete_limit = min(excess, limit)
                    cursor = connection.execute(
                        """
                        DELETE FROM connection_history
                        WHERE closed_at_utc_us IS NOT NULL
                          AND id IN (
                              SELECT id
                              FROM connection_history
                              WHERE closed_at_utc_us IS NOT NULL
                              ORDER BY first_seen_utc_us ASC,
                                       closed_at_utc_us ASC,
                                       id ASC
                              LIMIT ?
                          )
                        """,
                        (delete_limit,),
                    )
                    return _deleted_row_count(cursor)
        except HistoryRetentionRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRetentionRepositoryError(
                "Connection history cleanup could not be completed."
            ) from error

    def storage_diagnostics(self) -> HistoryStorageDiagnostics:
        """Measure history row counts and current main/WAL file sizes."""

        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS total_rows,
                           COUNT(*) FILTER (WHERE closed_at_utc_us IS NULL)
                               AS active_rows,
                           COUNT(*) FILTER (WHERE closed_at_utc_us IS NOT NULL)
                               AS completed_rows
                    FROM connection_history
                    """
                ).fetchone()
                if row is None:
                    raise HistoryRetentionRepositoryError(
                        "Connection history diagnostics could not be read."
                    )
                database_bytes = self._database.path.stat().st_size
                wal_bytes = _optional_file_size(
                    self._database.path.with_name(self._database.path.name + "-wal")
                )
                return HistoryStorageDiagnostics(
                    database_bytes=database_bytes,
                    wal_bytes=wal_bytes,
                    total_rows=int(row["total_rows"]),
                    active_rows=int(row["active_rows"]),
                    completed_rows=int(row["completed_rows"]),
                )
        except HistoryRetentionRepositoryError:
            raise
        except (
            SQLiteAdapterError,
            sqlite3.Error,
            OSError,
            TypeError,
            ValueError,
        ) as error:
            raise HistoryRetentionRepositoryError(
                "Connection history diagnostics could not be read."
            ) from error


def _require_positive_limit(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be greater than zero")


def _deleted_row_count(cursor: sqlite3.Cursor) -> int:
    count = cursor.rowcount
    if count < 0:
        raise HistoryRetentionRepositoryError(
            "Connection history cleanup count was unavailable."
        )
    return count


def _optional_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


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


class SQLiteDeviceRepository:
    """Atomic device/binding upsert on short-lived, migrated connections."""

    def __init__(self, database: SQLiteDatabase) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be a SQLiteDatabase")
        self._database = database

    def record_binding(
        self, device: DeviceIdentity, binding: IdentityBinding
    ) -> tuple[DeviceIdentity, IdentityBinding]:
        if not isinstance(device, DeviceIdentity) or not isinstance(binding, IdentityBinding):
            raise TypeError("device and binding must be portable device models")
        if binding.device_id != device.device_id:
            raise ValueError("binding must belong to device")
        at = datetime_to_epoch_microseconds(device.last_seen)
        if device.first_seen != device.last_seen or binding.first_seen != binding.last_seen or binding.last_seen != device.last_seen:
            raise ValueError("record_binding requires one observation timestamp")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    connection.execute(
                        """
                        INSERT INTO devices
                            (id, network_fingerprint, mac, first_seen_utc_us, last_seen_utc_us)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (network_fingerprint, mac) DO UPDATE SET
                            last_seen_utc_us = MAX(devices.last_seen_utc_us, excluded.last_seen_utc_us)
                        """,
                        (str(device.device_id), device.network_fingerprint, str(device.mac), at, at),
                    )
                    connection.execute(
                        """
                        INSERT INTO device_bindings
                            (id, device_id, ip_address, first_seen_utc_us, last_seen_utc_us)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (device_id, ip_address) DO UPDATE SET
                            last_seen_utc_us = MAX(device_bindings.last_seen_utc_us, excluded.last_seen_utc_us)
                        """,
                        (str(binding.binding_id), str(device.device_id), binding.ip_address, at, at),
                    )
                    device_row = connection.execute(
                        "SELECT * FROM devices WHERE id = ?", (str(device.device_id),)
                    ).fetchone()
                    binding_row = connection.execute(
                        """SELECT b.*, d.network_fingerprint, d.mac
                           FROM device_bindings AS b JOIN devices AS d ON d.id = b.device_id
                           WHERE b.id = ?""", (str(binding.binding_id),)
                    ).fetchone()
                    if device_row is None or binding_row is None:
                        raise DeviceDataCorrupt("Persisted device state is incomplete.")
                    return _row_to_device(device_row), _row_to_binding(binding_row)
        except DeviceRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise DeviceRepositoryError("Device observation could not be stored.") from error

    def list_devices(self, network_fingerprint: str) -> tuple[DeviceIdentity, ...]:
        if not isinstance(network_fingerprint, str) or len(network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in network_fingerprint):
            raise ValueError("network_fingerprint must be canonical SHA-256 hex")
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM devices WHERE network_fingerprint = ? ORDER BY mac ASC",
                    (network_fingerprint,),
                ).fetchall()
                return tuple(_row_to_device(row) for row in rows)
        except DeviceRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise DeviceRepositoryError("Devices could not be read.") from error

    def list_bindings(self, device_id: UUID, limit: int | None = None) -> tuple[IdentityBinding, ...]:
        if not isinstance(device_id, UUID):
            raise TypeError("device_id must be a UUID")
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100):
            raise ValueError("limit must be between 1 and 100")
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    """SELECT b.*, d.network_fingerprint, d.mac
                       FROM device_bindings AS b JOIN devices AS d ON d.id = b.device_id
                       WHERE b.device_id = ? ORDER BY b.last_seen_utc_us DESC, b.ip_address ASC
                       LIMIT ?""",
                    (str(device_id), limit if limit is not None else -1),
                ).fetchall()
                bindings = tuple(_row_to_binding(row) for row in rows)
                if limit is None:
                    return tuple(sorted(bindings, key=lambda b: (int(IPv4Address(b.ip_address)), str(b.binding_id))))
                return bindings
        except DeviceRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise DeviceRepositoryError("Device bindings could not be read.") from error

    def latest_binding_for_ip(self, network_fingerprint: str, ip_address: str) -> IdentityBinding | None:
        if not isinstance(network_fingerprint, str) or len(network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in network_fingerprint):
            raise ValueError("network_fingerprint must be canonical SHA-256 hex")
        ip = str(IPv4Address(ip_address))
        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    """SELECT b.*, d.network_fingerprint, d.mac
                       FROM device_bindings AS b JOIN devices AS d ON d.id = b.device_id
                       WHERE d.network_fingerprint = ? AND b.ip_address = ?
                       ORDER BY b.last_seen_utc_us DESC, b.first_seen_utc_us DESC, d.mac ASC
                       LIMIT 1""",
                    (network_fingerprint, ip),
                ).fetchone()
                return _row_to_binding(row) if row is not None else None
        except DeviceRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise DeviceRepositoryError("IP binding could not be read.") from error


class SQLiteDeviceProfileRepository:
    """Short transactional user edits; observed device rows remain untouched."""

    def __init__(self, database: SQLiteDatabase) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be SQLiteDatabase")
        self._database = database

    def create(self, device_id: UUID, profile: DeviceProfile) -> DeviceProfile:
        _profile_args(device_id, profile)
        try:
            with self._database.connection() as connection, transaction(connection):
                _require_device_scope(connection, device_id, profile.network_fingerprint)
                if connection.execute("SELECT 1 FROM device_profile_members WHERE device_id = ?", (str(device_id),)).fetchone():
                    raise DeviceProfileMergeConflict("Device already has a profile.")
                connection.execute(
                    """INSERT INTO device_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    _profile_values(profile),
                )
                connection.execute(
                    "INSERT INTO device_profile_members (device_id, profile_id) VALUES (?, ?)",
                    (str(device_id), str(profile.profile_id)),
                )
                return profile
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profile could not be created.") from error

    def get(self, profile_id: UUID) -> DeviceProfile | None:
        _require_uuid(profile_id, "profile_id")
        try:
            with self._database.connection() as connection:
                row = connection.execute("SELECT * FROM device_profiles WHERE id = ?", (str(profile_id),)).fetchone()
                return _row_to_profile(row) if row is not None else None
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profile could not be read.") from error

    def get_for_device(self, device_id: UUID) -> DeviceProfile | None:
        _require_uuid(device_id, "device_id")
        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    """SELECT p.* FROM device_profile_members AS m
                       JOIN device_profiles AS p ON p.id = m.profile_id
                       WHERE m.device_id = ?""",
                    (str(device_id),),
                ).fetchone()
                return _row_to_profile(row) if row is not None else None
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profile could not be read.") from error

    def snapshot_for_network(self, network_fingerprint: str, since: datetime) -> tuple[tuple[DeviceProfile, tuple[UUID, ...], tuple[IdentityBinding, ...]], ...]:
        """One consistent, bounded read for the inventory consumer, never per packet."""
        _check_fingerprint(network_fingerprint)
        since_us = datetime_to_epoch_microseconds(since)
        try:
            with self._database.connection() as connection:
                connection.execute("BEGIN")
                rows = connection.execute(
                    """SELECT * FROM device_profiles WHERE network_fingerprint = ?
                       AND merged_into IS NULL ORDER BY id LIMIT 513""",
                    (network_fingerprint,),
                ).fetchall()
                if len(rows) > 512:
                    raise DeviceProfileRepositoryError("Device profile snapshot capacity exceeded.")
                members = connection.execute(
                    """SELECT m.profile_id, m.device_id FROM device_profile_members AS m
                       JOIN device_profiles AS p ON p.id = m.profile_id
                       WHERE p.network_fingerprint = ? AND p.merged_into IS NULL
                       ORDER BY m.profile_id, m.device_id LIMIT 2049""",
                    (network_fingerprint,),
                ).fetchall()
                if len(members) > 2048:
                    raise DeviceProfileRepositoryError("Device profile membership capacity exceeded.")
                by_profile: dict[UUID, list[UUID]] = {UUID(row["id"]): [] for row in rows}
                for member in members:
                    by_profile[UUID(member["profile_id"])].append(UUID(member["device_id"]))
                bindings = connection.execute(
                    """SELECT m.profile_id, b.*, d.network_fingerprint, d.mac
                       FROM device_bindings AS b JOIN devices AS d ON d.id = b.device_id
                       JOIN device_profile_members AS m ON m.device_id = d.id
                       JOIN device_profiles AS p ON p.id = m.profile_id
                       WHERE p.network_fingerprint = ? AND p.merged_into IS NULL
                         AND b.last_seen_utc_us >= ?
                       ORDER BY b.last_seen_utc_us DESC, b.id LIMIT 4097""",
                    (network_fingerprint, since_us),
                ).fetchall()
                if len(bindings) > 4096:
                    raise DeviceProfileRepositoryError("Recent device binding snapshot capacity exceeded.")
                by_binding: dict[UUID, list[IdentityBinding]] = {UUID(row["id"]): [] for row in rows}
                for binding in bindings:
                    profile_bindings = by_binding[UUID(binding["profile_id"])]
                    if len(profile_bindings) < 20:
                        profile_bindings.append(_row_to_binding(binding))
                snapshot = tuple(
                    (_row_to_profile(row), tuple(by_profile[UUID(row["id"])]), tuple(by_binding[UUID(row["id"])]))
                    for row in rows
                )
                connection.execute("COMMIT")
                return snapshot
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, ValueError, KeyError) as error:
            raise DeviceProfileRepositoryError("Device profile snapshot could not be read.") from error

    def update(self, profile: DeviceProfile, *, expected_updated_at: datetime | None = None) -> DeviceProfile:
        if not isinstance(profile, DeviceProfile):
            raise TypeError("profile must be DeviceProfile")
        try:
            with self._database.connection() as connection, transaction(connection):
                row = connection.execute("SELECT * FROM device_profiles WHERE id = ?", (str(profile.profile_id),)).fetchone()
                if row is None:
                    raise DeviceProfileRepositoryError("Device profile does not exist.")
                old = _row_to_profile(row)
                if expected_updated_at is not None and old.updated_at != expected_updated_at:
                    raise DeviceProfileMergeConflict("Stale profile update was rejected.")
                if old.merged_into is not None or profile.merged_into is not None:
                    raise DeviceProfileMergeConflict("Merged profiles cannot be edited.")
                if profile.network_fingerprint != old.network_fingerprint or profile.created_at != old.created_at:
                    raise DeviceProfileMergeConflict("Profile identity cannot change.")
                if profile.updated_at < old.updated_at:
                    raise DeviceProfileMergeConflict("Stale profile update was rejected.")
                if profile.updated_at == old.updated_at:
                    if profile == old:
                        return old
                    raise DeviceProfileMergeConflict("Conflicting profile update timestamp.")
                if profile.trust != old.trust:
                    if profile.trust_changed_at != profile.updated_at:
                        raise DeviceProfileMergeConflict("Trust change time must equal update time.")
                elif profile.trust_changed_at != old.trust_changed_at:
                    raise DeviceProfileMergeConflict("Unchanged trust must preserve its change time.")
                connection.execute(
                    """UPDATE device_profiles SET label = ?, note = ?, trust = ?,
                       updated_at_utc_us = ?, trust_changed_at_utc_us = ?,
                       expected_macs_json = ?, expected_ips_json = ? WHERE id = ?""",
                    (_profile_values(profile)[2], _profile_values(profile)[3], profile.trust.value,
                     datetime_to_epoch_microseconds(profile.updated_at),
                     _optional_profile_time(profile.trust_changed_at),
                     _profile_values(profile)[8], _profile_values(profile)[9], str(profile.profile_id)),
                )
                return profile
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profile could not be updated.") from error

    def delete(self, profile_id: UUID) -> bool:
        _require_uuid(profile_id, "profile_id")
        try:
            with self._database.connection() as connection, transaction(connection):
                row = connection.execute("SELECT * FROM device_profiles WHERE id = ?", (str(profile_id),)).fetchone()
                if row is None:
                    return False
                if row["merged_into"] is not None or connection.execute(
                    "SELECT 1 FROM device_profiles WHERE merged_into = ?", (str(profile_id),)
                ).fetchone():
                    raise DeviceProfileMergeConflict("Merged profile history must be preserved.")
                connection.execute("DELETE FROM device_profile_members WHERE profile_id = ?", (str(profile_id),))
                connection.execute("DELETE FROM device_profiles WHERE id = ?", (str(profile_id),))
                return True
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profile could not be deleted.") from error

    def merge_devices(self, target_device_id: UUID, source_device_id: UUID, at: datetime) -> DeviceProfile:
        _require_uuid(target_device_id, "target_device_id")
        _require_uuid(source_device_id, "source_device_id")
        at_us = datetime_to_epoch_microseconds(at)
        try:
            with self._database.connection() as connection, transaction(connection):
                target_row = _profile_for_device_row(connection, target_device_id)
                if target_row is None:
                    raise DeviceProfileRepositoryError("Target device needs a profile.")
                target = _row_to_profile(target_row)
                _require_device_scope(connection, source_device_id, target.network_fingerprint)
                source_row = _profile_for_device_row(connection, source_device_id)
                if source_row is None:
                    connection.execute("INSERT INTO device_profile_members VALUES (?, ?)", (str(source_device_id), str(target.profile_id)))
                    return target
                source = _row_to_profile(source_row)
                if source.profile_id == target.profile_id:
                    return target
                if source.merged_into is not None or target.merged_into is not None:
                    raise DeviceProfileMergeConflict("Merged profiles cannot be merged again.")
                if source.network_fingerprint != target.network_fingerprint:
                    raise DeviceProfileDataCorrupt("Persisted profile scope is inconsistent.")
                if at_us < datetime_to_epoch_microseconds(max(source.updated_at, target.updated_at)):
                    raise DeviceProfileMergeConflict("Merge time cannot precede profile updates.")
                if (source.label and target.label and source.label != target.label) or (source.note and target.note and source.note != target.note):
                    raise DeviceProfileMergeConflict("Conflicting user text must be resolved before merge.")
                if source.trust is not DeviceTrust.UNKNOWN and target.trust is not DeviceTrust.UNKNOWN and source.trust != target.trust:
                    raise DeviceProfileMergeConflict("Conflicting trust must be resolved before merge.")
                trust = target.trust if target.trust is not DeviceTrust.UNKNOWN else source.trust
                changed = target.trust_changed_at if trust == target.trust else at
                macs = tuple(sorted(set((*target.expected_macs, *source.expected_macs)), key=str))
                ips = tuple(sorted(set((*target.expected_ips, *source.expected_ips)), key=lambda ip: int(IPv4Address(ip))))
                if len(macs) > 32 or len(ips) > 32:
                    raise DeviceProfileMergeConflict("Expected identity capacity would be exceeded.")
                merged = DeviceProfile(
                    target.profile_id, target.network_fingerprint, target.label or source.label,
                    target.note or source.note, trust, target.created_at, at,
                    changed, macs, ips,
                )
                values = _profile_values(merged)
                connection.execute(
                    """UPDATE device_profiles SET label = ?, note = ?, trust = ?, updated_at_utc_us = ?,
                       trust_changed_at_utc_us = ?, expected_macs_json = ?, expected_ips_json = ? WHERE id = ?""",
                    (values[2], values[3], values[4], values[6], values[7], values[8], values[9], values[0]),
                )
                connection.execute("UPDATE device_profile_members SET profile_id = ? WHERE profile_id = ?", (str(target.profile_id), str(source.profile_id)))
                connection.execute("UPDATE device_profiles SET merged_into = ? WHERE id = ?", (str(target.profile_id), str(source.profile_id)))
                return merged
        except DeviceProfileRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise DeviceProfileRepositoryError("Device profiles could not be merged.") from error


def _require_uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be UUID")


def _profile_args(device_id: UUID, profile: DeviceProfile) -> None:
    _require_uuid(device_id, "device_id")
    if not isinstance(profile, DeviceProfile) or profile.merged_into is not None:
        raise ValueError("profile must be an active DeviceProfile")


def _optional_profile_time(value: datetime | None) -> int | None:
    return datetime_to_epoch_microseconds(value) if value is not None else None


def _profile_values(profile: DeviceProfile) -> tuple[object, ...]:
    return (
        str(profile.profile_id), profile.network_fingerprint, profile.label, profile.note,
        profile.trust.value, datetime_to_epoch_microseconds(profile.created_at),
        datetime_to_epoch_microseconds(profile.updated_at), _optional_profile_time(profile.trust_changed_at),
        json.dumps([str(mac) for mac in profile.expected_macs], separators=(",", ":")),
        json.dumps(list(profile.expected_ips), separators=(",", ":")),
        str(profile.merged_into) if profile.merged_into else None,
    )


def _row_to_profile(row: sqlite3.Row) -> DeviceProfile:
    try:
        macs = json.loads(row["expected_macs_json"])
        ips = json.loads(row["expected_ips_json"])
        if not isinstance(macs, list) or not isinstance(ips, list):
            raise ValueError("invalid expected identities")
        return DeviceProfile(
            profile_id=UUID(row["id"]), network_fingerprint=row["network_fingerprint"],
            label=row["label"], note=row["note"], trust=DeviceTrust(row["trust"]),
            created_at=epoch_microseconds_to_datetime(row["created_at_utc_us"]),
            updated_at=epoch_microseconds_to_datetime(row["updated_at_utc_us"]),
            trust_changed_at=epoch_microseconds_to_datetime(row["trust_changed_at_utc_us"]) if row["trust_changed_at_utc_us"] is not None else None,
            expected_macs=tuple(MacAddress(mac) for mac in macs), expected_ips=tuple(ips),
            merged_into=UUID(row["merged_into"]) if row["merged_into"] else None,
        )
    except (AttributeError, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError) as error:
        raise DeviceProfileDataCorrupt("Persisted device profile is invalid.") from error


def _require_device_scope(connection: sqlite3.Connection, device_id: UUID, fingerprint: str) -> None:
    row = connection.execute("SELECT network_fingerprint FROM devices WHERE id = ?", (str(device_id),)).fetchone()
    if row is None or row[0] != fingerprint:
        raise DeviceProfileMergeConflict("Device is missing or belongs to another network.")


def _profile_for_device_row(connection: sqlite3.Connection, device_id: UUID) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT p.* FROM device_profile_members AS m JOIN device_profiles AS p ON p.id = m.profile_id
           WHERE m.device_id = ?""", (str(device_id),),
    ).fetchone()


def _row_to_device(row: sqlite3.Row) -> DeviceIdentity:
    try:
        device = DeviceIdentity(
            network_fingerprint=row["network_fingerprint"],
            mac=MacAddress(row["mac"]),
            first_seen=epoch_microseconds_to_datetime(row["first_seen_utc_us"]),
            last_seen=epoch_microseconds_to_datetime(row["last_seen_utc_us"]),
        )
        if str(device.device_id) != row["id"]:
            raise ValueError("device ID does not match identity")
        return device
    except (KeyError, IndexError, TypeError, ValueError, OverflowError) as error:
        raise DeviceDataCorrupt("Persisted device data is invalid.") from error


def _row_to_binding(row: sqlite3.Row) -> IdentityBinding:
    try:
        binding = IdentityBinding(
            network_fingerprint=row["network_fingerprint"],
            mac=MacAddress(row["mac"]),
            ip_address=row["ip_address"],
            first_seen=epoch_microseconds_to_datetime(row["first_seen_utc_us"]),
            last_seen=epoch_microseconds_to_datetime(row["last_seen_utc_us"]),
        )
        if str(binding.binding_id) != row["id"] or str(binding.device_id) != row["device_id"]:
            raise ValueError("binding ID does not match identity")
        return binding
    except (KeyError, IndexError, TypeError, ValueError, OverflowError) as error:
        raise DeviceDataCorrupt("Persisted binding data is invalid.") from error


class SQLiteGatewayBaselineRepository:
    """NS-025 baseline and transition history on short, atomic connections."""

    def __init__(self, database: SQLiteDatabase) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be a SQLiteDatabase")
        self._database = database

    def get(self, network_fingerprint: str) -> GatewayBaseline | None:
        _check_fingerprint(network_fingerprint)
        try:
            with self._database.connection() as connection:
                row = connection.execute(
                    "SELECT * FROM gateway_baselines WHERE network_fingerprint = ?",
                    (network_fingerprint,),
                ).fetchone()
                return _row_to_gateway_baseline(row) if row is not None else None
        except GatewayBaselineRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise GatewayBaselineRepositoryError("Gateway baseline could not be read.") from error

    def save(
        self, baseline: GatewayBaseline, change: GatewayBaselineChange | None = None
    ) -> GatewayBaseline:
        if not isinstance(baseline, GatewayBaseline):
            raise TypeError("baseline must be a GatewayBaseline")
        if change is not None and (
            not isinstance(change, GatewayBaselineChange)
            or change.network_fingerprint != baseline.network_fingerprint
            or change.gateway_ip != baseline.gateway_ip
            or change.new_mac != baseline.mac
        ):
            raise ValueError("change must match baseline identity")
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    existing = connection.execute(
                        "SELECT * FROM gateway_baselines WHERE network_fingerprint = ?",
                        (baseline.network_fingerprint,),
                    ).fetchone()
                    if existing is not None:
                        current = _row_to_gateway_baseline(existing)
                        if current.gateway_ip != baseline.gateway_ip:
                            raise GatewayBaselineDataCorrupt("Persisted gateway identity is inconsistent.")
                        if change is not None and change.reason == "first_observation":
                            return current
                        if current.status is GatewayBaselineStatus.VERIFIED and baseline.status is not GatewayBaselineStatus.VERIFIED:
                            return current
                        if change is not None and change.old_mac != current.mac:
                            return current
                        if baseline.last_seen < current.last_seen:
                            return current
                    connection.execute(
                        """
                        INSERT INTO gateway_baselines (
                            network_fingerprint, gateway_ip, mac, status,
                            first_seen_utc_us, last_seen_utc_us, learning_started_utc_us,
                            observation_count, conflicted, verified_at_utc_us,
                            pending_mac, pending_seen_utc_us
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(network_fingerprint) DO UPDATE SET
                            mac = excluded.mac,
                            status = excluded.status,
                            last_seen_utc_us = MAX(gateway_baselines.last_seen_utc_us, excluded.last_seen_utc_us),
                            observation_count = MAX(gateway_baselines.observation_count, excluded.observation_count),
                            conflicted = excluded.conflicted,
                            verified_at_utc_us = excluded.verified_at_utc_us,
                            pending_mac = excluded.pending_mac,
                            pending_seen_utc_us = excluded.pending_seen_utc_us
                        """,
                        (
                            baseline.network_fingerprint, baseline.gateway_ip,
                            str(baseline.mac), baseline.status.value,
                            datetime_to_epoch_microseconds(baseline.first_seen),
                            datetime_to_epoch_microseconds(baseline.last_seen),
                            datetime_to_epoch_microseconds(baseline.learning_started_at),
                            baseline.observation_count, int(baseline.conflicted),
                            datetime_to_epoch_microseconds(baseline.verified_at)
                            if baseline.verified_at is not None else None,
                            str(baseline.pending_mac) if baseline.pending_mac is not None else None,
                            datetime_to_epoch_microseconds(baseline.pending_seen_at)
                            if baseline.pending_seen_at is not None else None,
                        ),
                    )
                    if change is not None:
                        connection.execute(
                            """INSERT INTO gateway_baseline_changes
                               (network_fingerprint, gateway_ip, old_mac, new_mac,
                                changed_at_utc_us, reason) VALUES (?, ?, ?, ?, ?, ?)""",
                            (
                                change.network_fingerprint, change.gateway_ip,
                                str(change.old_mac) if change.old_mac is not None else None,
                                str(change.new_mac),
                                datetime_to_epoch_microseconds(change.changed_at),
                                change.reason,
                            ),
                        )
                    row = connection.execute(
                        "SELECT * FROM gateway_baselines WHERE network_fingerprint = ?",
                        (baseline.network_fingerprint,),
                    ).fetchone()
                    return _row_to_gateway_baseline(row)
        except GatewayBaselineRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise GatewayBaselineRepositoryError("Gateway baseline could not be stored.") from error

    def changes(self, network_fingerprint: str) -> tuple[GatewayBaselineChange, ...]:
        _check_fingerprint(network_fingerprint)
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    """SELECT * FROM gateway_baseline_changes
                       WHERE network_fingerprint = ? ORDER BY changed_at_utc_us, id""",
                    (network_fingerprint,),
                ).fetchall()
                return tuple(_row_to_gateway_change(row) for row in rows)
        except GatewayBaselineRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise GatewayBaselineRepositoryError("Gateway baseline history could not be read.") from error


def _check_fingerprint(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("network_fingerprint must be canonical SHA-256 hex")


def _row_to_gateway_baseline(row: sqlite3.Row) -> GatewayBaseline:
    try:
        return GatewayBaseline(
            row["network_fingerprint"], row["gateway_ip"], MacAddress(row["mac"]),
            GatewayBaselineStatus(row["status"]),
            epoch_microseconds_to_datetime(row["first_seen_utc_us"]),
            epoch_microseconds_to_datetime(row["last_seen_utc_us"]),
            epoch_microseconds_to_datetime(row["learning_started_utc_us"]),
            row["observation_count"], bool(row["conflicted"]),
            epoch_microseconds_to_datetime(row["verified_at_utc_us"])
            if row["verified_at_utc_us"] is not None else None,
            MacAddress(row["pending_mac"]) if row["pending_mac"] is not None else None,
            epoch_microseconds_to_datetime(row["pending_seen_utc_us"])
            if row["pending_seen_utc_us"] is not None else None,
        )
    except (KeyError, IndexError, TypeError, ValueError, OverflowError) as error:
        raise GatewayBaselineDataCorrupt("Persisted gateway baseline is invalid.") from error


def _row_to_gateway_change(row: sqlite3.Row) -> GatewayBaselineChange:
    try:
        return GatewayBaselineChange(
            row["network_fingerprint"], row["gateway_ip"],
            MacAddress(row["old_mac"]) if row["old_mac"] is not None else None,
            MacAddress(row["new_mac"]),
            epoch_microseconds_to_datetime(row["changed_at_utc_us"]), row["reason"],
        )
    except (KeyError, IndexError, TypeError, ValueError, OverflowError) as error:
        raise GatewayBaselineDataCorrupt("Persisted gateway baseline history is invalid.") from error


__all__ = (
    "SQLiteDeviceRepository",
    "SQLiteDeviceProfileRepository",
    "SQLiteGatewayBaselineRepository",
    "SQLiteConnectionHistoryRepository",
    "SQLiteHistoryRetentionRepository",
    "datetime_to_epoch_microseconds",
    "epoch_microseconds_to_datetime",
)
