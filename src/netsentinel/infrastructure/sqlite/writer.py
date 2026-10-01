"""SQLite-owned session wiring for the generic connection-history writer."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import sqlite3
from uuid import UUID, uuid4

from netsentinel.application.ports import HistoryRepositoryError
from netsentinel.application.services.history import ConnectionHistoryWriter
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionHistoryRecord,
    ConnectionOpened,
    ConnectionUpdated,
)
from netsentinel.infrastructure.sqlite.database import (
    SQLiteAdapterError,
    SQLiteDatabase,
    transaction,
)
from netsentinel.infrastructure.sqlite.repositories import (
    SQLiteConnectionHistoryRepository,
)


class SQLiteConnectionHistoryWriteSession:
    """Repository mapping bound to one writer-thread SQLite connection."""

    def __init__(
        self,
        repository: SQLiteConnectionHistoryRepository,
        connection: sqlite3.Connection,
    ) -> None:
        self._repository = repository
        self._connection = connection

    @contextmanager
    def batch(self) -> Iterator[None]:
        """Commit one ordered batch atomically on the owned connection."""

        try:
            with transaction(self._connection):
                yield
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history batch could not be written."
            ) from error

    def record_opened(self, event: ConnectionOpened) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionOpened):
            raise TypeError("event must be a ConnectionOpened")
        self._require_batch()
        try:
            return self._repository._record_opened_in_transaction(  # noqa: SLF001
                self._connection,
                event,
            )
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def reconcile_open(self, limit: int = 256) -> int:
        """Mark a bounded group of prior open observations as interrupted."""
        self._require_batch()
        try:
            cursor = self._connection.execute(
                """UPDATE connection_history SET observation_gap = 1
                   WHERE id IN (SELECT id FROM connection_history
                                WHERE closed_at_utc_us IS NULL AND observation_gap = 0
                                ORDER BY first_seen_utc_us, id LIMIT ?)""",
                (limit,),
            )
            return cursor.rowcount
        except sqlite3.Error as error:
            raise HistoryRepositoryError("History reconciliation failed.") from error

    def record_updated(self, event: ConnectionUpdated) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionUpdated):
            raise TypeError("event must be a ConnectionUpdated")
        self._require_batch()
        try:
            return self._repository._record_updated_in_transaction(  # noqa: SLF001
                self._connection,
                event,
            )
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def record_checkpoint(self, event: ConnectionUpdated) -> None:
        self._require_batch()
        try:
            self._repository._record_checkpoint_in_transaction(self._connection, event)  # noqa: SLF001
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError("Connection checkpoint could not be written.") from error

    def record_closed(self, event: ConnectionClosed) -> ConnectionHistoryRecord:
        if not isinstance(event, ConnectionClosed):
            raise TypeError("event must be a ConnectionClosed")
        self._require_batch()
        try:
            return self._repository._record_closed_in_transaction(  # noqa: SLF001
                self._connection,
                event,
            )
        except HistoryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError) as error:
            raise HistoryRepositoryError(
                "Connection history could not be written."
            ) from error

    def _require_batch(self) -> None:
        if not self._connection.in_transaction:
            raise HistoryRepositoryError(
                "Connection history writes require an active batch."
            )


class SQLiteHistoryWriteSessionFactory:
    """Open one migrated connection in the thread that invokes the factory."""

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

    def __call__(self):
        return self._open()

    @contextmanager
    def _open(self) -> Iterator[SQLiteConnectionHistoryWriteSession]:
        connection = self._database.connect()
        repository = SQLiteConnectionHistoryRepository(
            self._database,
            record_id_factory=self._record_id_factory,
        )
        try:
            yield SQLiteConnectionHistoryWriteSession(repository, connection)
        finally:
            connection.close()


class SQLiteHistoryWriter(ConnectionHistoryWriter):
    """Production writer configured with a worker-owned SQLite session."""

    def __init__(
        self,
        database: SQLiteDatabase,
        *,
        record_id_factory: Callable[[], UUID] = uuid4,
        **writer_options: object,
    ) -> None:
        super().__init__(
            SQLiteHistoryWriteSessionFactory(
                database,
                record_id_factory=record_id_factory,
            ),
            **writer_options,
        )


__all__ = (
    "SQLiteConnectionHistoryWriteSession",
    "SQLiteHistoryWriteSessionFactory",
    "SQLiteHistoryWriter",
)
