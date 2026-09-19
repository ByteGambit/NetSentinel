"""SQLite connection ownership, path policy, and transaction primitives.

This module is intentionally infrastructure-only.  Callers receive a configured
connection, but no connection is created and no directory is touched at import
time.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
from typing import Protocol


APPLICATION_DIRECTORY_NAME = "NetSentinel"
DATABASE_FILENAME = "netsentinel.sqlite3"
DEFAULT_BUSY_TIMEOUT_MS = 5_000


class SQLiteAdapterError(RuntimeError):
    """Base class for sanitized SQLite infrastructure failures."""


class DatabasePathError(SQLiteAdapterError):
    """The database directory could not be prepared safely."""


class DatabaseOpenError(SQLiteAdapterError):
    """SQLite could not open the requested database file."""


class DatabaseConfigurationError(SQLiteAdapterError):
    """Required connection pragmas could not be applied or verified."""


class DatabaseTransactionError(SQLiteAdapterError):
    """An explicit transaction could not be completed safely."""


class NestedTransactionError(DatabaseTransactionError):
    """Nested use of the simple transaction helper is unsupported."""


class _MigrationRunner(Protocol):
    def migrate(self, connection: sqlite3.Connection) -> int: ...


def default_database_path(
    *, local_app_data: str | os.PathLike[str] | None = None
) -> Path:
    """Return the per-user production database path without creating it.

    Windows' ``LOCALAPPDATA`` is the authoritative default.  The explicit
    argument exists for deterministic policy tests and packaging integration;
    an absent environment variable falls back to the conventional directory
    inside the current user's profile, never the repository or current working
    directory.
    """

    if local_app_data is None:
        configured_root = os.environ.get("LOCALAPPDATA")
        root = (
            Path(configured_root)
            if configured_root
            else Path.home() / "AppData" / "Local"
        )
    else:
        root = Path(local_app_data)
    return root.expanduser().resolve() / APPLICATION_DIRECTORY_NAME / DATABASE_FILENAME


@dataclass(frozen=True, slots=True)
class SQLiteConnectionFactory:
    """Open one file-backed SQLite connection owned by the calling thread."""

    path: Path
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        resolved_path = (
            default_database_path() if path is None else Path(path).expanduser().resolve()
        )
        object.__setattr__(self, "path", resolved_path)
        object.__setattr__(self, "busy_timeout_ms", busy_timeout_ms)

    def connect(self) -> sqlite3.Connection:
        """Create and configure a connection; the caller owns and closes it.

        ``isolation_level=None`` keeps SQLite in autocommit mode outside the
        explicit :func:`transaction` helper.  Python's default thread check is
        retained so a connection cannot be shared casually across workers.
        """

        self._prepare_parent_directory()
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1_000,
                isolation_level=None,
                check_same_thread=True,
            )
        except (sqlite3.Error, OSError) as error:
            raise DatabaseOpenError("Unable to open the SQLite database.") from error

        try:
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            journal_mode_row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            foreign_keys_row = connection.execute("PRAGMA foreign_keys").fetchone()
            busy_timeout_row = connection.execute("PRAGMA busy_timeout").fetchone()
            if journal_mode_row is None or str(journal_mode_row[0]).lower() != "wal":
                raise DatabaseConfigurationError(
                    "SQLite WAL journal mode could not be enabled."
                )
            if foreign_keys_row is None or foreign_keys_row[0] != 1:
                raise DatabaseConfigurationError(
                    "SQLite foreign-key enforcement could not be enabled."
                )
            if busy_timeout_row is None or busy_timeout_row[0] != self.busy_timeout_ms:
                raise DatabaseConfigurationError(
                    "SQLite busy timeout could not be configured."
                )
        except DatabaseConfigurationError:
            connection.close()
            raise
        except sqlite3.Error as error:
            connection.close()
            raise DatabaseConfigurationError(
                "Required SQLite connection settings could not be applied."
            ) from error
        return connection

    def _prepare_parent_directory(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.parent.is_dir():
                raise NotADirectoryError
        except OSError as error:
            raise DatabasePathError(
                "The SQLite database directory could not be prepared."
            ) from error


class SQLiteDatabase:
    """Production-safe entry point that migrates before returning a connection.

    The facade owns only connection setup.  A returned connection belongs to
    the caller.  Use :meth:`connection` when scoped automatic close is useful.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        migration_runner: _MigrationRunner | None = None,
    ) -> None:
        self._factory = SQLiteConnectionFactory(
            path,
            busy_timeout_ms=busy_timeout_ms,
        )
        self._migration_runner = migration_runner

    @property
    def path(self) -> Path:
        return self._factory.path

    def connect(self) -> sqlite3.Connection:
        """Open, validate, and migrate a writable database connection."""

        connection = self._factory.connect()
        try:
            runner = self._migration_runner
            if runner is None:
                from netsentinel.infrastructure.sqlite.migrations import (
                    default_migration_runner,
                )

                runner = default_migration_runner()
            runner.migrate(connection)
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a migrated connection and always close it on scope exit."""

        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run one short ``BEGIN IMMEDIATE`` transaction.

    Success commits; any exception rolls back.  The connection remains open.
    Nested transactions are deliberately rejected instead of silently changing
    semantics; NS-014 does not need a savepoint abstraction.
    """

    if connection.in_transaction:
        raise NestedTransactionError("Nested SQLite transactions are unsupported.")

    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as error:
        raise DatabaseTransactionError(
            "The SQLite transaction could not be started."
        ) from error

    try:
        yield connection
    except BaseException as error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error as rollback_error:
            raise DatabaseTransactionError(
                "The SQLite transaction could not be rolled back."
            ) from rollback_error
        if isinstance(error, sqlite3.Error):
            raise DatabaseTransactionError(
                "The SQLite transaction failed and was rolled back."
            ) from error
        raise
    else:
        try:
            connection.execute("COMMIT")
        except sqlite3.Error as error:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DatabaseTransactionError(
                "The SQLite transaction could not be committed."
            ) from error


__all__ = (
    "APPLICATION_DIRECTORY_NAME",
    "DATABASE_FILENAME",
    "DEFAULT_BUSY_TIMEOUT_MS",
    "DatabaseConfigurationError",
    "DatabaseOpenError",
    "DatabasePathError",
    "DatabaseTransactionError",
    "NestedTransactionError",
    "SQLiteAdapterError",
    "SQLiteConnectionFactory",
    "SQLiteDatabase",
    "default_database_path",
    "transaction",
)
