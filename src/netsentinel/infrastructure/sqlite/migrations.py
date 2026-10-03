"""Deterministic, transactional SQLite schema migrations."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
import re
import sqlite3

from netsentinel.infrastructure.sqlite.database import (
    DatabaseTransactionError,
    SQLiteAdapterError,
    transaction,
)


MIGRATION_TABLE = "schema_migrations"
_SCHEMA_PACKAGE = "netsentinel.infrastructure.sqlite.schema"
_TRANSACTION_CONTROL = re.compile(
    r"^\s*(?:(?:--[^\n]*\n)\s*)*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b",
    re.IGNORECASE,
)


class DatabaseSchemaError(SQLiteAdapterError):
    """Base class for unusable or incompatible schema metadata."""


class DatabaseSchemaInvalid(DatabaseSchemaError):
    """The migration ledger is missing, malformed, or inconsistent."""


class DatabaseSchemaTooNew(DatabaseSchemaError):
    """The database was created by a newer application schema."""

    def __init__(self, found_version: int, supported_version: int) -> None:
        self.found_version = found_version
        self.supported_version = supported_version
        super().__init__(
            "The SQLite schema is newer than this application supports."
        )


class DatabaseMigrationError(SQLiteAdapterError):
    """A numbered migration failed and was rolled back."""

    def __init__(self, version: int, name: str) -> None:
        self.version = version
        self.migration_name = name
        super().__init__(f"SQLite migration {version:03d} ({name}) failed.")


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable schema transition loaded from a trusted package resource."""

    version: int
    name: str
    sql: str

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("migration version must be an integer")
        if self.version < 1:
            raise ValueError("migration version must be positive")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("migration name must not be empty")
        if not isinstance(self.sql, str) or not self.sql.strip():
            raise ValueError("migration SQL must not be empty")


def _utc_epoch_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("migration clock must return a timezone-aware datetime")
    utc_value = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    return (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def _read_resource(resource_name: str, version: int, name: str) -> str:
    try:
        return (
            resources.files(_SCHEMA_PACKAGE)
            .joinpath(resource_name)
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, OSError, TypeError) as error:
        raise DatabaseMigrationError(version, name) from error


@lru_cache(maxsize=1)
def builtin_migrations() -> tuple[Migration, ...]:
    """Load the explicitly ordered built-in migration manifest."""

    return (
        Migration(
            version=1,
            name="initial_connection_history",
            sql=_read_resource("001_initial.sql", 1, "initial_connection_history"),
        ),
        Migration(
            version=2,
            name="history_retention_indexes",
            sql=_read_resource(
                "002_history_retention_indexes.sql",
                2,
                "history_retention_indexes",
            ),
        ),
        Migration(
            version=3,
            name="device_bindings",
            sql=_read_resource("003_devices.sql", 3, "device_bindings"),
        ),
        Migration(
            version=4,
            name="gateway_baselines",
            sql=_read_resource("004_gateway_baselines.sql", 4, "gateway_baselines"),
        ),
        Migration(
            version=5,
            name="alerts",
            sql=_read_resource("005_alerts.sql", 5, "alerts"),
        ),
        Migration(
            version=6,
            name="dns_history",
            sql=_read_resource("006_dns_history.sql", 6, "dns_history"),
        ),
        Migration(
            version=7,
            name="device_profiles",
            sql=_read_resource("007_device_profiles.sql", 7, "device_profiles"),
        ),
        Migration(
            version=8,
            name="vlan_summaries",
            sql=_read_resource("008_vlan_summaries.sql", 8, "vlan_summaries"),
        ),
        Migration(
            version=9,
            name="vlan_verification",
            sql=_read_resource("009_vlan_verification.sql", 9, "vlan_verification"),
        ),
        Migration(
            version=10,
            name="process_metadata",
            sql=_read_resource("010_process_metadata.sql", 10, "process_metadata"),
        ),
        Migration(
            version=11,
            name="history_observation_gaps",
            sql=_read_resource("011_history_observation_gaps.sql", 11, "history_observation_gaps"),
        ),
        Migration(
            version=12,
            name="dns_association_evidence",
            sql=_read_resource("012_dns_association_evidence.sql", 12, "dns_association_evidence"),
        ),
        Migration(
            version=13,
            name="connection_network_scope",
            sql=_read_resource("013_connection_network_scope.sql", 13, "connection_network_scope"),
        ),
        Migration(
            version=14,
            name="behavior_baselines",
            sql=_read_resource("014_behavior_baselines.sql", 14, "behavior_baselines"),
        ),
        Migration(
            version=15,
            name="risk_assessments",
            sql=_read_resource("015_risk_assessments.sql", 15, "risk_assessments"),
        ),
    )


class MigrationRunner:
    """Apply each missing migration once, in numeric order."""

    def __init__(
        self,
        migrations: Iterable[Migration],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        ordered = tuple(sorted(migrations, key=lambda migration: migration.version))
        versions = tuple(migration.version for migration in ordered)
        expected = tuple(range(1, len(ordered) + 1))
        if versions != expected:
            raise ValueError("migration versions must be unique and contiguous from 1")
        self._migrations = ordered
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def migrations(self) -> tuple[Migration, ...]:
        return self._migrations

    @property
    def latest_version(self) -> int:
        return self._migrations[-1].version if self._migrations else 0

    def current_version(self, connection: sqlite3.Connection) -> int:
        """Read and validate the complete migration ledger."""

        try:
            table_row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (MIGRATION_TABLE,),
            ).fetchone()
            if table_row is None:
                object_row = connection.execute(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                      AND type IN ('table', 'index', 'view', 'trigger')
                    LIMIT 1
                    """
                ).fetchone()
                if object_row is not None:
                    raise DatabaseSchemaInvalid(
                        "SQLite schema objects exist without migration metadata."
                    )
                return 0

            columns = connection.execute(
                f"PRAGMA table_info({MIGRATION_TABLE})"
            ).fetchall()
            column_map = {row[1]: row for row in columns}
            required_columns = {"version", "name", "applied_at_utc_us"}
            if not required_columns.issubset(column_map):
                raise DatabaseSchemaInvalid(
                    "SQLite migration metadata has an invalid structure."
                )
            if column_map["version"][5] != 1:
                raise DatabaseSchemaInvalid(
                    "SQLite migration version is not a primary key."
                )

            rows = connection.execute(
                f"SELECT version, name, applied_at_utc_us "
                f"FROM {MIGRATION_TABLE} ORDER BY version"
            ).fetchall()
        except DatabaseSchemaInvalid:
            raise
        except sqlite3.Error as error:
            raise DatabaseSchemaInvalid(
                "SQLite migration metadata could not be read."
            ) from error

        if not rows:
            raise DatabaseSchemaInvalid("SQLite migration metadata is empty.")

        parsed: list[tuple[int, str, int]] = []
        for row in rows:
            version, name, applied_at = row
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version < 1
                or not isinstance(name, str)
                or not name.strip()
                or isinstance(applied_at, bool)
                or not isinstance(applied_at, int)
                or applied_at < 0
            ):
                raise DatabaseSchemaInvalid(
                    "SQLite migration metadata contains invalid values."
                )
            parsed.append((version, name, applied_at))

        found_version = parsed[-1][0]
        if found_version > self.latest_version:
            raise DatabaseSchemaTooNew(found_version, self.latest_version)

        expected_versions = list(range(1, found_version + 1))
        if [row[0] for row in parsed] != expected_versions:
            raise DatabaseSchemaInvalid(
                "SQLite migration metadata contains a version gap."
            )
        for version, name, _ in parsed:
            if self._migrations[version - 1].name != name:
                raise DatabaseSchemaInvalid(
                    "SQLite migration metadata does not match this application."
                )
        return found_version

    def migrate(self, connection: sqlite3.Connection) -> int:
        """Apply missing migrations and return the resulting schema version."""

        current = self.current_version(connection)
        for migration in self._migrations[current:]:
            self._apply(connection, migration)
        return self.latest_version

    def _apply(self, connection: sqlite3.Connection, migration: Migration) -> None:
        try:
            statements = _split_sql_script(migration.sql)
            applied_at = _utc_epoch_microseconds(self._clock())
            with transaction(connection):
                for statement in statements:
                    if _TRANSACTION_CONTROL.match(statement):
                        raise DatabaseTransactionError(
                            "Migration SQL cannot manage transactions directly."
                        )
                    connection.execute(statement)
                connection.execute(
                    f"""
                    INSERT INTO {MIGRATION_TABLE} (version, name, applied_at_utc_us)
                    VALUES (?, ?, ?)
                    """,
                    (migration.version, migration.name, applied_at),
                )
        except DatabaseMigrationError:
            raise
        except (DatabaseTransactionError, sqlite3.Error, ValueError) as error:
            raise DatabaseMigrationError(migration.version, migration.name) from error


def _split_sql_script(script: str) -> tuple[str, ...]:
    """Split trusted resource SQL without using ``executescript``.

    ``sqlite3.Connection.executescript`` implicitly commits a pending
    transaction.  Executing complete statements one by one preserves SQLite's
    transactional DDL rollback semantics.
    """

    statements: list[str] = []
    buffer: list[str] = []
    for character in script:
        buffer.append(character)
        if character == ";":
            candidate = "".join(buffer)
            if sqlite3.complete_statement(candidate):
                statements.append(candidate)
                buffer.clear()
    if "".join(buffer).strip():
        raise ValueError("migration SQL ends with an incomplete statement")
    if not statements:
        raise ValueError("migration SQL contains no complete statements")
    return tuple(statements)


def default_migration_runner() -> MigrationRunner:
    return MigrationRunner(builtin_migrations())


__all__ = (
    "DatabaseMigrationError",
    "DatabaseSchemaError",
    "DatabaseSchemaInvalid",
    "DatabaseSchemaTooNew",
    "MIGRATION_TABLE",
    "Migration",
    "MigrationRunner",
    "builtin_migrations",
    "default_migration_runner",
)
