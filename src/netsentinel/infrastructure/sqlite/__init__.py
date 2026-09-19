"""Versioned SQLite infrastructure for local NetSentinel data."""

from netsentinel.infrastructure.sqlite.database import (
    DEFAULT_BUSY_TIMEOUT_MS,
    DatabaseConfigurationError,
    DatabaseOpenError,
    DatabasePathError,
    DatabaseTransactionError,
    NestedTransactionError,
    SQLiteAdapterError,
    SQLiteConnectionFactory,
    SQLiteDatabase,
    default_database_path,
    transaction,
)
from netsentinel.infrastructure.sqlite.migrations import (
    DatabaseMigrationError,
    DatabaseSchemaError,
    DatabaseSchemaInvalid,
    DatabaseSchemaTooNew,
    Migration,
    MigrationRunner,
    builtin_migrations,
    default_migration_runner,
)

__all__ = (
    "DEFAULT_BUSY_TIMEOUT_MS",
    "DatabaseConfigurationError",
    "DatabaseMigrationError",
    "DatabaseOpenError",
    "DatabasePathError",
    "DatabaseSchemaError",
    "DatabaseSchemaInvalid",
    "DatabaseSchemaTooNew",
    "DatabaseTransactionError",
    "Migration",
    "MigrationRunner",
    "NestedTransactionError",
    "SQLiteAdapterError",
    "SQLiteConnectionFactory",
    "SQLiteDatabase",
    "builtin_migrations",
    "default_database_path",
    "default_migration_runner",
    "transaction",
)
