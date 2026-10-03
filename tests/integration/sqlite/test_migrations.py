"""NS-014 integration coverage for SQLite setup and migrations."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
import sqlite3

import pytest

from netsentinel.infrastructure.sqlite import (
    DEFAULT_BUSY_TIMEOUT_MS,
    DatabaseConfigurationError,
    DatabaseMigrationError,
    DatabaseOpenError,
    DatabasePathError,
    DatabaseSchemaInvalid,
    DatabaseSchemaTooNew,
    NestedTransactionError,
    SQLiteConnectionFactory,
    SQLiteDatabase,
    Migration,
    MigrationRunner,
    builtin_migrations,
    default_database_path,
    default_migration_runner,
    transaction,
)


APPLIED_AT = datetime(2026, 9, 19, 12, 30, 45, 123_456, tzinfo=UTC)
EXPECTED_HISTORY_COLUMNS = {
    "id",
    "protocol",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "pid",
    "process_create_time_utc_us",
    "process_name",
    "process_status",
    "connection_state",
    "first_seen_utc_us",
    "last_seen_utc_us",
    "closed_at_utc_us",
    "close_reason",
    "executable_path", "process_name_status", "process_create_time_status",
    "executable_path_status", "parent_status", "parent_observed_at_utc_us",
    "parent_pid", "parent_create_time_utc_us", "parent_name",
    "parent_pid_status", "parent_create_time_status", "parent_name_status",
    "observation_gap", "monitoring_session_id", "lifecycle_id",
    "network_scope_status", "network_fingerprint", "network_interface_id",
    "network_interface_index", "network_scope_method", "network_scope_since_utc_us",
}


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "nested" / "netsentinel.sqlite3"


def _connect_raw(path: Path) -> sqlite3.Connection:
    return SQLiteConnectionFactory(path).connect()


def _extended_runner(*extra_migrations: Migration) -> MigrationRunner:
    return MigrationRunner(
        (*builtin_migrations(), *extra_migrations),
        clock=lambda: APPLIED_AT,
    )


def test_default_path_uses_local_app_data_without_creating_files(
    tmp_path: Path,
) -> None:
    local_app_data = tmp_path / "LocalAppData"

    path = default_database_path(local_app_data=local_app_data)

    assert path == (
        local_app_data.resolve() / "NetSentinel" / "netsentinel.sqlite3"
    )
    assert not local_app_data.exists()


def test_fresh_database_reaches_latest_schema_with_required_pragmas_and_objects(
    database_path: Path,
) -> None:
    database = SQLiteDatabase(database_path)

    with database.connection() as connection:
        metadata = connection.execute(
            "SELECT version, name, applied_at_utc_us FROM schema_migrations"
        ).fetchall()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        history_columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(connection_history)")
        }
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(connection_history)")
        }

        assert metadata[0][0:2] == (1, "initial_connection_history")
        assert isinstance(metadata[0][2], int)
        assert tables >= {"schema_migrations", "connection_history", "devices", "device_bindings"}
        assert set(history_columns) == EXPECTED_HISTORY_COLUMNS
        assert history_columns["first_seen_utc_us"] == "INTEGER"
        assert history_columns["last_seen_utc_us"] == "INTEGER"
        assert history_columns["process_create_time_utc_us"] == "INTEGER"
        assert indexes >= {
            "idx_connection_history_first_seen_id",
            "idx_connection_history_process_name",
            "idx_connection_history_completed_closed",
            "idx_connection_history_completed_oldest",
            "idx_connection_history_active_observation",
            "idx_connection_history_lifecycle",
        }
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert (
            connection.execute("PRAGMA busy_timeout").fetchone()[0]
            == DEFAULT_BUSY_TIMEOUT_MS
        )
        assert connection.row_factory is sqlite3.Row
        assert connection.isolation_level is None

    assert database_path.exists()
    assert database_path.parent.is_dir()


def test_schema_constraints_preserve_nullable_domain_semantics(
    database_path: Path,
) -> None:
    with SQLiteDatabase(database_path).connection() as connection:
        connection.execute(
            """
            INSERT INTO connection_history (
                id, protocol, local_address, local_port, remote_address,
                remote_port, pid, process_create_time_utc_us, process_name,
                process_status, connection_state, first_seen_utc_us,
                last_seen_utc_us, closed_at_utc_us, close_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "12345678-1234-1234-1234-123456789abc",
                "tcp",
                "127.0.0.1",
                50_000,
                None,
                None,
                None,
                None,
                None,
                "unavailable",
                "listen",
                1_000_000,
                2_000_000,
                None,
                None,
            ),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO connection_history (
                    id, protocol, local_address, local_port, remote_address,
                    remote_port, process_status, connection_state,
                    first_seen_utc_us, last_seen_utc_us
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "00000000-0000-0000-0000-000000000000",
                    "udp",
                    "127.0.0.1",
                    53,
                    "192.0.2.1",
                    None,
                    "unavailable",
                    "none",
                    2,
                    1,
                ),
            )


def test_migration_rerun_is_idempotent(database_path: Path) -> None:
    runner = MigrationRunner(builtin_migrations(), clock=lambda: APPLIED_AT)
    connection = _connect_raw(database_path)
    try:
        assert runner.migrate(connection) == 17
        before = connection.execute(
            "SELECT version, name, applied_at_utc_us FROM schema_migrations"
        ).fetchall()
        schema_before = connection.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()

        assert runner.migrate(connection) == 17

        after = connection.execute(
            "SELECT version, name, applied_at_utc_us FROM schema_migrations"
        ).fetchall()
        schema_after = connection.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        assert after == before
        assert schema_after == schema_before
    finally:
        connection.close()


def test_reopened_database_reports_the_persisted_schema_version(
    database_path: Path,
) -> None:
    with SQLiteDatabase(database_path).connection():
        pass

    reopened = _connect_raw(database_path)
    try:
        assert default_migration_runner().current_version(reopened) == 17
    finally:
        reopened.close()


def test_existing_version_one_database_upgrades_to_retention_indexes(
    database_path: Path,
) -> None:
    version_one_runner = MigrationRunner(
        builtin_migrations()[:1],
        clock=lambda: APPLIED_AT,
    )
    connection = _connect_raw(database_path)
    try:
        assert version_one_runner.migrate(connection) == 1
        assert default_migration_runner().migrate(connection) == 17
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(connection_history)")
        }
        assert indexes >= {
            "idx_connection_history_completed_closed",
            "idx_connection_history_completed_oldest",
        }
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'device_bindings'"
        ).fetchone() is not None
    finally:
        connection.close()


def test_existing_version_two_database_upgrades_to_device_tables(database_path: Path) -> None:
    old_runner = MigrationRunner(builtin_migrations()[:2], clock=lambda: APPLIED_AT)
    connection = _connect_raw(database_path)
    try:
        assert old_runner.migrate(connection) == 2
        assert default_migration_runner().migrate(connection) == 17
        assert {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )} >= {"devices", "device_bindings"}
    finally:
        connection.close()


def test_version_nine_history_upgrades_without_rewriting_legacy_rows(
    database_path: Path,
) -> None:
    connection = _connect_raw(database_path)
    try:
        assert MigrationRunner(builtin_migrations()[:9]).migrate(connection) == 9
        connection.execute(
            """INSERT INTO connection_history (
                id, protocol, local_address, local_port, pid,
                process_create_time_utc_us, process_name, process_status,
                connection_state, first_seen_utc_us, last_seen_utc_us
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("12345678-1234-1234-1234-123456789abc", "tcp", "127.0.0.1",
             5000, 42, 1_000_000, "old.exe", "available", "listen", 2_000_000,
             2_000_000),
        )
        assert default_migration_runner().migrate(connection) == 17
        row = connection.execute(
            "SELECT process_name, executable_path, parent_status FROM connection_history"
        ).fetchone()
        assert tuple(row) == ("old.exe", None, None)
        assert default_migration_runner().migrate(connection) == 17
    finally:
        connection.close()


def test_version_twelve_history_scope_stays_unknown_after_upgrade(database_path: Path) -> None:
    connection = _connect_raw(database_path)
    try:
        assert MigrationRunner(builtin_migrations()[:12]).migrate(connection) == 12
        connection.execute(
            "INSERT INTO connection_history (id, protocol, local_address, local_port, "
            "process_status, connection_state, first_seen_utc_us, last_seen_utc_us) "
            "VALUES (?, 'tcp', '192.0.2.10', 41000, 'unavailable', 'listen', 100, 100)",
            ("12345678-1234-1234-1234-123456789abc",),
        )
        assert default_migration_runner().migrate(connection) == 17
        row = connection.execute(
            "SELECT network_scope_status, network_fingerprint, network_scope_since_utc_us "
            "FROM connection_history"
        ).fetchone()
        assert tuple(row) == ("unknown", None, None)
    finally:
        connection.close()


def test_incremental_migrations_are_applied_in_deterministic_version_order(
    database_path: Path,
) -> None:
    version_eighteen = Migration(
        18,
        "ordered_probe",
        """
        CREATE TABLE migration_order_probe (position INTEGER NOT NULL);
        INSERT INTO migration_order_probe (position) VALUES (18);
        """,
    )
    initial_runner = MigrationRunner(builtin_migrations(), clock=lambda: APPLIED_AT)
    connection = _connect_raw(database_path)
    try:
        assert initial_runner.migrate(connection) == 17
        runner = MigrationRunner(
            (version_eighteen, *builtin_migrations()),
            clock=lambda: APPLIED_AT,
        )

        assert [item.version for item in runner.migrations] == list(range(1, 19))
        assert runner.migrate(connection) == 18
        assert runner.current_version(connection) == 18
        assert connection.execute(
            "SELECT position FROM migration_order_probe"
        ).fetchone()[0] == 18
        assert [
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ] == list(range(1, 19))
    finally:
        connection.close()


def test_failed_migration_rolls_back_ddl_and_does_not_advance_version(
    database_path: Path,
) -> None:
    failing = Migration(
        18,
        "deliberate_failure",
        """
        CREATE TABLE must_be_rolled_back (id INTEGER PRIMARY KEY);
        CREAT TABLE malformed_migration_statement (id INTEGER PRIMARY KEY);
        """,
    )
    connection = _connect_raw(database_path)
    try:
        default_migration_runner().migrate(connection)

        with pytest.raises(DatabaseMigrationError) as captured:
            _extended_runner(failing).migrate(connection)

        assert captured.value.version == 18
        assert "malformed_migration_statement" not in str(captured.value)
        assert default_migration_runner().current_version(connection) == 17
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'must_be_rolled_back'"
        ).fetchone() is None
        assert connection.in_transaction is False
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()


def test_future_schema_is_rejected_without_mutation_and_connection_is_closed(
    database_path: Path,
) -> None:
    connection = SQLiteDatabase(database_path).connect()
    connection.execute(
        """
        INSERT INTO schema_migrations (version, name, applied_at_utc_us)
        VALUES (18, 'future_schema', 1)
        """
    )
    before = connection.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    connection.close()

    class CapturingRunner:
        captured_connection: sqlite3.Connection | None = None

        def migrate(self, candidate: sqlite3.Connection) -> int:
            self.captured_connection = candidate
            return default_migration_runner().migrate(candidate)

    runner = CapturingRunner()
    with pytest.raises(DatabaseSchemaTooNew) as captured:
        SQLiteDatabase(database_path, migration_runner=runner).connect()

    assert captured.value.found_version == 18
    assert captured.value.supported_version == 17
    assert runner.captured_connection is not None
    with pytest.raises(sqlite3.ProgrammingError):
        runner.captured_connection.execute("SELECT 1")

    verification = _connect_raw(database_path)
    try:
        assert verification.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall() == before
        assert verification.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] == 18
    finally:
        verification.close()


@pytest.mark.parametrize(
    "metadata_sql, insert_sql",
    [
        (
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);",
            None,
        ),
        (
            """
            CREATE TABLE schema_migrations (
                version TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at_utc_us INTEGER NOT NULL
            );
            """,
            """
            INSERT INTO schema_migrations (version, name, applied_at_utc_us)
            VALUES ('invalid', 'invalid', 1);
            """,
        ),
    ],
)
def test_corrupt_migration_metadata_is_a_controlled_error(
    database_path: Path,
    metadata_sql: str,
    insert_sql: str | None,
) -> None:
    connection = _connect_raw(database_path)
    try:
        connection.execute(metadata_sql)
        if insert_sql is not None:
            connection.execute(insert_sql)

        with pytest.raises(DatabaseSchemaInvalid):
            default_migration_runner().migrate(connection)
        assert connection.in_transaction is False
    finally:
        connection.close()


def test_existing_schema_without_metadata_is_rejected(database_path: Path) -> None:
    connection = _connect_raw(database_path)
    try:
        connection.execute("CREATE TABLE unmanaged (id INTEGER PRIMARY KEY)")

        with pytest.raises(DatabaseSchemaInvalid):
            default_migration_runner().migrate(connection)

        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'unmanaged'"
        ).fetchone()[0] == "unmanaged"
    finally:
        connection.close()


def test_malformed_database_is_reported_as_a_sanitized_adapter_error(
    database_path: Path,
) -> None:
    database_path.parent.mkdir(parents=True)
    database_path.write_bytes(b"this is not a sqlite database")

    with pytest.raises(DatabaseConfigurationError) as captured:
        _connect_raw(database_path)

    assert "not a database" not in str(captured.value).lower()


def test_transaction_commits_rolls_back_and_keeps_connection_open(
    database_path: Path,
) -> None:
    connection = _connect_raw(database_path)
    try:
        connection.execute("CREATE TABLE values_table (value INTEGER NOT NULL)")
        with transaction(connection):
            connection.execute("INSERT INTO values_table VALUES (1)")
        assert [
            row[0]
            for row in connection.execute("SELECT value FROM values_table")
        ] == [1]

        with pytest.raises(RuntimeError, match="stop"):
            with transaction(connection):
                connection.execute("INSERT INTO values_table VALUES (2)")
                raise RuntimeError("stop")

        assert [
            row[0]
            for row in connection.execute("SELECT value FROM values_table")
        ] == [1]
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()


def test_nested_transaction_is_explicitly_rejected(database_path: Path) -> None:
    connection = _connect_raw(database_path)
    try:
        with transaction(connection):
            with pytest.raises(NestedTransactionError):
                with transaction(connection):
                    pass
    finally:
        connection.close()


def test_parent_directory_failure_and_database_open_failure_are_typed(
    tmp_path: Path,
) -> None:
    parent_blocker = tmp_path / "not-a-directory"
    parent_blocker.write_text("block", encoding="utf-8")
    with pytest.raises(DatabasePathError):
        SQLiteConnectionFactory(parent_blocker / "database.sqlite3").connect()

    database_directory = tmp_path / "directory-at-file-path"
    database_directory.mkdir()
    with pytest.raises(DatabaseOpenError):
        SQLiteConnectionFactory(database_directory).connect()


def test_scoped_connection_closes_cleanly(database_path: Path) -> None:
    database = SQLiteDatabase(database_path)
    with database.connection() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_domain_and_application_do_not_import_sqlite3() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    forbidden_roots = (
        repository_root / "src" / "netsentinel" / "domain",
        repository_root / "src" / "netsentinel" / "application",
    )
    violations: list[str] = []

    for root in forbidden_roots:
        for source_path in root.rglob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(
                    alias.name == "sqlite3" for alias in node.names
                ):
                    violations.append(str(source_path))
                if isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
                    violations.append(str(source_path))

    assert violations == []
