"""NS-017 integration coverage for safe connection-history retention."""

from __future__ import annotations

import ast
from dataclasses import fields
from datetime import UTC, datetime, timedelta, timezone
import inspect
from pathlib import Path
import sqlite3
from threading import enumerate as enumerate_threads
from uuid import UUID

import pytest

from netsentinel.application.ports import (
    HistoryRetentionRepositoryError,
    HistoryStorageDiagnostics,
)
from netsentinel.application.services.retention import (
    HistoryRetentionError,
    HistoryRetentionService,
    RetentionFailurePhase,
)
from netsentinel.bootstrap import create_history_retention_service
from netsentinel.infrastructure.sqlite import (
    SQLiteDatabase,
    SQLiteHistoryRetentionRepository,
    datetime_to_epoch_microseconds,
    transaction,
)
from netsentinel.shared.config import (
    DEFAULT_CLEANUP_CHUNK_SIZE,
    DEFAULT_MAX_HISTORY_ROWS,
    DEFAULT_RETENTION_DAYS,
    HistoryRetentionConfig,
)


NOW = datetime(2026, 9, 21, 12, 0, 0, 123_456, tzinfo=UTC)
CUTOFF = NOW - timedelta(days=30)


@pytest.fixture
def database(tmp_path: Path) -> SQLiteDatabase:
    return SQLiteDatabase(tmp_path / "ns017" / "retention.sqlite3")


@pytest.fixture
def retention_repository(
    database: SQLiteDatabase,
) -> SQLiteHistoryRetentionRepository:
    return SQLiteHistoryRetentionRepository(database)


def _config(*, days: int = 30, rows: int = 100, chunk: int = 10):
    return HistoryRetentionConfig(
        retention_days=days,
        max_history_rows=rows,
        cleanup_chunk_size=chunk,
    )


def _service(
    repository,
    *,
    days: int = 30,
    rows: int = 100,
    chunk: int = 10,
    now: datetime = NOW,
) -> HistoryRetentionService:
    return HistoryRetentionService(
        repository,
        config=_config(days=days, rows=rows, chunk=chunk),
        clock=lambda: now,
    )


def _record_id(number: int) -> str:
    return str(UUID(int=number))


def _seed(
    database: SQLiteDatabase,
    *,
    number: int,
    first_seen: datetime,
    closed_at: datetime | None,
    process_name: str | None = None,
) -> str:
    record_id = _record_id(number)
    first_us = datetime_to_epoch_microseconds(first_seen)
    closed_us = (
        datetime_to_epoch_microseconds(closed_at) if closed_at is not None else None
    )
    with database.connection() as connection:
        connection.execute(
            """
            INSERT INTO connection_history (
                id, protocol, local_address, local_port, remote_address,
                remote_port, pid, process_create_time_utc_us, process_name,
                process_status, connection_state, first_seen_utc_us,
                last_seen_utc_us, closed_at_utc_us, close_reason
            ) VALUES (?, 'tcp', '192.0.2.10', ?, '198.51.100.20', 443,
                      NULL, NULL, ?, 'unavailable', 'established', ?, ?, ?, ?)
            """,
            (
                record_id,
                40_000 + number,
                process_name,
                first_us,
                first_us,
                closed_us,
                "not_observed" if closed_at is not None else None,
            ),
        )
    return record_id


def _ids(database: SQLiteDatabase) -> tuple[str, ...]:
    with database.connection() as connection:
        return tuple(
            row[0]
            for row in connection.execute(
                "SELECT id FROM connection_history ORDER BY id"
            )
        )


def _count(database: SQLiteDatabase) -> int:
    with database.connection() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM connection_history").fetchone()[0])


def test_default_retention_config_is_valid_and_conservative() -> None:
    config = HistoryRetentionConfig()

    assert config.retention_days == DEFAULT_RETENTION_DAYS == 30
    assert config.max_history_rows == DEFAULT_MAX_HISTORY_ROWS == 100_000
    assert config.cleanup_chunk_size == DEFAULT_CLEANUP_CHUNK_SIZE == 500


@pytest.mark.parametrize(
    "field_name,value",
    (
        ("retention_days", -1),
        ("retention_days", 0),
        ("max_history_rows", -1),
        ("max_history_rows", 0),
        ("cleanup_chunk_size", -1),
        ("cleanup_chunk_size", 0),
        ("cleanup_chunk_size", True),
    ),
)
def test_invalid_retention_config_is_rejected(field_name: str, value: object) -> None:
    values = {
        "retention_days": 30,
        "max_history_rows": 100,
        "cleanup_chunk_size": 10,
    }
    values[field_name] = value

    with pytest.raises((TypeError, ValueError)):
        HistoryRetentionConfig(**values)


def test_empty_database_cleanup_and_manual_composition_are_safe(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manual" / "history.sqlite3"
    service = create_history_retention_service(
        database_path=path,
        config=_config(),
    )

    result = service.run_cleanup()

    assert result.deleted_rows == 0
    assert result.chunks_completed == 0
    assert not result.interrupted
    assert result.before.total_rows == result.after.total_rows == 0
    assert result.after.database_bytes > 0


def test_age_policy_deletes_strictly_before_cutoff_and_preserves_boundary_newer_and_active(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    old_closed = _seed(
        database,
        number=1,
        first_seen=CUTOFF - timedelta(days=2),
        closed_at=CUTOFF - timedelta(microseconds=1),
    )
    at_boundary = _seed(
        database,
        number=2,
        first_seen=CUTOFF - timedelta(days=1),
        closed_at=CUTOFF,
    )
    newer = _seed(
        database,
        number=3,
        first_seen=CUTOFF,
        closed_at=CUTOFF + timedelta(microseconds=1),
    )
    old_active = _seed(
        database,
        number=4,
        first_seen=CUTOFF - timedelta(days=200),
        closed_at=None,
    )

    result = _service(retention_repository).run_cleanup()

    assert result.cutoff == CUTOFF
    assert result.age_deleted_rows == 1
    assert result.row_limit_deleted_rows == 0
    assert result.chunks_completed == 1
    assert _ids(database) == tuple(sorted((at_boundary, newer, old_active)))
    assert old_closed not in _ids(database)


def test_utc_clock_is_exact_and_naive_or_non_utc_clock_is_rejected(
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    exact = _service(retention_repository).run_cleanup()
    assert exact.cutoff.microsecond == NOW.microsecond
    assert exact.cutoff.tzinfo is UTC

    naive = _service(retention_repository, now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="timezone-aware"):
        naive.run_cleanup()

    non_utc = _service(
        retention_repository,
        now=NOW.astimezone(timezone(timedelta(hours=3))),
    )
    with pytest.raises(ValueError, match="UTC offset"):
        non_utc.run_cleanup()


def test_row_limit_below_ceiling_changes_nothing(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    kept = {
        _seed(
            database,
            number=number,
            first_seen=NOW - timedelta(days=number),
            closed_at=NOW - timedelta(days=number) + timedelta(hours=1),
        )
        for number in range(1, 4)
    }

    result = _service(retention_repository, rows=4).run_cleanup()

    assert result.deleted_rows == 0
    assert set(_ids(database)) == kept


def test_row_limit_removes_oldest_completed_and_counts_but_never_deletes_active(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    oldest = _seed(
        database,
        number=1,
        first_seen=NOW - timedelta(days=5),
        closed_at=NOW - timedelta(days=4),
    )
    second = _seed(
        database,
        number=2,
        first_seen=NOW - timedelta(days=4),
        closed_at=NOW - timedelta(days=3),
    )
    newest = _seed(
        database,
        number=3,
        first_seen=NOW - timedelta(days=3),
        closed_at=NOW - timedelta(days=2),
    )
    active = _seed(
        database,
        number=4,
        first_seen=NOW - timedelta(days=500),
        closed_at=None,
    )

    result = _service(retention_repository, rows=2, chunk=1).run_cleanup()

    assert result.row_limit_deleted_rows == 2
    assert result.chunks_completed == 2
    assert _ids(database) == tuple(sorted((newest, active)))
    assert oldest not in _ids(database)
    assert second not in _ids(database)


def test_active_rows_can_force_all_completed_out_but_are_retained_above_limit(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    completed = _seed(
        database,
        number=1,
        first_seen=NOW - timedelta(days=2),
        closed_at=NOW - timedelta(days=1),
    )
    active_ids = {
        _seed(
            database,
            number=number,
            first_seen=NOW - timedelta(days=100 + number),
            closed_at=None,
        )
        for number in (2, 3, 4)
    }

    result = _service(retention_repository, rows=2).run_cleanup()

    assert result.row_limit_deleted_rows == 1
    assert completed not in _ids(database)
    assert set(_ids(database)) == active_ids
    assert result.after.total_rows == 3
    assert result.after.active_rows == 3


def test_age_then_row_policy_is_deterministic(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    age_old = _seed(
        database,
        number=1,
        first_seen=CUTOFF - timedelta(days=2),
        closed_at=CUTOFF - timedelta(microseconds=1),
    )
    row_oldest = _seed(
        database,
        number=2,
        first_seen=CUTOFF + timedelta(days=1),
        closed_at=CUTOFF + timedelta(days=2),
    )
    kept_completed = _seed(
        database,
        number=3,
        first_seen=CUTOFF + timedelta(days=3),
        closed_at=CUTOFF + timedelta(days=4),
    )
    kept_active = _seed(
        database,
        number=4,
        first_seen=CUTOFF - timedelta(days=500),
        closed_at=None,
    )

    result = _service(retention_repository, rows=2).run_cleanup()

    assert result.age_deleted_rows == 1
    assert result.row_limit_deleted_rows == 1
    assert age_old not in _ids(database)
    assert row_oldest not in _ids(database)
    assert _ids(database) == tuple(sorted((kept_completed, kept_active)))


def test_single_and_multi_chunk_cleanup_never_exceed_configured_chunk(
    database: SQLiteDatabase,
) -> None:
    for number in range(1, 8):
        _seed(
            database,
            number=number,
            first_seen=CUTOFF - timedelta(days=number),
            closed_at=CUTOFF - timedelta(microseconds=number),
        )

    class RecordingRepository(SQLiteHistoryRetentionRepository):
        deleted_per_call: list[int]

        def __init__(self, candidate: SQLiteDatabase) -> None:
            super().__init__(candidate)
            self.deleted_per_call = []

        def delete_completed_before(self, cutoff: datetime, limit: int) -> int:
            deleted = super().delete_completed_before(cutoff, limit)
            self.deleted_per_call.append(deleted)
            return deleted

    repository = RecordingRepository(database)
    result = _service(repository, chunk=3).run_cleanup()

    assert result.age_deleted_rows == 7
    assert result.chunks_completed == 3
    assert repository.deleted_per_call == [3, 3, 1]
    assert max(repository.deleted_per_call) <= 3
    assert _count(database) == 0


def test_interrupted_cleanup_commits_prior_chunks_and_rerun_continues_idempotently(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    for number in range(1, 6):
        _seed(
            database,
            number=number,
            first_seen=CUTOFF - timedelta(days=number),
            closed_at=CUTOFF - timedelta(microseconds=number),
        )
    checks = 0

    def stop_after_first_chunk() -> bool:
        nonlocal checks
        checks += 1
        return checks > 1

    interrupted = _service(retention_repository, chunk=2).run_cleanup(
        stop_requested=stop_after_first_chunk
    )

    assert interrupted.interrupted
    assert interrupted.deleted_rows == 2
    assert interrupted.chunks_completed == 1
    assert _count(database) == 3

    resumed = _service(retention_repository, chunk=2).run_cleanup()
    repeated = _service(retention_repository, chunk=2).run_cleanup()
    assert resumed.deleted_rows == 3
    assert resumed.chunks_completed == 2
    assert repeated.deleted_rows == 0
    assert repeated.chunks_completed == 0
    assert _count(database) == 0


def test_invalid_stop_predicate_is_a_typed_interruption_error(
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    with pytest.raises(HistoryRetentionError) as captured:
        _service(retention_repository).run_cleanup(
            stop_requested=lambda: "not-a-bool"  # type: ignore[return-value]
        )

    assert captured.value.phase is RetentionFailurePhase.INTERRUPTION
    assert captured.value.deleted_rows == 0
    assert captured.value.chunks_completed == 0


def test_failed_chunk_rolls_back_while_previous_commits_survive_and_error_is_sanitized(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    ids = []
    for number in range(1, 5):
        ids.append(
            _seed(
                database,
                number=number,
                first_seen=CUTOFF - timedelta(days=5 - number),
                closed_at=CUTOFF - timedelta(microseconds=number),
            )
        )
    failing_id = ids[2]
    with database.connection() as connection:
        connection.execute(
            f"""
            CREATE TRIGGER fail_second_retention_chunk
            BEFORE DELETE ON connection_history
            WHEN OLD.id = '{failing_id}'
            BEGIN
                SELECT RAISE(ABORT, 'sensitive sqlite failure detail');
            END
            """
        )

    with pytest.raises(HistoryRetentionError) as captured:
        _service(retention_repository, chunk=2).run_cleanup()

    assert captured.value.phase is RetentionFailurePhase.AGE_CLEANUP
    assert captured.value.deleted_rows == 2
    assert captured.value.chunks_completed == 1
    assert not isinstance(captured.value, sqlite3.Error)
    assert "sensitive" not in str(captured.value)
    assert set(_ids(database)) == set(ids[2:])

    with database.connection() as connection:
        connection.execute("DROP TRIGGER fail_second_retention_chunk")
    resumed = _service(retention_repository, chunk=2).run_cleanup()
    assert resumed.deleted_rows == 2
    assert _count(database) == 0


def test_active_lifecycle_becomes_eligible_only_after_it_is_closed(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    record_id = _seed(
        database,
        number=1,
        first_seen=CUTOFF - timedelta(days=100),
        closed_at=None,
    )

    first = _service(retention_repository).run_cleanup()
    assert first.deleted_rows == 0
    assert _ids(database) == (record_id,)

    with database.connection() as connection:
        connection.execute(
            """
            UPDATE connection_history
            SET closed_at_utc_us = ?, close_reason = 'not_observed'
            WHERE id = ?
            """,
            (
                datetime_to_epoch_microseconds(CUTOFF - timedelta(microseconds=1)),
                record_id,
            ),
        )

    second = _service(retention_repository).run_cleanup()
    assert second.deleted_rows == 1
    assert _ids(database) == ()


def test_timestamp_and_uuid_tie_break_is_deterministic(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    same_first = NOW - timedelta(days=3)
    same_close = NOW - timedelta(days=2)
    ids = [
        _seed(
            database,
            number=number,
            first_seen=same_first,
            closed_at=same_close,
        )
        for number in (3, 1, 2)
    ]

    result = _service(retention_repository, rows=2, chunk=1).run_cleanup()

    assert result.row_limit_deleted_rows == 1
    assert min(ids) not in _ids(database)
    assert set(_ids(database)) == set(ids) - {min(ids)}


def test_storage_diagnostics_report_empty_and_populated_files_without_path(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    empty = retention_repository.storage_diagnostics()
    for number in range(1, 401):
        _seed(
            database,
            number=number,
            first_seen=NOW - timedelta(seconds=number),
            closed_at=NOW,
            process_name=None,
        )
    populated = retention_repository.storage_diagnostics()

    assert empty.total_rows == 0
    assert empty.database_bytes > 0
    assert empty.wal_bytes >= 0
    assert empty.total_local_storage_bytes == empty.database_bytes + empty.wal_bytes
    assert populated.total_rows == 400
    assert populated.completed_rows == 400
    assert populated.total_local_storage_bytes > empty.total_local_storage_bytes
    assert {field.name for field in fields(HistoryStorageDiagnostics)} == {
        "database_bytes",
        "wal_bytes",
        "total_rows",
        "active_rows",
        "completed_rows",
    }
    assert all("path" not in field.name for field in fields(HistoryStorageDiagnostics))


def test_absent_wal_is_reported_as_zero(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    with database.connection():
        pass
    wal_path = database.path.with_name(database.path.name + "-wal")
    assert not wal_path.exists()

    diagnostics = retention_repository.storage_diagnostics()

    assert diagnostics.wal_bytes == 0


def test_diagnostics_failure_is_typed_and_does_not_expose_filesystem_detail(
    tmp_path: Path,
) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("block", encoding="utf-8")
    repository = SQLiteHistoryRetentionRepository(
        SQLiteDatabase(blocker / "sensitive-location.sqlite3")
    )
    service = _service(repository)

    with pytest.raises(HistoryRetentionError) as captured:
        service.storage_diagnostics()

    assert captured.value.phase is RetentionFailurePhase.DIAGNOSTICS
    assert "sensitive-location" not in str(captured.value)


def test_adapter_cleanup_errors_are_typed_and_sanitized(
    database: SQLiteDatabase,
    retention_repository: SQLiteHistoryRetentionRepository,
) -> None:
    _seed(
        database,
        number=1,
        first_seen=CUTOFF - timedelta(days=2),
        closed_at=CUTOFF - timedelta(days=1),
    )
    with database.connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_all_retention
            BEFORE DELETE ON connection_history
            BEGIN
                SELECT RAISE(ABORT, 'private sqlite detail');
            END
            """
        )

    with pytest.raises(HistoryRetentionRepositoryError) as captured:
        retention_repository.delete_completed_before(CUTOFF, 10)

    assert not isinstance(captured.value, sqlite3.Error)
    assert "private sqlite detail" not in str(captured.value)
    assert _count(database) == 1


def test_cleanup_connections_close_and_no_worker_thread_is_created(tmp_path: Path) -> None:
    class CapturingDatabase(SQLiteDatabase):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.opened: list[sqlite3.Connection] = []

        def connect(self) -> sqlite3.Connection:
            connection = super().connect()
            self.opened.append(connection)
            return connection

    database = CapturingDatabase(tmp_path / "connections" / "history.sqlite3")
    repository = SQLiteHistoryRetentionRepository(database)
    thread_names_before = {thread.name for thread in enumerate_threads()}

    _service(repository).run_cleanup()

    assert database.opened
    for connection in database.opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
    assert {thread.name for thread in enumerate_threads()} == thread_names_before


def test_layer_boundaries_parameter_binding_and_metadata_only_schema() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    forbidden_import_roots = (
        repository_root / "src" / "netsentinel" / "domain",
        repository_root / "src" / "netsentinel" / "application",
    )
    violations: list[str] = []
    for root in forbidden_import_roots:
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

    presentation_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (repository_root / "src" / "netsentinel" / "presentation").rglob("*.py")
    )
    assert "SQLiteHistoryRetentionRepository" not in presentation_text
    assert "sqlite3" not in presentation_text

    adapter_source = inspect.getsource(SQLiteHistoryRetentionRepository)
    assert "LIMIT ?" in adapter_source
    assert "closed_at_utc_us IS NOT NULL" in adapter_source
    assert "DELETE FROM connection_history" in adapter_source
    assert "DELETE FROM connection_history LIMIT" not in adapter_source
    assert "vacuum" not in adapter_source.lower()

    schema = (
        repository_root
        / "src"
        / "netsentinel"
        / "infrastructure"
        / "sqlite"
        / "schema"
        / "001_initial.sql"
    ).read_text(encoding="utf-8").lower()
    assert "payload" not in schema
    assert "request_body" not in schema
    assert "response_body" not in schema
    assert "credential" not in schema
