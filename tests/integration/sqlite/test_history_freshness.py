"""NS-058: durable freshness and conservative monitoring-session gaps."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from netsentinel.application.ports import ConnectionHistoryQuery
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionOpened, ConnectionSnapshot, ConnectionState,
    ConnectionUpdated, Endpoint, ProcessInfo, TransportProtocol,
)
from netsentinel.infrastructure.sqlite import (
    MigrationRunner, SQLiteConnectionHistoryRepository, SQLiteDatabase,
    SQLiteHistoryRetentionRepository, builtin_migrations,
)
from netsentinel.infrastructure.sqlite.writer import SQLiteHistoryWriteSessionFactory, SQLiteHistoryWriter


BASE = datetime(2026, 10, 1, 12, tzinfo=UTC)


def snapshot(at: datetime) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.1", 4567),
        remote_endpoint=Endpoint("198.51.100.1", 443),
        state=ConnectionState.ESTABLISHED,
        process=ProcessInfo.unavailable(),
        observed_at=at,
    )


def test_checkpoint_close_and_stale_checkpoint_keep_final_observation(tmp_path: Path) -> None:
    database = SQLiteDatabase(tmp_path / "history.sqlite3")
    repository = SQLiteConnectionHistoryRepository(database)
    session_id, lifecycle_id = uuid4(), uuid4()
    opened = ConnectionOpened(snapshot(BASE), session_id=session_id, lifecycle_id=lifecycle_id)
    later = snapshot(BASE + timedelta(minutes=1))
    checkpoint = ConnectionUpdated(opened.snapshot, later, session_id, lifecycle_id)
    with SQLiteHistoryWriteSessionFactory(database)() as session:
        with session.batch():
            session.record_opened(opened)
            session.record_checkpoint(checkpoint)
            session.record_closed(ConnectionClosed(later, later.observed_at + timedelta(seconds=1),
                                                   session_id=session_id, lifecycle_id=lifecycle_id))
        with session.batch():
            session.record_checkpoint(checkpoint)
    row = repository.query(ConnectionHistoryQuery(limit=10))[0]
    assert row.first_seen == BASE
    assert row.last_seen == later.observed_at
    assert row.closed_at == later.observed_at + timedelta(seconds=1)
    assert not row.observation_gap


def test_restart_marks_gap_without_close_and_same_key_gets_new_lifecycle(tmp_path: Path) -> None:
    database = SQLiteDatabase(tmp_path / "history.sqlite3")
    repository = SQLiteConnectionHistoryRepository(database)
    old = ConnectionOpened(snapshot(BASE), session_id=uuid4(), lifecycle_id=uuid4())
    repository.record_opened(old)
    with SQLiteHistoryWriteSessionFactory(database)() as session:
        with session.batch():
            assert session.reconcile_open() == 1
        with session.batch():
            assert session.reconcile_open() == 0
    new = ConnectionOpened(snapshot(BASE + timedelta(hours=1)), session_id=uuid4(), lifecycle_id=uuid4())
    repository.record_opened(new)
    rows = repository.query(ConnectionHistoryQuery(limit=10))
    assert len(rows) == 2
    assert rows[0].session_id == new.session_id
    assert rows[0].lifecycle_id == new.lifecycle_id
    assert not rows[0].observation_gap
    assert rows[1].observation_gap
    assert rows[1].closed_at is None
    assert rows[1].last_seen == BASE
    assert rows[1].lifecycle_id == old.lifecycle_id
    stale = ConnectionUpdated(old.snapshot, snapshot(BASE + timedelta(hours=2)),
                              old.session_id, old.lifecycle_id)
    with SQLiteHistoryWriteSessionFactory(database)() as session:
        with session.batch():
            session.record_checkpoint(stale)
    assert repository.get(rows[0].record_id).last_seen == new.occurred_at


def test_010_upgrade_preserves_legacy_unknown_and_gap_retention(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    with SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:10])).connection() as connection:
        connection.execute(
            """INSERT INTO connection_history
               (id, protocol, local_address, local_port, process_status,
                connection_state, first_seen_utc_us, last_seen_utc_us)
               VALUES (?, 'tcp', '192.0.2.3', 4000, 'unavailable', 'listen', 1, 1)""",
            (str(uuid4()),),
        )
    database = SQLiteDatabase(path)
    repository = SQLiteConnectionHistoryRepository(database)
    legacy = repository.query(ConnectionHistoryQuery(limit=10))[0]
    assert legacy.session_id is None
    assert legacy.lifecycle_id is None
    assert not legacy.observation_gap
    with database.connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 14
    with SQLiteHistoryWriteSessionFactory(database)() as session:
        with session.batch():
            assert session.reconcile_open() == 1
    assert repository.get(legacy.record_id).observation_gap
    retention = SQLiteHistoryRetentionRepository(database)
    assert retention.delete_completed_before(BASE, 10) == 1
    assert repository.get(legacy.record_id) is None


def test_writer_start_reconciles_prior_open_without_inventing_shutdown_close(tmp_path: Path) -> None:
    database = SQLiteDatabase(tmp_path / "history.sqlite3")
    repository = SQLiteConnectionHistoryRepository(database)
    opened = repository.record_opened(ConnectionOpened(snapshot(BASE)))
    assert opened.closed_at is None
    writer = SQLiteHistoryWriter(database, batch_interval=0)
    assert writer.start()
    assert writer.stop(2.0)
    reconciled = repository.get(opened.record_id)
    assert reconciled is not None
    assert reconciled.observation_gap
    assert reconciled.closed_at is None
    assert reconciled.last_seen == BASE
