"""NS-016 integration coverage for writer-to-SQLite persistence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from threading import get_ident

import pytest

from netsentinel.application.ports import ConnectionHistoryQuery
from netsentinel.bootstrap import create_desktop_engine
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ParentProcessInfo,
    ParentProcessStatus,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.infrastructure.sqlite import (
    SQLiteConnectionHistoryRepository,
    SQLiteDatabase,
    SQLiteHistoryWriter,
)
from netsentinel.shared.diagnostics import PersistenceState


FIRST = datetime(2026, 9, 19, 15, 0, tzinfo=UTC)


def test_desktop_composition_wires_persistence_without_eager_database_io(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "composition" / "history.sqlite3"

    engine = create_desktop_engine(database_path=database_path)

    health = engine.persistence_health_snapshot()
    assert health is not None
    assert health.state is PersistenceState.STOPPED
    assert health.queue_capacity == 2_048
    assert not database_path.exists()


def _events() -> tuple[ConnectionOpened, ConnectionUpdated, ConnectionClosed]:
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(5150, FIRST - timedelta(hours=1)),
        name="browser.exe",
        executable_path=r"C:\Apps\browser.exe",
        parent=ParentProcessInfo(
            status=ParentProcessStatus.ABSENT,
            observed_at=FIRST,
        ),
    )
    opened_snapshot = ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", 51_500),
        remote_endpoint=Endpoint("198.51.100.25", 443),
        state=ConnectionState.ESTABLISHED,
        process=process,
        observed_at=FIRST,
    )
    updated_snapshot = ConnectionSnapshot(
        protocol=opened_snapshot.protocol,
        local_endpoint=opened_snapshot.local_endpoint,
        remote_endpoint=opened_snapshot.remote_endpoint,
        state=ConnectionState.CLOSE_WAIT,
        process=process,
        observed_at=FIRST + timedelta(seconds=1),
    )
    return (
        ConnectionOpened(opened_snapshot),
        ConnectionUpdated(opened_snapshot, updated_snapshot),
        ConnectionClosed(updated_snapshot, FIRST + timedelta(seconds=2)),
    )


def test_writer_drains_open_update_close_to_real_temporary_sqlite(
    tmp_path: Path,
) -> None:
    class CapturingDatabase(SQLiteDatabase):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.connections: list[sqlite3.Connection] = []
            self.connection_thread_ids: list[int] = []

        def connect(self) -> sqlite3.Connection:
            connection = super().connect()
            self.connections.append(connection)
            self.connection_thread_ids.append(get_ident())
            return connection

    database_path = tmp_path / "ns016" / "writer.sqlite3"
    database = CapturingDatabase(database_path)
    writer = SQLiteHistoryWriter(
        database,
        queue_capacity=16,
        batch_size=8,
        batch_interval=0.05,
        retry_limit=1,
        retry_backoff=0.001,
        shutdown_timeout=1.0,
    )
    events = _events()

    assert not database_path.exists()
    assert writer.start()
    for event in events:
        assert writer.submit(event)
    assert writer.stop()

    # The writer opened exactly one connection, on its own thread, reused it
    # for the complete FIFO batch, and closed it before stop returned.
    assert len(database.connections) == 1
    assert len(set(database.connection_thread_ids)) == 1
    assert database.connection_thread_ids[0] != get_ident()
    inspection = sqlite3.connect(database_path)
    try:
        row = inspection.execute(
            "SELECT connection_state, first_seen_utc_us, last_seen_utc_us, "
            "closed_at_utc_us, close_reason FROM connection_history"
        ).fetchone()
    finally:
        inspection.close()
    assert row is not None
    assert row[0] == ConnectionState.CLOSE_WAIT.value
    assert row[1] < row[2] < row[3]
    assert row[4] == "not_observed"
    with pytest.raises(sqlite3.ProgrammingError):
        database.connections[0].execute("SELECT 1")

    # Reading uses a separate repository-owned connection after writer cleanup.
    records = SQLiteConnectionHistoryRepository(
        SQLiteDatabase(database_path)
    ).query(ConnectionHistoryQuery(limit=10))
    assert len(records) == 1
    assert records[0].first_seen == FIRST
    assert records[0].last_seen == FIRST + timedelta(seconds=1)
    assert records[0].closed_at == FIRST + timedelta(seconds=2)
    assert records[0].snapshot.state is ConnectionState.CLOSE_WAIT
    assert records[0].snapshot.process.executable_path == r"C:\Apps\browser.exe"
    assert records[0].snapshot.process.parent is not None
    assert records[0].snapshot.process.parent.status is ParentProcessStatus.ABSENT
    assert writer.health.counters.accepted_events == 3
    assert writer.health.counters.persisted_events == 3
    assert writer.health.queue_depth == 0
