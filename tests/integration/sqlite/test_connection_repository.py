"""NS-015 integration coverage for connection-history persistence."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from uuid import UUID

import pytest

from netsentinel.application.ports import (
    MAX_HISTORY_QUERY_LIMIT,
    ConnectionHistoryQuery,
    HistoryDataCorrupt,
    HistoryRecordNotFound,
    HistoryQueryCancelled,
    HistoryRepositoryError,
)
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionNetworkScope,
    NetworkAttributionMethod,
    NetworkScopeStatus,
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
    datetime_to_epoch_microseconds,
    epoch_microseconds_to_datetime,
)


FIRST = datetime(2026, 9, 19, 12, 30, 45, 123_456, tzinfo=UTC)
SECOND = datetime(2026, 9, 19, 12, 31, 46, 654_321, tzinfo=UTC)
CLOSED = datetime(2026, 9, 19, 12, 32, 47, 111_222, tzinfo=UTC)
CREATE_TIME = datetime(2026, 9, 19, 8, 0, 0, 987_654, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> SQLiteDatabase:
    return SQLiteDatabase(tmp_path / "ns015" / "history.sqlite3")


@pytest.fixture
def repository(database: SQLiteDatabase) -> SQLiteConnectionHistoryRepository:
    return SQLiteConnectionHistoryRepository(database)


def _process(
    *,
    status: ProcessInfoStatus = ProcessInfoStatus.AVAILABLE,
    pid: int | None = 4100,
    create_time: datetime | None = CREATE_TIME,
    name: str | None = "browser.exe",
) -> ProcessInfo:
    identity = (
        ProcessIdentity(pid=pid, create_time=create_time) if pid is not None else None
    )
    if status is not ProcessInfoStatus.AVAILABLE:
        name = None
    return ProcessInfo(status=status, identity=identity, name=name)


def _snapshot(
    *,
    observed_at: datetime = FIRST,
    protocol: TransportProtocol = TransportProtocol.TCP,
    state: ConnectionState | None = None,
    local_address: str = "192.0.2.10",
    local_port: int = 50_000,
    remote_address: str | None = "198.51.100.20",
    remote_port: int = 443,
    process: ProcessInfo | None = None,
    network_scope: ConnectionNetworkScope | None = None,
) -> ConnectionSnapshot:
    if state is None:
        state = (
            ConnectionState.NONE
            if protocol is TransportProtocol.UDP
            else ConnectionState.ESTABLISHED
        )
    remote = (
        Endpoint(remote_address, remote_port) if remote_address is not None else None
    )
    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local_address, local_port),
        remote_endpoint=remote,
        state=state,
        process=process if process is not None else _process(),
        observed_at=observed_at,
        network_scope=network_scope or ConnectionNetworkScope.unknown(),
    )


def _open(
    repository: SQLiteConnectionHistoryRepository,
    **snapshot_values: object,
):
    snapshot = _snapshot(**snapshot_values)
    return repository.record_opened(ConnectionOpened(snapshot))


def test_repository_uses_fresh_migrated_temporary_database(
    database: SQLiteDatabase,
) -> None:
    repository = SQLiteConnectionHistoryRepository(database)

    assert repository.query(ConnectionHistoryQuery(limit=10)) == ()
    assert database.path.name == "history.sqlite3"
    assert database.path.parent.name == "ns015"
    with database.connection() as connection:
        assert connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] == 17


def test_open_insert_and_lookup_round_trip_ipv4_process_and_timestamps(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    inserted = _open(repository)
    loaded = repository.get(inserted.record_id)

    assert loaded == inserted
    assert loaded is not None
    assert loaded.record_id != loaded.key
    assert loaded.snapshot.local_endpoint == Endpoint("192.0.2.10", 50_000)
    assert loaded.snapshot.remote_endpoint == Endpoint("198.51.100.20", 443)
    assert loaded.snapshot.protocol is TransportProtocol.TCP
    assert loaded.snapshot.process.identity == ProcessIdentity(4100, CREATE_TIME)
    assert loaded.first_seen == FIRST
    assert loaded.last_seen == FIRST
    assert loaded.first_seen.microsecond == 123_456
    assert loaded.closed_at is None
    assert repository.get(UUID("00000000-0000-0000-0000-000000000000")) is None


def test_network_scope_round_trip_and_change_limits_historical_window(repository) -> None:
    first_scope = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "first", 1,
                                         NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
    second_scope = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "b" * 64, "second", 2,
                                          NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
    opened = _open(repository, network_scope=first_scope)
    assert opened.snapshot.network_scope == first_scope
    assert opened.network_scope_since == FIRST
    current = _snapshot(observed_at=SECOND, network_scope=second_scope)
    updated = repository.record_updated(ConnectionUpdated(
        _snapshot(network_scope=first_scope), current, opened.session_id, opened.lifecycle_id,
    ))
    assert updated.snapshot.network_scope == second_scope
    assert updated.network_scope_since == SECOND
    later = _snapshot(observed_at=CLOSED, network_scope=second_scope)
    stable = repository.record_updated(ConnectionUpdated(
        current, later, opened.session_id, opened.lifecycle_id,
    ))
    assert stable.network_scope_since == SECOND


def test_ipv6_udp_and_nullable_remote_pid_metadata_round_trip(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    ipv6 = _open(
        repository,
        local_address="2001:0db8::1",
        remote_address="2001:0db8::2",
    )
    nullable = _open(
        repository,
        protocol=TransportProtocol.UDP,
        local_address="0.0.0.0",
        local_port=5353,
        remote_address=None,
        process=ProcessInfo.unavailable(),
    )

    assert ipv6.snapshot.local_endpoint.address == "2001:db8::1"
    assert ipv6.snapshot.remote_endpoint == Endpoint("2001:db8::2", 443)
    assert nullable.snapshot.protocol is TransportProtocol.UDP
    assert nullable.snapshot.state is ConnectionState.NONE
    assert nullable.snapshot.remote_endpoint is None
    assert nullable.snapshot.process.status is ProcessInfoStatus.UNAVAILABLE
    assert nullable.snapshot.process.identity is None
    assert nullable.snapshot.process.name is None


def test_known_pid_with_unknown_create_time_and_name_none_round_trip(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    process = _process(
        status=ProcessInfoStatus.ACCESS_DENIED,
        create_time=None,
    )

    record = _open(repository, process=process)

    assert record.snapshot.process.identity == ProcessIdentity(4100, None)
    assert record.snapshot.process.name is None


def test_process_and_parent_metadata_round_trip_and_lifecycle_snapshot(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    parent = ParentProcessInfo(
        status=ParentProcessStatus.OBSERVED,
        observed_at=FIRST,
        parent_pid=100,
        identity=ProcessIdentity(100, CREATE_TIME - timedelta(hours=1)),
        name="shell.exe",
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.AVAILABLE,
        name_status=ProcessInfoStatus.AVAILABLE,
    )
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(4100, CREATE_TIME),
        name="browser.exe",
        executable_path=r"C:\Users\someone\browser.exe",
        name_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.AVAILABLE,
        executable_path_status=ProcessInfoStatus.AVAILABLE,
        parent=parent,
    )
    opened = _open(repository, process=process)
    assert repository.get(opened.record_id).snapshot.process == process  # type: ignore[union-attr]
    assert opened.snapshot.process.parent == parent
    assert opened.key == _snapshot(process=_process()).key

    changed = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=process.identity,
        name=process.name,
        executable_path_status=ProcessInfoStatus.ACCESS_DENIED,
        parent=ParentProcessInfo(
            status=ParentProcessStatus.ABSENT,
            observed_at=SECOND,
        ),
    )
    current = _snapshot(observed_at=SECOND, process=changed)
    updated = repository.record_updated(ConnectionUpdated(
        _snapshot(process=process), current, opened.session_id, opened.lifecycle_id,
    ))
    assert updated.snapshot.process == changed
    assert updated.key == opened.key
    closed = repository.record_closed(ConnectionClosed(
        current, CLOSED, session_id=opened.session_id, lifecycle_id=opened.lifecycle_id,
    ))
    assert closed.snapshot.process == changed
    assert repository.get(closed.record_id) == closed


@pytest.mark.parametrize(
    "status", (ParentProcessStatus.NOT_FOUND, ParentProcessStatus.ACCESS_DENIED,
               ParentProcessStatus.REUSED, ParentProcessStatus.UNAVAILABLE),
)
def test_parent_failure_and_partial_field_availability_survive_restart(
    repository: SQLiteConnectionHistoryRepository,
    status: ParentProcessStatus,
) -> None:
    parent = ParentProcessInfo(
        status=status, observed_at=FIRST, parent_pid=100,
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.NOT_FOUND,
        name_status=ProcessInfoStatus.ACCESS_DENIED,
    )
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(4100, CREATE_TIME), name="browser.exe",
        executable_path_status=ProcessInfoStatus.ACCESS_DENIED,
        parent=parent,
    )
    record = _open(repository, process=process)
    loaded = repository.get(record.record_id)
    assert loaded is not None
    assert loaded.snapshot.process == process
    assert loaded.snapshot.process.parent is not None
    assert loaded.snapshot.process.parent.status is status


def test_observed_parent_with_unavailable_name_keeps_verified_identity(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    parent = ParentProcessInfo(
        status=ParentProcessStatus.OBSERVED,
        observed_at=FIRST,
        parent_pid=100,
        identity=ProcessIdentity(100, CREATE_TIME - timedelta(hours=1)),
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.AVAILABLE,
        name_status=ProcessInfoStatus.ACCESS_DENIED,
    )
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(4100, CREATE_TIME), name="browser.exe",
        parent=parent,
    )
    record = _open(repository, process=process)
    loaded = repository.get(record.record_id)
    assert loaded is not None
    assert loaded.snapshot.process.parent == parent
    assert loaded.snapshot.process.parent.name is None


def test_legacy_null_metadata_is_unknown_without_fabrication(
    database: SQLiteDatabase, repository: SQLiteConnectionHistoryRepository,
) -> None:
    with database.connection() as connection:
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
    record = repository.get(UUID("12345678-1234-1234-1234-123456789abc"))
    assert record is not None
    assert record.snapshot.process.identity == ProcessIdentity(
        42, epoch_microseconds_to_datetime(1_000_000)
    )
    assert record.snapshot.process.name == "old.exe"
    assert record.snapshot.process.executable_path is None
    assert record.snapshot.process.executable_path_status is ProcessInfoStatus.UNAVAILABLE
    assert record.snapshot.process.parent is None


def test_invalid_persisted_metadata_is_sanitized_and_path_is_bounded(
    database: SQLiteDatabase, repository: SQLiteConnectionHistoryRepository,
) -> None:
    record = _open(repository)
    with database.connection() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE connection_history SET parent_status = ? WHERE id = ?",
                ("broken", str(record.record_id)),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE connection_history SET executable_path = ? WHERE id = ?",
                ("x" * 4097, str(record.record_id)),
            )
        connection.execute(
            "UPDATE connection_history SET executable_path = ? WHERE id = ?",
            ("bad\npath", str(record.record_id)),
        )
    with pytest.raises(HistoryDataCorrupt) as captured:
        repository.get(record.record_id)
    assert "bad\npath" not in str(captured.value)

    with database.connection() as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE connection_history SET executable_path = NULL, parent_status = ? WHERE id = ?",
            ("broken", str(record.record_id)),
        )
    with pytest.raises(HistoryDataCorrupt):
        repository.get(record.record_id)


def test_closed_history_is_not_enriched_by_newer_process_metadata(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    old_snapshot = _snapshot(process=_process())
    old_record = repository.record_opened(ConnectionOpened(old_snapshot))
    repository.record_closed(ConnectionClosed(
        old_snapshot, SECOND, session_id=old_record.session_id,
        lifecycle_id=old_record.lifecycle_id,
    ))
    current = _snapshot(
        observed_at=CLOSED,
        process=ProcessInfo(
            status=ProcessInfoStatus.AVAILABLE,
            identity=old_snapshot.process.identity,
            name="browser.exe",
            executable_path=r"C:\new\browser.exe",
        ),
    )
    new_record = repository.record_opened(ConnectionOpened(current))
    assert new_record.record_id != old_record.record_id
    previous = repository.get(old_record.record_id)
    assert previous is not None
    assert previous.snapshot.process.executable_path is None


@pytest.mark.parametrize("status", tuple(ProcessInfoStatus))
def test_process_availability_enum_round_trip(
    repository: SQLiteConnectionHistoryRepository,
    status: ProcessInfoStatus,
) -> None:
    process = (
        ProcessInfo.unavailable()
        if status is ProcessInfoStatus.UNAVAILABLE
        else _process(status=status)
    )

    record = _open(repository, local_port=51_000 + list(ProcessInfoStatus).index(status), process=process)

    assert record.snapshot.process == process


@pytest.mark.parametrize(
    "state",
    tuple(state for state in ConnectionState if state is not ConnectionState.NONE),
)
def test_tcp_connection_state_enum_round_trip(
    repository: SQLiteConnectionHistoryRepository,
    state: ConnectionState,
) -> None:
    remote_address = None if state is ConnectionState.LISTEN else "198.51.100.20"

    record = _open(
        repository,
        state=state,
        local_port=52_000 + list(ConnectionState).index(state),
        remote_address=remote_address,
    )

    assert record.snapshot.state is state


def test_update_changes_same_record_metadata_and_preserves_first_seen(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    previous = _snapshot(
        process=_process(status=ProcessInfoStatus.ACCESS_DENIED),
    )
    opened = repository.record_opened(ConnectionOpened(previous))
    current = _snapshot(
        observed_at=SECOND,
        state=ConnectionState.CLOSE_WAIT,
        process=_process(name="renamed.exe"),
    )

    updated = repository.record_updated(ConnectionUpdated(
        previous, current, opened.session_id, opened.lifecycle_id,
    ))

    assert updated.record_id == opened.record_id
    assert updated.first_seen == FIRST
    assert updated.last_seen == SECOND
    assert updated.last_seen.microsecond == 654_321
    assert updated.snapshot.state is ConnectionState.CLOSE_WAIT
    assert updated.snapshot.process.name == "renamed.exe"
    assert len(repository.query(ConnectionHistoryQuery(limit=10))) == 1


def test_close_preserves_not_observed_semantics_and_is_idempotent(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    snapshot = _snapshot()
    opened = repository.record_opened(ConnectionOpened(snapshot))
    event = ConnectionClosed(
        snapshot,
        occurred_at=CLOSED,
        reason=ConnectionClosureReason.NOT_OBSERVED,
        session_id=opened.session_id,
        lifecycle_id=opened.lifecycle_id,
    )

    first_close = repository.record_closed(event)
    duplicate_close = repository.record_closed(event)

    assert first_close.record_id == opened.record_id == duplicate_close.record_id
    assert first_close.closed_at == CLOSED
    assert first_close.close_reason is ConnectionClosureReason.NOT_OBSERVED
    assert duplicate_close == first_close
    assert len(repository.query(ConnectionHistoryQuery(limit=10))) == 1


def test_duplicate_open_is_idempotent_even_after_close(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    event = ConnectionOpened(_snapshot())

    first = repository.record_opened(event)
    duplicate = repository.record_opened(event)
    repository.record_closed(ConnectionClosed(
        event.snapshot, CLOSED, session_id=event.session_id,
        lifecycle_id=event.lifecycle_id,
    ))
    delayed_duplicate = repository.record_opened(event)

    assert first.record_id == duplicate.record_id == delayed_duplicate.record_id
    assert delayed_duplicate.is_closed
    assert len(repository.query(ConnectionHistoryQuery(limit=10))) == 1


def test_missing_update_and_close_raise_portable_not_found_error(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    previous = _snapshot()
    current = _snapshot(observed_at=SECOND, state=ConnectionState.CLOSE_WAIT)

    with pytest.raises(HistoryRecordNotFound):
        repository.record_updated(ConnectionUpdated(previous, current))
    with pytest.raises(HistoryRecordNotFound):
        repository.record_closed(ConnectionClosed(previous, CLOSED))


def test_pid_reuse_with_different_create_times_creates_distinct_lifecycles(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    old_process = _process(create_time=CREATE_TIME)
    new_create_time = CREATE_TIME + timedelta(hours=1)
    new_process = _process(create_time=new_create_time)

    old_record = _open(repository, process=old_process)
    new_record = _open(repository, observed_at=SECOND, process=new_process)

    assert old_record.record_id != new_record.record_id
    assert old_record.key != new_record.key
    assert old_record.snapshot.process.identity.pid == 4100
    assert new_record.snapshot.process.identity == ProcessIdentity(4100, new_create_time)
    assert len(repository.query(ConnectionHistoryQuery(limit=10, pid=4100))) == 2


def test_epoch_microsecond_mapping_is_exact_and_rejects_naive_values() -> None:
    encoded = datetime_to_epoch_microseconds(FIRST)

    assert isinstance(encoded, int)
    assert epoch_microseconds_to_datetime(encoded) == FIRST
    assert epoch_microseconds_to_datetime(encoded).tzinfo is UTC
    with pytest.raises(ValueError, match="timezone-aware"):
        datetime_to_epoch_microseconds(FIRST.replace(tzinfo=None))


def test_query_order_limit_offset_and_same_timestamp_pagination_are_stable(
    database: SQLiteDatabase,
) -> None:
    ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000003"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    repository = SQLiteConnectionHistoryRepository(
        database,
        record_id_factory=lambda: next(ids),
    )
    for port in (40_001, 40_002, 40_003):
        _open(repository, local_port=port)

    complete = repository.query(ConnectionHistoryQuery(limit=3))
    page_one = repository.query(ConnectionHistoryQuery(limit=2))
    page_two = repository.query(ConnectionHistoryQuery(limit=2, offset=2))

    assert [str(item.record_id) for item in complete] == [
        "00000000-0000-0000-0000-000000000003",
        "00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000001",
    ]
    assert page_one + page_two == complete
    assert repository.query(ConnectionHistoryQuery(limit=3)) == complete


def test_query_protocol_process_pid_endpoint_and_time_filters(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    tcp = _open(repository, process=_process(name="Browser.EXE"))
    udp = _open(
        repository,
        observed_at=SECOND,
        protocol=TransportProtocol.UDP,
        local_port=5353,
        remote_address="203.0.113.53",
        remote_port=53,
        process=ProcessInfo.unavailable(),
    )

    assert repository.query(
        ConnectionHistoryQuery(limit=10, protocol=TransportProtocol.TCP)
    ) == (tcp,)
    assert repository.query(
        ConnectionHistoryQuery(limit=10, process_name="browser.exe")
    ) == (tcp,)
    assert repository.query(ConnectionHistoryQuery(limit=10, pid=4100)) == (tcp,)
    assert repository.query(
        ConnectionHistoryQuery(limit=10, endpoint_address="198.51.100.20")
    ) == (tcp,)
    assert repository.query(
        ConnectionHistoryQuery(limit=10, endpoint_address="203.0.113.53")
    ) == (udp,)
    assert repository.query(
        ConnectionHistoryQuery(
            limit=10,
            first_seen_from=SECOND,
            first_seen_to=SECOND,
        )
    ) == (udp,)


def test_process_filter_uses_parameter_binding_and_cannot_inject_sql(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    record = _open(repository)
    attack = "browser.exe' OR 1=1; DROP TABLE connection_history; --"

    assert repository.query(
        ConnectionHistoryQuery(limit=10, process_name=attack)
    ) == ()
    assert repository.get(record.record_id) == record


@pytest.mark.parametrize(
    "values",
    (
        {"limit": 0},
        {"limit": -1},
        {"limit": MAX_HISTORY_QUERY_LIMIT + 1},
        {"limit": 1, "offset": -1},
    ),
)
def test_invalid_pagination_is_rejected(values: dict[str, int]) -> None:
    with pytest.raises((TypeError, ValueError)):
        ConnectionHistoryQuery(**values)
    with pytest.raises(TypeError):
        ConnectionHistoryQuery()


def test_corrupt_persisted_enum_is_a_controlled_mapping_error(
    repository: SQLiteConnectionHistoryRepository,
    database: SQLiteDatabase,
) -> None:
    record = _open(repository)
    with database.connection() as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE connection_history SET process_status = ? WHERE id = ?",
            ("unsupported_status", str(record.record_id)),
        )

    with pytest.raises(HistoryDataCorrupt) as captured:
        repository.get(record.record_id)
    assert "unsupported_status" not in str(captured.value)


def test_write_failure_rolls_back_and_sanitizes_sqlite_error(
    repository: SQLiteConnectionHistoryRepository,
    database: SQLiteDatabase,
) -> None:
    with database.connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_history_insert
            BEFORE INSERT ON connection_history
            BEGIN
                SELECT RAISE(ABORT, 'sensitive sqlite trigger detail');
            END
            """
        )

    with pytest.raises(HistoryRepositoryError) as captured:
        _open(repository)

    assert not isinstance(captured.value, sqlite3.Error)
    assert "sensitive sqlite trigger detail" not in str(captured.value)
    assert repository.query(ConnectionHistoryQuery(limit=10)) == ()


def test_repository_closes_each_owned_connection(database: SQLiteDatabase) -> None:
    class CapturingDatabase(SQLiteDatabase):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.opened: list[sqlite3.Connection] = []

        def connect(self) -> sqlite3.Connection:
            connection = super().connect()
            self.opened.append(connection)
            return connection

    capturing = CapturingDatabase(database.path)
    repository = SQLiteConnectionHistoryRepository(capturing)

    repository.query(ConnectionHistoryQuery(limit=1))

    assert len(capturing.opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        capturing.opened[0].execute("SELECT 1")


def test_query_honors_portable_cancellation_before_sql(
    repository: SQLiteConnectionHistoryRepository,
) -> None:
    with pytest.raises(HistoryQueryCancelled):
        repository.query(
            ConnectionHistoryQuery(limit=10),
            is_cancelled=lambda: True,
        )


def test_domain_application_are_sqlite_free_and_repository_has_no_async_worker() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    forbidden_imports: dict[Path, set[str]] = {
        repository_root / "src" / "netsentinel" / "domain": {"sqlite3"},
        repository_root / "src" / "netsentinel" / "application": {"sqlite3"},
        repository_root / "src" / "netsentinel" / "infrastructure" / "sqlite" / "repositories.py": {
            "threading",
            "queue",
            "asyncio",
        },
    }
    violations: list[str] = []
    for root, forbidden in forbidden_imports.items():
        paths = root.rglob("*.py") if root.is_dir() else (root,)
        for source_path in paths:
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    if any(alias.name.split(".")[0] in forbidden for alias in node.names):
                        violations.append(str(source_path))
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    if node.module.split(".")[0] in forbidden:
                        violations.append(str(source_path))

    assert violations == []
