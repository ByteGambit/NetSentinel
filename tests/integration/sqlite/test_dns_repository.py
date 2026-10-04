"""NS-033 portable DNS history, migration, writer and retention tests."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
from threading import Event
from time import monotonic

import pytest

from netsentinel.application.ports import (
    DnsHistoryDataCorrupt, DnsHistoryQuery, DnsHistoryRepositoryError,
)
from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.application.services.dns_history import (
    DnsHistoryRetentionService, DnsHistoryWriter, DnsRetentionConfig,
)
from netsentinel.domain.dns import (
    DnsAnswer, DnsHistoryRecord, DnsQuestion, DnsRecordType,
    DnsTransaction, DnsTransactionStatus, DnsTransport,
)
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.database import SQLiteConnectionFactory, SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_repository import (
    SQLiteDnsHistoryRepository, SQLiteDnsHistorySessionFactory,
)
from netsentinel.infrastructure.sqlite.migrations import (
    DatabaseMigrationError, Migration, MigrationRunner, builtin_migrations,
)
from tests.fixtures.packets.dns import dns_query, dns_response

NOW = datetime(2026, 9, 23, 12, 34, 56, 123456, tzinfo=UTC)


def _tx(*, status: DnsTransactionStatus = DnsTransactionStatus.COMPLETED,
        transport: DnsTransport = DnsTransport.UDP, at: datetime = NOW,
        network: str = "a" * 64) -> DnsTransaction:
    response = status in (DnsTransactionStatus.COMPLETED, DnsTransactionStatus.UNMATCHED_RESPONSE)
    return DnsTransaction(
        status=status, network_fingerprint=network, transport=transport,
        client_ip="2001:db8::1", client_port=49152, server_ip="2001:db8::53",
        server_port=53, transaction_id=42,
        questions=() if status is DnsTransactionStatus.UNMATCHED_RESPONSE else (DnsQuestion("Example.COM", 1),),
        query_at=None if status is DnsTransactionStatus.UNMATCHED_RESPONSE else at,
        response_at=at + timedelta(microseconds=31) if response else None,
        latency_seconds=.000031 if status is DnsTransactionStatus.COMPLETED else None,
        response_code=3 if response else None, truncated=False,
        answers=(DnsAnswer("example.com", DnsRecordType.A, "192.0.2.1", 30),
                 DnsAnswer("example.com", DnsRecordType.AAAA, "2001:db8::2", 31)) if response else (),
        retry_count=2,
    )


@pytest.fixture
def repo(tmp_path: Path) -> SQLiteDnsHistoryRepository:
    return SQLiteDnsHistoryRepository(SQLiteDatabase(tmp_path / "dns.sqlite3"))


@pytest.mark.parametrize("status", list(DnsTransactionStatus))
@pytest.mark.parametrize("transport", list(DnsTransport))
def test_round_trip_status_transport_answers_and_microseconds(repo, status, transport):
    record = DnsHistoryRecord(UUID(int=1), _tx(status=status, transport=transport))
    repo.record(record)
    assert repo.get(record.id) == record
    assert repo.query(DnsHistoryQuery(limit=1, status=status, transport=transport)) == (record,)


def test_identity_is_uuid_and_replay_safe_without_merging_distinct_transactions(repo):
    first = DnsHistoryRecord(UUID(int=1), _tx())
    second = DnsHistoryRecord(UUID(int=2), _tx(at=NOW + timedelta(seconds=1)))
    repo.record(first)
    repo.record(first)
    repo.record(second)
    assert len(repo.query(DnsHistoryQuery(limit=10))) == 2
    with pytest.raises(DnsHistoryRepositoryError):
        repo.record(DnsHistoryRecord(first.id, second.transaction))
    assert repo.get(first.id) == first


def test_bounded_filters_pagination_ordering_and_sql_parameters(repo):
    records = [
        DnsHistoryRecord(UUID(int=i), _tx(at=NOW + timedelta(seconds=i), network="b" * 64 if i == 3 else "a" * 64))
        for i in range(1, 5)
    ]
    for record in records:
        repo.record(record)
    assert repo.query(DnsHistoryQuery(limit=2)) == (records[3], records[2])
    assert repo.query(DnsHistoryQuery(limit=2, offset=2)) == (records[1], records[0])
    assert repo.query(DnsHistoryQuery(limit=10, network_fingerprint="b" * 64)) == (records[2],)
    assert repo.query(DnsHistoryQuery(limit=10, qname="EXAMPLE.COM.")) == tuple(reversed(records))
    assert repo.query(DnsHistoryQuery(limit=10, qtype=1)) == tuple(reversed(records))
    assert repo.query(DnsHistoryQuery(limit=10, qtype=28)) == ()
    assert repo.query(DnsHistoryQuery(limit=10, server_ip="2001:db8::53")) == tuple(reversed(records))
    assert repo.query(DnsHistoryQuery(limit=10, event_from=NOW + timedelta(seconds=2),
                                      event_to=NOW + timedelta(seconds=3))) == (records[2], records[1])
    with pytest.raises(ValueError):
        DnsHistoryQuery(limit=1, qname="x' OR 1=1 --")
    with pytest.raises(ValueError):
        DnsHistoryQuery(limit=501)
    with pytest.raises(ValueError):
        DnsHistoryQuery(limit=1, qname="a" * 254)


def test_retention_age_boundary_row_cap_and_interruption(repo):
    records = [DnsHistoryRecord(UUID(int=i), _tx(at=NOW - timedelta(days=i))) for i in range(1, 6)]
    for record in records:
        repo.record(record)
    service = DnsHistoryRetentionService(repo, config=DnsRetentionConfig(3, 2, 1), clock=lambda: NOW)
    calls = [0]
    def stop():
        calls[0] += 1
        return calls[0] == 2
    partial = service.run_cleanup(stop_requested=stop)
    assert partial.interrupted and partial.age_deleted == 1
    final = service.run_cleanup()
    assert not final.interrupted
    assert repo.query(DnsHistoryQuery(limit=10)) == (records[0], records[1])


def test_previous_schema_migrates_and_reopens(tmp_path):
    database = SQLiteDatabase(tmp_path / "old.sqlite3")
    connection = SQLiteConnectionFactory(database.path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:5]).migrate(connection) == 5
        assert MigrationRunner(builtin_migrations()).migrate(connection) == 18
        assert {row[1] for row in connection.execute("PRAGMA index_list(dns_history)")} >= {
            "idx_dns_history_event_id", "idx_dns_history_network_event", "idx_dns_history_qname_event",
        }
    finally:
        connection.close()
    with database.connection() as reopened:
        assert reopened.execute("SELECT COUNT(*) FROM dns_history").fetchone()[0] == 0


def test_dns_migration_failure_rolls_back_schema_and_version(tmp_path):
    path = tmp_path / "migration_failure.sqlite3"
    connection = SQLiteConnectionFactory(path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:5]).migrate(connection) == 5
        bad = Migration(6, "broken_dns", "CREATE TABLE temporary_dns (id INTEGER); CREAT TABLE malformed (id INTEGER);")
        with pytest.raises(DatabaseMigrationError):
            MigrationRunner((*builtin_migrations()[:5], bad)).migrate(connection)
        assert MigrationRunner(builtin_migrations()[:5]).current_version(connection) == 5
        assert connection.execute("SELECT name FROM sqlite_master WHERE name = 'temporary_dns'").fetchone() is None
        assert not connection.in_transaction
        assert MigrationRunner(builtin_migrations()).migrate(connection) == 18
    finally:
        connection.close()


def test_corrupt_row_is_typed_and_payload_columns_absent(repo):
    record = DnsHistoryRecord(UUID(int=5), _tx())
    repo.record(record)
    with repo._database.connection() as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(dns_history)")}
        assert not columns.intersection({"packet", "payload", "raw_payload", "frame", "scapy"})
        connection.execute("UPDATE dns_history SET answers_json = ? WHERE id = ?", ('not json', str(record.id)))
    with pytest.raises(DnsHistoryDataCorrupt):
        repo.get(record.id)


def test_writer_drains_to_worker_owned_connection_and_restarts(tmp_path):
    database = SQLiteDatabase(tmp_path / "writer.sqlite3")
    writer = DnsHistoryWriter(SQLiteDnsHistorySessionFactory(database), batch_size=2,
                              queue_capacity=4, batch_interval=.01)
    assert writer.start()
    ids = [writer.submit(_tx(at=NOW + timedelta(seconds=i))) for i in range(3)]
    assert all(isinstance(value, UUID) for value in ids)
    assert writer.stop(2)
    health = writer.health_snapshot()
    assert health.persisted == 3 and health.queue_depth == 0 and not health.running
    assert writer.start()
    writer.submit(_tx(at=NOW + timedelta(seconds=4)))
    assert writer.stop(2)
    assert len(SQLiteDnsHistoryRepository(database).query(DnsHistoryQuery(limit=10))) == 4


def test_writer_overflow_is_nonblocking_and_shutdown_is_bounded():
    entered = Event()
    release = Event()

    @contextmanager
    def blocked_session():
        entered.set()
        release.wait(2)
        class Session:
            def write_batch(self, records):
                pass
        yield Session()

    writer = DnsHistoryWriter(blocked_session, queue_capacity=1, batch_size=1,
                              shutdown_timeout=.01)
    assert writer.start() and entered.wait(1)
    assert writer.submit(_tx()) is not None
    before = monotonic()
    assert writer.submit(_tx()) is None
    assert monotonic() - before < .1
    assert writer.health_snapshot().dropped == 1
    assert writer.health_snapshot().error_code == "overflow"
    assert not writer.stop()
    release.set()
    assert writer.stop(2)
    assert not writer.health_snapshot().running


def test_writer_isolates_failed_record_and_commits_good_neighbors(tmp_path):
    database = SQLiteDatabase(tmp_path / "isolate.sqlite3")
    bad_id = UUID(int=42)
    with database.connection() as connection:
        connection.execute(
            "CREATE TRIGGER reject_dns_row BEFORE INSERT ON dns_history "
            "WHEN NEW.id = '00000000-0000-0000-0000-00000000002a' "
            "BEGIN SELECT RAISE(ABORT, 'private database detail'); END"
        )
    writer = DnsHistoryWriter(SQLiteDnsHistorySessionFactory(database),
                              queue_capacity=4, batch_size=3, batch_interval=.1,
                              retry_limit=1)
    writer.start()
    for value in (UUID(int=1), bad_id, UUID(int=3)):
        assert writer.submit(DnsHistoryRecord(value, _tx())) == value
    assert writer.stop(2)
    health = writer.health_snapshot()
    assert health.persisted == 2 and health.failed == 1 and health.retries >= 1
    assert health.error_code == "write_failed"
    repo = SQLiteDnsHistoryRepository(database)
    assert [r.id for r in repo.query(DnsHistoryQuery(limit=10))] == [UUID(int=3), UUID(int=1)]


def test_retention_keeps_exact_cutoff_and_uses_deterministic_oldest_id(repo):
    cutoff = NOW - timedelta(days=3)
    older = DnsHistoryRecord(UUID(int=1), _tx(at=cutoff - timedelta(microseconds=1)))
    boundary = DnsHistoryRecord(UUID(int=2), _tx(at=cutoff))
    newer = DnsHistoryRecord(UUID(int=3), _tx(at=NOW))
    for record in (older, boundary, newer):
        repo.record(record)
    assert repo.delete_before(cutoff, 1) == 1
    assert repo.get(boundary.id) == boundary
    assert repo.delete_oldest_over_limit(1, 1) == 1
    assert repo.get(boundary.id) is None and repo.get(newer.id) == newer
    with pytest.raises(ValueError):
        repo.delete_before(cutoff, 501)
    with pytest.raises(ValueError):
        DnsRetentionConfig(chunk_size=501)


def test_packet_parser_tracker_to_sqlite_readback(tmp_path):
    database = SQLiteDatabase(tmp_path / "pipeline.sqlite3")
    repo = SQLiteDnsHistoryRepository(database)
    context = SimpleNamespace(interface_id="{WIFI}", interface_index=12, fingerprint="c" * 64)
    ticks = [0.0]
    tracker = DnsTrackingService(clock=lambda: ticks[0])
    for tcp in (False, True):
        query = _packet_observation(dns_query(tcp=tcp), context, NOW)
        response = _packet_observation(dns_response(tcp=tcp), context, NOW + timedelta(microseconds=17))
        assert tracker.observe(query) == ()
        ticks[0] += .125
        result, = tracker.observe(response)
        record = DnsHistoryRecord(UUID(int=10 + int(tcp)), result)
        repo.record(record)
        assert repo.get(record.id) == record
    assert len(repo.query(DnsHistoryQuery(limit=10))) == 2
