"""NS-063 canonical DNS evidence and restart-safe association contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest

from netsentinel.application.ports import DnsHistoryQuery
from netsentinel.application.services.dns_association import DnsAssociationService
from netsentinel.application.services.dns_history import DnsHistoryRetentionService, DnsHistoryWriter, DnsRetentionConfig
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkAttributionMethod, NetworkScopeStatus,
)
from netsentinel.domain.dns import (
    DnsAnswer, DnsAssociationProvenance, DnsEvidenceSourceStatus, DnsHistoryRecord, DnsQuestion,
    DnsRecordType, DnsTransaction, DnsTransactionStatus, DnsTransport,
)
from netsentinel.infrastructure.sqlite.database import SQLiteConnectionFactory, SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_association_repository import SQLiteDnsAssociationRepository
from netsentinel.infrastructure.sqlite import dns_association_repository as association_module
from netsentinel.infrastructure.sqlite.dns_repository import (
    SQLiteDnsHistoryRepository, SQLiteDnsHistorySessionFactory, _COLUMNS, _encode,
)
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations

AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
NETWORK = "a" * 64


def _transaction(
    *, at: datetime = AT, answers: tuple[DnsAnswer, ...] | None = None,
    client: str = "192.0.2.20", network: str = NETWORK,
    server: str = "198.51.100.53",
) -> DnsTransaction:
    if answers is None:
        answers = (DnsAnswer("example.com", DnsRecordType.A, "1.2.3.4", 60),)
    return DnsTransaction(
        DnsTransactionStatus.COMPLETED, network, DnsTransport.UDP, client, 53000,
        server, 53, 42, (DnsQuestion("example.com", 1),),
        at - timedelta(milliseconds=1), at, .001, 0, False, answers, 0,
    )


def _scope(network: str = NETWORK) -> ConnectionNetworkScope:
    return ConnectionNetworkScope(
        NetworkScopeStatus.RESOLVED, network, "adapter", 1,
        NetworkAttributionMethod.LOCAL_ADDRESS_MATCH,
    )


def _persist(
    history: SQLiteDnsHistoryRepository, service: DnsAssociationService,
    tx: DnsTransaction,
) -> tuple[DnsHistoryRecord, tuple]:
    associations = service.observe(tx)
    record = DnsHistoryRecord(uuid4(), tx, associations)
    history.record(record)
    return record, associations


def test_evidence_associations_and_history_are_distinct_and_idempotent(tmp_path) -> None:
    db = SQLiteDatabase(tmp_path / "evidence.sqlite3")
    history = SQLiteDnsHistoryRepository(db)
    associations = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 10.0)
    answers = (
        DnsAnswer("example.com", DnsRecordType.A, "1.2.3.4", 60),
        DnsAnswer("example.com", DnsRecordType.A, "1.2.3.5", 30),
    )
    first, observed = _persist(history, service, _transaction(answers=answers))
    assert len(observed) == 2
    assert len({item.evidence_id for item in observed}) == 1
    assert observed[0].evidence_id == first.transaction.evidence_id
    history.record(first)
    history.record(DnsHistoryRecord(uuid4(), first.transaction, observed))
    assert len(history.query(DnsHistoryQuery(limit=10))) == 1
    assert len(associations.get_by_evidence_id(observed[0].evidence_id)) == 2
    second, second_observed = _persist(history, service, _transaction(at=AT + timedelta(seconds=1), answers=answers))
    assert second.transaction.evidence_id != first.transaction.evidence_id
    assert len(associations.get_by_evidence_id(second_observed[0].evidence_id)) == 2
    assert len(history.query(DnsHistoryQuery(limit=10))) == 2
    assert history.get_by_evidence_id(first.transaction.evidence_id) == first
    assert history.source_status(first.transaction.evidence_id) is DnsEvidenceSourceStatus.AVAILABLE
    assert history.get_by_evidence_id(second.transaction.evidence_id) == second
    assert associations.active_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20",
                                     now_utc=AT + timedelta(seconds=2), limit=1)


def test_historical_interval_excludes_future_expired_and_other_scope(tmp_path) -> None:
    db = SQLiteDatabase(tmp_path / "historical.sqlite3")
    history = SQLiteDnsHistoryRepository(db)
    repository = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    _persist(history, service, _transaction(at=AT - timedelta(seconds=30)))
    _persist(history, service, _transaction(at=AT + timedelta(seconds=30)))
    _persist(history, service, _transaction(at=AT - timedelta(seconds=120)))
    matches = repository.overlapping_by_ip(
        "1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20",
        first_seen=AT, last_seen=AT + timedelta(seconds=5),
    )
    assert len(matches) == 1
    assert matches[0].observed_at == AT - timedelta(seconds=30)
    assert repository.overlapping_by_ip(
        "1.2.3.4", network_scope=_scope("b" * 64), client_ip="192.0.2.20",
        first_seen=AT, last_seen=AT + timedelta(seconds=5),
    ) == ()
    assert repository.overlapping_by_ip(
        "1.2.3.4", network_scope=_scope(), client_ip="192.0.2.21",
        first_seen=AT, last_seen=AT + timedelta(seconds=5),
    ) == ()


def test_historical_candidate_order_prefers_direct_at_equal_time(tmp_path) -> None:
    db = SQLiteDatabase(tmp_path / "order.sqlite3")
    history = SQLiteDnsHistoryRepository(db)
    repository = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    answers = (
        DnsAnswer("example.com", DnsRecordType.CNAME, "edge.example", 30),
        DnsAnswer("edge.example", DnsRecordType.A, "1.2.3.4", 60),
    )
    _persist(history, service, _transaction(answers=answers))
    rows = repository.overlapping_by_ip(
        "1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20",
        first_seen=AT, last_seen=AT + timedelta(seconds=1),
    )
    assert tuple(item.provenance for item in rows) == (
        DnsAssociationProvenance.DIRECT_ANSWER, DnsAssociationProvenance.CNAME_DERIVED,
    )


def test_cname_ttl_zero_scope_resolver_and_restart(tmp_path) -> None:
    path = tmp_path / "restart.sqlite3"
    db = SQLiteDatabase(path)
    history = SQLiteDnsHistoryRepository(db)
    associations = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    cname = (
        DnsAnswer("example.com", DnsRecordType.CNAME, "edge.example", 20),
        DnsAnswer("edge.example", DnsRecordType.A, "1.2.3.4", 60),
    )
    first, observed = _persist(history, service, _transaction(answers=cname))
    assert {item.provenance for item in observed} == {
        DnsAssociationProvenance.DIRECT_ANSWER, DnsAssociationProvenance.CNAME_DERIVED,
    }
    assert {item.ttl for item in observed} == {20, 60}
    assert associations.get_by_evidence_id(first.transaction.evidence_id) == observed
    _persist(history, service, _transaction(at=AT + timedelta(seconds=1), answers=cname,
                                            server="198.51.100.54"))
    assert service.stats().active == 2  # Resolver is metadata, not a semantic key.
    _persist(history, service, _transaction(at=AT + timedelta(seconds=2),
                                            answers=(DnsAnswer("example.com", DnsRecordType.A,
                                                               "1.2.3.5", 0),)))
    assert associations.active_by_ip("1.2.3.5", network_scope=_scope(), client_ip="192.0.2.20",
                                     now_utc=AT + timedelta(seconds=2)) == ()
    _persist(history, service, _transaction(at=AT + timedelta(seconds=3), client="192.0.2.21",
                                            network="b" * 64))
    assert associations.active_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.21",
                                     now_utc=AT + timedelta(seconds=4)) == ()
    assert associations.active_by_ip("1.2.3.4", network_scope=ConnectionNetworkScope.unknown(),
                                     client_ip="192.0.2.20", now_utc=AT) == ()
    reopened = SQLiteDnsAssociationRepository(SQLiteDatabase(path))
    fresh = reopened.active_for_restore(now_utc=AT + timedelta(seconds=5))
    ticks = [100.0]
    restored = DnsAssociationService(clock=lambda: ticks[0])
    restored.restore(fresh, now_utc=AT + timedelta(seconds=5))
    assert restored.lookup_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20").candidates
    assert restored.lookup_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.21").candidates == ()
    ticks[0] = 160.0
    assert restored.lookup_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20").candidates == ()
    backward = DnsAssociationService(clock=lambda: 0.0)
    backward.restore(fresh, now_utc=AT - timedelta(seconds=1))
    assert backward.stats().active == 0
    assert reopened.active_for_restore(now_utc=AT + timedelta(hours=2)) == ()


def test_same_ip_repeated_rrs_keep_distinct_association_rows(tmp_path) -> None:
    db = SQLiteDatabase(tmp_path / "same-ip.sqlite3")
    history = SQLiteDnsHistoryRepository(db)
    associations = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    answers = (
        DnsAnswer("example.com", DnsRecordType.A, "1.2.3.4", 30),
        DnsAnswer("example.com", DnsRecordType.A, "1.2.3.4", 60),
    )
    record, observed = _persist(history, service, _transaction(answers=answers))
    assert len(observed) == 2
    assert {item.ttl for item in associations.get_by_evidence_id(record.transaction.evidence_id)} == {30, 60}
    history.record(record)
    assert len(associations.get_by_evidence_id(record.transaction.evidence_id)) == 2


def test_legacy_unknown_origin_and_retention_does_not_cascade(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite3"
    connection = SQLiteConnectionFactory(path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:11]).migrate(connection) == 11
        legacy = DnsHistoryRecord(uuid4(), _transaction())
        values = _encode(legacy)[:-1]
        columns = _COLUMNS.removesuffix(", evidence_id")
        connection.execute(
            f"INSERT INTO dns_history ({columns}) VALUES ({','.join('?' for _ in values)})",
            values,
        )
        assert MigrationRunner(builtin_migrations()).migrate(connection) == 13
    finally:
        connection.close()
    db = SQLiteDatabase(path)
    history = SQLiteDnsHistoryRepository(db)
    old = history.get(legacy.id)
    assert old is not None and old.transaction.evidence_id is None
    assert history.source_status(old.transaction.evidence_id) is DnsEvidenceSourceStatus.UNKNOWN_LEGACY
    assert history.get_by_evidence_id(legacy.transaction.evidence_id) is None
    assert history.legacy_ip_observed(
        "1.2.3.4", network_fingerprint=NETWORK, client_ip="192.0.2.20",
        first_seen=AT, last_seen=AT + timedelta(seconds=1),
    )
    assert not history.legacy_ip_observed(
        "1.2.3.4", network_fingerprint="b" * 64, client_ip="192.0.2.20",
        first_seen=AT, last_seen=AT + timedelta(seconds=1),
    )
    assert not history.legacy_ip_observed(
        "1.2.3.4", network_fingerprint=NETWORK, client_ip="192.0.2.20",
        first_seen=AT - timedelta(minutes=2), last_seen=AT - timedelta(minutes=1),
    )
    service = DnsAssociationService(clock=lambda: 0.0)
    new, observed = _persist(history, service, _transaction(at=AT + timedelta(days=1)))
    assert observed
    association_repo = SQLiteDnsAssociationRepository(db)
    cleanup = DnsHistoryRetentionService(
        history, association_repository=association_repo,
        config=DnsRetentionConfig(retention_days=1, max_rows=1, chunk_size=1),
        clock=lambda: AT + timedelta(days=1, seconds=1),
    )
    result = cleanup.run_cleanup()
    assert result.age_deleted == 1 and result.association_age_deleted == 0
    assert history.get(legacy.id) is None
    assert history.get(new.id) is not None
    assert association_repo.get_by_evidence_id(new.transaction.evidence_id)
    assert association_repo.get_by_evidence_id(legacy.transaction.evidence_id) == ()
    # Independent source expiry does not violate a foreign key or rewrite an ID.
    cleanup_later = DnsHistoryRetentionService(
        history, association_repository=association_repo,
        config=DnsRetentionConfig(retention_days=1, max_rows=1, chunk_size=1),
        clock=lambda: AT + timedelta(days=3),
    )
    result = cleanup_later.run_cleanup()
    assert result.age_deleted == 1 and result.association_age_deleted == 1
    assert history.get_by_evidence_id(new.transaction.evidence_id) is None
    assert history.source_status(new.transaction.evidence_id) is DnsEvidenceSourceStatus.SOURCE_UNAVAILABLE
    assert association_repo.get_by_evidence_id(new.transaction.evidence_id) == ()


def test_association_write_failure_does_not_erase_runtime_observation(tmp_path) -> None:
    db = SQLiteDatabase(tmp_path / "failure.sqlite3")
    with db.connection() as connection:
        connection.execute("CREATE TRIGGER fail_association BEFORE INSERT ON dns_associations "
                           "BEGIN SELECT RAISE(ABORT, 'failure'); END")
    history = SQLiteDnsHistoryRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    tx = _transaction()
    observed = service.observe(tx)
    from netsentinel.application.ports import DnsHistoryRepositoryError

    with pytest.raises(DnsHistoryRepositoryError):
        history.record(DnsHistoryRecord(uuid4(), tx, observed))
    assert service.stats().active == 1
    assert history.get_by_evidence_id(tx.evidence_id) is None
    assert service.lookup_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20").candidates
    writer = DnsHistoryWriter(SQLiteDnsHistorySessionFactory(db), retry_limit=0, batch_interval=0)
    assert writer.start()
    assert writer.submit(tx, associations=observed) is not None
    assert writer.stop(2)
    assert writer.health_snapshot().failed == 1
    assert writer.health_snapshot().error_code == "write_failed"
    assert service.stats().active == 1


def test_hard_storage_cap_bounded_queries_and_schema_exclusions(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(association_module, "MAX_STORED_ASSOCIATIONS", 3)
    db = SQLiteDatabase(tmp_path / "bounded.sqlite3")
    history = SQLiteDnsHistoryRepository(db)
    associations = SQLiteDnsAssociationRepository(db)
    service = DnsAssociationService(clock=lambda: 0.0)
    ids = []
    for index in range(5):
        record, _ = _persist(history, service, _transaction(at=AT + timedelta(seconds=index)))
        ids.append(record.transaction.evidence_id)
    with db.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM dns_associations").fetchone()[0] == 3
        columns = {row[1] for row in connection.execute("PRAGMA table_info(dns_associations)")}
        assert not columns.intersection({"pid", "process_name", "process_identity", "executable_path"})
        connection_columns = {row[1] for row in connection.execute("PRAGMA table_info(connection_history)")}
        assert "remote_hostname" not in connection_columns
    assert associations.get_by_evidence_id(ids[0]) == ()
    assert len(associations.active_by_ip("1.2.3.4", network_scope=_scope(), client_ip="192.0.2.20",
                                         now_utc=AT + timedelta(seconds=5), limit=2)) == 1
    with pytest.raises(ValueError):
        associations.active_for_restore(now_utc=AT, limit=2049)
    with pytest.raises(ValueError):
        associations.active_by_ip("1.2.3.4' OR 1=1 --", network_scope=_scope(),
                                  client_ip="192.0.2.20", now_utc=AT)
