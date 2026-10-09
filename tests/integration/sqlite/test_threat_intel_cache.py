"""NS-085 offline acceptance: fake UTC, restart, corruption, eviction, purge."""

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
from uuid import UUID

import pytest

from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheEntry, ThreatIntelCacheFreshness as F, ThreatIntelCacheKey,
    ThreatIntelCacheLookup, ThreatIntelCacheMutationStatus as M, ThreatIntelCachePolicy,
    ThreatIntelCachedResult,
)
from netsentinel.domain.threat_intelligence import (
    HashAlgorithm, ThreatIntelDataType as D, ThreatIntelError,
    ThreatIntelResult, ThreatIntelResultStatus as R, ThreatIntelSubject,
    ThreatIntelSubjectKind as K,
)
from netsentinel.infrastructure.sqlite import SQLiteDatabase, MigrationRunner, builtin_migrations, transaction
from netsentinel.infrastructure.sqlite.threat_intel_cache_codec import (
    decode_entry, encode_entry, utc_microseconds,
)
from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
from tests.fixtures.threat_intelligence import A, B, DESCRIPTORS, NOW, grant, query


@pytest.fixture
def cache(tmp_path):
    database = SQLiteDatabase(tmp_path / 'cache.sqlite3')
    repository = SQLiteThreatIntelCacheRepository(database)
    return database, repository, ThreatIntelCacheService(repository, DESCRIPTORS)


def result(status=R.HIT, provider=A, value='8.8.8.8', data_type=D.IP_REPUTATION,
           at=NOW, request_id=1):
    request = replace(query(provider, data_type, value, consent=grant(provider, data_type)),
                      queried_at=at, request_id=UUID(int=request_id))
    return ThreatIntelResult(request, status, at,
                             ThreatIntelError.TIMEOUT if status is R.ERROR else None)


def put(service, **kwargs):
    value = result(**kwargs)
    assert service.put(value, value.received_at).status is M.STORED
    return ThreatIntelCacheKey.from_result(value)


@pytest.mark.parametrize('status,ttl', [(R.HIT, timedelta(hours=24)), (R.NO_HIT, timedelta(hours=1))])
@pytest.mark.parametrize('offset,state', [(-1, F.FRESH), (0, F.STALE), (1, F.STALE),
                                        (43200, F.STALE), (86400, F.EXPIRED), (86401, F.EXPIRED)])
def test_absolute_ttl_boundaries_restart_and_status(cache, status, ttl, offset, state):
    database, _, service = cache
    key = put(service, status=status)
    clock = NOW + ttl + timedelta(seconds=offset)
    # New repository/service constitutes restart; no entry was preloaded.
    restarted = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), DESCRIPTORS)
    lookup = restarted.get(key, clock)
    assert lookup.freshness is state
    if state in (F.FRESH, F.STALE):
        assert lookup.entry.result.status is status
        assert lookup.entry.result.received_at == NOW
        assert lookup.entry.result.request_id == UUID(int=1)
        assert lookup.entry.fresh_until == NOW + ttl
        assert lookup.entry.stale_until == NOW + ttl + timedelta(hours=24)
    else:
        assert lookup.entry is None
    assert {s.value for s in R} == {'hit', 'no_hit', 'error'}


@pytest.mark.parametrize('status', [R.HIT, R.NO_HIT])
@pytest.mark.parametrize('elapsed', [timedelta(0), timedelta(days=1, hours=1)])
def test_error_never_poison_or_becomes_negative(cache, status, elapsed):
    _, _, service = cache
    key = put(service, status=status)
    before = service.get(key, NOW + elapsed)
    assert service.put(result(R.ERROR, at=NOW + elapsed), NOW + elapsed).status is M.ERROR_SKIPPED
    assert service.get(key, NOW + elapsed) == before


@pytest.mark.parametrize('error', list(ThreatIntelError))
def test_error_without_entry_remains_miss(cache, error):
    _, _, service = cache
    value = replace(result(R.ERROR), error=error)
    assert service.put(value, NOW).status is M.ERROR_SKIPPED
    assert service.get(ThreatIntelCacheKey.from_result(value), NOW).freshness is F.MISS


@pytest.mark.parametrize('kind,algorithm,left,right', [
    (K.IP, None, '8.8.8.8', '8.8.8.8'),
    (K.IP, None, '2001:4860:4860:0:0:0:0:8888', '2001:4860:4860::8888'),
    (K.DOMAIN, None, 'EXAMPLE.COM', 'example.com.'),
    (K.HASH, HashAlgorithm.SHA256, 'A' * 64, 'a' * 64),
])
def test_subject_reuses_ns084_canonicalization(kind, algorithm, left, right):
    subject_a, subject_b = ThreatIntelSubject(kind, left, algorithm), ThreatIntelSubject(kind, right, algorithm)
    data_type = next(d for d in D if d.subject_kind is kind)
    assert ThreatIntelCacheKey(A, data_type, subject_a) == ThreatIntelCacheKey(A, data_type, subject_b)


def test_two_providers_types_versions_and_purge_isolation(cache):
    _, _, service = cache
    keys = []
    for provider in (A, B):
        for dtype, value in ((D.IP_REPUTATION, '8.8.8.8'), (D.DOMAIN_REPUTATION, 'example.com'),
                             (D.HASH_REPUTATION, 'a' * 64)):
            keys.append(put(service, provider=provider, data_type=dtype, value=value))
    for key in keys:
        assert service.get(key, NOW).freshness is F.FRESH
        assert service.get(replace(key, result_version=3), NOW).freshness is F.UNSUPPORTED
    assert service.purge(provider=A).affected == 3
    assert all(service.get(k, NOW).freshness is F.MISS for k in keys[:3])
    assert all(service.get(k, NOW).freshness is F.FRESH for k in keys[3:])
    assert service.purge(key=keys[3]).affected == 1
    assert service.get(keys[4], NOW).freshness is F.FRESH
    assert service.purge().affected == 2


def test_read_does_not_touch_or_extend_ttl(cache):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        original = tuple(connection.execute('SELECT * FROM threat_intel_cache').fetchone())
    for hours in (1, 10, 24, 30):
        service.get(key, NOW + timedelta(hours=hours))
    with database.connection() as connection:
        assert tuple(connection.execute('SELECT * FROM threat_intel_cache').fetchone()) == original


@pytest.mark.parametrize('delta,state', [(-1, F.CLOCK_ANOMALY), (-300, F.CLOCK_ANOMALY),
                                        (-301, F.CORRUPT), (10**8, F.EXPIRED)])
def test_clock_shift_conservative(cache, delta, state):
    _, _, service = cache
    key = put(service)
    lookup = service.get(key, NOW + timedelta(seconds=delta))
    assert lookup.freshness is state and lookup.entry is None


def test_future_result_and_naive_time_rejected(cache):
    _, _, service = cache
    assert service.put(result(at=NOW + timedelta(seconds=1)), NOW).status is M.INVALID
    with pytest.raises(ValueError):
        service.get(ThreatIntelCacheKey.from_result(result()), datetime(2026, 10, 4))


@pytest.mark.parametrize('previous,next_status', [(R.HIT, R.NO_HIT), (R.NO_HIT, R.HIT)])
def test_latest_fetch_upsert_and_late_result(cache, previous, next_status):
    database, _, service = cache
    key = put(service, status=previous)
    newer = result(next_status, at=NOW + timedelta(minutes=1))
    assert service.put(newer, newer.received_at).status is M.STORED
    assert service.put(result(previous), newer.received_at).status is M.NO_CHANGE
    assert service.get(key, newer.received_at).entry.result.status is next_status
    assert service.get(key, newer.received_at).entry.result.received_at == newer.received_at
    with database.connection() as connection:
        assert connection.execute('SELECT COUNT(*) FROM threat_intel_cache').fetchone()[0] == 1


def test_equal_fetch_tie_deterministic_and_idempotent(cache):
    _, _, service = cache
    low, high = result(request_id=1), result(request_id=2)
    key = ThreatIntelCacheKey.from_result(low)
    for order in ((low, high), (high, low)):
        service.purge()
        for value in order:
            service.put(value, NOW)
        assert service.get(key, NOW).entry.result.request_id == UUID(int=2)
    assert service.put(high, NOW).status is M.NO_CHANGE


def test_concurrent_same_key_newest_fetch_wins(cache):
    database, _, _ = cache
    values = [result(at=NOW + timedelta(seconds=n), request_id=n + 1) for n in range(10)]
    def write(value):
        service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), DESCRIPTORS)
        return service.put(value, NOW + timedelta(seconds=10))
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(write, reversed(values)))
    assert all(o.status in (M.STORED, M.NO_CHANGE) for o in outcomes)
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), DESCRIPTORS)
    lookup = service.get(ThreatIntelCacheKey.from_result(values[0]), NOW + timedelta(seconds=10))
    assert lookup.entry.result.received_at == values[-1].received_at
    with database.connection() as connection:
        assert connection.execute('SELECT COUNT(*) FROM threat_intel_cache').fetchone()[0] == 1


@pytest.mark.parametrize('ages,victim', [((72, 25, 1), 0), ((25, 26, 1), 1), ((1, 2, 3), 2)])
def test_eviction_expired_then_stale_then_oldest_fresh(cache, ages, victim):
    database, _, _ = cache
    policy = ThreatIntelCachePolicy(max_disk_entries=3)
    repository = SQLiteThreatIntelCacheRepository(database, policy)
    service = ThreatIntelCacheService(repository, DESCRIPTORS, policy)
    keys = []
    for index, age in enumerate(ages):
        at = NOW - timedelta(hours=age)
        value = result(value=f'8.8.8.{index + 1}', at=at)
        assert service.put(value, NOW).status is M.STORED
        keys.append(ThreatIntelCacheKey.from_result(value))
    added = result(value='8.8.4.4')
    outcome = service.put(added, NOW)
    assert outcome.evicted == 1
    assert service.get(keys[victim], NOW).freshness is F.MISS
    assert service.get(ThreatIntelCacheKey.from_result(added), NOW).freshness is F.FRESH
    with database.connection() as connection:
        assert connection.execute('SELECT COUNT(*) FROM threat_intel_cache').fetchone()[0] == 3


def test_purge_chunk_and_cleanup_bound(cache):
    database, _, _ = cache
    policy = ThreatIntelCachePolicy(cleanup_chunk=2)
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database, policy), DESCRIPTORS, policy)
    for n in range(5):
        put(service, value=f'8.8.8.{n + 1}')
    outcome = service.cleanup(NOW + timedelta(days=3))
    assert outcome.affected == 2 and outcome.remaining
    outcome = service.purge()
    assert outcome.affected == 2 and outcome.remaining
    outcome = service.purge()
    assert outcome.affected == 1 and not outcome.remaining


@pytest.mark.parametrize('payload', ['{', '{}', '[]', 'null', '{"extra":1}', '"' + 'x' * 4000 + '"'])
def test_corrupt_one_row_does_not_poison_other_provider(cache, payload):
    database, _, service = cache
    a, b = put(service), put(service, provider=B)
    with database.connection() as connection:
        connection.execute('UPDATE threat_intel_cache SET normalized_result = ? WHERE provider_id = ?',
                           (payload, A.value))
    assert service.get(a, NOW).freshness is F.CORRUPT
    assert service.get(b, NOW).freshness is F.FRESH


@pytest.mark.parametrize('field,new_value', [('status', 'error'), ('status', 'clean'), ('query_policy_version', 2),
                                           ('query_policy_version', True), ('request_id', 'invalid'),
                                           ('queried_at', '2026-10-04T00:00:00'), ('received_at', '2099-01-01T00:00:00+00:00')])
def test_strict_codec_corruption(cache, field, new_value):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        original = connection.execute('SELECT normalized_result FROM threat_intel_cache').fetchone()[0]
        payload = json.loads(original)
        payload[field] = new_value
        connection.execute('UPDATE threat_intel_cache SET normalized_result = ?',
                           (json.dumps(payload, sort_keys=True, separators=(',', ':')),))
    assert service.get(key, NOW).freshness is F.CORRUPT


def test_duplicate_fields_and_future_format(cache):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        payload = connection.execute('SELECT normalized_result FROM threat_intel_cache').fetchone()[0]
        connection.execute('UPDATE threat_intel_cache SET normalized_result = ?',
                           (payload[:-1] + ',"status":"hit"}',))
    assert service.get(key, NOW).freshness is F.CORRUPT
    with database.connection() as connection:
        connection.execute('UPDATE threat_intel_cache SET format_version = 3')
    assert service.get(key, NOW).freshness is F.UNSUPPORTED


def test_payload_exact_byte_boundary_and_schema_cap(cache):
    database, _, service = cache
    key = put(service)
    entry = service.get(key, NOW).entry
    payload = encode_entry(entry, 4096)
    size = len(payload.encode('utf-8'))
    assert encode_entry(entry, size) == payload
    assert decode_entry(key, payload, *[utc_microseconds(t) for t in
                        (NOW, entry.fresh_until, entry.stale_until)], size) == entry
    with pytest.raises(ValueError):
        encode_entry(entry, size - 1)
    policy = ThreatIntelCachePolicy(max_payload_bytes=size - 1)
    restricted = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database, policy), DESCRIPTORS, policy)
    assert restricted.put(result(), NOW).status is M.INVALID
    assert restricted.get(key, NOW).freshness is F.CORRUPT
    with database.connection() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute('UPDATE threat_intel_cache SET normalized_result = ?', ('x' * 4097,))


def test_corrupt_oversize_storage_is_size_gated_before_materializing(cache):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        connection.execute('PRAGMA ignore_check_constraints = ON')
        connection.execute('UPDATE threat_intel_cache SET normalized_result = ?', ('x' * 100_000,))
    assert service.get(key, NOW).freshness is F.CORRUPT


def test_persisted_time_corruption_is_size_gated(cache):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        connection.execute('PRAGMA ignore_check_constraints = ON')
        connection.execute('UPDATE threat_intel_cache SET received_at_utc_us = ?', ('x' * 100_000,))
    assert service.get(key, NOW).freshness is F.CORRUPT


def test_reopen_with_tightened_policy_preserves_absolute_freshness(cache):
    database, _, service = cache
    key = put(service)
    policy = ThreatIntelCachePolicy(hit_ttl=timedelta(seconds=1), stale_grace=timedelta(0))
    restarted = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database, policy), DESCRIPTORS)
    lookup = restarted.get(key, NOW + timedelta(hours=2))
    assert lookup.freshness is F.FRESH
    assert lookup.entry.fresh_until == NOW + timedelta(hours=24)


def test_default_hard_disk_capacity_plus_one(cache):
    database, _, service = cache
    key = put(service)
    # Populate exactly the hard capacity using normalized snapshots in one
    # fixture transaction; the repository's +1 write must atomically evict.
    with database.connection() as connection, transaction(connection):
        row = tuple(connection.execute('SELECT * FROM threat_intel_cache').fetchone())
        for n in range(1023):
            connection.execute('INSERT INTO threat_intel_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                               (row[0], row[1], row[2], f'9.1.{n // 256}.{n % 256}', *row[4:]))
    value = result(value='8.8.4.4', at=NOW + timedelta(seconds=1))
    assert service.put(value, value.received_at).evicted == 1
    with database.connection() as connection:
        assert connection.execute('SELECT COUNT(*) FROM threat_intel_cache').fetchone()[0] == 1024
    assert service.get(key, value.received_at).freshness is F.MISS


def test_eviction_failure_rolls_back_entire_new_write(cache):
    database, _, _ = cache
    policy = ThreatIntelCachePolicy(max_disk_entries=1)
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database, policy), DESCRIPTORS)
    first = put(service)
    with database.connection() as connection:
        connection.execute("CREATE TRIGGER fail_ti_delete BEFORE DELETE ON threat_intel_cache "
                           "BEGIN SELECT RAISE(ABORT, 'private failure'); END")
    newer = result(value='8.8.4.4', at=NOW + timedelta(seconds=1))
    assert service.put(newer, newer.received_at).status is M.UNAVAILABLE
    assert service.get(first, newer.received_at).freshness is F.FRESH
    assert service.get(ThreatIntelCacheKey.from_result(newer), newer.received_at).freshness is F.MISS


def test_database_unavailable_typed_and_sanitized(cache, tmp_path):
    database, _, service = cache
    key = put(service)
    blocker = tmp_path / 'blocked'
    blocker.write_text('private error secret')
    bad = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(SQLiteDatabase(blocker / 'db')), DESCRIPTORS)
    assert bad.get(key, NOW).freshness is F.UNAVAILABLE
    assert bad.put(result(), NOW).status is M.UNAVAILABLE
    assert bad.purge().status is M.UNAVAILABLE
    assert bad.cleanup(NOW).status is M.UNAVAILABLE
    assert 'private' not in repr(bad.get(key, NOW))


def test_transaction_failure_rolls_back_upsert_and_eviction(cache):
    database, _, service = cache
    key = put(service)
    with database.connection() as connection:
        connection.execute("CREATE TRIGGER fail_ti_update BEFORE UPDATE ON threat_intel_cache "
                           "BEGIN SELECT RAISE(ABORT, 'private failure'); END")
    newer = result(R.NO_HIT, at=NOW + timedelta(seconds=1))
    assert service.put(newer, newer.received_at).status is M.UNAVAILABLE
    assert service.get(key, newer.received_at).entry.result.status is R.HIT


def test_purge_only_ti_leaves_all_other_stores_unchanged(cache):
    database, _, service = cache
    put(service)
    with database.connection() as connection:
        # Real history sentinel, alongside complete schema/data snapshot of other stores.
        connection.execute("INSERT INTO connection_history (id, protocol, local_address, local_port, "
                           "process_status, connection_state, first_seen_utc_us, last_seen_utc_us) "
                           "VALUES ('12345678-1234-1234-1234-123456789abc', 'tcp', '127.0.0.1', 5000, 'unavailable', 'listen', 1, 1)")
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                  if row[0] != 'threat_intel_cache']
        before = {t: [tuple(r) for r in connection.execute(f'SELECT * FROM "{t}"')] for t in tables}
    assert service.purge().affected == 1
    with database.connection() as connection:
        after = {t: [tuple(r) for r in connection.execute(f'SELECT * FROM "{t}"')] for t in tables}
    assert after == before


def test_registry_removed_and_consent_not_required_for_local_inspection(cache):
    _, repository, service = cache
    key = put(service)
    # Cache API takes no current consent: revoke has no mutation hook here.
    assert service.get(key, NOW).freshness is F.FRESH
    removed = ThreatIntelCacheService(repository, ())
    assert removed.get(key, NOW).freshness is F.UNSUPPORTED
    assert removed.put(result(), NOW).status is M.UNSUPPORTED
    assert removed.purge(provider=A).affected == 1


def test_no_sensitive_payload_or_repr_and_no_network_side_effects(cache):
    database, _, service = cache
    value = result()
    key = put(service)
    entry = service.get(key, NOW).entry
    with database.connection() as connection:
        payload = connection.execute('SELECT normalized_result FROM threat_intel_cache').fetchone()[0]
    assert str(value.query.consent.consent_id) not in payload
    assert set(json.loads(payload)) == {'status', 'request_id', 'queried_at', 'received_at', 'trigger', 'query_policy_version'}
    assert key.subject.value not in repr(key)
    assert key.subject.value not in repr(entry)
    roots = Path(__file__).resolve().parents[3] / 'src/netsentinel'
    for relative in ('domain/threat_intel_cache.py', 'application/services/threat_intel_cache.py',
                     'infrastructure/sqlite/threat_intel_cache_codec.py',
                     'infrastructure/sqlite/threat_intel_cache_repository.py'):
        tree = ast.parse((roots / relative).read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        assert not any(m and m.split('.')[0] in {'requests', 'httpx', 'socket', 'urllib'} for m in imports)
        assert not any(m and ('risk_evidence' in m or 'assessment' in m or 'alerts' in m) for m in imports)


def test_migration_017_to_018_preserves_data_and_key_index(tmp_path):
    database = SQLiteDatabase(tmp_path / 'old.sqlite3', migration_runner=MigrationRunner(builtin_migrations()[:17]))
    with database.connection() as connection:
        assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 17
        before = [tuple(r) for r in connection.execute('SELECT * FROM schema_migrations')]
    upgraded = SQLiteDatabase(database.path)
    with upgraded.connection() as connection:
        assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 20
        assert [tuple(r) for r in connection.execute('SELECT * FROM schema_migrations WHERE version <= 17')] == before
        plan = connection.execute('EXPLAIN QUERY PLAN SELECT normalized_result FROM threat_intel_cache WHERE '
                                  'provider_id=? AND data_type=? AND subject_kind=? AND canonical_subject=? '
                                  'AND hash_algorithm=? AND result_version=?',
                                  (A.value, D.IP_REPUTATION.value, 'ip', '8.8.8.8', '', 1)).fetchone()[3]
        assert 'PRIMARY KEY' in plan and 'SEARCH' in plan


@pytest.mark.parametrize('kwargs', [dict(max_disk_entries=1025), dict(max_payload_bytes=4097),
                                     dict(cleanup_chunk=129), dict(hit_ttl=timedelta(0)),
                                     dict(negative_ttl=timedelta(seconds=-1)), dict(max_disk_entries=True)])
def test_policy_hard_limits(kwargs):
    with pytest.raises(ValueError):
        ThreatIntelCachePolicy(**kwargs)


def test_invalid_subject_type_and_lookup_state_rejected():
    with pytest.raises(ValueError):
        ThreatIntelCacheKey(A, D.DOMAIN_REPUTATION, ThreatIntelSubject(K.IP, '8.8.8.8'))
    with pytest.raises(ValueError):
        ThreatIntelSubject(K.IP, 'invalid')
    with pytest.raises(ValueError):
        ThreatIntelCachedResult.from_result(result(R.ERROR))
    with pytest.raises(ValueError):
        ThreatIntelCacheLookup(F.FRESH)
    value = result()
    key = ThreatIntelCacheKey.from_result(value)
    entry = ThreatIntelCacheEntry(key, ThreatIntelCachedResult.from_result(value),
                                  NOW + timedelta(hours=1), NOW + timedelta(hours=2))
    with pytest.raises(ValueError):
        ThreatIntelCacheLookup(F.MISS, entry)
