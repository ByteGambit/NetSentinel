"""NS-071 offline lifecycle, persistence, quota and writer acceptance."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import sqlite3
from threading import Event, Thread
from uuid import uuid4

import pytest

from netsentinel.application.services.behavior_baseline import (
    BaselineCommand, BaselineWriter, BehaviorBaselineService, baseline_state,
)
from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.behavior_features import BehaviorCapacity, BehaviorFeatureAccumulator
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.behavior_baseline import (
    BaselineLoad, BaselineRead, BaselineOrigin, BaselineState, BaselineStorageState, BaselineSummary,
    MAX_BASELINE_PAYLOAD_BYTES, validate_baseline_summary,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import (
    ConnectionNetworkScope, ConnectionOpened, ConnectionRoundObservation, ConnectionSnapshot,
    ConnectionState, Endpoint, NetworkAttributionMethod, NetworkScopeStatus,
    ObservationOrigin, ObservationQuality, ProcessIdentity, ProcessInfo,
    ProcessInfoStatus, TransportProtocol,
)
from netsentinel.infrastructure.sqlite.behavior_baselines import (
    SQLiteBaselineRepository, baseline_repository_session, encode_summary,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
from netsentinel.shared.config import BehaviorBaselineConfig

NOW = datetime(2026, 10, 3, tzinfo=UTC)


class Clock:
    tick = 0.0
    utc = NOW

    def wall(self):
        return self.utc

    def mono(self):
        return self.tick


def key(app="browser", revision=None, network="a" * 64):
    return BehaviorScopeKey(f"winpath:v1:c:\\apps\\{app}.exe", ApplicationIdentityQuality.STABLE,
                            revision, NetworkScopeStatus.RESOLVED, network)


def features(scope=None, *, samples=20, seconds=600.0, loss=False, reduced=0):
    return BehaviorFeatureSnapshot(
        scope or key(), samples, reduced, seconds,
        (FeatureCount("203.0.113.1", samples),) if samples else (),
        (FeatureCount(443, samples),) if samples else (),
        (FeatureCount(TransportProtocol.TCP, samples),) if samples else (),
        0, 0, 0, 0, int(samples > 0), int(samples > 0), int(samples > 0), False, loss,
    )


def summary(service, scope=None, **kwargs):
    return BaselineSummary(features(scope, **kwargs), NOW, NOW, service.policy_key)


class MemoryRepository:
    def __init__(self):
        self.records = {}
        self.loaded = BaselineLoad(())
        self.block = False
        self.entered = Event()
        self.release = Event()
        self.fail = False
        self.calls = 0

    def load(self, limit):
        return self.loaded

    def write(self, value, scope, *, reset=False):
        self.entered.set()
        if self.block:
            assert self.release.wait(5)
        self.calls += 1
        if self.fail:
            raise OSError("private error must not reach diagnostics")
        if reset:
            self.records.pop(scope, None)
        if value is not None:
            self.records[scope] = value
        return 0

    def cleanup(self, now):
        return 0


@contextmanager
def memory_session(repository):
    yield repository


def make_service(repository=None, clock=None, config=None, capacity=None):
    repository = repository or MemoryRepository()
    clock = clock or Clock()
    writer = BaselineWriter(lambda: memory_session(repository))
    service = BehaviorBaselineService(writer, clock=clock.wall, monotonic_clock=clock.mono,
                                      config=config, capacity=capacity)
    return service, writer, repository, clock


def start_loaded(service, writer):
    loaded = Event()
    original = writer.on_load
    def notify(value):
        original(value)
        loaded.set()
    writer.on_load = notify
    assert service.start()
    assert loaded.wait(5)


@pytest.mark.parametrize("samples,seconds,expected", [
    (0, 0, BaselineState.LEARNING), (1, 600, BaselineState.INSUFFICIENT_DATA),
    (20, 599, BaselineState.INSUFFICIENT_DATA), (19, 600, BaselineState.INSUFFICIENT_DATA),
    (20, 600, BaselineState.READY),
])
def test_warmup_requires_both_real_evidence_thresholds(samples, seconds, expected):
    service, _, _, _ = make_service()
    service.restore(BaselineLoad(()))
    service.observe((features(samples=samples, seconds=seconds),), NOW, ObservationQuality.COMPLETE)
    assert service.snapshot(key()).state is expected


@pytest.mark.parametrize("quality_field", ["capacity_loss", "reduced_appearances", "unknown_destinations"])
def test_quality_loss_prevents_ready(quality_field):
    service, _, _, _ = make_service()
    f = features()
    if quality_field == "unknown_destinations":
        f = replace(f, destinations=(FeatureCount("203.0.113.1", 19),), ports=(FeatureCount(443, 19),), unknown_destinations=1)
    else:
        f = replace(f, **{quality_field: True if quality_field == "capacity_loss" else 1})
    assert baseline_state(BaselineSummary(f, NOW, NOW, service.policy_key), NOW, service.config) is BaselineState.INSUFFICIENT_QUALITY


def event(session, *, origin=ObservationOrigin.OBSERVED, network=None, path=r"C:\Apps\browser.exe"):
    return ConnectionOpened(ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint("192.0.2.1", 50000), Endpoint("203.0.113.1", 443),
        ConnectionState.ESTABLISHED,
        ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(7, NOW - timedelta(hours=1)), "browser.exe", executable_path=path),
        NOW, network or ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "if", 1, NetworkAttributionMethod.LOCAL_ADDRESS_MATCH),
    ), origin=origin, session_id=session)


def observe(acc, service, clock, session, events=(), snapshots=(), quality=ObservationQuality.COMPLETE):
    contributions = acc.observe_round(ConnectionRoundObservation(session, clock.utc, quality), events, snapshots)
    service.observe(contributions, clock.utc, quality)


def test_actual_accumulator_initial_failed_reduced_gap_and_bucket_rotation():
    service, _, _, clock = make_service()
    service.restore(BaselineLoad(()))
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock.mono)
    session = uuid4()
    first = event(session, origin=ObservationOrigin.INITIAL)
    observe(acc, service, clock, session, (first,), (first.snapshot,))
    assert service.snapshot(key()).summary.features.observed_appearances == 0
    clock.tick = 1
    observe(acc, service, clock, session, (event(session),), (first.snapshot,))
    clock.tick = 2
    observe(acc, service, clock, session, quality=ObservationQuality.FAILED)
    clock.tick = 3
    observe(acc, service, clock, session, (event(session),), quality=ObservationQuality.REDUCED)
    clock.tick = 100_000
    observe(acc, service, clock, session, snapshots=(first.snapshot,))
    f = service.snapshot(key()).summary.features
    assert (f.observed_appearances, f.reduced_appearances, f.monitored_seconds) == (2, 1, 1)
    assert f.gap_seen
    assert acc.snapshot().scopes[0].observed_appearances == 0


def test_restart_eight_hours_and_fresh_monotonic_never_reconstruct_buckets(tmp_path):
    database = SQLiteDatabase(tmp_path / "baseline.db")
    config = BehaviorBaselineConfig()
    clock = Clock()
    def create():
        writer = BaselineWriter(lambda: baseline_repository_session(database, config))
        service = BehaviorBaselineService(writer, clock=clock.wall, monotonic_clock=clock.mono)
        start_loaded(service, writer)
        return service, writer
    first, writer = create()
    clock.tick = 123_456
    first.observe((features(seconds=360),), NOW, ObservationQuality.COMPLETE)
    assert first.stop()
    clock.tick = 0
    clock.utc += timedelta(hours=8)
    second, writer = create()
    try:
        restored = second.snapshot(key())
        assert restored.origin is BaselineOrigin.RESTORED
        assert restored.summary.features.monitored_seconds == 360
        assert restored.summary.features.observed_appearances == 20
        acc = BehaviorFeatureAccumulator(monotonic_clock=clock.mono)
        session = uuid4()
        initial = event(session, origin=ObservationOrigin.INITIAL)
        observe(acc, second, clock, session, (initial,), (initial.snapshot,))
        observe(acc, second, clock, session, quality=ObservationQuality.FAILED)
        assert second.snapshot(key()).summary.features.monitored_seconds == 360
        assert second.snapshot(key()).summary.features.observed_appearances == 20
        clock.tick = 1
        observe(acc, second, clock, session, snapshots=(initial.snapshot,))
        assert second.snapshot(key()).summary.features.monitored_seconds == 360
        clock.tick = 2
        observe(acc, second, clock, session, snapshots=(initial.snapshot,))
        assert second.snapshot(key()).summary.features.monitored_seconds == 361
        assert acc.snapshot().scopes[0].monitored_seconds == 1
    finally:
        assert second.stop()
    with database.connection() as connection:
        payload = connection.execute("SELECT payload FROM behavior_baselines").fetchone()[0]
        assert "bucket" not in payload and "monotonic" not in payload


@pytest.mark.parametrize("revision", [None, "b" * 64, "c" * 64])
def test_repository_roundtrip_identity_revision_network_features(tmp_path, revision):
    service, _, _, _ = make_service()
    value = summary(service, key(revision=revision))
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(value, value.features.scope)
        read = repo.load(128).records[0]
        assert read.summary == value
        assert encode_summary(value) == encode_summary(read.summary)
        assert "winpath" not in encode_summary(value)  # normalized scope columns


@pytest.mark.parametrize("scope", [
    replace(key(), identity_quality=ApplicationIdentityQuality.PROVISIONAL, application_key="instance:v1:7:123"),
    replace(key(), network_status=NetworkScopeStatus.UNKNOWN, network_token="session:192.0.2.1"),
    replace(key(), network_status=NetworkScopeStatus.AMBIGUOUS, network_token="session:192.0.2.1"),
])
def test_ephemeral_scopes_are_session_only_and_never_written(tmp_path, scope):
    service, writer, repo, _ = make_service()
    start_loaded(service, writer)
    service.observe((features(scope),), NOW, ObservationQuality.COMPLETE)
    assert service.snapshot(scope).origin is BaselineOrigin.SESSION_ONLY
    assert service.checkpoint(force=True) == 0
    assert service.stop()
    assert not repo.records
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        with pytest.raises(ValueError):
            SQLiteBaselineRepository(connection).write(summary(service, scope), scope)


@pytest.mark.parametrize("offset,expected", [(-1, BaselineState.CLOCK_ANOMALY), (30 * 86400, BaselineState.STALE), (90 * 86400, BaselineState.EXPIRED), (500 * 365 * 86400, BaselineState.EXPIRED)])
def test_wall_clock_stale_expiry_backward_forward_are_typed_and_sticky(offset, expected):
    service, _, _, clock = make_service()
    service.restore(BaselineLoad(()))
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    clock.utc += timedelta(seconds=offset)
    assert service.snapshot(key()).state is expected
    service.observe((features(samples=1, seconds=1),), clock.utc, ObservationQuality.COMPLETE)
    clock.utc = NOW
    assert service.snapshot(key()).state is expected
    assert service.snapshot(key()).summary.features.monitored_seconds == 600


@pytest.mark.parametrize("update,expected", [
    ({"summary_version": 99}, BaselineState.UNSUPPORTED_VERSION),
    ({"feature_policy_version": 99}, BaselineState.POLICY_MISMATCH),
    ({"payload": "{"}, BaselineState.CORRUPT),
    ({"payload": '{"observed_appearances": -1}'}, BaselineState.CORRUPT),
    ({"revision_digest": "z" * 64}, BaselineState.CORRUPT),
    ({"network_fingerprint": "z" * 64}, BaselineState.CORRUPT),
    ({"application_key": "winpath:v1:relative.exe"}, BaselineState.CORRUPT),
    ({"last_observed_at": "not a time"}, BaselineState.CORRUPT),
])
def test_corrupt_and_future_rows_never_become_trusted(tmp_path, update, expected):
    service, _, _, _ = make_service()
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(summary(service), key())
        for column, value in update.items():
            # Column names are fixed fixture constants, never domain input.
            assert column in {"summary_version", "feature_policy_version", "payload", "revision_digest", "network_fingerprint", "application_key", "last_observed_at"}
            connection.execute(f"UPDATE behavior_baselines SET {column} = ?", (value,))
        read = repo.load(128).records[0]
        assert read.state is expected
        service.restore(BaselineLoad((read,)))
        service.observe((features(),), NOW, ObservationQuality.COMPLETE)
        if read.scope is None:
            assert service.snapshot(key()).state is BaselineState.INSUFFICIENT_QUALITY
        else:
            assert service.snapshot(read.scope).state is expected


@pytest.mark.parametrize("mutation", [
    {"monitored_seconds": -1}, {"monitored_seconds": float("inf")}, {"monitored_seconds": True},
    {"observed_appearances": -1}, {"observed_appearances": True}, {"reduced_appearances": 21},
    {"destinations": [{"value": "bad IP", "observed_appearances": 20}]},
    {"ports": [{"value": 65536, "observed_appearances": 20}]},
    {"protocols": [{"value": "icmp", "observed_appearances": 20}]},
    {"destination_diversity": 2}, {"other_ports": 1},
    {"destinations": [{"value": "203.0.113.1", "observed_appearances": 20}] * 65},
    {"bucket_index": 123}, {"gap_seen": 1},
])
def test_malformed_impossible_payloads_are_rejected(tmp_path, mutation):
    service, _, _, _ = make_service()
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        value = summary(service)
        payload = json.loads(encode_summary(value))
        payload.update(mutation)
        repo.write(value, key())
        connection.execute("UPDATE behavior_baselines SET payload = ?", (json.dumps(payload),))
        assert repo.load(128).records[0].state is BaselineState.CORRUPT


def test_payload_size_constraint_and_parse_bound(tmp_path):
    service, _, _, _ = make_service()
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(summary(service), key())
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE behavior_baselines SET payload = ?", ("x" * (MAX_BASELINE_PAYLOAD_BYTES + 1),))
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE behavior_baselines SET payload = ?", ("x" * (MAX_BASELINE_PAYLOAD_BYTES + 1),))
        assert repo.load(128).records[0].state is BaselineState.CORRUPT


def test_policy_configuration_mismatch_requires_explicit_reset(tmp_path):
    service, _, _, _ = make_service()
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(replace(summary(service), policy_key="previous-policy"), key())
        service.restore(repo.load(128))
        assert service.snapshot(key()).state is BaselineState.POLICY_MISMATCH
        service.observe((features(),), NOW, ObservationQuality.COMPLETE)
        assert service.checkpoint(force=True) == 0


def test_retention_chunk_row_cap_and_eviction_origin(tmp_path):
    config = BehaviorBaselineConfig(max_rows=3, load_limit=3, cleanup_chunk_size=2)
    service, _, _, _ = make_service(config=config)
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection, config)
        for i in range(6):
            value = summary(service, key(str(i)))
            repo.write(value, value.features.scope)
            assert connection.execute("SELECT COUNT(*) FROM behavior_baselines").fetchone()[0] <= 3
        loaded = repo.load(3)
        assert loaded.capacity_loss
        service.restore(loaded)
        assert service.snapshot(key("0")).state is BaselineState.UNAVAILABLE
        assert repo.cleanup(NOW + timedelta(days=90)) == 2
        assert repo.cleanup(NOW + timedelta(days=90)) == 1
        assert repo.cleanup(NOW + timedelta(days=90)) == 0


def test_hard_schema_row_limit_and_startup_query_limit(tmp_path):
    service, _, _, _ = make_service()
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(summary(service), key())
        sql = """INSERT INTO behavior_baselines SELECT ?, revision_digest, network_fingerprint,
                 summary_version, feature_policy_version, policy_key, last_observed_at, persisted_at, payload
                 FROM behavior_baselines WHERE application_key = ?"""
        for i in range(511):
            connection.execute(sql, (key(str(i)).application_key, key().application_key))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(sql, (key("overflow").application_key, key().application_key))
        loaded = repo.load(128)
        assert len(loaded.records) == 128 and loaded.capacity_loss
        with pytest.raises(ValueError):
            repo.load(129)
        service.restore(loaded)
        assert len(service._records) <= 128
        assert len({scope.application_key for scope in service._records}) <= 64


def test_legacy_013_upgrade_is_empty_no_history_inference(tmp_path):
    database = SQLiteDatabase(tmp_path / "test.db", migration_runner=MigrationRunner(builtin_migrations()[:13]))
    with database.connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 13
    with SQLiteDatabase(database.path).connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 17
        assert SQLiteBaselineRepository(connection).load(128) == BaselineLoad(())
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert not {"behavior_events", "connection_appearance_log", "poll_snapshots"} & tables


def test_coalescing_and_reset_with_older_write_inflight_no_resurrection():
    service, writer, repo, _ = make_service()
    start_loaded(service, writer)
    repo.block = True
    service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    assert service.checkpoint(force=True) == 1
    assert repo.entered.wait(5)
    try:
        for _ in range(100):
            service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
            service.checkpoint(force=True)
        assert writer.pending_count == 1
        assert service.reset(key())
        assert service.reset(key())
        assert service.snapshot(key()).origin is BaselineOrigin.RESET
        # Captured stale checkpoint is rejected while the reset is pending.
        assert not writer.submit(BaselineCommand(key(), summary(service), 1))
    finally:
        repo.release.set()
        assert service.stop()
    assert key() not in repo.records
    assert repo.calls == 2


def test_reset_new_learning_scope_isolation_and_restart(tmp_path):
    database = SQLiteDatabase(tmp_path / "test.db")
    config = BehaviorBaselineConfig()
    writer = BaselineWriter(lambda: baseline_repository_session(database, config))
    service = BehaviorBaselineService(writer, clock=lambda: NOW)
    start_loaded(service, writer)
    a, b, c = key(), key(network="b" * 64), key(revision="c" * 64)
    service.observe(tuple(features(scope) for scope in (a, b, c)), NOW, ObservationQuality.COMPLETE)
    service.checkpoint(force=True)
    assert service.reset(a)
    assert service.stop()
    with database.connection() as connection:
        reads = SQLiteBaselineRepository(connection).load(128)
    restored, _, _, _ = make_service()
    restored.restore(reads)
    assert restored.snapshot(a).summary is None
    assert restored.snapshot(b).summary.features.observed_appearances == 20
    assert restored.snapshot(c).summary.features.observed_appearances == 20


def test_reset_then_observe_coalesces_delete_before_new_summary():
    service, writer, repo, _ = make_service()
    start_loaded(service, writer)
    repo.block = True
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    service.checkpoint(force=True)
    assert repo.entered.wait(5)
    try:
        assert service.reset(key())
        service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
        service.checkpoint(force=True)
        assert writer.pending_count == 1
    finally:
        repo.release.set()
        assert service.stop()
    assert repo.records[key()].features.observed_appearances == 1


def test_writer_backpressure_and_shutdown_timeout_are_bounded():
    service, writer, repo, _ = make_service()
    writer.capacity = 2
    start_loaded(service, writer)
    repo.block = True
    assert writer.submit(BaselineCommand(key(), summary(service), 1))
    assert repo.entered.wait(5)
    try:
        for i in range(10):
            scope = key(str(i))
            writer.submit(BaselineCommand(scope, summary(service, scope), i + 2))
        assert writer.pending_count == 2
        assert writer.rejected == 8
        assert not writer.stop(0)
        assert not writer.start()
    finally:
        repo.release.set()
        assert writer.stop(5)


def test_write_failure_keeps_monitoring_and_dirty_state_for_retry():
    service, writer, repo, _ = make_service()
    repo.fail = True
    start_loaded(service, writer)
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    assert service.stop()
    assert service.snapshot(key()).summary.features.observed_appearances == 20
    diagnostics = service.diagnostics()
    assert diagnostics.storage is BaselineStorageState.UNAVAILABLE
    assert diagnostics.write_failures >= 1 and diagnostics.dirty_scopes == 1
    assert "private" not in repr(diagnostics)
    repo.fail = False
    start_loaded(service, writer)
    assert service.stop()
    assert repo.records[key()].features.observed_appearances == 20


def test_load_failure_is_not_empty_baseline_and_monitoring_still_learns():
    repo = MemoryRepository()
    def failed_load(limit):
        raise OSError("unavailable")
    repo.load = failed_load
    service, writer, _, _ = make_service(repo)
    start_loaded(service, writer)
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    assert service.snapshot(key()).state is BaselineState.INSUFFICIENT_QUALITY
    assert service.snapshot(key()).origin is BaselineOrigin.PREVIOUS_UNAVAILABLE
    assert service.diagnostics().storage is BaselineStorageState.UNAVAILABLE
    assert service.stop()


def test_checkpoint_interval_crash_tail_and_same_process_restart():
    service, writer, repo, clock = make_service()
    start_loaded(service, writer)
    service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    assert writer.checkpoints == 0 and writer.pending_count == 0
    clock.tick = 29
    assert service.checkpoint() == 0
    clock.tick = 30
    assert service.checkpoint() == 1
    assert writer.stop()  # Crash simulation: no service final flush.
    assert repo.records[key()].features.observed_appearances == 1
    service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    assert repo.records[key()].features.observed_appearances == 1
    assert service.snapshot(key()).summary.features.observed_appearances == 2
    start_loaded(service, writer)
    assert service.stop()
    assert repo.records[key()].features.observed_appearances == 2


def test_capacity_loss_overflow_and_diversity_roundtrip(tmp_path):
    cap = BehaviorCapacity(destinations=1, ports=1)
    service, _, _, _ = make_service(capacity=cap)
    service.restore(BaselineLoad(()))
    service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    delta = replace(features(samples=1, seconds=1), destinations=(FeatureCount("203.0.113.2", 1),), ports=(FeatureCount(80, 1),))
    service.observe((delta,), NOW, ObservationQuality.COMPLETE)
    value = service.snapshot(key()).summary
    assert value.features.capacity_loss
    assert value.features.other_destinations == value.features.other_ports == 1
    assert value.features.destination_diversity == 1
    validate_baseline_summary(value)
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(value, key())
        assert repo.load(128).records[0].summary == value


@pytest.mark.parametrize("kwargs", [{"load_limit": 129}, {"max_rows": 513}, {"cleanup_chunk_size": 65}, {"stale_days": 90}, {"minimum_samples": True}, {"checkpoint_interval": float("nan")}])
def test_configuration_bounds(kwargs):
    with pytest.raises(ValueError):
        BehaviorBaselineConfig(**kwargs)


def test_deterministic_encoding_of_logically_equal_feature_maps():
    service, _, _, _ = make_service()
    f = features()
    f = replace(f, destinations=(FeatureCount("203.0.113.2", 10), FeatureCount("203.0.113.1", 10)), destination_diversity=2)
    a = BaselineSummary(f, NOW, NOW, service.policy_key)
    b = replace(a, features=replace(f, destinations=tuple(reversed(f.destinations))))
    assert encode_summary(a) == encode_summary(b)


def test_live_contributions_merge_once_with_startup_history_and_shutdown_flush():
    repo = MemoryRepository()
    service, writer, _, clock = make_service(repo)
    repo.loaded = BaselineLoad((BaselineRead(key(), BaselineState.LEARNING, summary(service)),))
    loading, release = Event(), Event()
    def load(limit):
        loading.set()
        assert release.wait(5)
        return repo.loaded
    repo.load = load
    assert service.start()
    assert loading.wait(5)
    try:
        service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
        assert service.checkpoint(force=True) == 0
        stopped = []
        stop_thread = Thread(target=lambda: stopped.append(service.stop(5)))
        stop_thread.start()
        with writer._condition:
            assert writer._condition.wait_for(lambda: writer.stopping, timeout=5)
    finally:
        release.set()
        stop_thread.join(5)
        assert stopped == [True]
    assert repo.records[key()].features.observed_appearances == 21
    assert repo.records[key()].features.monitored_seconds == 601


def test_reset_while_startup_load_is_inflight_does_not_restore_old_state():
    repo = MemoryRepository()
    service, writer, _, _ = make_service(repo)
    repo.loaded = BaselineLoad((BaselineRead(key(), BaselineState.LEARNING, summary(service)),))
    loading, release = Event(), Event()
    def load(limit):
        loading.set()
        assert release.wait(5)
        return repo.loaded
    repo.load = load
    assert service.start()
    assert loading.wait(5)
    try:
        assert service.reset(key())
        service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    finally:
        release.set()
        assert service.stop()
    assert repo.records[key()].features.observed_appearances == 1


def test_engine_uses_real_accumulator_and_continues_when_storage_load_fails():
    repo = MemoryRepository()
    def fail(limit):
        raise OSError("sensitive path")
    repo.load = fail
    service, writer, _, clock = make_service(repo)
    start_loaded(service, writer)
    connection = event(uuid4()).snapshot
    class Collector:
        def collect(self):
            return (connection,)
    class Enricher:
        def enrich(self, values):
            return tuple(values)
    engine = MonitoringEngine(collector=Collector(), enricher=Enricher(),
                              tracker=ConnectionTrackingService(clock=clock.wall),
                              behavior_baselines=service, clock=clock.wall, monotonic_clock=clock.mono)
    for tick in range(3):
        clock.tick = tick
        engine._poll_once()
    assert engine.health.counters.successful_rounds == 3
    assert engine.behavior_features.snapshot().scopes[0].monitored_seconds == 2
    assert service.snapshot(key()).summary.features.monitored_seconds == 2
    assert service.snapshot(key()).summary.features.observed_appearances == 0
    assert engine.stop()


def test_reset_can_relearn_after_disk_loss_and_survive_restart(tmp_path):
    service, writer, repo, _ = make_service()
    repo.loaded = BaselineLoad((), capacity_loss=True)
    start_loaded(service, writer)
    assert service.reset(key())
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    assert service.snapshot(key()).state is BaselineState.READY
    assert service.stop()
    restored, _, _, _ = make_service()
    restored.restore(BaselineLoad((BaselineRead(key(), BaselineState.LEARNING, repo.records[key()]),), capacity_loss=True))
    assert restored.snapshot(key()).state is BaselineState.READY
    assert restored.snapshot(key("missing")).state is BaselineState.UNAVAILABLE


def test_monitored_coverage_is_cumulative_without_silent_poll_samples():
    service, _, _, clock = make_service()
    service.restore(BaselineLoad(()))
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock.mono)
    session = uuid4()
    first = event(session, origin=ObservationOrigin.INITIAL)
    observe(acc, service, clock, session, (first,), (first.snapshot,))
    for tick in range(1, 901):
        clock.tick = tick
        observe(acc, service, clock, session, snapshots=(first.snapshot,))
    value = service.snapshot(key())
    assert value.summary.features.monitored_seconds == 900
    assert value.summary.features.observed_appearances == 0
    assert value.state is BaselineState.INSUFFICIENT_DATA
    assert acc.snapshot().scopes[0].monitored_seconds < 720


def test_sql_metacharacters_in_application_key_are_bound_parameters(tmp_path):
    service, _, _, _ = make_service()
    scope = key("a');drop table behavior_baselines;--")
    with SQLiteDatabase(tmp_path / "test.db").connection() as connection:
        repo = SQLiteBaselineRepository(connection)
        repo.write(summary(service, scope), scope)
        assert repo.load(128).records[0].scope == scope
        repo.write(None, scope, reset=True)
        assert repo.load(128).records == ()
