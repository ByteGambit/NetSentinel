"""NS-025 persistence, upgrade and history checks without a live LAN."""

from datetime import UTC, datetime, timedelta
import pytest

from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.ports import GatewayBaselineDataCorrupt, GatewayBaselineRepositoryError
from netsentinel.domain.devices import GatewayBaselineStatus
from netsentinel.infrastructure.sqlite.database import SQLiteConnectionFactory, SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations, default_migration_runner
from netsentinel.infrastructure.sqlite.repositories import SQLiteGatewayBaselineRepository
from netsentinel.shared.diagnostics import (
    CaptureCapabilityReason, CaptureCapabilitySnapshot, CaptureCounters,
    CaptureHealthSnapshot, CaptureState, CapabilityStatus,
)
from netsentinel.application.services.device_inventory import DeviceInventoryProblem
import netsentinel.bootstrap as bootstrap

from tests.unit.application.test_gateway_baseline import (
    MAC_A, MAC_B, FakeContexts, context, packet,
)


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)


def test_upgrade_round_trip_history_and_scope(tmp_path):
    path = tmp_path / "baseline.sqlite3"
    old = SQLiteConnectionFactory(path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:3]).migrate(old) == 3
        assert default_migration_runner().migrate(old) == 15
        assert default_migration_runner().migrate(old) == 15
    finally:
        old.close()
    database = SQLiteDatabase(path)
    repo = SQLiteGatewayBaselineRepository(database)
    a = context()
    b = context("ethernet", "10.0.0.1", "10.0.0.0/24")
    provider = FakeContexts(a, b)
    first = GatewayBaselineService(repo, provider, clock=lambda: T0)
    assert first.observe(a, packet(a)).status is GatewayBaselineStatus.LEARNING
    assert first.observe(b, packet(b, mac=MAC_B)).mac == MAC_B
    restarted = GatewayBaselineService(repo, provider, clock=lambda: T0 + timedelta(seconds=61))
    assert restarted.observe(a, packet(a, at=T0 + timedelta(seconds=61))).status is GatewayBaselineStatus.LEARNED
    assert restarted.confirm(a, MAC_A).status is GatewayBaselineStatus.VERIFIED
    assert restarted.observe(a, packet(a, mac=MAC_B, at=T0 + timedelta(seconds=62))).mac == MAC_A
    latest = SQLiteGatewayBaselineRepository(SQLiteDatabase(path))
    assert latest.get(a.fingerprint).status is GatewayBaselineStatus.VERIFIED
    assert latest.get(a.fingerprint).pending_mac == MAC_B
    switched = GatewayBaselineService(latest, provider, clock=lambda: T0 + timedelta(seconds=63))
    assert switched.confirm(a, MAC_B).mac == MAC_B
    assert latest.get(b.fingerprint).status is GatewayBaselineStatus.LEARNING
    assert latest.get(a.fingerprint).first_seen == T0
    assert latest.get(a.fingerprint).last_seen == T0 + timedelta(seconds=62)
    assert [c.changed_at for c in latest.changes(a.fingerprint)] == [T0, T0 + timedelta(seconds=61), T0 + timedelta(seconds=63)]
    assert len(latest.changes(b.fingerprint)) == 1
    with database.connection() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"gateway_baselines", "gateway_baseline_changes"} <= tables
        columns = {row[1] for row in connection.execute("PRAGMA table_info(gateway_baselines)")}
        assert "payload" not in columns and "packet" not in columns


def test_existing_inventory_consumer_feeds_baseline_without_new_worker(monkeypatch, tmp_path):
    ctx = context()
    provider = FakeContexts(ctx)

    class FakeCapture:
        def __init__(self):
            self.observations = [packet(ctx)]

        def health_snapshot(self):
            return CaptureHealthSnapshot(
                CaptureState.RUNNING,
                CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, T0),
                0, 4, CaptureCounters(), ctx.interface_id, ctx.fingerprint,
            )

        def drain(self, limit):
            result = tuple(self.observations[:limit])
            del self.observations[:limit]
            return result

        def stop(self, timeout=None):
            return True

    capture = FakeCapture()
    monkeypatch.setattr(bootstrap, "create_network_context_provider", lambda: provider)
    monkeypatch.setattr(bootstrap, "create_packet_capture", lambda **kwargs: capture)
    path = tmp_path / "inventory.sqlite3"
    service = bootstrap.create_device_inventory_service_factory(database_path=path)()
    result = service.refresh()
    assert result.problem is DeviceInventoryProblem.NONE
    assert len(result.entries) == 1
    assert SQLiteGatewayBaselineRepository(SQLiteDatabase(path)).get(ctx.fingerprint).mac == MAC_A
    assert bootstrap.create_gateway_baseline_service(
        database_path=path, context_provider=provider
    ).get(ctx).mac == MAC_A
    assert capture.observations == []

    class FailingBaseline:
        def observe(self, context, observation):
            raise RuntimeError("secret storage detail")

    service._gateway_baseline = FailingBaseline()
    capture.observations.append(packet(ctx, mac=MAC_B, at=T0 + timedelta(seconds=1)))
    degraded = service.refresh()
    assert degraded.problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
    assert len(degraded.entries) == 2


def test_failed_history_write_rolls_back_baseline_and_corrupt_data_is_sanitized(tmp_path):
    database = SQLiteDatabase(tmp_path / "failure.sqlite3")
    repo = SQLiteGatewayBaselineRepository(database)
    ctx = context()
    with database.connection() as connection:
        connection.execute("""
            CREATE TRIGGER reject_gateway_change BEFORE INSERT ON gateway_baseline_changes
            BEGIN SELECT RAISE(ABORT, 'secret database detail'); END
        """)
    svc = GatewayBaselineService(repo, FakeContexts(ctx), clock=lambda: T0)
    with pytest.raises(GatewayBaselineRepositoryError) as captured:
        svc.observe(ctx, packet(ctx))
    assert "secret database detail" not in str(captured.value)
    assert repo.get(ctx.fingerprint) is None
    with database.connection() as connection:
        connection.execute("DROP TRIGGER reject_gateway_change")
    svc.observe(ctx, packet(ctx))
    with database.connection() as connection:
        connection.execute(
            "UPDATE gateway_baselines SET mac = '01:00:5e:00:00:01' WHERE network_fingerprint = ?",
            (ctx.fingerprint,),
        )
    with pytest.raises(GatewayBaselineDataCorrupt):
        repo.get(ctx.fingerprint)
