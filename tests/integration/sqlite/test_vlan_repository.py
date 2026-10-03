"""NS-044 SQLite aggregate round-trip and deterministic capacity."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.ports import VlanSummaryRepositoryError
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from netsentinel.infrastructure.sqlite.migrations import (
    DatabaseMigrationError, Migration, MigrationRunner, builtin_migrations,
)
from netsentinel.infrastructure.sqlite.repositories import datetime_to_epoch_microseconds
from tests.unit.application.test_vlan_baseline import AT, Clock, context, packet


def test_round_trip_restart_preserves_counts_first_last_and_frozen_reference(tmp_path) -> None:
    database = SQLiteDatabase(tmp_path / "vlan.sqlite3")
    clock = Clock()
    ctx = context()
    first = VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=clock)
    first.observe(ctx, packet(ctx, 10, at=AT + timedelta(seconds=4)))
    clock.at += timedelta(seconds=60)
    first.observe(ctx, packet(ctx, 10, at=AT + timedelta(seconds=6)))

    restarted = VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=clock)
    restored = restarted.get(ctx)
    assert restored.baseline_state is VlanBaselineState.LEARNED
    assert restored.learned_vlan_ids == (10,)
    assert restored.vlan_ids[0].count == 2
    assert restored.first_seen == AT + timedelta(seconds=4)
    assert restored.last_seen == AT + timedelta(seconds=6)
    changed = restarted.observe(ctx, packet(ctx, 20, at=AT + timedelta(seconds=5)))
    assert changed.tagged_count == 3
    assert changed.learned_vlan_ids == (10,)
    assert changed.vlan_ids[1].learned is False
    assert changed.last_seen == AT + timedelta(seconds=6)
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM vlan_summaries").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM vlan_id_summaries").fetchone()[0] == 2
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 17


def test_scope_eviction_removes_child_rows_with_deterministic_oldest_first(tmp_path) -> None:
    database = SQLiteDatabase(tmp_path / "capacity.sqlite3")
    repo = SQLiteVlanSummaryRepository(database, max_scopes=2)
    service = VlanSummaryService(repo, clock=Clock())
    a, b, c = context("A", 1), context("B", 2), context("C", 3)
    service.observe(a, packet(a, 10))
    service.observe(b, packet(b, 20, at=AT + timedelta(seconds=1)))
    service.observe(c, packet(c, 30, at=AT + timedelta(seconds=2)))
    assert service.get(a) is None
    assert service.get(b).vlan_ids[0].vlan_id == 20
    assert service.get(c).vlan_ids[0].vlan_id == 30
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM vlan_summaries").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM vlan_id_summaries").fetchone()[0] == 2


def test_restart_resumes_incomplete_warmup_without_early_learning(tmp_path) -> None:
    database = SQLiteDatabase(tmp_path / "learning.sqlite3")
    clock = Clock()
    ctx = context()
    VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=clock).observe(ctx, packet(ctx, 10))
    clock.at += timedelta(seconds=59)
    service = VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=clock)
    assert service.observe(ctx, packet(ctx, 10)).baseline_state is VlanBaselineState.LEARNING
    clock.at += timedelta(seconds=1)
    learned = service.observe(ctx, packet(ctx, 10))
    assert learned.baseline_state is VlanBaselineState.LEARNED
    assert learned.learned_vlan_ids == (10,)


def test_explicit_verification_roundtrip_and_passive_observations_do_not_change_it(tmp_path) -> None:
    path = tmp_path / "verified.sqlite3"
    ctx = context()
    clock = Clock()
    service = VlanSummaryService(SQLiteVlanSummaryRepository(SQLiteDatabase(path)),
                                 clock=clock, warmup=timedelta(0))
    service.observe(ctx, packet(ctx, 10, at=AT))
    service.observe(ctx, packet(ctx, 10, at=AT + timedelta(seconds=1)))
    clock.at += timedelta(seconds=2)
    verified = service.verify_baseline(ctx)
    assert verified.baseline_state is VlanBaselineState.VERIFIED
    assert verified.verified_at == clock.at
    restarted = VlanSummaryService(SQLiteVlanSummaryRepository(SQLiteDatabase(path)), clock=clock)
    assert restarted.get(ctx).verified_at == verified.verified_at
    with pytest.raises(VlanSummaryRepositoryError):
        restarted._repository.save(replace(verified, baseline_state=VlanBaselineState.LEARNED,
                                           verified_at=None))
    with pytest.raises(VlanSummaryRepositoryError):
        restarted._repository.save(replace(
            verified, vlan_ids=(replace(verified.vlan_ids[0], learned=False),)))
    clock.at += timedelta(seconds=1)
    after = restarted.observe(ctx, packet(ctx, 20, at=AT + timedelta(seconds=3)))
    assert after.baseline_state is VlanBaselineState.VERIFIED
    assert after.verified_at == verified.verified_at
    assert after.learned_vlan_ids == (10,)
    assert restarted.verify_baseline(ctx).verified_at == verified.verified_at


def test_008_upgrade_preserves_learned_summary_and_adds_verification(tmp_path) -> None:
    path = tmp_path / "upgrade.sqlite3"
    old_db = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:8]))
    ctx = context()
    stamp = datetime_to_epoch_microseconds(AT)
    with old_db.connection() as connection:
        connection.execute(
            "INSERT INTO vlan_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx.fingerprint, ctx.interface_id.casefold(), ctx.interface_index,
             stamp, stamp, stamp, "learned", 0, 2, 0, 0, 0, 0),
        )
        connection.execute(
            "INSERT INTO vlan_id_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx.fingerprint, ctx.interface_id.casefold(), ctx.interface_index,
             10, 2, stamp, stamp, 1),
        )
        assert "verified_at_utc_us" not in [row[1] for row in connection.execute(
            "PRAGMA table_info(vlan_summaries)")]
    database = SQLiteDatabase(path)
    service = VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=Clock())
    assert service.get(ctx).baseline_state is VlanBaselineState.LEARNED
    assert service.verify_baseline(ctx).baseline_state is VlanBaselineState.VERIFIED
    with database.connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 17
        assert connection.execute("SELECT verified_at_utc_us FROM vlan_summaries").fetchone()[0] == stamp


def test_failed_009_migration_rolls_back_column_and_version(tmp_path) -> None:
    path = tmp_path / "rollback.sqlite3"
    old_db = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:8]))
    with old_db.connection():
        pass
    broken = Migration(9, "vlan_verification",
                       "ALTER TABLE vlan_summaries ADD COLUMN verified_at_utc_us INTEGER; BAD SQL;")
    runner = MigrationRunner((*builtin_migrations()[:8], broken))
    with pytest.raises(DatabaseMigrationError):
        with SQLiteDatabase(path, migration_runner=runner).connection():
            pass
    with old_db.connection() as connection:
        assert "verified_at_utc_us" not in [row[1] for row in connection.execute(
            "PRAGMA table_info(vlan_summaries)")]
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 8
