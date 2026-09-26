"""NS-044 SQLite aggregate round-trip and deterministic capacity."""

from __future__ import annotations

from datetime import timedelta

from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
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
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 8


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
