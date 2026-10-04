"""NS-092 accelerated, deterministic caps; elapsed time is informational."""

from dataclasses import asdict, replace
from datetime import timedelta
import json
from time import perf_counter
from uuid import UUID

import pytest

from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incident_timeline import IncidentTimelineQueryService
from netsentinel.domain.connections import ConnectionRoundObservation, ObservationQuality, ProcessIdentity
from netsentinel.domain.incidents import (
    IncidentConnectionRef, IncidentCorrelationStatus as C, IncidentPolicy, IncidentProcessRef,
)
from netsentinel.domain.incident_persistence import (
    MAX_INCIDENT_BYTES, MAX_LINK_BYTES, MAX_REVISION_BYTES, IncidentState, IncidentStatus as S,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
from tests.fixtures.incident_acceptance import all_pages, deny_network, table_state, timeline_input
from tests.fixtures.incidents import NOW, SESSION, DESTINATION, SCOPE, item

pytestmark = pytest.mark.performance


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    deny_network(monkeypatch)


def test_accelerated_incident_soak(tmp_path):
    started = perf_counter()
    policy = IncidentPolicy()
    runtime = IncidentCorrelator(policy)
    # Small PID pool reused with unique create times; unknowns and network scopes
    # share one destination without sharing process/connection evidence.
    max_active = 0
    for n in range(320):
        process = None if n % 5 == 0 else IncidentProcessRef(SESSION,
            ProcessIdentity(n % 4 + 1, NOW - timedelta(seconds=n + 1)))
        seed = item(n + 1, process=process, scope=replace(SCOPE, network_fingerprint=f"{n % 3:064x}"))
        assert runtime.correlate(seed).status is C.NEW_INCIDENT
        d = runtime.diagnostics()
        max_active = max(max_active, d.active_incidents)
        assert d.active_incidents <= policy.max_incidents
        assert d.index_entries <= policy.max_index_entries
    for _ in range(4096):
        assert runtime.correlate(seed).status is C.DUPLICATE
    assert max_active == policy.max_incidents == 256
    assert runtime.diagnostics().evictions == 64
    # One retained incident reaches the actual relation ceiling atomically.
    long_runtime = IncidentCorrelator()
    for n in range(128):
        result = long_runtime.correlate(timeline_input(n))
        assert result.status in (C.NEW_INCIDENT, C.ATTACHED)
    snapshot = result.incident
    assert len(snapshot.relations) == policy.max_relations
    assert long_runtime.correlate(timeline_input(128)).status is C.CAPACITY_LIMITED
    assert len(long_runtime.snapshot()[0].relations) == 128
    db = SQLiteDatabase(tmp_path / "soak.db")
    repository = SQLiteIncidentRepository(db)
    service = IncidentPersistenceService(repository)
    stored = service.create_or_get(snapshot, now=NOW + timedelta(seconds=1)).record
    # Revisions prune at the frozen actual default, while current revision grows.
    for n in range(80):
        result = service.resolve(stored.incident_id, expected_revision=stored.revision,
                                 now=NOW + timedelta(seconds=2 + n))
        stored = result.record
    revision_seed = service.create_or_get(IncidentCorrelator().correlate(item(10000)).incident, now=NOW).record
    for n in range(80):
        stamp = NOW + timedelta(seconds=n + 1)
        if n % 2 == 0:
            changed = service.resolve(revision_seed.incident_id, expected_revision=revision_seed.revision, now=stamp)
        else:
            value = item(10000 + n, stamp=stamp, connection=item(10000).connection)
            changed = service.reopen(revision_seed.incident_id, value, expected_revision=revision_seed.revision, now=stamp)
        assert changed.status is S.CHANGED
        revision_seed = changed.record
    history = repository.history(revision_seed.incident_id, limit=32)
    assert len(history.entries) == repository.policy.max_revisions == 32
    before = table_state(db)
    for _ in range(128):
        assert service.append(stored.incident_id, timeline_input(0), now=NOW + timedelta(days=1)).status is S.NO_CHANGE
    assert table_state(db) == before
    # Fill actual parent quota, using create API to avoid cohort hydration >256.
    protected = []
    for n in range(repository.policy.max_incidents - 2):
        isolated = item(20000 + n, process=None, connection=None)
        record = service.create_or_get(IncidentCorrelator().correlate(isolated).incident, now=NOW).record
        assert record is not None
        if n < 20:
            service.resolve(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=1))
        elif n == 20:
            service.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=1))
            protected.append(record.incident_id)
        else:
            protected.append(record.incident_id)
        assert service.diagnostics()["live_continuity_incidents"] <= repository.policy.max_hydration
    rejected = service.create_or_get(IncidentCorrelator().correlate(item(30000, process=None)).incident, now=NOW)
    assert rejected.status is S.CAPACITY_REACHED
    assert service.observe(item(30001, process=None), now=NOW).status is S.CAPACITY_REACHED  # hydration overflow
    with db.connection() as conn:
        metrics = {
            "persisted_incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "total_revisions": conn.execute("SELECT COUNT(*) FROM incident_revisions").fetchone()[0],
            "logical_refs": conn.execute("SELECT COUNT(*) FROM incident_references").fetchone()[0],
            "max_snapshot_bytes": conn.execute("SELECT MAX(length(CAST(payload AS BLOB))) FROM incidents").fetchone()[0],
            "max_link_bytes": conn.execute("SELECT MAX(length(CAST(payload AS BLOB))) FROM incident_references").fetchone()[0],
            "max_revision_bytes": conn.execute("SELECT MAX(length(CAST(payload AS BLOB))) FROM incident_revisions").fetchone()[0],
            "max_refs_per_incident": conn.execute("SELECT MAX(n) FROM (SELECT COUNT(*) n FROM incident_references GROUP BY incident_id)").fetchone()[0],
            "max_revisions_per_incident": conn.execute("SELECT MAX(n) FROM (SELECT COUNT(*) n FROM incident_revisions GROUP BY incident_id)").fetchone()[0],
        }
    assert metrics["persisted_incidents"] == 1024
    assert metrics["max_snapshot_bytes"] <= MAX_INCIDENT_BYTES
    assert metrics["max_link_bytes"] <= MAX_LINK_BYTES
    assert metrics["max_revision_bytes"] <= MAX_REVISION_BYTES
    assert metrics["max_refs_per_incident"] <= repository.policy.max_links
    assert metrics["max_revisions_per_incident"] == 32
    assert metrics["total_revisions"] <= 1024 * 32
    query = IncidentTimelineQueryService(SQLiteIncidentTimelineRepository(db))
    before = table_state(db)
    rows, pages = all_pages(query, stored.incident_id)
    assert len(rows) == len({r.entry_id for r in rows}) == 257
    assert pages == 11
    assert table_state(db) == before
    restarted = IncidentTimelineQueryService(SQLiteIncidentTimelineRepository(SQLiteDatabase(db.path)))
    assert all_pages(restarted, stored.incident_id)[0] == rows
    # Underlying absent sources remain expired/readable across all selected rows.
    from netsentinel.domain.incident_persistence import IncidentSourceStatus
    expired_count = sum(r.source_status is IncidentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE for r in rows)
    assert expired_count == 256
    deleted = repository.cleanup(NOW + timedelta(hours=1), NOW + timedelta(hours=1))
    assert deleted == repository.policy.cleanup_chunk == 16
    deleted_second = repository.cleanup(NOW + timedelta(hours=1), NOW + timedelta(hours=1))
    assert deleted_second == 5  # remaining resolved parents + long timeline
    with db.connection() as conn:
        remaining = {UUID(r[0]): r[1] for r in conn.execute("SELECT incident_id, state FROM incidents")}
    assert all(remaining[i] in (IncidentState.OPEN.value, IncidentState.ACKNOWLEDGED.value) for i in protected)
    assert repository.get(revision_seed.incident_id).record.state is IncidentState.OPEN
    # Aggregate diagnostics contain numbers only, no refs/IP/path/SQL/provider body.
    diagnostics = asdict(runtime.diagnostics())
    assert all(type(v) is int and 0 <= v <= 2**63 - 1 for v in diagnostics.values())
    assert diagnostics["duplicates"] == 4096 and diagnostics["new_incidents"] == 320
    metrics.update(synthetic_inputs=320 + 4096 + 129 + 128 + 1022 + 80 + 80 + 4,
                   duplicate_inputs=4096 + 128 + 79, logical_incidents_created=320 + 1024,
                   max_active=max_active, max_relations=128, max_hydration=service.diagnostics()["live_continuity_incidents"],
                   timeline_rows=len(rows), pages=pages, source_expired_rows=expired_count,
                   evictions=64, cleanup=deleted + deleted_second, capacity_rejections=3,
                   runtime_diagnostics=diagnostics, elapsed_seconds=round(perf_counter() - started, 3))
    print("NS092_SOAK " + json.dumps(metrics, sort_keys=True))


def test_global_index_gap_and_reference_storm_bounds():
    runtime = IncidentCorrelator()
    max_indexes, limited = 0, 0
    # Evidence storms reach the global index ceiling, not only parent eviction.
    for group in range(256):
        connection = IncidentConnectionRef(SESSION, UUID(int=group + 1))
        for n in range(64):
            result = runtime.correlate(item(group * 64 + n + 1, connection=connection, process=None))
            limited += result.status is C.CAPACITY_LIMITED
            d = runtime.diagnostics()
            max_indexes = max(max_indexes, d.index_entries)
            assert d.index_entries <= runtime.policy.max_index_entries
            assert d.active_incidents <= runtime.policy.max_incidents
        if limited:
            break
    assert limited and max_indexes >= runtime.policy.max_index_entries - 2
    max_keys = max(len(state.keys) for state in runtime._states.values())
    assert max_keys <= runtime.policy.max_keys_per_incident
    for n in range(257):
        runtime.observe_round(ConnectionRoundObservation(SESSION, NOW + timedelta(microseconds=n), ObservationQuality.REDUCED))
        assert runtime.diagnostics().gap_markers <= runtime.policy.max_gaps
    assert runtime.diagnostics().gap_markers == 256
    assert not runtime.observe_round(ConnectionRoundObservation(SESSION, NOW + timedelta(seconds=1), ObservationQuality.REDUCED))
    # Moving event time beyond the actual retention horizon removes every old
    # membership/marker. Expiry does not resolve or inflate risk.
    created = runtime.correlate(item(99999, stamp=NOW + timedelta(minutes=21),
                                    process=None, connection=None, destination=None))
    assert created.status is C.NEW_INCIDENT
    final = runtime.diagnostics()
    assert final.active_incidents == 1 and final.gap_markers == 0
    assert final.index_entries == 2 and len(runtime._observations) == 1
    assert final.expired > 0
    print("NS092_INDEX " + json.dumps({"max_index_entries": max_indexes, "max_keys_per_incident": max_keys,
                                      "gap_markers": 256, "capacity_limited": final.capacity_limited,
                                      "expired_incidents": final.expired}))


@pytest.mark.parametrize("field,maximum", [("evidence", 64), ("connections", 32), ("processes", 16), ("destinations", 32), ("scopes", 16), ("assessments", 16), ("alerts", 16)])
def test_per_incident_reference_caps_are_atomic(tmp_path, field, maximum):
    from netsentinel.domain.alert_risk import AlertAssessmentReference
    correlator = IncidentCorrelator()
    seed = item()
    values = []
    for n in range(maximum + 1):
        value = timeline_input(n, seed.connection)
        if field == "evidence":
            value = item(n + 1, connection=seed.connection)
        elif field == "connections":
            value = item(1, stamp=NOW + timedelta(microseconds=n), connection=IncidentConnectionRef(SESSION, UUID(int=n + 1)))
        elif field == "processes":
            value = replace(value, process=IncidentProcessRef(SESSION, ProcessIdentity(n + 1, NOW)))
        elif field == "destinations":
            value = replace(value, destination=replace(DESTINATION, port=n))
        elif field == "scopes":
            value = replace(value, scope=replace(SCOPE, network_fingerprint=f"{n:064x}"))
        elif field == "assessments":
            value = replace(value, assessment=AlertAssessmentReference(f"{n:064x}", 1, SCOPE.network_status))
        else:
            value = replace(value, alert_id=UUID(int=n + 1))
        values.append(value)
        result = correlator.correlate(value)
        if n < maximum:
            assert result.status in (C.NEW_INCIDENT, C.ATTACHED)
        else:
            assert result.status is C.CAPACITY_LIMITED
    snapshot = correlator.snapshot()[0]
    assert len(getattr(snapshot, field)) == maximum
    # The durable adapter uses the same correlation policy and rejects atomically.
    service = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(tmp_path / f"{field}.db")))
    record = service.create_or_get(snapshot, now=NOW + timedelta(seconds=1)).record
    before = service.get(record.incident_id).record
    assert service.append(record.incident_id, values[-1], now=NOW + timedelta(seconds=2)).status is S.CAPACITY_REACHED
    assert service.get(record.incident_id).record == before
