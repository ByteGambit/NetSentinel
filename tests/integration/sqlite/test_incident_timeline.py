"""NS-091 batch query count, coherent snapshots, exact assessment and read purity."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.services.incident_timeline import TimelineRequest, TimelineKind, TimelineStatus
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incidents import IncidentObservationRef, IncidentObservationKind
from netsentinel.domain.incident_persistence import IncidentSourceStatus as Source, IncidentStatus as Status
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
from netsentinel.application.services.incidents import IncidentCorrelator
from tests.fixtures.incident_timeline import story
from tests.fixtures.incidents import NOW, item
from tests.fixtures.risk_assessments import key, snapshot, evidence


def state(db):
    with db.connection() as connection:
        return tuple(tuple(tuple(r) for r in connection.execute(f"SELECT * FROM {table} ORDER BY 1,2")) for table in
            ("incidents", "incident_references", "incident_revisions", "alerts", "risk_assessments", "risk_assessment_revisions"))


def trace(db, monkeypatch):
    statements = []
    original = db.connection
    @contextmanager
    def connection():
        with original() as conn:
            conn.set_trace_callback(statements.append)
            yield conn
    monkeypatch.setattr(db, "connection", connection)
    return statements


@pytest.mark.parametrize("count", [1, 25, 128])
def test_source_queries_are_batched_not_one_per_row(tmp_path, monkeypatch, count):
    db, _, record, repository, query = story(tmp_path, count)
    statements = trace(db, monkeypatch)
    result = query.lookup(TimelineRequest(record.incident_id))
    assert result.status is TimelineStatus.FOUND
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 5  # parent, reference integrity, latest revision, batch connection, history
    assert sum("FROM connection_history" in s for s in selects) == 1
    assert sum("BEGIN" in s for s in statements) == 1


def test_reads_are_pure_restart_safe_and_schema_020(tmp_path):
    db, writer, record, repository, query = story(tmp_path)
    writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(minutes=1))
    before = state(db)
    list_page = query.lookup(TimelineRequest())
    page = query.lookup(TimelineRequest(record.incident_id))
    assert state(db) == before
    assert list_page.entries[0].record == page.record
    restarted = SQLiteIncidentTimelineRepository(db).read_snapshot(record.incident_id)
    assert restarted.incident.record == page.record
    from netsentinel.infrastructure.sqlite.migrations import builtin_migrations
    assert builtin_migrations()[-1].version == 20


@pytest.mark.parametrize("mode", ["available", "expired", "corrupt", "unsupported", "bad_scope"])
def test_exact_assessment_time_and_degraded_source_are_not_whole_page_failures(tmp_path, mode):
    db, writer, record, repository, query = story(tmp_path)
    k = key(original_observed_at=NOW)
    saved = SQLiteAssessmentRepository(db).save(k, snapshot(), NOW + timedelta(hours=1)).revision
    # Later revision must not replace the exact incident pointer.
    SQLiteAssessmentRepository(db).save(k, snapshot(evidence(result_code="other")), NOW + timedelta(hours=2))
    ref = AlertAssessmentReference(k.assessment_id, saved.revision, None)
    if mode == "bad_scope":
        from netsentinel.domain.connections import NetworkScopeStatus
        ref = replace(ref, network_status=NetworkScopeStatus.RESOLVED)
    value = replace(item(2, stamp=NOW, assessment=ref, scope=record.snapshot.scopes[0] if mode == "bad_scope" else k.scope, connection=record.snapshot.connections[0]), observation=IncidentObservationRef(
        IncidentObservationKind.ASSESSMENT_PRODUCED, ref, NOW))
    record = writer.append(record.incident_id, value, now=NOW + timedelta(seconds=2)).record
    if mode != "available" and mode != "bad_scope":
        with db.connection() as connection:
            if mode == "expired":
                connection.execute("DELETE FROM risk_assessment_revisions WHERE assessment_id = ? AND revision = 1", (k.assessment_id,))
            elif mode == "corrupt":
                connection.execute("UPDATE risk_assessment_revisions SET snapshot = 'invalid' WHERE assessment_id = ? AND revision = 1", (k.assessment_id,))
            else:
                connection.execute("UPDATE risk_assessment_revisions SET format_version = 99 WHERE assessment_id = ? AND revision = 1", (k.assessment_id,))
            connection.commit()
    page = query.lookup(TimelineRequest(record.incident_id))
    assert page.status is TimelineStatus.FOUND
    e = next(e for e in page.entries if e.kind is TimelineKind.ASSESSMENT)
    assert e.observation_time == NOW
    expected = {"available": Source.AVAILABLE, "expired": Source.SOURCE_EXPIRED_OR_UNAVAILABLE,
                "corrupt": Source.CORRUPT, "unsupported": Source.UNSUPPORTED_VERSION, "bad_scope": Source.CORRUPT}[mode]
    assert e.source_status is expected
    if mode == "available":
        assert e.assessment_time == NOW + timedelta(hours=1)
        assert e.revision == 1
    else:
        assert e.assessment_time is None
        assert "unknown" in e.time_semantics
    assert len(page.entries) >= 7


def test_list_keyset_uses_total_uuid_order_and_survives_bad_record(tmp_path):
    db, writer, first, repository, query = story(tmp_path)
    for n in range(2, 9):
        value = item(n, process=None, connection=None, destination=None)
        writer.create_or_get(IncidentCorrelator().correlate(value).incident, now=NOW)
    before = state(db)
    entries = []
    cursor = None
    while True:
        page = query.lookup(TimelineRequest(after_id=cursor, limit=3))
        entries.extend(page.entries)
        if not page.has_more:
            break
        cursor = page.after_id
    ids = [str(e.record.incident_id) for e in entries]
    assert ids == sorted(ids) and len(ids) == len(set(ids)) == 8
    assert state(db) == before
    with db.connection() as connection:
        connection.execute("UPDATE incidents SET payload = 'broken' WHERE incident_id = ?", (str(first.incident_id),))
        connection.commit()
    page = query.lookup(TimelineRequest(limit=100))
    assert len(page.entries) == 8
    assert sum(e.status is Status.CORRUPT for e in page.entries) == 1


def test_duplicate_append_has_one_story_and_unchanged_cursor(tmp_path):
    db, writer, record, repository, query = story(tmp_path)
    value = item(stamp=NOW)
    record = writer.create_or_get(IncidentCorrelator().correlate(value).incident, now=NOW).record
    before = query.lookup(TimelineRequest(record.incident_id, limit=1))
    result = writer.append(record.incident_id, value, now=NOW + timedelta(days=1))
    assert result.status is Status.NO_CHANGE
    assert query.lookup(TimelineRequest(record.incident_id, limit=1)) == before


def test_missing_action_history_is_partial_degradation(tmp_path):
    db, writer, record, repository, query = story(tmp_path)
    record = writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2)).record
    # Corrupt older history, preserve current record's integrity witness.
    with db.connection() as connection:
        connection.execute("UPDATE incident_revisions SET payload = 'broken' WHERE incident_id = ? AND revision = 1", (str(record.incident_id),))
        connection.commit()
    page = query.lookup(TimelineRequest(record.incident_id))
    assert page.status is TimelineStatus.FOUND
    assert "corrupt" in " ".join(page.limitations)
    assert len(page.entries) == 6
