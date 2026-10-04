"""NS-092 persisted real story and long timeline, offscreen worker acceptance."""

from datetime import timedelta
from threading import Event, current_thread

import pytest

from netsentinel.application.services.incident_timeline import MAX_LOADED_ROWS, TimelineKind, TimelineRequest
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.incident_persistence import IncidentSourceStatus
from netsentinel.presentation.incident_query import IncidentQueryCoordinator
from netsentinel.presentation.views.incidents import IncidentsView
from tests.fixtures.incident_acceptance import Story, all_pages, deny_network, table_state, timeline_input
from tests.fixtures.incidents import NOW, item


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    deny_network(monkeypatch)


def open_view(qtbot, story, detail_factory=None):
    queries = (IncidentQueryCoordinator(lambda: story.query),
               IncidentQueryCoordinator(detail_factory or (lambda: story.query)))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        assert query.start()
    widget.show()
    qtbot.waitUntil(lambda: widget.model.rowCount() > 0)
    return widget, queries


def test_persisted_incident_story_open_page_after_restart_is_read_only(qtbot, tmp_path):
    story = Story(tmp_path / "gui.db").build()
    record = story.incidents.acknowledge(story.record.incident_id, expected_revision=story.record.revision,
                                       now=NOW + timedelta(seconds=3)).record
    with story.db.connection() as conn:
        conn.execute("DELETE FROM connection_history")
    restarted = story.restart()
    expected, _ = all_pages(restarted.query, record.incident_id)
    before = table_state(restarted.db)
    widget, queries = open_view(qtbot, restarted)
    try:
        assert widget.model.rowCount() == 2  # risk story + independent DNS context
        widget.select_incident(record.incident_id)
        qtbot.waitUntil(lambda: not widget._detail_loading)
        assert widget.timeline_model.entries == expected
        assert {r.kind for r in expected} == set(TimelineKind)
        text = widget.summary.toPlainText()
        assert str(record.incident_id) in text and "acknowledged" in text
        assert "Process observed" in text
        assert "Process created" not in text and "Process started" not in text
        assert "does not prove causality" in widget.help.text()
        expired_row = next(i for i, r in enumerate(expected) if r.source_status is IncidentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE)
        widget.timeline.selectRow(expired_row)
        assert "no longer retained or available" in widget.row_detail.toPlainText()
        unresolved = next(i for i, r in enumerate(expected) if r.source_status is IncidentSourceStatus.UNRESOLVED)
        widget.timeline.selectRow(unresolved)
        assert "could not be resolved" in widget.row_detail.toPlainText()
        assert table_state(restarted.db) == before
        widget.refresh_detail()
        qtbot.waitUntil(lambda: not widget._detail_loading)
        assert widget.timeline_model.entries == expected
        assert table_state(restarted.db) == before
    finally:
        for query in queries:
            assert query.stop()


def test_real_story_equal_time_paging_and_restart_has_total_order(tmp_path):
    story = Story(tmp_path / "equal.db").build()
    # Observation/inference share NOW; assessment/action share the exact later
    # timestamp, crossing small page boundaries rather than SQL natural order.
    record = story.incidents.acknowledge(story.record.incident_id, expected_revision=story.record.revision,
                                       now=story.result.assessment.revision.assessed_at).record
    rows, _ = all_pages(story.query, record.incident_id, 1)
    assert rows == tuple(sorted(rows, key=lambda r: r.sort_key))
    assert len(rows) == len({r.entry_id for r in rows})
    for size in (2, 3, 5, 25, 100):
        assert all_pages(story.restart().query, record.incident_id, size)[0] == rows
    at_assessment = [r.kind for r in rows if r.primary_time == record.acknowledged_at]
    assert at_assessment == [TimelineKind.ASSESSMENT, TimelineKind.USER_ACTION]


def test_long_persisted_timeline_ui_cap_query_bound_and_read_purity(qtbot, tmp_path, monkeypatch):
    from contextlib import contextmanager
    story = Story(tmp_path / "long.db")
    correlator = IncidentCorrelator()
    for n in range(128):
        snapshot = correlator.correlate(timeline_input(n)).incident
    record = story.incidents.create_or_get(snapshot, now=NOW + timedelta(seconds=1)).record
    story.incidents.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2))
    # Source states are batch-resolved: five SELECTs regardless of timeline size.
    original = story.db.connection
    statements: list[str] = []
    threads: list[str] = []
    @contextmanager
    def traced():
        with original() as conn:
            threads.append(current_thread().name)
            conn.set_trace_callback(statements.append)
            yield conn
    before = table_state(story.db)
    widget, queries = open_view(qtbot, story)
    try:
        widget.select_incident(record.incident_id)
        qtbot.waitUntil(lambda: not widget._detail_loading)
        monkeypatch.setattr(story.db, "connection", traced)
        widget.refresh_detail()
        qtbot.waitUntil(lambda: not widget._detail_loading)
        pages = 1
        while widget.more_button.isEnabled():
            widget.load_more()
            qtbot.waitUntil(lambda: not widget._detail_loading)
            pages += 1
            assert widget.timeline_model.rowCount() <= MAX_LOADED_ROWS
        entries = widget.timeline_model.entries
        assert len(entries) == len({e.entry_id for e in entries}) == 256
        assert entries == tuple(sorted(entries, key=lambda e: e.sort_key))
        assert "Display limit reached" in widget.detail_state.text()
        selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
        assert len(selects) == pages * 5
        assert set(threads) == {"netsentinel-incident-query"}
        monkeypatch.setattr(story.db, "connection", original)
        assert table_state(story.db) == before
        print(f"NS092_GUI loaded_rows={len(entries)} pages={pages} selects={len(selects)}")
    finally:
        for query in queries:
            assert query.stop()


@pytest.mark.parametrize("operation", ["switch", "cancel", "destroy"])
def test_long_page_cancellation_and_latest_slot_cannot_overwrite_selection(qtbot, tmp_path, operation):
    story = Story(tmp_path / "cancel.db")
    correlator = IncidentCorrelator()
    for n in range(128):
        snapshot = correlator.correlate(timeline_input(n)).incident
    a = story.incidents.create_or_get(snapshot, now=NOW + timedelta(seconds=1)).record
    b = story.incidents.create_or_get(IncidentCorrelator().correlate(item(999, process=None, connection=None)).incident, now=NOW).record
    entered, release = Event(), Event()
    calls = []
    class BlockPage:
        def lookup(self, request):
            calls.append(request)
            if request.cursor is not None:
                entered.set()
                assert release.wait(5)
            return story.query.lookup(request)
    widget, queries = open_view(qtbot, story, lambda: BlockPage())
    try:
        widget.select_incident(a.incident_id)
        qtbot.waitUntil(lambda: not widget._detail_loading)
        widget.load_more()
        qtbot.waitUntil(entered.is_set)
        # While one real page read is blocked, requests coalesce to one slot.
        for _ in range(1000):
            queries[1].request(TimelineRequest(b.incident_id))
        with queries[1]._condition:
            assert queries[1]._pending is not None
            assert queries[1]._pending[1].incident_id == b.incident_id
        if operation == "switch":
            widget.select_incident(b.incident_id)
        else:
            widget.cancel()
            if operation == "destroy":
                widget.deleteLater()
        release.set()
        if operation == "switch":
            qtbot.waitUntil(lambda: not widget._detail_loading)
            assert widget.selected_incident_id == b.incident_id
            assert widget.timeline_model.rowCount() == 2
            assert str(b.incident_id) in widget.summary.toPlainText()
        elif operation == "cancel":
            assert queries[1].stop()
            assert widget.timeline_model.rowCount() == 25
        assert len(calls) <= 3  # first page, active second page, latest B
    finally:
        release.set()
        for query in queries:
            assert query.stop()
