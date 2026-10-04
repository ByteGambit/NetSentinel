"""NS-091 offscreen paging, plain text, generation/cancel and shutdown tests."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from threading import Event, current_thread
from time import monotonic
from uuid import UUID

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QPushButton

from netsentinel.application.services.incident_timeline import (
    TimelineRequest, TimelineKind, TimelineStatus,
    TimelinePage, MAX_LOADED_ROWS, SOURCE_TEXT,
)
from netsentinel.domain.incident_persistence import IncidentPage, IncidentResult, IncidentState, IncidentStatus, IncidentSourceStatus
from netsentinel.presentation.app import create_application
from netsentinel.presentation.incident_query import IncidentQueryCoordinator
from netsentinel.presentation.models.incidents import IncidentTableModel, TimelineTableModel
from netsentinel.presentation.views.incidents import IncidentsView
from netsentinel.presentation.views.main_window import PageId, PAGE_ORDER
from tests.fixtures.incident_timeline import story
from tests.fixtures.incidents import NOW
from tests.gui.test_connections_view import FakeEngine


@pytest.fixture
def view(qtbot, tmp_path):
    db, writer, record, repository, service = story(tmp_path)
    queries = (IncidentQueryCoordinator(lambda: service), IncidentQueryCoordinator(lambda: service))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        query.start()
    widget.show()
    qtbot.waitUntil(lambda: widget.model.rowCount() == 1)
    yield widget, record, writer, service
    for query in queries:
        assert query.stop()


def select(qtbot, widget, incident_id):
    widget.select_incident(incident_id)
    qtbot.waitUntil(lambda: widget.timeline_model.rowCount() > 0)


def test_page_load_select_keyboard_plain_text_and_accessibility(qtbot, view):
    widget, record, _, _ = view
    widget.table.setFocus()
    qtbot.keyClick(widget.table, Qt.Key.Key_Down)
    qtbot.waitUntil(lambda: widget.timeline_model.rowCount() == 6)
    assert widget.selected_incident_id == record.incident_id
    text = widget.summary.toPlainText()
    assert str(record.incident_id) in text
    assert "First observed (local)" in text and "Last observed (local)" in text
    assert "Incident state: open" in text
    assert "Process observed" in text
    assert "name unavailable" in text
    assert "Process created" not in text and "Process started" not in text
    widget.timeline.setFocus()
    qtbot.keyClick(widget.timeline, Qt.Key.Key_Down)
    assert "Observation time:" in widget.row_detail.toPlainText()
    assert "Assessment time: Unknown" in widget.row_detail.toPlainText()
    for control in (widget.table, widget.timeline, widget.more_button, widget.refresh_button, widget.summary, widget.row_detail):
        assert control.accessibleName()
    assert widget.summary.isReadOnly() and widget.row_detail.isReadOnly()
    assert widget.help.textFormat() is Qt.TextFormat.PlainText
    assert "does not prove causality" in widget.help.text()
    assert not widget.timeline.isSortingEnabled()


@pytest.mark.parametrize("column", range(5))
@pytest.mark.parametrize("role", [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole, Qt.ItemDataRole.AccessibleDescriptionRole, Qt.ItemDataRole.ToolTipRole])
def test_every_timeline_column_has_text_semantics(qtbot, view, column, role):
    widget, record, _, _ = view
    select(qtbot, widget, record.incident_id)
    assert widget.timeline_model.data(widget.timeline_model.index(0, column), role)


@pytest.mark.parametrize("column", range(6))
@pytest.mark.parametrize("role", [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole, Qt.ItemDataRole.AccessibleDescriptionRole])
def test_every_list_column_has_text_semantics(view, column, role):
    widget, _, _, _ = view
    assert widget.model.data(widget.model.index(0, column), role)


@pytest.mark.parametrize("state", list(IncidentState))
def test_lifecycle_state_and_times_are_separate(qtbot, view, state):
    widget, record, writer, _ = view
    if state is IncidentState.ACKNOWLEDGED:
        record = writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(minutes=1)).record
    if state is IncidentState.RESOLVED:
        record = writer.resolve(record.incident_id, expected_revision=1, now=NOW + timedelta(minutes=2)).record
    select(qtbot, widget, record.incident_id)
    widget.refresh_detail()
    qtbot.waitUntil(lambda: not widget._detail_loading)
    text = widget.summary.toPlainText()
    assert "Incident state: " + state.value in text
    assert "incident revision: " + str(record.revision) in text
    assert widget.timeline_model.entries[0].observation_time == NOW
    actions = [e for e in widget.timeline_model.entries if e.kind is TimelineKind.USER_ACTION]
    if state is not IncidentState.OPEN:
        assert len(actions) == 1
        assert actions[0].action_time > record.snapshot.last_observed_at


@pytest.mark.parametrize("source", list(IncidentSourceStatus))
def test_source_status_and_html_like_snapshot_text_remain_plain(qtbot, view, source):
    widget, record, _, query = view
    page = query.lookup(TimelineRequest(record.incident_id))
    entry = replace(page.entries[0], source_status=source, explanation="<b>untrusted</b> & process",
                    title="Connection observed <script>")
    page = replace(page, entries=(entry,), context=("<b>snapshot remains</b>",))
    widget._selected_id = record.incident_id
    widget._detail_generation = 9
    widget._detail_ready(9, page)
    widget.timeline.selectRow(0)
    assert SOURCE_TEXT[source] in widget.row_detail.toPlainText()
    assert "<b>untrusted</b>" in widget.row_detail.toPlainText()
    assert "<b>snapshot remains</b>" in widget.summary.toPlainText()
    assert widget.timeline_model.data(widget.timeline_model.index(0, 4)) == SOURCE_TEXT[source]


def test_offscreen_long_timeline_loads_to_explicit_memory_cap(qtbot, tmp_path):
    _, writer, record, _, service = story(tmp_path, 128)
    writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2))
    queries = tuple(IncidentQueryCoordinator(lambda: service) for _ in range(2))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        query.start()
    try:
        widget.show()
        select(qtbot, widget, record.incident_id)
        while widget.more_button.isEnabled():
            count = widget.timeline_model.rowCount()
            widget.load_more()
            qtbot.waitUntil(lambda: not widget._detail_loading, timeout=10000)
            assert widget.timeline_model.rowCount() > count
        entries = widget.timeline_model.entries
        assert len(entries) == MAX_LOADED_ROWS
        assert len({e.entry_id for e in entries}) == MAX_LOADED_ROWS
        assert entries == tuple(sorted(entries, key=lambda e: e.sort_key))
        assert "Display limit reached" in widget.detail_state.text()
        assert not widget.more_button.isEnabled()
        widget.timeline.scrollToBottom()
        assert len(widget.timeline.findChildren(QPushButton)) == 0
        widget.refresh_detail()
        qtbot.waitUntil(lambda: not widget._detail_loading, timeout=10000)
        assert widget.timeline_model.rowCount() == 25
    finally:
        for query in queries:
            assert query.stop()


class BlockingService:
    def __init__(self, service):
        self.service = service
        self.started, self.release, self.finished = Event(), Event(), Event()
        self.calls = []
        self.block = True

    def lookup(self, request):
        self.calls.append((request, current_thread().name))
        if self.block:
            self.started.set()
            self.release.wait(10)
            self.block = False
        result = self.service.lookup(request)
        self.finished.set()
        return result


@pytest.mark.parametrize("sequence", ["a_b", "a_b_a", "cancel", "hide", "refresh", "page_switch"])
def test_selection_cancel_refresh_discards_late_results(qtbot, tmp_path, sequence):
    _, _, record, _, service = story(tmp_path, 20)
    blocked = BlockingService(service)
    query = IncidentQueryCoordinator(lambda: blocked)
    list_query = IncidentQueryCoordinator(lambda: service)
    widget = IncidentsView(queries=(list_query, query))
    qtbot.addWidget(widget)
    query.start()
    list_query.start()
    try:
        widget.select_incident(record.incident_id)
        qtbot.waitUntil(blocked.started.is_set)
        first_generation = widget._detail_generation
        old = service.lookup(TimelineRequest(record.incident_id))
        if sequence in ("a_b", "a_b_a", "page_switch"):
            widget.select_incident(UUID(int=999))
            if sequence == "a_b_a":
                widget.select_incident(record.incident_id)
        elif sequence == "cancel":
            widget.cancel()
        elif sequence == "hide":
            widget.cancel()  # hideEvent applies this exact invalidation path
        else:
            widget.refresh_detail()
        widget._detail_ready(first_generation, old)  # queued old signal also guarded in GUI
        assert widget.timeline_model.rowCount() == 0
        blocked.release.set()
        qtbot.waitUntil(blocked.finished.is_set)
        if sequence in ("a_b", "page_switch"):
            qtbot.waitUntil(lambda: "unavailable" in widget.detail_state.text().lower())
            assert widget.selected_incident_id == UUID(int=999)
            assert widget.timeline_model.rowCount() == 0
        elif sequence in ("a_b_a", "refresh"):
            qtbot.waitUntil(lambda: widget.timeline_model.rowCount() == 25)
            assert widget.selected_incident_id == record.incident_id
            assert len(blocked.calls) == 2
        else:
            QApplication.processEvents()
            assert widget.timeline_model.rowCount() == 0
        assert all(name == "netsentinel-incident-query" for _, name in blocked.calls)
    finally:
        blocked.release.set()
        assert query.stop()
        assert list_query.stop()


def test_worker_factory_and_db_reads_off_gui_signal_delivery_on_gui(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path)
    owners, delivered = [], []
    def factory():
        owners.append(current_thread().name)
        return service
    query = IncidentQueryCoordinator(factory)
    query.result_ready.connect(lambda g, result: delivered.append((g, current_thread().name)))
    query.start()
    try:
        generation = query.request(TimelineRequest(record.incident_id))
        qtbot.waitUntil(lambda: bool(delivered))
        assert owners == ["netsentinel-incident-query"]
        assert delivered == [(generation, current_thread().name)]
    finally:
        assert query.stop()


def test_shutdown_is_bounded_pending_dropped_no_destroyed_widget_callback(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path)
    blocked = BlockingService(service)
    query = IncidentQueryCoordinator(lambda: blocked)
    delivered = []
    query.result_ready.connect(lambda *args: delivered.append(args))
    query.start()
    query.request(TimelineRequest(record.incident_id))
    qtbot.waitUntil(blocked.started.is_set)
    query.request(TimelineRequest(UUID(int=999)))
    start = monotonic()
    assert not query.stop(timeout=0.01)
    assert monotonic() - start < 0.5
    blocked.release.set()
    assert query.stop(timeout=2)
    QApplication.processEvents()
    assert not delivered
    assert len(blocked.calls) == 1
    with pytest.raises(RuntimeError):
        query.request(TimelineRequest(record.incident_id))


def test_empty_unavailable_and_partial_failure_keep_page_usable(qtbot):
    widget = IncidentsView()
    qtbot.addWidget(widget)
    assert "unavailable" in widget.state.text().lower()
    widget._list_generation = 1
    widget._list_ready(1, IncidentPage(()))
    assert widget.state.text() == "No incidents yet."
    widget._list_ready(1, IncidentPage((IncidentResult(IncidentStatus.CORRUPT),)))
    assert widget.model.rowCount() == 1
    assert "corrupt" in widget.model.data(widget.model.index(0, 1))
    widget._detail_generation = 2
    widget._detail_ready(2, TimelinePage(TimelineStatus.UNAVAILABLE, message="Incident timeline unavailable."))
    assert widget.model.rowCount() == 1
    assert "unavailable" in widget.detail_state.text()


def test_navigation_and_application_lifecycle_compose_incident_workers(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path)
    shell = create_application(FakeEngine(), [], incident_service_factory=lambda: service)
    qtbot.addWidget(shell.window)
    assert PageId.INCIDENTS in PAGE_ORDER
    shell.lifecycle.start()
    try:
        shell.window.show()
        shell.window.navigate_to(PageId.INCIDENTS)
        widget = shell.window.page_widget(PageId.INCIDENTS)
        qtbot.waitUntil(lambda: widget.model.rowCount() == 1)
        assert shell.window.current_page is PageId.INCIDENTS
        for page in (PageId.ALERTS, PageId.CONNECTIONS, PageId.HISTORY, PageId.INCIDENTS):
            shell.window.navigate_to(page)
            assert shell.window.current_page is page
        assert shell.incident_queries
    finally:
        assert shell.lifecycle.shutdown()
    assert not widget.refresh_button.isEnabled()


def test_models_hard_limits_and_structural_local_read_only_boundary(qtbot):
    model, timeline = IncidentTableModel(), TimelineTableModel()
    with pytest.raises(ValueError):
        model.set_entries([None] * 101)
    with pytest.raises(ValueError):
        timeline.set_entries([None] * (MAX_LOADED_ROWS + 1))
    for name in ("presentation/views/incidents.py", "presentation/models/incidents.py", "presentation/incident_query.py", "application/services/incident_timeline.py"):
        source = (Path("src/netsentinel") / name).read_text(encoding="utf-8")
        assert "import sqlite3" not in source
        assert "Process created" not in source and "Process started" not in source
        assert "requests." not in source and "urllib" not in source
    assert "acknowledge(" not in Path("src/netsentinel/presentation/views/incidents.py").read_text(encoding="utf-8")


def test_changed_revision_during_load_more_keeps_previous_page_and_requests_refresh(qtbot, tmp_path):
    _, writer, record, _, service = story(tmp_path, 20)
    queries = tuple(IncidentQueryCoordinator(lambda: service) for _ in range(2))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        query.start()
    try:
        select(qtbot, widget, record.incident_id)
        original = widget.timeline_model.entries
        writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2))
        widget.load_more()
        qtbot.waitUntil(lambda: not widget._detail_loading)
        assert "updated" in widget.detail_state.text()
        assert widget.timeline_model.entries == original
        assert not widget.more_button.isEnabled()
        widget.refresh_detail()
        qtbot.waitUntil(lambda: not widget._detail_loading)
        assert "incident revision: 2" in widget.summary.toPlainText()
    finally:
        for query in queries:
            query.stop()


def test_pending_second_page_cancelled_on_incident_switch(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path, 20)
    blocked = BlockingService(service)
    blocked.block = False
    queries = (IncidentQueryCoordinator(lambda: service), IncidentQueryCoordinator(lambda: blocked))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        query.start()
    try:
        select(qtbot, widget, record.incident_id)
        blocked.block = True
        blocked.finished.clear()
        widget.load_more()
        qtbot.waitUntil(blocked.started.is_set)
        widget.select_incident(UUID(int=999))
        assert not widget.timeline_model.entries
        blocked.release.set()
        qtbot.waitUntil(lambda: not widget._detail_loading)
        assert not widget.timeline_model.entries
        assert widget.selected_incident_id == UUID(int=999)
        assert "unavailable" in widget.detail_state.text().lower()
    finally:
        blocked.release.set()
        for query in queries:
            query.stop()


def test_worker_pending_slot_coalesces_storm_and_factory_failure_is_sanitized(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path)
    blocked = BlockingService(service)
    query = IncidentQueryCoordinator(lambda: blocked)
    results = []
    query.result_ready.connect(lambda *args: results.append(args))
    query.start()
    try:
        query.request(TimelineRequest(record.incident_id))
        qtbot.waitUntil(blocked.started.is_set)
        for _ in range(100):
            generation = query.request(TimelineRequest(record.incident_id))
        blocked.release.set()
        qtbot.waitUntil(lambda: bool(results))
        assert results[0][0] == generation
        assert len(blocked.calls) == 2
    finally:
        blocked.release.set()
        query.stop()
    def broken():
        raise RuntimeError("secret sqlite/path")
    failed = IncidentQueryCoordinator(broken)
    failures = []
    failed.query_failed.connect(failures.append)
    failed.start()
    try:
        generation = failed.request(TimelineRequest(record.incident_id))
        qtbot.waitUntil(lambda: bool(failures))
        assert failures == [generation]
    finally:
        failed.stop()


def test_deleted_view_has_no_late_callback(qtbot, tmp_path):
    _, _, record, _, service = story(tmp_path)
    blocked = BlockingService(service)
    queries = (IncidentQueryCoordinator(lambda: service), IncidentQueryCoordinator(lambda: blocked))
    widget = IncidentsView(queries=queries)
    for query in queries:
        query.start()
    widget.select_incident(record.incident_id)
    qtbot.waitUntil(blocked.started.is_set)
    widget.deleteLater()
    qtbot.waitUntil(lambda: __import__('PyQt6.sip', fromlist=['isdeleted']).isdeleted(widget))
    blocked.release.set()
    for query in queries:
        assert query.stop()
    QApplication.processEvents()  # No Qt exception or callback into the destroyed page.


def test_list_next_previous_and_refresh_preserve_stable_selection(qtbot, tmp_path):
    _, writer, record, _, service = story(tmp_path)
    from netsentinel.application.services.incidents import IncidentCorrelator
    from tests.fixtures.incidents import item
    for n in range(2, 31):
        writer.create_or_get(IncidentCorrelator().correlate(item(n, process=None, connection=None, destination=None)).incident, now=NOW)
    queries = tuple(IncidentQueryCoordinator(lambda: service) for _ in range(2))
    widget = IncidentsView(queries=queries)
    qtbot.addWidget(widget)
    for query in queries:
        query.start()
    try:
        widget.show()
        qtbot.waitUntil(lambda: not widget._list_loading)
        assert widget.model.rowCount() == 25
        first = widget.model.entries
        selected = first[0].record.incident_id
        select(qtbot, widget, selected)
        widget.refresh()
        qtbot.waitUntil(lambda: not widget._list_loading and not widget._detail_loading)
        assert widget.selected_incident_id == selected
        widget.next_page()
        qtbot.waitUntil(lambda: not widget._list_loading)
        assert widget.model.rowCount() == 5
        assert not set(e.record.incident_id for e in first).intersection(e.record.incident_id for e in widget.model.entries)
        widget.previous_page()
        qtbot.waitUntil(lambda: not widget._list_loading)
        assert widget.model.entries == first
    finally:
        for query in queries:
            query.stop()


def test_assessment_selection_lazily_reuses_exact_ns083_explanation(qtbot, tmp_path):
    from netsentinel.domain.alert_risk import AlertAssessmentReference
    from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
    from netsentinel.application.services.risk_explanation import RiskExplanationQueryService
    from netsentinel.presentation.risk_query import RiskQueryCoordinator
    from tests.fixtures.risk_assessments import key, snapshot
    from tests.fixtures.incidents import item
    db, writer, record, _, service = story(tmp_path)
    k = key(original_observed_at=NOW)
    saved = SQLiteAssessmentRepository(db).save(k, snapshot(), NOW + timedelta(hours=1)).revision
    ref = AlertAssessmentReference(k.assessment_id, saved.revision, None)
    value = item(2, stamp=NOW, scope=k.scope, connection=record.snapshot.connections[0], assessment=ref)
    record = writer.append(record.incident_id, value, now=NOW + timedelta(seconds=2)).record
    reads = []
    class ExactRepository:
        def revision(self, assessment_id, revision):
            reads.append((assessment_id, revision, current_thread().name))
            return SQLiteAssessmentRepository(db).revision(assessment_id, revision)
    risk = RiskQueryCoordinator(lambda: RiskExplanationQueryService(ExactRepository()))
    queries = tuple(IncidentQueryCoordinator(lambda: service) for _ in range(2))
    widget = IncidentsView(queries=queries, risk_queries=risk)
    qtbot.addWidget(widget)
    for query in (*queries, risk):
        query.start()
    try:
        select(qtbot, widget, record.incident_id)
        assert not reads  # No per-row eager risk query.
        row = next(i for i, e in enumerate(widget.timeline_model.entries) if e.kind is TimelineKind.ASSESSMENT)
        widget.timeline.selectRow(row)
        qtbot.waitUntil(lambda: bool(widget.risk.values))
        assert reads == [(k.assessment_id, 1, "netsentinel-risk-query")]
        assert widget.risk.values["Assessment revision"].text() == "1"
        assert "not a malware probability" in widget.risk.values["Score meaning"].text()
        detail = widget.row_detail.toPlainText()
        assert "Observation time: " + NOW.isoformat(timespec="microseconds") in detail
        assert "Assessment time: " + (NOW + timedelta(hours=1)).isoformat(timespec="microseconds") in detail
        widget.timeline.selectRow(0)
        assert not widget.tabs.isTabVisible(2)
        unknown = replace(widget.timeline_model.entries[row], assessment_time=None)
        widget.timeline_model.set_entries((unknown,))
        assert widget.timeline_model.data(widget.timeline_model.index(0, 0)).startswith("Assessment time unknown;")
    finally:
        for query in (*queries, risk):
            query.stop()


def test_reopen_is_system_lifecycle_action_and_does_not_change_first_observed(qtbot, view):
    from netsentinel.domain.incidents import IncidentInput, IncidentObservationRef, IncidentObservationKind
    widget, record, writer, _ = view
    record = writer.resolve(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2)).record
    connection = record.snapshot.connections[0]
    observed = NOW + timedelta(seconds=3)
    value = IncidentInput(IncidentObservationRef(IncidentObservationKind.CONNECTION_UPDATED, connection, observed),
        record.snapshot.scopes[0], record.snapshot.processes[0], connection, record.snapshot.destinations[0])
    record = writer.reopen(record.incident_id, value, expected_revision=2, now=NOW + timedelta(seconds=4)).record
    widget.select_incident(record.incident_id)
    widget.refresh_detail()
    qtbot.waitUntil(lambda: not widget._detail_loading)
    reopened = next(e for e in widget.timeline_model.entries if e.title == "Incident reopened")
    assert reopened.action_time == NOW + timedelta(seconds=4)
    assert "system_correlation" in reopened.explanation
    assert record.snapshot.first_observed_at == NOW
    assert "Incident state: open; incident revision: 3" in widget.summary.toPlainText()
