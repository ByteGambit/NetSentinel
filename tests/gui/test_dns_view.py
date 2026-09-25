"""NS-034 offscreen DNS history, formatting, filtering and worker tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, enumerate as enumerate_threads
from uuid import UUID

from PyQt6.QtCore import QDateTime, QTimer, Qt

from netsentinel.application.ports import DnsHistoryQuery, DnsHistoryQueryCancelled
from netsentinel.application.services.dns_history_query import DnsHistoryQueryService
from netsentinel.domain.dns import (DnsAnswer, DnsHistoryRecord, DnsQuestion,
    DnsRecordType, DnsTransaction, DnsTransactionStatus, DnsTransport)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_repository import SQLiteDnsHistoryRepository
from netsentinel.presentation.dns_query import DnsQueryCoordinator
from netsentinel.presentation.models.dns import (DnsTableModel, format_dns_endpoint,
    format_latency, format_rcode, format_record_type)
from netsentinel.presentation.views.dns import DnsView
from netsentinel.presentation.views.main_window import MainWindow, PageId

AT = datetime(2026, 9, 23, 12, 34, 56, 123456, tzinfo=UTC)


def record(index=1, *, status=DnsTransactionStatus.COMPLETED,
           transport=DnsTransport.UDP, rcode=0, questions=None,
           answers=None, server="198.51.100.53") -> DnsHistoryRecord:
    at = AT + timedelta(seconds=index)
    has_response = status in (DnsTransactionStatus.COMPLETED, DnsTransactionStatus.UNMATCHED_RESPONSE)
    query_at = None if status is DnsTransactionStatus.UNMATCHED_RESPONSE else at
    response_at = at + timedelta(microseconds=17) if has_response else None
    tx = DnsTransaction(
        status=status, network_fingerprint="a" * 64, transport=transport,
        client_ip="192.0.2.20", client_port=53000, server_ip=server, server_port=53,
        transaction_id=42, questions=questions if questions is not None else
        (() if status is DnsTransactionStatus.UNMATCHED_RESPONSE else (DnsQuestion("Example.COM", 1),)),
        query_at=query_at, response_at=response_at,
        latency_seconds=.0124 if status is DnsTransactionStatus.COMPLETED else None,
        response_code=rcode if has_response else None, truncated=has_response,
        answers=answers if answers is not None else
        ((DnsAnswer("example.com", DnsRecordType.A, "192.0.2.99", 30),) if has_response else ()),
        retry_count=2,
    )
    return DnsHistoryRecord(UUID(int=index), tx)


class FakeRepository:
    def __init__(self, rows=()):
        self.rows = tuple(rows)
        self.calls = []
        self.release: Event | None = None
        self.started = Event()
        self.fail = False

    def query(self, query, *, is_cancelled=None):
        self.calls.append(query)
        self.started.set()
        while self.release is not None and not self.release.wait(.01):
            if is_cancelled and is_cancelled():
                raise DnsHistoryQueryCancelled("cancelled")
        if self.fail:
            raise RuntimeError("private/path SQL traceback")
        rows = list(self.rows)
        if query.qname:
            rows = [row for row in rows if row.transaction.questions and row.transaction.questions[0].name == query.qname]
        if query.qtype is not None:
            rows = [row for row in rows if row.transaction.questions and row.transaction.questions[0].record_type == query.qtype]
        if query.server_ip:
            rows = [row for row in rows if row.transaction.server_ip == query.server_ip]
        if query.status:
            rows = [row for row in rows if row.transaction.status is query.status]
        if query.transport:
            rows = [row for row in rows if row.transaction.transport is query.transport]
        if query.event_from:
            rows = [row for row in rows if (row.transaction.query_at or row.transaction.response_at) >= query.event_from]
        if query.event_to:
            rows = [row for row in rows if (row.transaction.query_at or row.transaction.response_at) <= query.event_to]
        rows.sort(key=lambda row: (row.transaction.query_at or row.transaction.response_at, row.id), reverse=True)
        return tuple(rows[query.offset:query.offset + query.limit])


def make_view(qtbot, repository):
    coordinator = DnsQueryCoordinator(lambda: DnsHistoryQueryService(repository))
    coordinator.start()
    view = DnsView(coordinator=coordinator)
    qtbot.addWidget(view)
    view.show()
    qtbot.waitUntil(lambda: not view._loading, timeout=3000)
    return view, coordinator


def test_dns_view_empty_model_and_safe_formatting(qtbot):
    view, coordinator = make_view(qtbot, FakeRepository())
    try:
        assert view.model.rowCount() == 0
        assert "No DNS history" in view.state_label.text()
        assert "DoH/DoT" in view.capability_label.text()
        assert "Saved DNS history" in view.capture_label.text()
        assert format_dns_endpoint("2001:db8::1", 53) == "[2001:db8::1]:53"
        assert format_dns_endpoint("192.0.2.1", 53) == "192.0.2.1:53"
        assert format_latency(None) == "—"
        assert format_latency(.0124) == "12.4 ms"
        assert format_rcode(0) == "NOERROR"
        assert format_rcode(3) == "NXDOMAIN"
        assert format_rcode(2) == "SERVFAIL"
        assert format_rcode(15) == "RCODE 15"
        assert format_record_type(65000) == "TYPE 65000"
    finally:
        assert coordinator.stop()


def test_model_status_details_and_stable_selection(qtbot):
    rows = (record(1), record(2, status=DnsTransactionStatus.TIMED_OUT, transport=DnsTransport.TCP),
            record(3, status=DnsTransactionStatus.UNMATCHED_RESPONSE, rcode=3),
            record(4, status=DnsTransactionStatus.EVICTED))
    repository = FakeRepository(rows)
    view, coordinator = make_view(qtbot, repository)
    try:
        assert view.model.rowCount() == 4
        displayed = [view.model.data(view.model.index(i, 1)) for i in range(4)]
        assert displayed == ["Query evicted", "Unmatched response", "Timed out", "Response matched"]
        row = view.model.row_for_id(rows[0].id)
        view.table.selectRow(row)
        assert view.details.values["id"].text() == str(rows[0].id)
        assert view.details.values["retries"].text() == "2"
        assert view.details.values["truncated"].text() == "Yes"
        assert "example.com." in view.details.questions.toPlainText()
        assert "192.0.2.99" in view.details.answers.toPlainText()
        assert view.details.values["query_time"].text().endswith("123456 +0000") or "123456" in view.details.values["query_time"].text()
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view._selected_id == rows[0].id
        repository.rows = rows[1:]
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view._selected_id is None
        assert view.details.values["id"].text() == "—"
    finally:
        assert coordinator.stop()


def test_filters_validation_and_error_redaction(qtbot):
    repository = FakeRepository((record(1), record(2, transport=DnsTransport.TCP)))
    view, coordinator = make_view(qtbot, repository)
    try:
        view.qname_filter.setText("EXAMPLE.COM")
        qtbot.waitUntil(lambda: len(repository.calls) >= 2 and not view._loading, timeout=3000)
        assert repository.calls[-1].qname == "example.com."
        view.type_filter.setCurrentIndex(view.type_filter.findData(1))
        qtbot.waitUntil(lambda: repository.calls[-1].qtype == 1 and not view._loading, timeout=3000)
        view.server_filter.setText("bad IP")
        qtbot.waitUntil(lambda: view.validation_label.isVisible(), timeout=3000)
        assert "valid DNS server" in view.validation_label.text()
        view.server_filter.setText("198.51.100.53")
        qtbot.waitUntil(lambda: not view._loading and repository.calls[-1].server_ip == "198.51.100.53", timeout=3000)
        view.from_enabled.setChecked(True)
        view.to_enabled.setChecked(True)
        view.from_time.setDateTime(QDateTime.fromString("2026-09-24 12:00:00", "yyyy-MM-dd HH:mm:ss"))
        view.to_time.setDateTime(QDateTime.fromString("2026-09-23 12:00:00", "yyyy-MM-dd HH:mm:ss"))
        assert "From time" in view.validation_label.text()
        repository.fail = True
        view.from_enabled.setChecked(False)
        view.to_enabled.setChecked(False)
        qtbot.waitUntil(lambda: not view._loading and "unavailable" in view.state_label.text(), timeout=3000)
        assert "private" not in view.state_label.text()
        assert "SQL" not in view.state_label.text()
    finally:
        assert coordinator.stop()


def test_slow_worker_keeps_qt_heartbeat_and_cancels_stale(qtbot):
    repository = FakeRepository((record(1),))
    repository.release = Event()
    coordinator = DnsQueryCoordinator(lambda: DnsHistoryQueryService(repository))
    coordinator.start()
    view = DnsView(coordinator=coordinator)
    qtbot.addWidget(view)
    ticks = []
    timer = QTimer()
    timer.setInterval(0)
    timer.timeout.connect(lambda: ticks.append(1))
    try:
        view.show()
        timer.start()
        qtbot.waitUntil(repository.started.is_set, timeout=3000)
        qtbot.waitUntil(lambda: len(ticks) > 20, timeout=3000)
        view.status_filter.setCurrentIndex(view.status_filter.findData(DnsTransactionStatus.TIMED_OUT))
        repository.release.set()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view.model.rowCount() == 0
        assert repository.calls[-1].status is DnsTransactionStatus.TIMED_OUT
    finally:
        timer.stop()
        assert coordinator.stop()
        assert not coordinator.worker_alive


def test_real_sqlite_repository_service_coordinator_view_pages(qtbot, tmp_path: Path):
    database = SQLiteDatabase(tmp_path / "dns.sqlite3")
    repository = SQLiteDnsHistoryRepository(database)
    for index in range(1, 121):
        repository.record(record(index))
    view, coordinator = make_view(qtbot, repository)
    try:
        assert view.model.rowCount() == 50
        assert view._has_next
        assert repository.query(DnsHistoryQuery(limit=1))[0].id == view.model.records[0].id
        view.next_page()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view.model.rowCount() == 50
        view.next_page()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view.model.rowCount() == 20
        assert not view._has_next
        assert not view.next_button.isEnabled()
        view.previous_page()
        qtbot.waitUntil(lambda: not view._loading, timeout=3000)
        assert view.page_index == 1
    finally:
        assert coordinator.stop()
        assert not any(t.name == "netsentinel-dns-query" and t.is_alive() for t in enumerate_threads())


def test_status_type_name_server_and_time_filters_reset_page(qtbot):
    repository = FakeRepository((record(1), record(2, status=DnsTransactionStatus.TIMED_OUT),
                                 record(3, rcode=3, server="203.0.113.53")))
    view, coordinator = make_view(qtbot, repository)
    try:
        view._page_index = 2
        view.status_filter.setCurrentIndex(view.status_filter.findData(DnsTransactionStatus.TIMED_OUT))
        qtbot.waitUntil(lambda: not view._loading and repository.calls[-1].status is DnsTransactionStatus.TIMED_OUT)
        assert view.page_index == 0
        assert view.model.rowCount() == 1
        view.status_filter.setCurrentIndex(0)
        view.server_filter.setText("203.0.113.53")
        qtbot.waitUntil(lambda: not view._loading and repository.calls[-1].server_ip == "203.0.113.53")
        assert view.model.rowCount() == 1
        view.server_filter.clear()
        view.from_enabled.setChecked(True)
        view.from_time.setDateTime(QDateTime.fromString("2026-09-23 12:34:58", "yyyy-MM-dd HH:mm:ss"))
        qtbot.waitUntil(lambda: not view._loading and repository.calls[-1].event_from is not None)
        assert repository.calls[-1].event_from.tzinfo is not None
        assert repository.calls[-1].event_from.utcoffset() == timedelta(0)
        assert repository.calls[-1].limit == 51  # one look-ahead record
        assert repository.calls[-1].offset == 0
    finally:
        assert coordinator.stop()


def test_bounded_questions_answers_and_accessible_controls(qtbot):
    questions = tuple(DnsQuestion(f"q{i}.example", 1) for i in range(4))
    answers = tuple(DnsAnswer(f"a{i}.example", DnsRecordType.A, "192.0.2.99", i) for i in range(16))
    view, coordinator = make_view(qtbot, FakeRepository((record(1, questions=questions, answers=answers),)))
    try:
        view.table.selectRow(0)
        assert len(view.details.questions.toPlainText().splitlines()) == 4
        assert len(view.details.answers.toPlainText().splitlines()) == 16
        for control in (view.qname_filter, view.type_filter, view.server_filter,
                        view.status_filter, view.from_enabled, view.from_time,
                        view.to_enabled, view.to_time, view.table, view.details,
                        view.refresh_button, view.previous_button, view.next_button):
            assert control.accessibleName()
        view.table.setFocus()
        qtbot.keyClick(view.table, Qt.Key.Key_Down)
        assert view.table.currentIndex().isValid()
    finally:
        assert coordinator.stop()


def test_dns_config_alert_button_opens_filtered_alerts(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    window.navigate_to(PageId.DNS)
    dns = window.page_widget(PageId.DNS)
    qtbot.mouseClick(dns.alert_button, Qt.MouseButton.LeftButton)
    assert window.current_page is PageId.ALERTS
    alerts = window.page_widget(PageId.ALERTS)
    assert alerts.rule_filter.currentData() == "dns_server_set_change"
