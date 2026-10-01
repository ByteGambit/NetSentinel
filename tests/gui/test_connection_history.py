"""NS-018 offscreen history query, model, pagination, and lifecycle tests."""

from __future__ import annotations

import ast
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, enumerate as enumerate_threads
from uuid import uuid4

from PyQt6.QtCore import QDateTime, QTimer, Qt
from PyQt6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from netsentinel.application.events import EventDispatcher
from netsentinel.application.ports import (
    ConnectionHistoryQuery,
    HistoryQueryCancelled,
    HistoryRepositoryError,
)
from netsentinel.application.services.history_query import ConnectionHistoryQueryService
from netsentinel.domain.connections import (
    ConnectionClosureReason,
    ConnectionHistoryRecord,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.infrastructure.sqlite import (
    SQLiteConnectionHistoryRepository,
    SQLiteDatabase,
)
from netsentinel.presentation.app import create_application
from netsentinel.presentation.history_query import HistoryQueryCoordinator
from netsentinel.presentation.models.history import (
    format_local_timestamp,
    history_row_from_record,
)
from netsentinel.presentation.views.history import HISTORY_PAGE_SIZE, HistoryView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


BASE = datetime(2026, 9, 21, 10, 11, 12, 123_456, tzinfo=UTC)


def record(
    index: int = 0,
    *,
    name: str | None = "browser.exe",
    pid: int | None = 100,
    protocol: TransportProtocol = TransportProtocol.TCP,
    local: str = "192.0.2.10",
    remote: str | None = "198.51.100.20",
    closed: bool = True,
) -> ConnectionHistoryRecord:
    observed = BASE + timedelta(seconds=index)
    identity = ProcessIdentity(pid, BASE - timedelta(hours=1)) if pid is not None else None
    process = (
        ProcessInfo(ProcessInfoStatus.AVAILABLE, identity, name)
        if name is not None and identity is not None
        else ProcessInfo.unavailable()
    )


    state = ConnectionState.NONE if protocol is TransportProtocol.UDP else ConnectionState.ESTABLISHED
    snapshot = ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local, 40_000 + index),
        remote_endpoint=Endpoint(remote, 443) if remote is not None else None,
        state=state,
        process=process,
        observed_at=observed,
    )
    return ConnectionHistoryRecord(
        record_id=uuid4(),
        first_seen=observed - timedelta(seconds=5),
        last_seen=observed,
        snapshot=snapshot,
        closed_at=observed + timedelta(seconds=2) if closed else None,
        close_reason=ConnectionClosureReason.NOT_OBSERVED if closed else None,
    )


def test_history_row_distinguishes_gap_open_and_legacy_unknown() -> None:
    legacy = record(closed=False)
    assert history_row_from_record(legacy).close_reason_display == "Historical status unknown"
    active = replace(legacy, session_id=uuid4(), lifecycle_id=uuid4())
    assert history_row_from_record(active).close_reason_display == "Currently observed / open"
    gap = replace(active, observation_gap=True)
    row = history_row_from_record(gap)
    assert row.close_reason_display == "Last observed before monitoring gap"
    assert row.closed_display == "Unknown (monitoring gap)"
    assert row.duration_display == history_row_from_record(active).duration_display


class FakeRepository:
    def __init__(self, records=()) -> None:
        self.records = list(records)
        self.calls: list[ConnectionHistoryQuery] = []
        self.lock = Lock()
        self.started = Event()
        self.release: Event | None = None
        self.failure: Exception | None = None

    def query(self, query, *, is_cancelled=None):
        with self.lock:
            self.calls.append(query)
        self.started.set()
        if self.release is not None:
            while not self.release.wait(0.01):
                if is_cancelled is not None and is_cancelled():
                    raise HistoryQueryCancelled("cancelled")
        if self.failure is not None:
            raise self.failure
        rows = list(self.records)
        if query.protocol is not None:
            rows = [r for r in rows if r.snapshot.protocol is query.protocol]
        if query.process_name is not None:
            rows = [r for r in rows if (r.snapshot.process.name or "").casefold() == query.process_name.casefold()]
        if query.pid is not None:
            rows = [r for r in rows if r.snapshot.process.identity is not None and r.snapshot.process.identity.pid == query.pid]
        if query.endpoint_address is not None:
            rows = [r for r in rows if r.snapshot.local_endpoint.address == query.endpoint_address or (r.snapshot.remote_endpoint is not None and r.snapshot.remote_endpoint.address == query.endpoint_address)]
        if query.first_seen_from is not None:
            rows = [r for r in rows if r.first_seen >= query.first_seen_from]
        if query.first_seen_to is not None:
            rows = [r for r in rows if r.first_seen <= query.first_seen_to]
        return tuple(rows[query.offset : query.offset + query.limit])


def coordinator(repository: FakeRepository) -> HistoryQueryCoordinator:
    return HistoryQueryCoordinator(lambda: ConnectionHistoryQueryService(repository))


def shown_view(qtbot: QtBot, repository: FakeRepository) -> tuple[HistoryView, HistoryQueryCoordinator]:
    worker = coordinator(repository)
    worker.start()
    view = HistoryView(worker)
    qtbot.addWidget(view)
    view.show()
    return view, worker


def test_history_view_navigation_and_empty_state(qtbot: QtBot) -> None:
    repo = FakeRepository()
    worker = coordinator(repo)
    worker.start()
    window = MainWindow(history_queries=worker)
    qtbot.addWidget(window)
    window.show()

    assert window.navigation_item(PageId.HISTORY).text() == "History"
    assert isinstance(window.page_widget(PageId.HISTORY), HistoryView)
    window.navigate_to(PageId.HISTORY)
    view = window.page_widget(PageId.HISTORY)
    assert isinstance(view, HistoryView)
    qtbot.waitUntil(lambda: not view._loading, timeout=2_000)
    assert view.model.rowCount() == 0
    assert view.state_label.text() == "No history records found."
    assert worker.stop()


def test_history_model_formats_metadata_and_detail_selection(qtbot: QtBot) -> None:
    rows = (
        record(0),
        record(1, local="2001:db8::1", remote="2001:db8::2"),
        record(2, name=None, pid=None, remote=None, protocol=TransportProtocol.UDP, closed=False),
    )
    view, worker = shown_view(qtbot, FakeRepository(rows))
    qtbot.waitUntil(lambda: view.model.rowCount() == 3, timeout=2_000)

    assert view.model.data(view.model.index(0, 3)) == "192.0.2.10:40000"
    assert view.model.data(view.model.index(1, 3)) == "[2001:db8::1]:40001"
    assert view.model.data(view.model.index(1, 4)) == "[2001:db8::2]:443"
    assert view.model.data(view.model.index(2, 0)) == "—"
    assert view.model.data(view.model.index(2, 1)) == "—"
    assert view.model.data(view.model.index(2, 4)) == "—"
    assert view.model.data(view.model.index(2, 8)) == "—"
    assert ".123456 " in history_row_from_record(rows[0]).last_seen_display
    assert history_row_from_record(rows[0]).close_reason_display == "No longer observed"

    view.table.selectRow(0)
    qtbot.waitUntil(lambda: view.details.values["process"].text() == "browser.exe")
    assert view.details.values["close_reason"].text() == "No longer observed"
    view.table.selectRow(1)
    assert view.details.values["local"].text() == "[2001:db8::1]:40001"
    assert worker.stop()


def test_atomic_new_query_clears_stale_selection(qtbot: QtBot) -> None:
    repo = FakeRepository((record(0),))
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: view.model.rowCount() == 1)
    view.table.selectRow(0)
    assert view.details.values["process"].text() == "browser.exe"

    repo.records = [record(2, name="service.exe")]
    view.refresh()
    assert view.details.values["process"].text() == "—"
    qtbot.waitUntil(lambda: view.model.rows[0].process_display == "service.exe")
    assert view.table.selectionModel().hasSelection() is False
    assert worker.stop()


def test_pagination_is_bounded_and_respects_boundaries(qtbot: QtBot) -> None:
    repo = FakeRepository(tuple(record(i) for i in range(120)))
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: view.model.rowCount() == 50)
    assert repo.calls[-1].limit == HISTORY_PAGE_SIZE + 1
    assert repo.calls[-1].offset == 0
    assert view.previous_button.isEnabled() is False
    assert view.next_button.isEnabled() is True

    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading)
    assert view.model.rowCount() == 50
    assert repo.calls[-1].offset == 50
    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 2 and not view._loading)
    assert view.model.rowCount() == 20
    assert view.next_button.isEnabled() is False
    view.next_page()
    assert view.page_index == 2
    view.previous_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading)
    assert worker.stop()


def test_filters_are_structured_debounced_and_reset_page(qtbot: QtBot) -> None:
    repo = FakeRepository(tuple(record(i) for i in range(70)))
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: view.model.rowCount() == 50)
    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading)

    view.process_filter.setText("browser.exe")
    view.pid_filter.setText("100")
    view.endpoint_filter.setText("198.51.100.20")
    view.protocol_filter.setCurrentIndex(1)
    qtbot.waitUntil(lambda: not view._loading and repo.calls[-1].offset == 0, timeout=2_000)
    query = repo.calls[-1]
    assert view.page_index == 0
    assert query.process_name == "browser.exe"
    assert query.pid == 100
    assert query.endpoint_address == "198.51.100.20"
    assert query.protocol is TransportProtocol.TCP
    assert len([t for t in enumerate_threads() if t.name == "netsentinel-history-query"]) == 1
    assert worker.stop()


def test_time_filter_is_utc_aware_and_refresh_preserves_page_and_filters(
    qtbot: QtBot,
) -> None:
    repo = FakeRepository(tuple(record(i) for i in range(70)))
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: view.model.rowCount() == 50)
    local_from = QDateTime.fromMSecsSinceEpoch(
        int((BASE - timedelta(days=1)).timestamp() * 1_000)
    ).toLocalTime()
    local_to = QDateTime.fromMSecsSinceEpoch(
        int((BASE + timedelta(days=1)).timestamp() * 1_000)
    ).toLocalTime()
    view.from_time.setDateTime(local_from)
    view.to_time.setDateTime(local_to)
    view.from_enabled.setChecked(True)
    view.to_enabled.setChecked(True)
    qtbot.waitUntil(lambda: not view._loading and repo.calls[-1].first_seen_to is not None)
    assert repo.calls[-1].first_seen_from is not None
    assert repo.calls[-1].first_seen_from.tzinfo is UTC
    assert repo.calls[-1].first_seen_to is not None
    assert repo.calls[-1].first_seen_to.tzinfo is UTC

    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading)
    previous_query = repo.calls[-1]
    calls_before_refresh = len(repo.calls)
    view.refresh_button.click()
    qtbot.waitUntil(
        lambda: len(repo.calls) > calls_before_refresh and not view._loading
    )
    refreshed = repo.calls[-1]
    assert refreshed.offset == previous_query.offset == HISTORY_PAGE_SIZE
    assert refreshed.first_seen_from == previous_query.first_seen_from
    assert refreshed.first_seen_to == previous_query.first_seen_to
    assert worker.stop()


def test_invalid_filters_do_not_start_query(qtbot: QtBot) -> None:
    repo = FakeRepository()
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: len(repo.calls) == 1)
    calls = len(repo.calls)
    view.endpoint_filter.setText("not-an-ip")
    qtbot.wait(350)
    assert len(repo.calls) == calls
    assert "valid" in view.validation_label.text().lower()

    view.endpoint_filter.clear()
    view.from_enabled.setChecked(True)
    view.to_enabled.setChecked(True)
    view.from_time.setDateTime(QDateTime.currentDateTime().addDays(1))
    view.to_time.setDateTime(QDateTime.currentDateTime())
    calls = len(repo.calls)
    view.refresh()
    assert len(repo.calls) == calls
    assert "must not be after" in view.validation_label.text()
    assert worker.stop()


def test_loading_keeps_event_loop_responsive_and_shutdown_cancels(qtbot: QtBot) -> None:
    repo = FakeRepository((record(),))
    repo.release = Event()
    worker = coordinator(repo)
    worker.start()
    view = HistoryView(worker)
    qtbot.addWidget(view)
    heartbeats: list[int] = []
    timer = QTimer(view)
    timer.setInterval(5)
    timer.timeout.connect(lambda: heartbeats.append(1))
    timer.start()
    view.show()
    assert repo.started.wait(1.0)
    qtbot.waitUntil(lambda: len(heartbeats) >= 3, timeout=1_000)
    assert view.state_label.text() == "Loading history…"
    assert worker.stop(timeout=1.0)
    assert worker.worker_alive is False


def test_query_error_is_sanitized(qtbot: QtBot, tmp_path: Path) -> None:
    repo = FakeRepository()
    secret_path = str(tmp_path / "private.sqlite3")
    repo.failure = HistoryRepositoryError(f"sqlite failed at {secret_path}: SELECT *")
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: not view._loading)
    text = view.state_label.text()
    assert text == "Unable to load connection history."
    assert secret_path not in text
    assert "SELECT" not in text
    assert worker.stop()


def test_stale_query_cannot_overwrite_newer_request(qtbot: QtBot) -> None:
    old = record(0, name="old.exe")
    new = record(1, name="new.exe")

    class StaleRepository(FakeRepository):
        def __init__(self) -> None:
            super().__init__()
            self.old_started = Event()
            self.old_release = Event()

        def query(self, query, *, is_cancelled=None):
            self.calls.append(query)
            if query.process_name == "old.exe":
                self.old_started.set()
                self.old_release.wait(1.0)
                return (old,)
            return (new,)

    repo = StaleRepository()
    worker = coordinator(repo)
    worker.start()
    delivered = []
    worker.page_ready.connect(lambda generation, page: delivered.append((generation, page)))
    worker.request(ConnectionHistoryQuery(limit=50, process_name="old.exe"))
    assert repo.old_started.wait(1.0)
    newest = worker.request(ConnectionHistoryQuery(limit=50, process_name="new.exe"))
    repo.old_release.set()
    qtbot.waitUntil(lambda: len(delivered) == 1, timeout=2_000)
    assert delivered[0][0] == newest
    assert delivered[0][1].records == (new,)
    assert worker.stop()


def test_retention_empty_page_recovers_to_previous_page(qtbot: QtBot) -> None:
    repo = FakeRepository(tuple(record(i) for i in range(60)))
    view, worker = shown_view(qtbot, repo)
    qtbot.waitUntil(lambda: view.model.rowCount() == 50)
    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading)
    repo.records = list(repo.records[:40])
    view.refresh()
    qtbot.waitUntil(lambda: view.page_index == 0 and not view._loading)
    assert view.model.rowCount() == 40
    assert view.details.values["process"].text() == "—"
    assert worker.stop()


def test_real_sqlite_migration_repository_worker_and_three_pages(
    qtbot: QtBot, tmp_path: Path
) -> None:
    database = SQLiteDatabase(tmp_path / "history.sqlite3")
    writer = SQLiteConnectionHistoryRepository(database)
    for index in range(120):
        item = record(index)
        writer.record_opened(ConnectionOpened(item.snapshot))

    worker = HistoryQueryCoordinator(
        lambda: ConnectionHistoryQueryService(
            SQLiteConnectionHistoryRepository(database)
        )
    )
    worker.start()
    view = HistoryView(worker)
    qtbot.addWidget(view)
    view.show()
    qtbot.waitUntil(lambda: view.model.rowCount() == 50, timeout=5_000)
    assert view.model.rows[0].record_id is not None
    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 1 and not view._loading, timeout=5_000)
    assert view.model.rowCount() == 50
    view.next_button.click()
    qtbot.waitUntil(lambda: view.page_index == 2 and not view._loading, timeout=5_000)
    assert view.model.rowCount() == 20
    assert worker.stop()


def test_history_accessibility_and_layer_boundaries(qtbot: QtBot) -> None:
    view, worker = shown_view(qtbot, FakeRepository())
    widgets = (
        view.process_filter,
        view.pid_filter,
        view.endpoint_filter,
        view.protocol_filter,
        view.from_enabled,
        view.from_time,
        view.to_enabled,
        view.to_time,
        view.refresh_button,
        view.table,
        view.previous_button,
        view.next_button,
        view.details,
    )
    assert all(widget.accessibleName() for widget in widgets)
    assert worker.stop()

    root = Path(__file__).resolve().parents[2] / "src" / "netsentinel"
    for relative in ("application", "domain"):
        for path in (root / relative).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            assert "sqlite3" not in imports
    history_sources = (
        root / "presentation" / "history_query.py",
        root / "presentation" / "models" / "history.py",
        root / "presentation" / "views" / "history.py",
    )
    for path in history_sources:
        text = path.read_text(encoding="utf-8")
        assert "SQLiteConnectionHistoryRepository" not in text
        assert "import sqlite3" not in text


def test_history_keyboard_tab_order_starts_with_structured_filters(
    qtbot: QtBot,
) -> None:
    view, worker = shown_view(qtbot, FakeRepository())
    view.activateWindow()
    view.process_filter.setFocus()
    QApplication.processEvents()
    qtbot.waitUntil(lambda: QApplication.focusWidget() is view.process_filter)
    qtbot.keyClick(view.process_filter, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is view.pid_filter
    qtbot.keyClick(view.pid_filter, Qt.Key.Key_Tab)
    assert QApplication.focusWidget() is view.endpoint_filter
    assert worker.stop()


def test_local_timestamp_uses_aware_local_conversion_and_keeps_microseconds() -> None:
    rendered = format_local_timestamp(BASE)
    assert rendered == BASE.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z")
    assert "123456" in rendered


class FakeEngine:
    def __init__(self) -> None:
        self.dispatcher = EventDispatcher()
        self.stop_calls = 0

    def health_snapshot(self):
        return EngineHealthSnapshot(
            state=EngineState.RUNNING,
            capabilities=CapabilitySnapshot(),
            counters=EngineCounters(),
            worker_alive=True,
        )

    def start(self):
        return True

    def stop(self, timeout=None):
        self.stop_calls += 1
        return True


def test_application_shutdown_stops_history_worker_before_widget_destruction(
    qtbot: QtBot,
) -> None:
    repo = FakeRepository((record(),))
    repo.release = Event()
    engine = FakeEngine()
    shell = create_application(
        engine,
        argv=[],
        history_service_factory=lambda: ConnectionHistoryQueryService(repo),
    )
    qtbot.addWidget(shell.window)
    shell.lifecycle.start()
    shell.window.show()
    shell.window.navigate_to(PageId.HISTORY)
    assert repo.started.wait(1.0)
    shell.window.close()
    QApplication.processEvents()
    assert shell.history_queries is not None
    assert shell.history_queries.worker_alive is False
    assert engine.stop_calls == 1
    assert not any(t.name == "netsentinel-history-query" for t in enumerate_threads())
