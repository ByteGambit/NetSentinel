"""NS-055 process context detail behavior on both connection surfaces."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from PyQt6.QtCore import QModelIndex, Qt
from pytestqt.qtbot import QtBot

from netsentinel.application.services.history_query import (
    ConnectionHistoryPage,
    ConnectionHistoryQueryService,
)
from netsentinel.domain.connections import (
    ConnectionOpened,
    ConnectionUpdated,
    ParentProcessInfo,
    ParentProcessStatus,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
)
from netsentinel.infrastructure.sqlite import SQLiteConnectionHistoryRepository, SQLiteDatabase
from netsentinel.presentation.history_query import HistoryQueryCoordinator
from netsentinel.presentation.process_context import PROCESS_CONTEXT_FIELDS, process_context_text
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.history import HistoryView
from tests.gui.test_connection_history import BASE, record
from tests.gui.test_connections_view import _snapshot


def _process(*, path: str | None, path_status: ProcessInfoStatus, parent: ParentProcessInfo | None) -> ProcessInfo:
    return ProcessInfo(
        ProcessInfoStatus.AVAILABLE,
        ProcessIdentity(4242, BASE - timedelta(hours=1)),
        "<test>&.exe",
        executable_path=path,
        executable_path_status=path_status,
        parent=parent,
    )


def _observed_parent() -> ParentProcessInfo:
    return ParentProcessInfo(
        ParentProcessStatus.OBSERVED,
        BASE,
        parent_pid=3180,
        identity=ProcessIdentity(3180, BASE - timedelta(hours=2)),
        name="WINWORD.EXE",
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.AVAILABLE,
        name_status=ProcessInfoStatus.AVAILABLE,
    )


def test_live_full_plain_text_accessibility_and_refresh(qtbot: QtBot) -> None:
    view = ConnectionsView()
    qtbot.addWidget(view)
    view.show()
    path = "file://<test>&/http://tool.exe"
    initial = _snapshot(process=_process(path=path, path_status=ProcessInfoStatus.AVAILABLE, parent=_observed_parent()))
    view.source_model.handle_connection_opened(ConnectionOpened(initial))
    view.table.selectRow(0)
    assert view.details.value_text("process") == "<test>&.exe"
    assert view.details.value_text("pid") == "4242"
    assert view.details.value_text("executable") == path
    assert "verified" in view.details.value_text("parent_status")
    assert view.details.value_text("parent_name") == "WINWORD.EXE"
    assert view.details.value_text("parent_pid") == "3180"
    assert view.details.value_text("parent_create_time") != "Not available"
    assert view.details.value_text("parent_observed_at") != "Not observed"
    for key, _title in PROCESS_CONTEXT_FIELDS:
        label = view.details.value_labels[key]
        assert label.textFormat() is Qt.TextFormat.PlainText
        assert label.accessibleName()
        assert label.openExternalLinks() is False
    assert view.details.value_labels["process"].textFormat() is Qt.TextFormat.PlainText
    selected = view.selected_row_id
    current = replace(initial, observed_at=BASE + timedelta(seconds=1), process=replace(initial.process, executable_path="http://other&<x>"))
    view.source_model.handle_connection_updated(ConnectionUpdated(initial, current))
    assert view.selected_row_id == selected
    assert view.details.value_text("executable") == "http://other&<x>"
    view.search_edit.setText("no match")
    assert view.details.value_text("executable") == "—"


def test_partial_exited_and_reused_states() -> None:
    absent = ParentProcessInfo(ParentProcessStatus.ABSENT, BASE)
    partial = process_context_text(_process(path=None, path_status=ProcessInfoStatus.ACCESS_DENIED, parent=absent))
    assert partial["executable"] == "Restricted by Windows permissions"
    assert partial["parent_status"] == "No parent reported"
    assert partial["parent_pid"] == "No parent reported"

    reused = ParentProcessInfo(
        ParentProcessStatus.REUSED,
        BASE,
        parent_pid=3180,
        pid_status=ProcessInfoStatus.AVAILABLE,
    )
    reused_text = process_context_text(_process(path=None, path_status=ProcessInfoStatus.NOT_FOUND, parent=reused))
    assert reused_text["executable"] == "Process no longer found"
    assert reused_text["parent_name"] == "Not verified"
    assert "unverified" in reused_text["parent_status"]
    unknown = process_context_text(ProcessInfo.unavailable())
    assert unknown["process"] == "Not available"
    assert unknown["parent_status"] == "Not observed"


def test_history_worker_displays_persisted_snapshot_and_legacy(qtbot: QtBot, tmp_path) -> None:
    database = SQLiteDatabase(tmp_path / "process-context.sqlite3")
    writer = SQLiteConnectionHistoryRepository(database)
    saved = record(0)
    saved = replace(saved, snapshot=replace(saved.snapshot, process=_process(path="C:/<test>&/tool.exe", path_status=ProcessInfoStatus.AVAILABLE, parent=_observed_parent())))
    writer.record_opened(ConnectionOpened(saved.snapshot))
    legacy = record(1)
    writer.record_opened(ConnectionOpened(legacy.snapshot))
    # Model the nullable metadata columns of a pre-010 history row.
    with database.connection() as connection:
        connection.execute(
            """UPDATE connection_history
               SET executable_path = NULL, executable_path_status = NULL,
                   process_name_status = NULL, process_create_time_status = NULL,
                   parent_status = NULL
               WHERE process_name = ?""",
            ("browser.exe",),
        )
        connection.commit()

    worker = HistoryQueryCoordinator(lambda: ConnectionHistoryQueryService(SQLiteConnectionHistoryRepository(database)))
    worker.start()
    view = HistoryView(worker)
    qtbot.addWidget(view)
    view.show()
    qtbot.waitUntil(lambda: view.model.rowCount() == 2, timeout=3_000)
    matching = next(i for i, row in enumerate(view.model.rows) if row.process_info.identity and row.process_info.identity.pid == 4242)
    view.table.selectRow(matching)
    assert view.details.values["executable"].text() == "C:/<test>&/tool.exe"
    assert view.details.values["parent_name"].text() == "WINWORD.EXE"
    assert view.details.values["executable"].textFormat() is Qt.TextFormat.PlainText
    selected_id = view.model.rows[matching].record_id
    view.refresh()
    qtbot.waitUntil(lambda: not view._loading, timeout=3_000)
    assert view.model.row_at(view.table.currentIndex().row()).record_id == selected_id
    legacy_index = next(i for i, row in enumerate(view.model.rows) if row.record_id != selected_id)
    view.table.selectRow(legacy_index)
    assert view.details.values["parent_status"].text() == "Not observed"
    assert view.details.values["executable"].text() == "Not available"
    view.table.clearSelection()
    view.table.setCurrentIndex(QModelIndex())
    assert view.details.status_label.text() == "No history record selected."
    assert view.details.values["executable"].text() == "—"
    assert worker.stop()


def test_maximum_path_is_displayed_as_plain_text(qtbot: QtBot) -> None:
    view = ConnectionsView()
    qtbot.addWidget(view)
    view.show()
    path = "C:/" + "x" * (4096 - 4)
    snapshot = _snapshot(process=_process(path=path, path_status=ProcessInfoStatus.AVAILABLE, parent=None))
    view.source_model.handle_connection_opened(ConnectionOpened(snapshot))
    view.table.selectRow(0)
    assert view.details.value_text("executable") == path
    assert view.details.value_labels["executable"].wordWrap()


def test_stale_history_page_does_not_replace_selected_detail(qtbot: QtBot) -> None:
    view = HistoryView()
    qtbot.addWidget(view)
    old = record(0, name="old.exe")
    current = record(1, name="current.exe")
    view._latest_generation = 2
    view._page_ready(2, ConnectionHistoryPage((current,), 0, 50, False, False))
    view.table.selectRow(0)
    assert view.details.values["process"].text() == "current.exe"
    view._page_ready(1, ConnectionHistoryPage((old,), 0, 50, False, False))
    assert view.details.values["process"].text() == "current.exe"
    assert view.model.rows[0].record_id == current.record_id
