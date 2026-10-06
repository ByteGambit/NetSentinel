"""NS-099 list/detail and horizontal-overflow regressions in the real shell."""

from dataclasses import replace
from uuid import UUID
from pathlib import Path

import pytest
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import QScrollArea

from netsentinel.domain.incident_persistence import IncidentResult, IncidentStatus
from netsentinel.presentation.incident_query import IncidentQueryCoordinator
from netsentinel.presentation.views.main_window import MainWindow, PageId
from tests.fixtures.incident_timeline import story
from tests.gui.test_connection_history import record as history_record
from tests.gui.test_dns_view import record as dns_record


VIEWPORTS = ((1280, 720), (1366, 768), (1920, 1080))


@pytest.fixture(autouse=True)
def readable_font(qapp):
    """Use actual normal Windows glyph metrics when the host font is available."""
    previous = qapp.font()
    font = Path("C:/Windows/Fonts/segoeui.ttf")
    font_id = -1
    if font.is_file():
        font_id = QFontDatabase.addApplicationFont(str(font))
        assert font_id >= 0
        qapp.setFont(QFont("Segoe UI", 9))
    yield
    qapp.setFont(previous)
    if font_id >= 0:
        assert QFontDatabase.removeApplicationFont(font_id)


def settle(qtbot):
    qtbot.wait(60)


def visible_control(window, control):
    assert control.isVisible()
    rect = control.rect().translated(control.mapTo(window, QPoint()))
    assert window.rect().contains(rect), (control.accessibleName(), rect, window.size())


def visible_rows(table):
    return table.viewport().height() // table.verticalHeader().defaultSectionSize()


@pytest.mark.parametrize("size", VIEWPORTS)
def test_incident_list_survives_detail_and_splitter_resize(qtbot, tmp_path, size):
    _, _, record, _, service = story(tmp_path)
    queries = tuple(IncidentQueryCoordinator(lambda: service) for _ in range(2))
    window = MainWindow(incident_queries=queries)
    qtbot.addWidget(window)
    for query in queries:
        query.start()
    try:
        window.resize(*size)
        window.show()
        window.navigate_to(PageId.INCIDENTS)
        view = window.page_widget(PageId.INCIDENTS)
        qtbot.waitUntil(lambda: view.model.rowCount() == 1)
        assert not view.tabs.isVisible()
        assert view.detail_panel.height() < view.table.height()
        view.model.set_entries(tuple(IncidentResult(IncidentStatus.FOUND,
            record if i == 0 else replace(record, snapshot=replace(record.snapshot, incident_id=UUID(int=100 + i)))) for i in range(12)))
        view.table.selectRow(0)
        qtbot.waitUntil(lambda: view.timeline_model.rowCount() > 0)
        settle(qtbot)
        assert window.size().width() == size[0] and window.size().height() == size[1]
        assert visible_rows(view.table) >= 5
        for control in (view.previous_button, view.next_button, view.more_button,
                        view.detail_refresh_button, view.tabs):
            visible_control(window, control)
        assert view.timeline.viewport().height() > view.timeline.verticalHeader().defaultSectionSize()
        assert not view.findChildren(QScrollArea)
        view.splitter.setSizes([1, 10000])
        settle(qtbot)
        assert visible_rows(view.table) >= 5
        view.table.setFocus()
        qtbot.keyClick(view.table, Qt.Key.Key_Down)
        assert view.table.currentIndex().row() == 1
        window.resize(1280, 720)
        settle(qtbot)
        assert visible_rows(view.table) >= 5
        visible_control(window, view.next_button)
    finally:
        for query in queries:
            assert query.stop()


@pytest.mark.parametrize("size", VIEWPORTS)
def test_dns_empty_selected_and_long_detail_keep_history_reachable(qtbot, size):
    window = MainWindow()
    qtbot.addWidget(window)
    window.resize(*size)
    window.show()
    window.navigate_to(PageId.DNS)
    view = window.page_widget(PageId.DNS)
    settle(qtbot)
    assert not view.details.detail_scroll.isVisible()
    assert view.details.height() < view.table.height() / 2
    view.model.replace_records(tuple(dns_record(i) for i in range(1, 13)))
    view.table.selectRow(0)
    view.details.values["network"].setText("Synthetic previously observed network context " * 8)
    view.details.answers.setPlainText("\n".join(f"long.synthetic.example AAAA 2001:db8::{i} (TTL 3600s)" for i in range(16)))
    settle(qtbot)
    assert window.size().height() == size[1]
    assert visible_rows(view.table) >= 6
    for control in (view.previous_button, view.next_button, view.from_time, view.to_time):
        visible_control(window, control)
    assert view.details.findChildren(QScrollArea) == [view.details.detail_scroll]
    assert view.details.answers.verticalScrollBarPolicy() is Qt.ScrollBarPolicy.ScrollBarAlwaysOff
    view.details.detail_scroll.ensureWidgetVisible(view.details.answers)
    settle(qtbot)
    assert view.details.answers.mapTo(view.details.detail_scroll.viewport(), QPoint()).y() < view.details.detail_scroll.viewport().height()
    view.splitter.setSizes([1, 10000])
    settle(qtbot)
    assert visible_rows(view.table) >= 6
    view.table.setFocus()
    qtbot.keyClick(view.table, Qt.Key.Key_Down)
    assert view.table.currentIndex().row() == 1
    assert view.details.values["id"].text() == str(view.model.records[1].id)
    view.details.clear()
    settle(qtbot)
    assert not view.details.detail_scroll.isVisible()
    assert view.details.height() < view.table.height() / 2


@pytest.mark.parametrize("size", VIEWPORTS)
def test_history_keeps_full_values_and_scrolls_to_timestamp_columns(qtbot, size):
    window = MainWindow()
    qtbot.addWidget(window)
    window.resize(*size)
    window.show()
    window.navigate_to(PageId.HISTORY)
    view = window.page_widget(PageId.HISTORY)
    view.model.replace_records(tuple(history_record(i, name="synthetic-long-process-name-for-layout.exe",
        local="2001:db8:1234:5678:90ab:cdef:1234:5678", remote="2001:db8:4321:8765:abcd:ef90:4321:8765") for i in range(12)))
    settle(qtbot)
    if size[0] < 1920:
        assert view.table.horizontalScrollBar().maximum() > 0
    for column in range(view.model.columnCount()):
        text = view.model.index(0, column).data()
        assert view.table.columnWidth(column) >= view.table.fontMetrics().horizontalAdvance(text) + 4
        view.table.scrollTo(view.model.index(0, column))
        settle(qtbot)
        cell = view.table.visualRect(view.model.index(0, column))
        assert cell.left() >= 0 and cell.right() < view.table.viewport().width()
    assert view.table.textElideMode() is Qt.TextElideMode.ElideNone
    view.table.selectRow(0)
    view.table.setFocus()
    qtbot.keyClick(view.table, Qt.Key.Key_Down)
    assert view.table.currentIndex().row() == 1
    view.page_scroll.ensureWidgetVisible(view.next_button)
    settle(qtbot)
    visible_control(window, view.next_button)
    assert not view.details.findChildren(QScrollArea)
