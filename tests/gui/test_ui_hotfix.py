"""NS-093 follow-up hotfix: page flow, endpoint readability and native palettes."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest
from PyQt6.QtCore import QPoint, QPointF, Qt
from PyQt6.QtGui import QColor, QPalette, QWheelEvent
from PyQt6.QtWidgets import QApplication, QFrame, QLabel, QScrollArea

from netsentinel.domain.connections import (
    ConnectionOpened, ParentProcessInfo, ParentProcessStatus, ProcessIdentity,
    ProcessInfo, ProcessInfoStatus,
)
from netsentinel.presentation.models.history import history_row_from_record
from netsentinel.presentation.process_context import format_process_created, process_context_text
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.history import HistoryView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from tests.fixtures.risk_explanations import model
from tests.fixtures.risk_assessments import snapshot
from tests.gui.test_connection_history import BASE, record
from tests.gui.test_connections_view import _snapshot


SIZES = ((1280, 720), (1366, 768), (1600, 900), (1920, 1080))


def settle(qtbot):
    QApplication.processEvents()
    qtbot.wait(20)
    QApplication.processEvents()


def wheel(widget):
    position = widget.rect().center()
    event = QWheelEvent(QPointF(position), QPointF(widget.mapToGlobal(position)),
                        QPoint(), QPoint(0, -120), Qt.MouseButton.NoButton,
                        Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
    QApplication.sendEvent(widget, event)
    return event


def assert_reachable(scroll, widget, qtbot):
    scroll.ensureWidgetVisible(widget)
    settle(qtbot)
    rect = scroll.viewport().rect()
    point = widget.mapTo(scroll.viewport(), widget.rect().center())
    assert rect.contains(point), (widget.accessibleName(), point, rect)


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("page", (PageId.CONNECTIONS, PageId.HISTORY))
def test_monitoring_page_table_and_details_share_page_flow(qtbot, size, page):
    window = MainWindow()
    qtbot.addWidget(window)
    window.resize(*size)
    window.show()
    window.navigate_to(page)
    view = window.page_widget(page)
    if isinstance(view, ConnectionsView):
        for i in range(25):
            view.source_model.handle_connection_opened(ConnectionOpened(_snapshot(local_port=40000 + i)))
    else:
        assert isinstance(view, HistoryView)
        view.model.replace_records(tuple(record(i) for i in range(25)))
    view.table.selectRow(0)
    settle(qtbot)
    rows_visible = view.table.viewport().height() // view.table.verticalHeader().defaultSectionSize()
    assert 6 <= rows_visible <= 10
    assert view.table.rowAt(0) == 0
    assert view.table.rowAt(view.table.viewport().height() - 1) >= 5
    assert view.details.isVisible()
    assert not view.details.findChildren(QScrollArea)
    assert view.page_scroll.verticalScrollBar().maximum() > 0
    assert view.page_scroll.horizontalScrollBar().maximum() == 0
    if isinstance(view, ConnectionsView):
        assert view.table.columnWidth(4) >= view.table.fontMetrics().horizontalAdvance("255.255.255.255:65535")
        # Live connections retain their endpoint-spare-width policy.
        assert view.table.columnViewportPosition(4) + view.table.fontMetrics().horizontalAdvance("198.51.100.20") <= view.table.viewport().width()
        bottom = view.details.signer_button
        assert_reachable(view.page_scroll, bottom, qtbot)
        view.page_scroll.verticalScrollBar().setValue(0)
        before = view.page_scroll.verticalScrollBar().value()
        assert not wheel(view.details.value_labels["process"]).isAccepted()
        wheel(view.page_scroll.viewport())
        settle(qtbot)
        assert view.page_scroll.verticalScrollBar().value() > before
        assert view.details.value_text("remote_address") == _snapshot().remote_endpoint.address
    else:
        # NS-099 History preserves content widths and permits horizontal overflow.
        endpoint = view.model.index(0, 4)
        assert view.table.columnWidth(4) >= view.table.fontMetrics().horizontalAdvance(endpoint.data()) + 4
        view.table.scrollTo(endpoint)
        settle(qtbot)
        assert view.table.visualRect(endpoint).right() < view.table.viewport().width()
        assert_reachable(view.page_scroll, view.details.destination.context_details, qtbot)
        view.table.selectRow(1)
        assert view.details.values["local"].text().endswith(":40001")


@pytest.mark.parametrize("size", SIZES)
def test_connection_tabs_expand_async_text_and_reach_controls(qtbot, size):
    view = ConnectionsView()
    qtbot.addWidget(view)
    view.resize(size[0] - 300, size[1] - 50)
    view.show()
    view.source_model.handle_connection_opened(ConnectionOpened(_snapshot()))
    view.table.selectRow(0)
    view.details.baseline.text.setText("\n".join("Observed baseline context " * 8 for _ in range(80)))
    view.details.risk.set_model(model(snapshot()))
    view.details.threat_intel.result.setPlainText("\n".join(f"Provider evidence line {i}" for i in range(100)))
    for index in range(view.details.tabs.count()):
        view.details.tabs.setCurrentIndex(index)
        settle(qtbot)
        active = view.details.tabs.currentWidget()
        assert active.isVisible()
        assert not active.findChildren(QScrollArea)
        if index == 1:
            assert view.details.baseline.text.height() >= view.details.baseline.text.heightForWidth(view.details.baseline.text.width())
            assert_reachable(view.page_scroll, view.details.baseline.reset_button, qtbot)
            assert_reachable(view.page_scroll, view.details.baseline.preferences, qtbot)
        if index == 2:
            for section in range(view.details.risk.tabs.count()):
                view.details.risk.tabs.setCurrentIndex(section)
                settle(qtbot)
                assert not view.details.risk.findChildren(QScrollArea)
                for text in view.details.risk.section_texts.values():
                    assert text.verticalScrollBar().maximum() == 0
        if index == 3:
            text = view.details.threat_intel.result
            assert text.height() >= text.document().size().height()
            assert text.verticalScrollBar().maximum() == 0
            view.page_scroll.verticalScrollBar().setValue(view.page_scroll.verticalScrollBar().maximum())
            settle(qtbot)
            assert text.mapTo(view.page_scroll.viewport(), text.rect().bottomLeft()).y() <= view.page_scroll.viewport().height()


def test_monitoring_endpoint_sizing_and_font_sized_rows(qtbot):
    for view in (ConnectionsView(), HistoryView()):
        qtbot.addWidget(view)
        if isinstance(view, HistoryView):
            view.model.replace_records((record(local="2001:db8::10", remote="2001:db8:1234:5678:abcd:ef90:1234:5678"),))
        view.resize(1280, 720)
        view.show()
        settle(qtbot)
        local, remote = view.table.columnWidth(3), view.table.columnWidth(4)
        view.resize(1920, 1080)
        settle(qtbot)
        if isinstance(view, ConnectionsView):
            assert view.table.columnWidth(3) > local
            assert view.table.columnWidth(4) > remote
        else:
            assert view.table.columnWidth(3) == local
            assert view.table.columnWidth(4) == remote
        assert view.table.columnWidth(1) < view.table.columnWidth(4)
        assert view.table.columnWidth(2) < view.table.columnWidth(4)
        font = view.font()
        font.setPointSize(font.pointSize() + 6)
        view.setFont(font)
        view.resize(1600, 900)
        settle(qtbot)
        assert view.table.viewport().height() // view.table.verticalHeader().defaultSectionSize() >= 6


@pytest.mark.parametrize("created", (None, datetime(1970, 1, 1, tzinfo=UTC),
                                     datetime(1601, 1, 1, tzinfo=UTC),
                                     datetime(1969, 12, 31, 23, 59, tzinfo=UTC)))
@pytest.mark.parametrize("pid", (0, 4242))
def test_process_epoch_and_missing_values_are_unavailable_for_any_pid(created, pid):
    process = ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(pid, created), "process.exe")
    assert process_context_text(process)["process_create_time"] == "Not available"
    saved = record()
    row = history_row_from_record(replace(saved, snapshot=replace(saved.snapshot, process=process)))
    assert row.process_create_time_display == "Not available"
    assert process.identity.create_time == created  # Presentation does not change identity.


@pytest.mark.parametrize("created", (datetime(1970, 1, 1, tzinfo=UTC), datetime(1601, 1, 1, tzinfo=UTC), BASE))
def test_parent_creation_uses_same_normalization(created):
    parent = ParentProcessInfo(ParentProcessStatus.OBSERVED, BASE, parent_pid=100,
                              identity=ProcessIdentity(100, created), name="parent.exe",
                              pid_status=ProcessInfoStatus.AVAILABLE,
                              create_time_status=ProcessInfoStatus.AVAILABLE,
                              name_status=ProcessInfoStatus.AVAILABLE)
    process = ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(42, BASE), "child.exe", parent=parent)
    text = process_context_text(process)
    assert text["parent_create_time"] == ("Not available" if created.year <= 1970 else BASE.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z"))
    assert text["parent_observed_at"] == BASE.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z")


def test_creation_normalization_compares_utc_epoch_and_keeps_valid_precision():
    epoch_local = datetime(1970, 1, 1, 3, tzinfo=timezone(timedelta(hours=3)))
    assert format_process_created(epoch_local) == "Not available"
    assert format_process_created(datetime(2026, 1, 1)) == "Not available"
    assert format_process_created(BASE) == BASE.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z")
    assert format_process_created(None, ProcessInfoStatus.ACCESS_DENIED) == "Restricted by Windows permissions"


def contrast(a, b):
    def luminance(c):
        values = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                  for v in (c.redF(), c.greenF(), c.blueF())]
        return sum(v * weight for v, weight in zip(values, (0.2126, 0.7152, 0.0722)))
    x, y = sorted((luminance(a), luminance(b)))
    return (y + 0.05) / (x + 0.05)


@pytest.mark.parametrize("dark", (True, False))
def test_dashboard_cards_headings_and_empty_pages_follow_native_palette(qtbot, qapp, dark):
    original = qapp.palette()
    palette = QPalette(original)
    background, foreground, card = (("#202020", "#eeeeee", "#303030") if dark else
                                    ("#ffffff", "#202020", "#f0f0f0"))
    for role, color in ((QPalette.ColorRole.Window, background), (QPalette.ColorRole.Base, background),
                        (QPalette.ColorRole.AlternateBase, card), (QPalette.ColorRole.WindowText, foreground),
                        (QPalette.ColorRole.Text, foreground)):
        palette.setColor(role, QColor(color))
    qapp.setPalette(palette)
    try:
        window = MainWindow()
        qtbot.addWidget(window)
        window.resize(1366, 768)
        window.show()
        for page in PageId:
            window.navigate_to(page)
            settle(qtbot)
            widget = window.page_widget(page)
            headings = [label for label in widget.findChildren(QLabel) if "font-size: 24px" in label.styleSheet()]
            for label in headings:
                assert contrast(label.palette().color(QPalette.ColorRole.WindowText), palette.color(QPalette.ColorRole.Window)) >= 4.5
            if isinstance(widget, DashboardView):
                for name in ("dashboardTrafficCard", "dashboardVlanCard", "dashboardHealthCard"):
                    frame = widget.findChild(QFrame, name)
                    assert frame is not None
                    bg = frame.palette().color(QPalette.ColorRole.Window)
                    assert bg == QColor(card)
                    for label in frame.findChildren(QLabel):
                        assert contrast(label.palette().color(QPalette.ColorRole.WindowText), bg) >= 4.5
                assert contrast(widget.vlan_rows.palette().color(QPalette.ColorRole.Text), widget.vlan_rows.palette().color(QPalette.ColorRole.Base)) >= 4.5
        brand = window.findChild(QLabel, "brand")
        assert brand.palette().color(QPalette.ColorRole.WindowText) == QColor("#102a43")
        assert "#f4f6f8" in window.navigation.styleSheet()
    finally:
        qapp.setPalette(original)
