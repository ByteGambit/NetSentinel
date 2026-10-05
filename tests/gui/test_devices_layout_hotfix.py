"""Unnumbered Devices maintenance: list height, page flow and profile access."""

from dataclasses import replace
from datetime import timedelta

import pytest
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QApplication, QHeaderView, QScrollArea, QSizePolicy

from netsentinel.application.services.device_profiles import DeviceProfileService
from netsentinel.domain.devices import IdentityBinding
from netsentinel.presentation.device_profile import DeviceProfileCoordinator
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.presentation.widgets.device_profile import DeviceProfileDialog
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureState
from tests.gui.test_devices_view import AT, context, entry, health, snapshot
from tests.gui.test_ui_hotfix import SIZES, assert_reachable, settle, wheel


def entries(ctx, count):
    return tuple(entry(ctx, mac=f"02:11:22:33:44:{i:02x}", ip=f"192.168.1.{i + 20}")
                 for i in range(count))


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("count", (0, 1, 32))
@pytest.mark.parametrize("running", (False, True))
def test_devices_list_height_and_page_flow_do_not_depend_on_count_or_capture(qtbot, size, count, running):
    window = MainWindow()
    qtbot.addWidget(window)
    window.resize(*size)
    window.show()
    window.navigate_to(PageId.DEVICES)
    view = window.page_widget(PageId.DEVICES)
    assert isinstance(view, DevicesView)
    ctx = context()
    rows = entries(ctx, count)
    view.set_snapshot(snapshot(ctx, rows, capability=health(
        state=CaptureState.RUNNING if running else CaptureState.STOPPED,
        reason=CaptureCapabilityReason.NONE)))
    settle(qtbot)
    assert view.model.rowCount() == count
    assert 6 <= view.table.viewport().height() // view.table.verticalHeader().defaultSectionSize() <= 10
    initial_height = view.table.height()
    assert view.table.viewport().mapTo(view.page_scroll.viewport(), view.table.viewport().rect().bottomLeft()).y() <= view.page_scroll.viewport().height()
    assert view.details.isVisible() and view.profile_panel.isVisible()
    assert view.details.sizePolicy().verticalPolicy() is QSizePolicy.Policy.Maximum
    assert view.profile_panel.sizePolicy().verticalPolicy() is QSizePolicy.Policy.Maximum
    assert view.findChildren(QScrollArea) == [view.page_scroll]
    if size[1] <= 768:
        assert view.page_scroll.verticalScrollBar().maximum() > 0
    assert view.page_scroll.horizontalScrollBar().maximum() == 0
    if running:
        assert view.status_label.text() == f"Passive capture active · {count} observed device(s)."
        assert view.capture_button.text() == "Stop passive capture"
    else:
        assert view.status_label.text() == "Passive capture is off. Showing saved observations; the list may be incomplete."
        assert view.capture_button.text() == "Start passive capture"
    if count:
        view.table.selectRow(0)
        assert view.details.values["mac"].text() == str(rows[0].device.mac)
        assert view.selected_row_id == rows[0].device.device_id
        assert_reachable(view.page_scroll, view.details.values["bindings"], qtbot)
        view.page_scroll.verticalScrollBar().setValue(0)
        assert not wheel(view.details.values["mac"]).isAccepted()
        wheel(view.page_scroll.viewport())
        if view.page_scroll.verticalScrollBar().maximum() > 0:
            assert view.page_scroll.verticalScrollBar().value() > 0
    for button in (view.profile_edit_button, view.profile_refresh_button, view.profile_alerts_button):
        assert_reachable(view.page_scroll, button, qtbot)
    assert view.table.height() == initial_height
    if count > 10:
        assert view.table.verticalScrollBar().maximum() > 0
        view.table.selectRow(count - 1)
        settle(qtbot)
        assert view.details.values["mac"].text() == str(rows[-1].device.mac)
        assert view.selected_row_id == rows[-1].device.device_id
        assert view.table.rowAt(0) > 0
        assert view.table.rowViewportPosition(count - 1) < view.table.viewport().height()


@pytest.mark.parametrize("size", SIZES)
def test_long_detail_and_profile_expand_without_squeezing_table(qtbot, size):
    view = DevicesView()
    qtbot.addWidget(view)
    view.resize(size[0] - 300, size[1] - 50)
    view.show()
    ctx = context("Ethernet with a long interface description " * 3)
    one = entry(ctx)
    older = tuple(IdentityBinding(ctx.fingerprint, one.device.mac, f"192.168.1.{i}",
                                 AT - timedelta(minutes=i), AT - timedelta(minutes=i)) for i in range(1, 20))
    view.set_snapshot(snapshot(ctx, (replace(one, bindings=one.bindings + older),)))
    view.table.selectRow(0)
    settle(qtbot)
    before = view.table.height()
    view.profile_values["note"].setText("\n".join(f"Saved profile note line {i}" for i in range(40)))
    settle(qtbot)
    assert view.table.height() == before
    for label in (view.details.values["bindings"], view.details.values["interface"], view.profile_values["note"]):
        assert label.height() >= label.heightForWidth(label.width())
    assert not view.details.findChildren(QScrollArea)
    assert not view.profile_panel.findChildren(QScrollArea)
    assert_reachable(view.page_scroll, view.profile_alerts_button, qtbot)


def test_network_column_stretches_with_readable_minimum_and_horizontal_access(qtbot):
    view = DevicesView()
    qtbot.addWidget(view)
    view.resize(980, 670)
    view.show()
    ctx = context()
    view.set_snapshot(snapshot(ctx, entries(ctx, 32)))
    settle(qtbot)
    header = view.table.horizontalHeader()
    assert header.stretchLastSection()
    for column in range(4):
        assert header.sectionResizeMode(column) is QHeaderView.ResizeMode.ResizeToContents
    assert view.table.columnWidth(4) >= view.table.fontMetrics().horizontalAdvance("Ethernet · 255.255.255.255/32")
    narrow = view.table.columnWidth(4)
    view.resize(2400, 1080)
    settle(qtbot)
    assert view.table.columnWidth(4) > narrow
    view.resize(850, 500)
    settle(qtbot)
    assert view.table.horizontalScrollBar().maximum() > 0
    view.table.scrollTo(view.proxy_model.index(0, 4))
    settle(qtbot)
    assert view.table.columnViewportPosition(4) < view.table.viewport().width()
    assert view.table.columnWidth(4) >= narrow
    assert view.page_scroll.horizontalScrollBar().maximum() == 0


def test_larger_font_keeps_at_least_six_rows(qtbot):
    view = DevicesView()
    qtbot.addWidget(view)
    font = view.font()
    font.setPointSize(font.pointSize() + 6)
    view.setFont(font)
    view.resize(980, 670)
    view.show()
    view.set_snapshot(snapshot(context(), entries(context(), 32)))
    settle(qtbot)
    assert view.table.verticalHeader().defaultSectionSize() >= view.table.fontMetrics().height() + 10
    assert view.table.viewport().height() // view.table.verticalHeader().defaultSectionSize() >= 6


def test_profile_buttons_work_after_page_scroll_and_keyboard_selection(qtbot):
    class Repository:
        profile = None
        loads = 0

        def get_for_device(self, device_id):
            self.loads += 1
            return self.profile

        def create(self, device_id, profile):
            self.profile = profile
            return profile

    repository = Repository()
    coordinator = DeviceProfileCoordinator(lambda: DeviceProfileService(repository))
    window = MainWindow(device_profiles=coordinator)
    qtbot.addWidget(window)
    window.resize(1280, 720)
    window.show()
    window.navigate_to(PageId.DEVICES)
    view = window.page_widget(PageId.DEVICES)
    assert isinstance(view, DevicesView)
    ctx = context()
    rows = entries(ctx, 2)
    assert coordinator.start()
    try:
        view.set_snapshot(snapshot(ctx, rows))
        view.table.setCurrentIndex(view.proxy_model.index(0, 0))
        view.table.setFocus()
        qtbot.keyClick(view.table, Qt.Key.Key_Down)
        assert view.selected_row_id == rows[1].device.device_id
        qtbot.waitUntil(lambda: not view._profile_loading)
        assert view.profile_edit_button.isEnabled()
        assert_reachable(view.page_scroll, view.profile_edit_button, qtbot)

        def fill_and_save():
            dialog = QApplication.activeModalWidget()
            assert isinstance(dialog, DeviceProfileDialog)
            dialog.label_edit.setText("Layout test profile")
            dialog.note_edit.setPlainText("Saved locally in the fixture repository")
            dialog.save_button.click()

        QTimer.singleShot(0, fill_and_save)
        qtbot.mouseClick(view.profile_edit_button, Qt.MouseButton.LeftButton)
        qtbot.waitUntil(lambda: view.profile_values["label"].text() == "Layout test profile")
        assert view.profile_values["note"].text() == "Saved locally in the fixture repository"
        assert view.profile_edit_button.text() == "Edit profile"
        assert_reachable(view.page_scroll, view.profile_refresh_button, qtbot)
        before = repository.loads
        qtbot.mouseClick(view.profile_refresh_button, Qt.MouseButton.LeftButton)
        qtbot.waitUntil(lambda: repository.loads > before and not view._profile_loading)
        assert view.profile_alerts_button.isEnabled()
        assert_reachable(view.page_scroll, view.profile_alerts_button, qtbot)
        qtbot.mouseClick(view.profile_alerts_button, Qt.MouseButton.LeftButton)
        assert window.current_page is PageId.ALERTS
        assert window.page_widget(PageId.ALERTS)._linked_profile == (
            str(repository.profile.profile_id), ctx.fingerprint)
    finally:
        assert coordinator.stop()
