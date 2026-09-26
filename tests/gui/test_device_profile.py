"""NS-041 explicit profile editing and stale Qt delivery."""

from datetime import UTC, datetime
from threading import Event
from uuid import uuid4

from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QDialog

from netsentinel.application.services.device_profiles import DeviceProfileService, ProfileEdit
from netsentinel.domain.devices import DeviceProfile, DeviceTrust
from netsentinel.presentation.device_profile import DeviceProfileCoordinator
from netsentinel.presentation.views.devices import DevicesView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.presentation.widgets.device_profile import DeviceProfileDialog
from tests.gui.test_devices_view import context, entry, snapshot


def test_editor_cancel_validation_expected_identity_and_accessibility(qtbot):
    dialog = DeviceProfileDialog(None, "02:11:22:33:44:55", "192.168.1.40")
    qtbot.addWidget(dialog)
    assert dialog.label_edit.accessibleName() == "Profile label"
    assert dialog.note_edit.accessibleName() == "Profile note"
    assert dialog.trust_selector.accessibleName() == "Trust selector"
    dialog.observed_mac_button.click()
    dialog.observed_ip_button.click()
    assert dialog.mac_list.item(0).text() == "02:11:22:33:44:55"
    assert dialog.ip_list.item(0).text() == "192.168.1.40"
    dialog.add_mac.click()
    assert "valid" in dialog.error_label.text()
    dialog.mac_input.setText("02-11-22-33-44-55")
    dialog.add_mac.click()
    assert "already" in dialog.error_label.text()
    dialog.note_edit.setPlainText("x" * 1025)
    dialog.save_button.click()
    assert "1024" in dialog.error_label.text()
    assert dialog.draft is None
    dialog.cancel_button.click()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.draft is None


def test_editor_save_returns_explicit_draft(qtbot):
    dialog = DeviceProfileDialog(None, "02:11:22:33:44:55", "192.168.1.40")
    qtbot.addWidget(dialog)
    dialog.label_edit.setText("Laptop")
    dialog.note_edit.setPlainText("Owner note")
    dialog.trust_selector.setCurrentIndex(dialog.trust_selector.findData(DeviceTrust.TRUSTED))
    dialog.observed_mac_button.click()
    dialog.observed_ip_button.click()
    dialog.save_button.click()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.draft == ProfileEdit("Laptop", "Owner note", DeviceTrust.TRUSTED,
                                       ("02:11:22:33:44:55",), ("192.168.1.40",))


def test_profile_worker_and_view_latest_selection(qtbot):
    ctx = context()
    a = entry(ctx)
    b = entry(ctx, mac="02:11:22:33:44:66", ip="192.168.1.41")
    class Repository:
        def get_for_device(self, device_id):
            return None
    coordinator = DeviceProfileCoordinator(lambda: DeviceProfileService(Repository()))
    view = DevicesView(profiles=coordinator)
    qtbot.addWidget(view)
    assert coordinator.start()
    view.set_snapshot(snapshot(ctx, (a, b)))
    view.table.selectRow(0)
    qtbot.waitUntil(lambda: "No user profile" in view.profile_status.text())
    first = view.selected_row_id
    view.table.selectRow(1)
    second = view.selected_row_id
    assert first != second
    stale = DeviceProfile(uuid4(), ctx.fingerprint, "Old", "", DeviceTrust.UNKNOWN,
                          datetime.now(UTC), datetime.now(UTC))
    coordinator.loaded.emit(view._profile_generation - 1, first, stale)
    qtbot.waitUntil(lambda: "No user profile" in view.profile_status.text())
    assert view._profile is None
    assert view.profile_edit_button.isEnabled()
    assert coordinator.stop()
    assert not coordinator.worker_alive
    before = view.profile_status.text()
    coordinator.loaded.emit(view._profile_generation, second, stale)
    assert view.profile_status.text() == before


def test_profile_save_is_serial_and_uses_worker_thread(qtbot):
    ctx = context()
    a = entry(ctx)
    class Repository:
        def __init__(self):
            self.profile = None
            self.thread = None
        def get_for_device(self, device_id):
            self.thread = QThread.currentThread()
            return self.profile
        def create(self, device_id, profile):
            self.profile = profile
            self.thread = QThread.currentThread()
            return profile
    repo = Repository()
    coordinator = DeviceProfileCoordinator(lambda: DeviceProfileService(repo))
    view = DevicesView(profiles=coordinator)
    qtbot.addWidget(view)
    coordinator.start()
    view.set_snapshot(snapshot(ctx, (a,)))
    view.table.selectRow(0)
    qtbot.waitUntil(lambda: "No user profile" in view.profile_status.text())
    edit = ProfileEdit("Laptop", "Private note", DeviceTrust.TRUSTED,
                       ("02:11:22:33:44:55",), ("192.168.1.40",))
    assert coordinator.save(a.device.device_id, ctx.fingerprint, None, edit)
    qtbot.waitUntil(lambda: view.profile_values["label"].text() == "Laptop")
    assert repo.thread is not view.thread()
    assert repo.profile.trust_changed_at is not None
    assert view.profile_values["note"].text() == "Private note"
    assert view.profile_values["macs"].text() == "02:11:22:33:44:55"
    assert coordinator.stop()


def test_profile_alert_link_opens_scoped_alert_browser(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    profile_id = uuid4()
    fingerprint = "a" * 64
    window._show_profile_alerts(profile_id, fingerprint)
    assert window.current_page is PageId.ALERTS
    alerts = window.page_widget(PageId.ALERTS)
    assert alerts._linked_profile == (str(profile_id), fingerprint)


def test_profile_worker_bounds_pending_writes(qtbot):
    entered, release = Event(), Event()
    calls = []
    class SlowService:
        def save(self, device_id, fingerprint, original, edit):
            calls.append(edit.label)
            if len(calls) == 1:
                entered.set()
                release.wait(2)
            return None
    coordinator = DeviceProfileCoordinator(lambda: SlowService())
    assert coordinator.start()
    device_id = uuid4()
    def edit(label):
        return ProfileEdit(label, "", DeviceTrust.UNKNOWN, (), ())
    assert coordinator.save(device_id, "a" * 64, None, edit("first"))
    qtbot.waitUntil(entered.is_set)
    assert coordinator.save(device_id, "a" * 64, None, edit("second"))
    assert not coordinator.save(device_id, "a" * 64, None, edit("third"))
    release.set()
    qtbot.waitUntil(lambda: calls == ["first", "second"])
    assert coordinator.stop()
