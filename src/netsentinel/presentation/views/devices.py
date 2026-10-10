"""Passive LAN device inventory, binding detail, and capture capability."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import translate

from uuid import UUID

from typing import cast
from PyQt6.QtCore import QAbstractItemModel
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QHeaderView
from PyQt6.QtCore import QSortFilterProxyModel, Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QTableView, QVBoxLayout, QWidget)

from netsentinel.presentation.theme import PAGE_TITLE, SECONDARY_TEXT
from netsentinel.presentation.widgets.page_flow import MonitoringPageScroll
from netsentinel.application.services.device_inventory import DeviceInventoryProblem, DeviceInventorySnapshot
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator
from netsentinel.presentation.device_profile import DeviceProfileCoordinator
from netsentinel.presentation.widgets.device_profile import DeviceProfileDialog
from netsentinel.domain.devices import DeviceProfile
from netsentinel.presentation.models.devices import DeviceRow, DevicesTableModel, ROW_ID_ROLE, SEARCH_ROLE, format_seen
from netsentinel.presentation.viewmodels import MISSING_VALUE
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureState


class DevicesFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._term = ""
        self.setDynamicSortFilter(True)

    def set_search(self, value: str) -> None:
        self._term = value.strip().casefold()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # noqa: N802
        if not self._term:
            return True
        source = cast(QAbstractItemModel, self.sourceModel())
        values = source.data(source.index(source_row, 0, source_parent), SEARCH_ROLE)
        return any(self._term in value.casefold() for value in values)


class DeviceDetailsWidget(QGroupBox):
    def __init__(self, parent=None) -> None:
        super().__init__(translate('Devices', 'Selected device'), parent)
        self.setAccessibleName(translate('Devices', 'Device details'))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.values: dict[str, QLabel] = {}
        layout = QFormLayout(self)
        for key, title in (("mac", translate('Devices', 'MAC')), ("ip", translate('Devices', 'Last observed IPv4')),
                           ("interface", translate('Devices', 'Network / interface')), ("first", translate('Devices', 'First seen')),
                           ("last", translate('Devices', 'Last seen')), ("local", translate('Devices', 'Locally administered MAC')),
                           ("bindings", translate('Devices', 'Observed IPv4 bindings'))):
            label = QLabel(MISSING_VALUE, self)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setAccessibleName(render_text(translate('Devices', 'IP-MAC binding history') if key == 'bindings' else title))
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if key in ("bindings", "interface"):
                label.setWordWrap(True)
            self.values[key] = label
            layout.addRow(f"{title}:", label)

    def clear(self) -> None:
        for label in self.values.values():
            label.setText(render_text(MISSING_VALUE))

    def set_row(self, row: DeviceRow) -> None:
        self.values['mac'].setText(render_text(row.mac))
        self.values['ip'].setText(render_text(row.current_ip_display))
        self.values['interface'].setText(render_text(f'{row.interface_name} · {row.subnet}'))
        self.values['first'].setText(render_text(format_seen(row.first_seen)))
        self.values['last'].setText(render_text(format_seen(row.last_seen)))
        self.values['local'].setText(render_text(translate('Devices', 'Yes') if row.locally_administered else translate('Devices', 'No')))
        bindings = [format_text(translate('Devices', '{value1} (last seen {value2})'), value1=binding.ip_address, value2=format_seen(binding.last_seen)) for binding in row.bindings]
        self.values['bindings'].setText(render_text(render_join('\n', bindings) if bindings else MISSING_VALUE))


class DevicesView(QWidget):
    profile_alerts_requested = pyqtSignal(object, str)

    def __init__(self, parent: QWidget | None = None, *, coordinator: DeviceInventoryCoordinator | None = None,
                 profiles: DeviceProfileCoordinator | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("devicesView")
        self.setAccessibleName(translate('Devices', 'Devices page'))
        self.coordinator = coordinator
        self.profiles = profiles
        self.model = DevicesTableModel(self)
        self.proxy_model = DevicesFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self._selected_id: UUID | None = None
        self._snapshot: DeviceInventorySnapshot | None = None
        self._profile_generation: int | None = None
        self._profile: DeviceProfile | None = None
        self._profile_loading = False
        self._profile_busy = False
        self._stale_notice = False
        self._profile_load_error = False

        title = QLabel(translate('Devices', 'Devices'), self)
        title.setStyleSheet(PAGE_TITLE)
        subtitle = QLabel(translate('Devices', 'Passive observations on the selected local network.'), self)
        subtitle.setStyleSheet(SECONDARY_TEXT)
        self.network_selector = QComboBox(self)
        self.network_selector.setAccessibleName(translate('Devices', 'Devices network selector'))
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText(translate('Devices', 'Search MAC, IPv4 or interface'))
        self.search_edit.setAccessibleName(translate('Devices', 'Search devices'))
        self.refresh_button = QPushButton(translate('Devices', 'Refresh'), self)
        self.refresh_button.setAccessibleName(translate('Devices', 'Refresh devices'))
        self.capture_button = QPushButton(translate('Devices', 'Start passive capture'), self)
        self.capture_button.setAccessibleName(translate('Devices', 'Start or stop passive device capture'))
        self.capture_button.setEnabled(coordinator is not None)
        controls = QHBoxLayout()
        for widget in (self.network_selector, self.search_edit, self.refresh_button, self.capture_button):
            controls.addWidget(widget)

        self.status_label = QLabel(translate('Devices', 'Loading device inventory…') if coordinator else translate('Devices', 'Passive capture is off. Connect a device source to load saved observations.'), self)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setAccessibleName(translate('Devices', 'Device inventory status'))
        self.status_label.setWordWrap(True)
        self.event_label = QLabel("", self)
        self.event_label.setTextFormat(Qt.TextFormat.PlainText)
        self.event_label.setAccessibleName(translate('Devices', 'New device information'))
        self.event_label.hide()
        self.table = QTableView(self)
        self.table.setAccessibleName(translate('Devices', 'Devices table'))
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        cast(QHeaderView, self.table.verticalHeader()).hide()
        header = cast(QHeaderView, self.table.horizontalHeader())
        for column in range(4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        # Stretch the last section while retaining a readable initial width;
        # Qt can then use table horizontal scrolling when all columns do not fit.
        self.table.setColumnWidth(4, self.table.fontMetrics().horizontalAdvance(translate('Devices', 'Ethernet · 255.255.255.255/32')) + 24)
        header.setStretchLastSection(True)
        self.details = DeviceDetailsWidget(self)
        self.profile_panel = QGroupBox(translate('Devices', 'User-saved profile'), self)
        self.profile_panel.setAccessibleName(translate('Devices', 'Device profile details'))
        self.profile_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        profile_layout = QVBoxLayout(self.profile_panel)
        self.profile_status = QLabel(translate('Devices', 'Select an observed device to view its profile.'), self.profile_panel)
        self.profile_status.setTextFormat(Qt.TextFormat.PlainText)
        self.profile_status.setAccessibleName(translate('Devices', 'Profile status'))
        self.profile_status.setWordWrap(True)
        profile_layout.addWidget(self.profile_status)
        self.profile_values: dict[str, QLabel] = {}
        profile_form = QFormLayout()
        for key, field_title in (("label", translate('Devices', 'Label')), ("trust", translate('Devices', 'User trust designation')),
                           ("note", translate('Devices', 'Note')), ("macs", translate('Devices', 'Expected MACs')),
                           ("ips", translate('Devices', 'Expected IPv4')), ("updated", translate('Devices', 'Last user update')),
                           ("trust_changed", translate('Devices', 'Trust changed'))):
            value = QLabel(MISSING_VALUE, self.profile_panel)
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setAccessibleName(format_text(translate('Devices', 'Profile {value1}'), value1=field_title.lower()))
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.profile_values[key] = value
            profile_form.addRow(f"{field_title}:", value)
        profile_layout.addLayout(profile_form)
        self.profile_edit_button = QPushButton(translate('Devices', 'Create profile'), self.profile_panel)
        self.profile_edit_button.setAccessibleName(translate('Devices', 'Create or edit device profile'))
        self.profile_refresh_button = QPushButton(translate('Devices', 'Reload profile'), self.profile_panel)
        self.profile_refresh_button.setAccessibleName(translate('Devices', 'Reload selected device profile'))
        self.profile_alerts_button = QPushButton(translate('Devices', 'Related identity alerts'), self.profile_panel)
        self.profile_alerts_button.setAccessibleName(translate('Devices', 'Show related device identity alerts'))
        profile_actions = QHBoxLayout()
        profile_actions.addWidget(self.profile_edit_button)
        profile_actions.addWidget(self.profile_refresh_button)
        profile_actions.addWidget(self.profile_alerts_button)
        profile_actions.addStretch()
        profile_layout.addLayout(profile_actions)
        self._profile_controls()
        self.page_scroll = MonitoringPageScroll(self.table, self)
        layout = self.page_scroll.page_layout
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(controls)
        layout.addWidget(self.status_label)
        layout.addWidget(self.event_label)
        layout.addWidget(self.table)
        layout.addWidget(self.details)
        layout.addWidget(self.profile_panel)
        layout.addStretch(1)
        self.search_edit.textChanged.connect(self._search_changed)
        cast(QItemSelectionModel, self.table.selectionModel()).currentChanged.connect(self._selection_changed)
        self.network_selector.currentIndexChanged.connect(self._network_changed)
        self.refresh_button.clicked.connect(lambda: self._request("refresh"))
        self.capture_button.clicked.connect(self._toggle_capture)
        self.profile_edit_button.clicked.connect(self._edit_profile)
        self.profile_refresh_button.clicked.connect(self._load_profile)
        self.profile_alerts_button.clicked.connect(self._show_profile_alerts)
        if coordinator is not None:
            coordinator.snapshot_ready.connect(self.set_snapshot)
            coordinator.load_failed.connect(self._load_failed)
        if profiles is not None:
            profiles.loaded.connect(self._profile_loaded)
            profiles.load_failed.connect(self._profile_load_failed)
            profiles.saved.connect(self._profile_saved)
            profiles.save_failed.connect(self._profile_save_failed)

    @property
    def selected_row_id(self) -> UUID | None:
        return self._selected_id

    def set_snapshot(self, snapshot: DeviceInventorySnapshot) -> None:
        if self.coordinator is not None and not self.coordinator.accepting:
            return
        if not isinstance(snapshot, DeviceInventorySnapshot):
            raise TypeError("snapshot must be a DeviceInventorySnapshot")
        scope_changed = self._snapshot is not None and self._snapshot.selected_fingerprint != snapshot.selected_fingerprint
        self._snapshot = snapshot
        old_id = self._selected_id
        self.network_selector.blockSignals(True)
        self.network_selector.clear()
        for context in snapshot.contexts:
            self.network_selector.addItem(f"{context.interface_name} · {context.subnet}", context.fingerprint)
        self.network_selector.setCurrentIndex(self.network_selector.findData(snapshot.selected_fingerprint))
        self.network_selector.blockSignals(False)
        self.model.apply(snapshot.selected_fingerprint, snapshot.entries)
        self._restore_selection(old_id)
        self._update_status(snapshot)
        if scope_changed:
            self.event_label.clear()
            self.event_label.hide()
        if snapshot.new_devices:
            self.event_label.setText(format_text(translate('Devices', 'New device observed: {value1}'), value1=snapshot.new_devices[-1].device.mac))
            self.event_label.show()

    def _update_status(self, snapshot: DeviceInventorySnapshot) -> None:
        problem = snapshot.problem
        if problem is DeviceInventoryProblem.CONTEXT_PERMISSION:
            message = translate('Devices', 'Network interface information is unavailable because access was denied.')
        elif problem is DeviceInventoryProblem.CONTEXT_UNAVAILABLE:
            message = translate('Devices', 'Network interface information is temporarily unavailable.')
        elif problem is DeviceInventoryProblem.REPOSITORY_UNAVAILABLE:
            message = translate('Devices', 'Saved device inventory is unavailable. Try refreshing.')
        elif problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE:
            message = translate('Devices', 'Some device observations could not be processed. Saved inventory remains visible.')
        elif problem is DeviceInventoryProblem.ALERT_UNAVAILABLE:
            message = translate('Devices', 'Security alerts could not be saved. Device inventory remains visible.')
        elif snapshot.selected_fingerprint is None:
            message = translate('Devices', 'No active local network context is available.')
        else:
            health = snapshot.capture
            reason = health.capability.reason if health is not None else CaptureCapabilityReason.NOT_PROBED
            if reason is CaptureCapabilityReason.PERMISSION_DENIED:
                message = translate('Devices', 'Passive capture needs permission for this interface. Saved devices remain visible.')
            elif reason is CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE:
                message = translate('Devices', 'Passive capture is unavailable. Scapy or Npcap may be missing. Saved devices remain visible.')
            elif reason in (CaptureCapabilityReason.INTERFACE_UNAVAILABLE, CaptureCapabilityReason.NETWORK_CHANGED):
                message = translate('Devices', 'The selected network interface changed or is unavailable.')
            elif reason is CaptureCapabilityReason.TRANSIENT_FAILURE:
                message = translate('Devices', 'Passive capture is temporarily unavailable. Saved devices remain visible.')
            elif health is not None and health.state is CaptureState.RUNNING:
                message = translate('Devices', 'Passive capture active · %n observed device(s).', None, len(snapshot.entries))
            else:
                message = translate('Devices', 'Passive capture is off. Showing saved observations; the list may be incomplete.')
        self.status_label.setText(render_text(message))
        running = snapshot.capture is not None and snapshot.capture.state is CaptureState.RUNNING
        self.capture_button.setText(render_text(translate('Devices', 'Stop passive capture') if running else translate('Devices', 'Start passive capture')))
        self.capture_button.setEnabled(self.coordinator is not None and snapshot.selected_fingerprint is not None)

    def _restore_selection(self, row_id: UUID | None) -> None:
        if row_id is not None:
            for proxy_row in range(self.proxy_model.rowCount()):
                index = self.proxy_model.index(proxy_row, 0)
                if index.data(ROW_ID_ROLE) == row_id:
                    self.table.setCurrentIndex(index)
                    row = self.model.row_for_id(row_id)
                    if row is not None:
                        self._selected_id = row_id
                        self.details.set_row(row)
                    return
        self.table.clearSelection()
        self._selected_id = None
        self.details.clear()
        self._clear_profile()

    def _selection_changed(self, current, _previous) -> None:
        previous_id = self._selected_id
        row_id = current.data(ROW_ID_ROLE) if current.isValid() else None
        self._selected_id = row_id if isinstance(row_id, UUID) else None
        row = self.model.row_for_id(self._selected_id) if self._selected_id else None
        self.details.clear() if row is None else self.details.set_row(row)
        if self._selected_id != previous_id:
            self._load_profile()

    def _clear_profile(self) -> None:
        if self.profiles is not None:
            self.profiles.invalidate()
        self._profile_generation = None
        self._profile = None
        self._profile_loading = False
        self._profile_load_error = False
        self.profile_status.setText(translate('Devices', 'Select an observed device to view its profile.'))
        for value in self.profile_values.values():
            value.setText(render_text(MISSING_VALUE))
        self._profile_controls()

    def _load_profile(self) -> None:
        self._profile = None
        for value in self.profile_values.values():
            value.setText(render_text(MISSING_VALUE))
        if self._selected_id is None:
            self._clear_profile()
            return
        if self.profiles is None:
            self.profile_status.setText(translate('Devices', 'Saved profiles are unavailable.'))
            self._profile_controls()
            return
        self._profile_loading = True
        self._profile_load_error = False
        self.profile_status.setText(translate('Devices', 'Loading user profile…'))
        self._profile_controls()
        try:
            self._profile_generation = self.profiles.load(self._selected_id)
        except RuntimeError:
            self._profile_loading = False
            self._profile_load_error = True
            self.profile_status.setText(translate('Devices', 'Saved profiles are unavailable. Try selecting this device again.'))
            self._profile_controls()

    def _profile_loaded(self, generation: int, device_id: object, profile: object) -> None:
        if self.profiles is not None and not self.profiles.accepting:
            return
        if generation != self._profile_generation or device_id != self._selected_id:
            return
        self._profile_loading = False
        self._profile_load_error = False
        self._profile = profile if isinstance(profile, DeviceProfile) else None
        if self._profile is None:
            self.profile_status.setText(translate('Devices', 'No user profile is saved for this observed device.'))
        else:
            self.profile_status.setText(render_text(translate('Devices', 'Profile changed elsewhere. Latest values loaded; review and retry.') if self._stale_notice else translate('Devices', 'User-saved expectations; observations do not edit this profile.')))
            self.profile_values['label'].setText(render_text(self._profile.label or MISSING_VALUE))
            self.profile_values['trust'].setText(render_text(display_enum(self._profile.trust, 'title')))
            self.profile_values['note'].setText(render_text(self._profile.note or MISSING_VALUE))
            self.profile_values['macs'].setText(render_text(render_join(', ', map(str, self._profile.expected_macs)) or MISSING_VALUE))
            self.profile_values['ips'].setText(render_text(render_join(', ', self._profile.expected_ips) or MISSING_VALUE))
            self.profile_values['updated'].setText(render_text(format_seen(self._profile.updated_at)))
            self.profile_values['trust_changed'].setText(render_text(format_seen(self._profile.trust_changed_at) if self._profile.trust_changed_at else MISSING_VALUE))
        self._stale_notice = False
        self._profile_controls()

    def _profile_load_failed(self, generation: int, device_id: object) -> None:
        if self.profiles is not None and not self.profiles.accepting:
            return
        if generation != self._profile_generation or device_id != self._selected_id:
            return
        self._profile_loading = False
        self._profile_load_error = True
        self.profile_status.setText(translate('Devices', 'Saved profile is unavailable. Try selecting this device again.'))
        self._profile_controls()

    def _profile_controls(self) -> None:
        available = self.profiles is not None and self._selected_id is not None
        self.profile_edit_button.setEnabled(available and not self._profile_loading and not self._profile_busy
                                            and not self._profile_load_error)
        self.profile_edit_button.setText(render_text(translate('Devices', 'Edit profile') if self._profile else translate('Devices', 'Create profile')))
        self.profile_refresh_button.setEnabled(available and not self._profile_loading and not self._profile_busy)
        self.profile_alerts_button.setEnabled(self._profile is not None and not self._profile_loading
                                              and not self._profile_busy)

    def _edit_profile(self) -> None:
        row = self.model.row_for_id(self._selected_id) if self._selected_id else None
        if row is None or self.profiles is None or self._profile_loading or self._profile_busy:
            return
        dialog = DeviceProfileDialog(self._profile, row.mac, row.ip_address, self)
        result = dialog.exec()
        draft = dialog.draft
        dialog.deleteLater()
        if result != DeviceProfileDialog.DialogCode.Accepted or draft is None:
            return
        self._profile_busy = True
        self.profile_status.setText(translate('Devices', 'Saving user profile…'))
        self._profile_controls()
        if not self.profiles.save(row.row_id, row.network_fingerprint, self._profile, draft):
            self._profile_save_failed(row.row_id, "unavailable")

    def _profile_saved(self, device_id: object, profile: object) -> None:
        if self.profiles is not None and not self.profiles.accepting:
            return
        self._profile_busy = False
        if device_id == self._selected_id:
            self.profile_status.setText(translate('Devices', 'Profile saved. Reloading…'))
            self._load_profile()
        self._request("refresh")

    def _profile_save_failed(self, device_id: object, reason: str) -> None:
        if self.profiles is not None and not self.profiles.accepting:
            return
        self._profile_busy = False
        if device_id == self._selected_id:
            self.profile_status.setText(render_text(translate('Devices', 'Profile changed elsewhere. Latest values are loading; review and retry.') if reason == 'stale' else translate('Devices', 'Profile could not be saved. Review values and try again.') if reason == 'invalid' else translate('Devices', 'Profile storage is unavailable. Try again.')))
            if reason == "stale":
                self._stale_notice = True
                self._load_profile()
            else:
                self._profile_controls()

    def _show_profile_alerts(self) -> None:
        if self._profile is not None:
            self.profile_alerts_requested.emit(self._profile.profile_id, self._profile.network_fingerprint)

    def _search_changed(self, text: str) -> None:
        previous_id = self._selected_id
        self.proxy_model.set_search(text)
        self._restore_selection(previous_id)

    def _network_changed(self, index: int) -> None:
        if index >= 0:
            self._request("select", self.network_selector.itemData(index))

    def _toggle_capture(self) -> None:
        running = self._snapshot is not None and self._snapshot.capture is not None and self._snapshot.capture.state is CaptureState.RUNNING
        self._request("capture_stop" if running else "capture_start")

    def _request(self, command: str, fingerprint: str | None = None) -> None:
        if self.coordinator is not None:
            self.coordinator.request(command, fingerprint)

    def _load_failed(self) -> None:
        if self.coordinator is None or self.coordinator.accepting:
            self.status_label.setText(translate('Devices', 'Device inventory is unavailable. Try refreshing.'))


__all__ = ("DeviceDetailsWidget", "DevicesFilterProxyModel", "DevicesView")
