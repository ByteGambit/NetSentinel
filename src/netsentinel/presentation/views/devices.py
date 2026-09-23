"""Passive LAN device inventory, binding detail, and capture capability."""

from __future__ import annotations

from uuid import UUID

from PyQt6.QtCore import QSortFilterProxyModel, Qt
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QSplitter, QTableView, QVBoxLayout, QWidget)

from netsentinel.application.services.device_inventory import DeviceInventoryProblem, DeviceInventorySnapshot
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator
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
        source = self.sourceModel()
        values = source.data(source.index(source_row, 0, source_parent), SEARCH_ROLE)
        return any(self._term in value.casefold() for value in values)


class DeviceDetailsWidget(QGroupBox):
    def __init__(self, parent=None) -> None:
        super().__init__("Selected device", parent)
        self.setAccessibleName("Device details")
        self.values: dict[str, QLabel] = {}
        layout = QFormLayout(self)
        for key, title in (("mac", "MAC"), ("ip", "Last observed IPv4"),
                           ("interface", "Network / interface"), ("first", "First seen"),
                           ("last", "Last seen"), ("local", "Locally administered MAC"),
                           ("bindings", "Observed IPv4 bindings")):
            label = QLabel(MISSING_VALUE, self)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setAccessibleName("IP-MAC binding history" if key == "bindings" else title)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if key == "bindings":
                label.setWordWrap(True)
            self.values[key] = label
            layout.addRow(f"{title}:", label)

    def clear(self) -> None:
        for label in self.values.values():
            label.setText(MISSING_VALUE)

    def set_row(self, row: DeviceRow) -> None:
        self.values["mac"].setText(row.mac)
        self.values["ip"].setText(row.current_ip_display)
        self.values["interface"].setText(f"{row.interface_name} · {row.subnet}")
        self.values["first"].setText(format_seen(row.first_seen))
        self.values["last"].setText(format_seen(row.last_seen))
        self.values["local"].setText("Yes" if row.locally_administered else "No")
        bindings = [f"{binding.ip_address} (last seen {format_seen(binding.last_seen)})" for binding in row.bindings]
        self.values["bindings"].setText("\n".join(bindings) if bindings else MISSING_VALUE)


class DevicesView(QWidget):
    def __init__(self, parent: QWidget | None = None, *, coordinator: DeviceInventoryCoordinator | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("devicesView")
        self.setAccessibleName("Devices page")
        self.coordinator = coordinator
        self.model = DevicesTableModel(self)
        self.proxy_model = DevicesFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self._selected_id: UUID | None = None
        self._snapshot: DeviceInventorySnapshot | None = None

        title = QLabel("Devices", self)
        title.setStyleSheet("font-size: 24px; font-weight: 700; color: #102a43;")
        subtitle = QLabel("Passive observations on the selected local network.", self)
        subtitle.setStyleSheet("color: #627d98;")
        self.network_selector = QComboBox(self)
        self.network_selector.setAccessibleName("Devices network selector")
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText("Search MAC, IPv4 or interface")
        self.search_edit.setAccessibleName("Search devices")
        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.setAccessibleName("Refresh devices")
        self.capture_button = QPushButton("Start passive capture", self)
        self.capture_button.setAccessibleName("Start or stop passive device capture")
        self.capture_button.setEnabled(coordinator is not None)
        controls = QHBoxLayout()
        for widget in (self.network_selector, self.search_edit, self.refresh_button, self.capture_button):
            controls.addWidget(widget)

        self.status_label = QLabel("Loading device inventory…" if coordinator else "Passive capture is off. Connect a device source to load saved observations.", self)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setAccessibleName("Device inventory status")
        self.status_label.setWordWrap(True)
        self.event_label = QLabel("", self)
        self.event_label.setTextFormat(Qt.TextFormat.PlainText)
        self.event_label.setAccessibleName("New device information")
        self.event_label.hide()
        self.table = QTableView(self)
        self.table.setAccessibleName("Devices table")
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        for column, width in enumerate((165, 165, 175, 175, 250)):
            self.table.setColumnWidth(column, width)
        self.details = DeviceDetailsWidget(self)
        splitter = QSplitter(Qt.Orientation.Vertical, self)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(controls)
        layout.addWidget(self.status_label)
        layout.addWidget(self.event_label)
        layout.addWidget(splitter, 1)
        self.search_edit.textChanged.connect(self._search_changed)
        self.table.selectionModel().currentChanged.connect(self._selection_changed)
        self.network_selector.currentIndexChanged.connect(self._network_changed)
        self.refresh_button.clicked.connect(lambda: self._request("refresh"))
        self.capture_button.clicked.connect(self._toggle_capture)
        if coordinator is not None:
            coordinator.snapshot_ready.connect(self.set_snapshot)
            coordinator.load_failed.connect(self._load_failed)

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
            self.event_label.setText(f"New device observed: {snapshot.new_devices[-1].device.mac}")
            self.event_label.show()

    def _update_status(self, snapshot: DeviceInventorySnapshot) -> None:
        problem = snapshot.problem
        if problem is DeviceInventoryProblem.CONTEXT_PERMISSION:
            message = "Network interface information is unavailable because access was denied."
        elif problem is DeviceInventoryProblem.CONTEXT_UNAVAILABLE:
            message = "Network interface information is temporarily unavailable."
        elif problem is DeviceInventoryProblem.REPOSITORY_UNAVAILABLE:
            message = "Saved device inventory is unavailable. Try refreshing."
        elif problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE:
            message = "Some device observations could not be processed. Saved inventory remains visible."
        elif snapshot.selected_fingerprint is None:
            message = "No active local network context is available."
        else:
            health = snapshot.capture
            reason = health.capability.reason if health is not None else CaptureCapabilityReason.NOT_PROBED
            if reason is CaptureCapabilityReason.PERMISSION_DENIED:
                message = "Passive capture needs permission for this interface. Saved devices remain visible."
            elif reason is CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE:
                message = "Passive capture is unavailable. Scapy or Npcap may be missing. Saved devices remain visible."
            elif reason in (CaptureCapabilityReason.INTERFACE_UNAVAILABLE, CaptureCapabilityReason.NETWORK_CHANGED):
                message = "The selected network interface changed or is unavailable."
            elif reason is CaptureCapabilityReason.TRANSIENT_FAILURE:
                message = "Passive capture is temporarily unavailable. Saved devices remain visible."
            elif health is not None and health.state is CaptureState.RUNNING:
                message = f"Passive capture active · {len(snapshot.entries)} observed device(s)."
            else:
                message = "Passive capture is off. Showing saved observations; the list may be incomplete."
        self.status_label.setText(message)
        running = snapshot.capture is not None and snapshot.capture.state is CaptureState.RUNNING
        self.capture_button.setText("Stop passive capture" if running else "Start passive capture")
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

    def _selection_changed(self, current, _previous) -> None:
        row_id = current.data(ROW_ID_ROLE) if current.isValid() else None
        self._selected_id = row_id if isinstance(row_id, UUID) else None
        row = self.model.row_for_id(self._selected_id) if self._selected_id else None
        self.details.clear() if row is None else self.details.set_row(row)

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
            self.status_label.setText("Device inventory is unavailable. Try refreshing.")


__all__ = ("DeviceDetailsWidget", "DevicesFilterProxyModel", "DevicesView")
