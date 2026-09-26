"""Explicit user editor for a network-scoped device profile."""

from __future__ import annotations

from ipaddress import IPv4Address

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QPushButton, QTextEdit, QVBoxLayout, QWidget)

from netsentinel.application.services.device_profiles import ProfileEdit, ProfileInputError, validate_edit
from netsentinel.domain.devices import DeviceProfile, DeviceTrust
from netsentinel.domain.observations import MacAddress


class DeviceProfileDialog(QDialog):
    """Edits a detached draft; Cancel never calls the profile service."""

    def __init__(self, profile: DeviceProfile | None, observed_mac: str,
                 observed_ip: str | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit device profile" if profile else "Create device profile")
        self.setAccessibleName("Device profile editor")
        self.draft: ProfileEdit | None = None
        self._observed_mac = observed_mac
        self._observed_ip = observed_ip
        self.label_edit = QLineEdit(profile.label if profile else "", self)
        self.label_edit.setMaxLength(128)
        self.label_edit.setAccessibleName("Profile label")
        self.note_edit = QTextEdit(self)
        self.note_edit.setPlainText(profile.note if profile else "")
        self.note_edit.setAccessibleName("Profile note")
        self.note_edit.setMaximumHeight(95)
        self.trust_selector = QComboBox(self)
        self.trust_selector.setAccessibleName("Trust selector")
        for state in DeviceTrust:
            self.trust_selector.addItem(state.value.title(), state)
        self.trust_selector.setCurrentIndex(self.trust_selector.findData(profile.trust if profile else DeviceTrust.UNKNOWN))
        trust_help = QLabel("Trust is your label for this device; it does not verify its identity or safety.", self)
        trust_help.setWordWrap(True)
        trust_help.setTextFormat(Qt.TextFormat.PlainText)
        self.mac_list = QListWidget(self)
        self.mac_list.setAccessibleName("Expected MAC list")
        self.mac_list.setMaximumHeight(90)
        self.ip_list = QListWidget(self)
        self.ip_list.setAccessibleName("Expected IP list")
        self.ip_list.setMaximumHeight(90)
        for mac in profile.expected_macs if profile else ():
            self.mac_list.addItem(str(mac))
        for ip in profile.expected_ips if profile else ():
            self.ip_list.addItem(ip)
        self.mac_input = QLineEdit(self)
        self.mac_input.setPlaceholderText("00:11:22:33:44:55")
        self.mac_input.setAccessibleName("Expected MAC input")
        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("192.0.2.10")
        self.ip_input.setAccessibleName("Expected IPv4 input")
        self.add_mac = QPushButton("Add MAC", self)
        self.add_mac.setAccessibleName("Add expected MAC")
        self.remove_mac = QPushButton("Remove MAC", self)
        self.remove_mac.setAccessibleName("Remove expected MAC")
        self.observed_mac_button = QPushButton("Add observed MAC as expected", self)
        self.observed_mac_button.setAccessibleName("Add observed MAC as expected")
        self.add_ip = QPushButton("Add IP", self)
        self.add_ip.setAccessibleName("Add expected IP")
        self.remove_ip = QPushButton("Remove IP", self)
        self.remove_ip.setAccessibleName("Remove expected IP")
        self.observed_ip_button = QPushButton("Add observed IP as expected", self)
        self.observed_ip_button.setAccessibleName("Add observed IP as expected")
        self.observed_ip_button.setEnabled(observed_ip is not None)
        self.error_label = QLabel("", self)
        self.error_label.setTextFormat(Qt.TextFormat.PlainText)
        self.error_label.setAccessibleName("Profile validation status")
        self.error_label.setWordWrap(True)
        self.save_button = QPushButton("Save profile", self)
        self.save_button.setAccessibleName("Save profile")
        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.setAccessibleName("Cancel profile edit")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Label:", self.label_edit)
        form.addRow("Note:", self.note_edit)
        form.addRow("Trust:", self.trust_selector)
        layout.addLayout(form)
        layout.addWidget(trust_help)
        layout.addWidget(QLabel("Expected MACs (user saved):", self))
        layout.addWidget(self.mac_list)
        mac_controls = QHBoxLayout()
        for widget in (self.mac_input, self.add_mac, self.remove_mac, self.observed_mac_button):
            mac_controls.addWidget(widget)
        layout.addLayout(mac_controls)
        layout.addWidget(QLabel("Expected IPv4 addresses (user saved):", self))
        layout.addWidget(self.ip_list)
        ip_controls = QHBoxLayout()
        for widget in (self.ip_input, self.add_ip, self.remove_ip, self.observed_ip_button):
            ip_controls.addWidget(widget)
        layout.addLayout(ip_controls)
        layout.addWidget(self.error_label)
        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.save_button)
        layout.addLayout(actions)
        self.add_mac.clicked.connect(lambda: self._add_mac(self.mac_input.text()))
        self.add_ip.clicked.connect(lambda: self._add_ip(self.ip_input.text()))
        self.observed_mac_button.clicked.connect(lambda: self._add_mac(self._observed_mac))
        self.observed_ip_button.clicked.connect(lambda: self._add_ip(self._observed_ip or ""))
        self.remove_mac.clicked.connect(lambda: self._remove(self.mac_list))
        self.remove_ip.clicked.connect(lambda: self._remove(self.ip_list))
        self.save_button.clicked.connect(self._accept_draft)
        self.cancel_button.clicked.connect(self.reject)

    def _add_mac(self, value: str) -> None:
        try:
            mac = MacAddress(value)
            if mac.is_zero or mac.is_broadcast or mac.is_multicast:
                raise ValueError("not unicast")
            self._add(self.mac_list, str(mac), "MAC")
            self.mac_input.clear()
        except (TypeError, ValueError):
            self.error_label.setText("Enter a valid nonzero unicast MAC address.")

    def _add_ip(self, value: str) -> None:
        try:
            self._add(self.ip_list, str(IPv4Address(value)), "IPv4")
            self.ip_input.clear()
        except (TypeError, ValueError):
            self.error_label.setText("Enter a valid IPv4 address.")

    def _add(self, target: QListWidget, value: str, name: str) -> None:
        if any(target.item(i).text() == value for i in range(target.count())):
            self.error_label.setText(f"This expected {name} is already listed.")
        elif target.count() >= 32:
            self.error_label.setText(f"Keep at most 32 expected {name} addresses.")
        else:
            target.addItem(value)
            self.error_label.clear()

    def _remove(self, target: QListWidget) -> None:
        if target.currentRow() >= 0:
            target.takeItem(target.currentRow())
            self.error_label.clear()

    def _accept_draft(self) -> None:
        edit = ProfileEdit(
            self.label_edit.text(), self.note_edit.toPlainText(),
            self.trust_selector.currentData(),
            tuple(self.mac_list.item(i).text() for i in range(self.mac_list.count())),
            tuple(self.ip_list.item(i).text() for i in range(self.ip_list.count())),
        )
        try:
            validate_edit(edit)
        except ProfileInputError as error:
            self.error_label.setText(str(error))
            return
        self.draft = edit
        self.accept()


__all__ = ("DeviceProfileDialog",)
