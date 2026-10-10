"""Explicit user editor for a network-scoped device profile."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import format_text, render_text

from netsentinel.presentation.i18n.text import translate

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
        self.setWindowTitle(translate('DeviceProfile', 'Edit device profile') if profile else translate('DeviceProfile', 'Create device profile'))
        self.setAccessibleName(translate('DeviceProfile', 'Device profile editor'))
        self.draft: ProfileEdit | None = None
        self._observed_mac = observed_mac
        self._observed_ip = observed_ip
        self.label_edit = QLineEdit(profile.label if profile else "", self)
        self.label_edit.setMaxLength(128)
        self.label_edit.setAccessibleName(translate('DeviceProfile', 'Profile label'))
        self.note_edit = QTextEdit(self)
        self.note_edit.setPlainText(render_text(profile.note if profile else ''))
        self.note_edit.setAccessibleName(translate('DeviceProfile', 'Profile note'))
        self.note_edit.setMaximumHeight(95)
        self.trust_selector = QComboBox(self)
        self.trust_selector.setAccessibleName(translate('DeviceProfile', 'Trust selector'))
        for state in DeviceTrust:
            self.trust_selector.addItem(display_enum(state, 'title'), state)
        self.trust_selector.setCurrentIndex(self.trust_selector.findData(profile.trust if profile else DeviceTrust.UNKNOWN))
        trust_help = QLabel(translate('DeviceProfile', 'Trust is your label for this device; it does not verify its identity or safety.'), self)
        trust_help.setWordWrap(True)
        trust_help.setTextFormat(Qt.TextFormat.PlainText)
        self.mac_list = QListWidget(self)
        self.mac_list.setAccessibleName(translate('DeviceProfile', 'Expected MAC list'))
        self.mac_list.setMaximumHeight(90)
        self.ip_list = QListWidget(self)
        self.ip_list.setAccessibleName(translate('DeviceProfile', 'Expected IP list'))
        self.ip_list.setMaximumHeight(90)
        for mac in profile.expected_macs if profile else ():
            self.mac_list.addItem(str(mac))
        for ip in profile.expected_ips if profile else ():
            self.ip_list.addItem(ip)
        self.mac_input = QLineEdit(self)
        self.mac_input.setPlaceholderText("00:11:22:33:44:55")
        self.mac_input.setAccessibleName(translate('DeviceProfile', 'Expected MAC input'))
        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("192.0.2.10")
        self.ip_input.setAccessibleName(translate('DeviceProfile', 'Expected IPv4 input'))
        self.add_mac = QPushButton(translate('DeviceProfile', 'Add MAC'), self)
        self.add_mac.setAccessibleName(translate('DeviceProfile', 'Add expected MAC'))
        self.remove_mac = QPushButton(translate('DeviceProfile', 'Remove MAC'), self)
        self.remove_mac.setAccessibleName(translate('DeviceProfile', 'Remove expected MAC'))
        self.observed_mac_button = QPushButton(translate('DeviceProfile', 'Add observed MAC as expected'), self)
        self.observed_mac_button.setAccessibleName(translate('DeviceProfile', 'Add observed MAC as expected'))
        self.add_ip = QPushButton(translate('DeviceProfile', 'Add IP'), self)
        self.add_ip.setAccessibleName(translate('DeviceProfile', 'Add expected IP'))
        self.remove_ip = QPushButton(translate('DeviceProfile', 'Remove IP'), self)
        self.remove_ip.setAccessibleName(translate('DeviceProfile', 'Remove expected IP'))
        self.observed_ip_button = QPushButton(translate('DeviceProfile', 'Add observed IP as expected'), self)
        self.observed_ip_button.setAccessibleName(translate('DeviceProfile', 'Add observed IP as expected'))
        self.observed_ip_button.setEnabled(observed_ip is not None)
        self.error_label = QLabel("", self)
        self.error_label.setTextFormat(Qt.TextFormat.PlainText)
        self.error_label.setAccessibleName(translate('DeviceProfile', 'Profile validation status'))
        self.error_label.setWordWrap(True)
        self.save_button = QPushButton(translate('DeviceProfile', 'Save profile'), self)
        self.save_button.setAccessibleName(translate('DeviceProfile', 'Save profile'))
        self.cancel_button = QPushButton(translate('DeviceProfile', 'Cancel'), self)
        self.cancel_button.setAccessibleName(translate('DeviceProfile', 'Cancel profile edit'))
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Label:", self.label_edit)
        form.addRow("Note:", self.note_edit)
        form.addRow("Trust:", self.trust_selector)
        layout.addLayout(form)
        layout.addWidget(trust_help)
        layout.addWidget(QLabel(translate('DeviceProfile', 'Expected MACs (user saved):'), self))
        layout.addWidget(self.mac_list)
        mac_controls = QHBoxLayout()
        for widget in (self.mac_input, self.add_mac, self.remove_mac, self.observed_mac_button):
            mac_controls.addWidget(widget)
        layout.addLayout(mac_controls)
        layout.addWidget(QLabel(translate('DeviceProfile', 'Expected IPv4 addresses (user saved):'), self))
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
            self._add(self.mac_list, str(mac), translate('DeviceProfile', 'MAC'))
            self.mac_input.clear()
        except (TypeError, ValueError):
            self.error_label.setText(translate('DeviceProfile', 'Enter a valid nonzero unicast MAC address.'))

    def _add_ip(self, value: str) -> None:
        try:
            self._add(self.ip_list, str(IPv4Address(value)), "IPv4")
            self.ip_input.clear()
        except (TypeError, ValueError):
            self.error_label.setText(translate('DeviceProfile', 'Enter a valid IPv4 address.'))

    def _add(self, target: QListWidget, value: str, name: str) -> None:
        if any(target.item(i).text() == value for i in range(target.count())):
            self.error_label.setText(format_text(translate('DeviceProfile', 'This expected {value1} is already listed.'), value1=name))
        elif target.count() >= 32:
            self.error_label.setText(format_text(translate('DeviceProfile', 'Keep at most 32 expected {value1} addresses.'), value1=name))
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
            self.error_label.setText(render_text(str(error)))
            return
        self.draft = edit
        self.accept()


__all__ = ("DeviceProfileDialog",)
