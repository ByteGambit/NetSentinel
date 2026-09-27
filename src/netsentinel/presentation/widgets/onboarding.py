"""First-run explanation and explicit completion gate."""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.presentation.views.diagnostics import DiagnosticsView


class OnboardingDialog(QDialog):
    def __init__(self, coordinator: CapabilityCoordinator, finish: Callable[[], bool], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._finish = finish
        self.completed = False
        self.setWindowTitle("Welcome to NetSentinel")
        self.setAccessibleName("NetSentinel first-run onboarding")
        self.resize(620, 590)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget(scroll)
        content = QVBoxLayout(body)
        for accessible, message in (
            ("Onboarding title", "Welcome to NetSentinel"),
            ("Onboarding purpose", "NetSentinel shows local connection activity and, when you explicitly start passive capture, observed LAN, DNS and VLAN metadata. Alerts are signals to investigate, not proof of an attack or a security guarantee."),
            ("Onboarding passive behavior", "Connection monitoring starts after you finish. Packet capture stays off until you choose a network in Devices and press Start passive capture. This setup sends no packets, scans no network and never requests elevation."),
            ("Onboarding privacy", "Local history may store bounded connection, device, DNS and alert metadata. User labels and notes are saved only when you choose to save them. Raw packet payloads and credentials are not stored. Logs exclude secrets, payloads, SQL and local paths."),
            ("Onboarding limitations", "Missing packet capture dependencies, interface access or permissions can limit live passive features. Saved data and connection monitoring may still work. Npcap installation and permission changes are manual outside NetSentinel."),
        ):
            label = QLabel(message, body)
            label.setWordWrap(True)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setAccessibleName(accessible)
            content.addWidget(label)
        self.diagnostics = DiagnosticsView(coordinator, body)
        content.addWidget(self.diagnostics)
        scroll.setWidget(body)
        outer.addWidget(scroll)
        self.error = QLabel("", self)
        self.error.setWordWrap(True)
        self.error.setAccessibleName("Onboarding save status")
        outer.addWidget(self.error)
        self.finish_button = QPushButton("Finish and open NetSentinel", self)
        self.finish_button.setAccessibleName("Finish onboarding")
        self.finish_button.clicked.connect(self._complete)
        outer.addWidget(self.finish_button)
        self.finished.connect(lambda _result: self.diagnostics.deactivate())
        self.diagnostics.retry()

    def _complete(self) -> None:
        if self.completed:
            return
        self.finish_button.setEnabled(False)
        try:
            saved = self._finish()
        except Exception:
            saved = False
        if not saved:
            self.error.setText("Settings could not be saved. Check local storage and try again.")
            self.finish_button.setEnabled(True)
            return
        self.completed = True
        self.accept()


__all__ = ("OnboardingDialog",)
