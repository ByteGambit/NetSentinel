"""Versioned informational guide. Reading/finishing never grants consent."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget

from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.shared.config import AppConfig


GUIDE_PAGES = (
    ("Visibility first", (
        "NetSentinel helps you see which processes communicate, where they connect and why observed behavior may deserve review.",
        "NetSentinel does not upload your network history by default.",
        "Visibility → context → explainable assessment. This is an educational monitoring tool, not an antivirus replacement. No automatic blocking is performed.",
        "Pilot builds may be unsigned and blocked by Windows policies. Updates are manual. Broad public release still requires the remaining beta gates; do not bypass Windows security.",
    )),
    ("Local monitoring and capture", (
        "On first run, connection monitoring starts after Finish or Skip. Packet capture is separate: choose a current network in Devices and press Start passive capture. Completing this guide never starts capture.",
        "Passive capture adds observed LAN, classic DNS, broadcast and VLAN metadata. No raw packet payload history is stored. This guide sends no probes or scans and never requests elevation.",
        "Without Npcap or interface access, packet features may be unavailable while supported connection monitoring and saved views still work. Installation and permission changes are manual outside NetSentinel.",
        "Connection visibility uses polling: very short-lived connections can be missed. Process metadata is not recorded process creation/termination events. Per-flow upload/download byte totals are unavailable.",
    )),
    ("Optional external reputation", (
        "The production provider is AbuseIPDB, for a selected public IPv4/IPv6 address and a manual lookup only. Default external reputation requests: zero. Capture consent and provider consent are independent.",
        "Use Settings → Threat intelligence / reputation consent to permit this data type, then explicitly request a lookup. Saving consent alone sends nothing. The provider naturally sees your source IP; provider retention is unknown.",
        "The request contains the selected IP and the provider authentication key required for that request. Connection/DNS history, local paths, command lines, file contents, raw packets and user notes are not uploaded. Keys are never included in support exports.",
        "A usable credential is also required. This guide does not read secrets or test credential readiness. An unavailable secret backend prevents provider requests; review the lookup status in Connections.",
    )),
    ("What evidence can conclude", (
        "Concern score is a deterministic review-priority score, not a malware probability. Severity describes concern, confidence describes evidence support and measurement quality describes observation coverage; these are separate.",
        "Classic DNS is observed only where capture sees it; universal DoH/DoT visibility is unavailable. Domain/IP/process associations can be many-to-many or ambiguous, and do not prove a causal connection. Local ASN/country context is not physical user location or maliciousness.",
        "A hash identifies bytes read from disk at observation time, not running process memory integrity. Signed does not mean safe; unsigned does not mean malicious.",
        "TI HIT is not a malware verdict; NO_HIT is not a safety verdict. Stale, error and unknown are distinct. Novel/rare behavior is not malicious by itself; insufficient baseline coverage limits conclusions.",
        "Incident timelines group related evidence; ordering is not causality or forensic completeness. Source detail may expire under retention while a retained explanation remains.",
    )),
    ("Privacy, storage and feedback", (
        "Local data can still be sensitive: connection/process history, executable metadata, IP/domain context, DNS/devices, alerts, incidents, baseline, preferences and optional TI cache can reveal activity or username-bearing paths.",
        "Settings → Storage & Privacy provides retention, confirmed local deletion and sanitized support export. Deletion does not guarantee secure erasure or immediate SQLite/WAL shrink; database encryption is not guaranteed.",
        "Help → Feedback & Support: review the fixed sanitized categories, preview, save a local file, then manually share through a maintainer-approved channel. Export is not Send. No automatic upload or crash uploader.",
        "Support exports exclude raw history, IP/domain/path/MAC/hash, evidence, notes, config and secrets. Bounded metadata is not anonymous or a forensic record. Review before sharing; never post secrets or vulnerability details publicly.",
    )),
    ("Current capabilities", (
        "You can continue with optional features disabled. Available describes capability; Running/Stopped describes activity. Neither is a security verdict. Some checks may be unavailable without preventing this guide from opening.",
        "Desktop notifications are disabled by default. Use their separate Settings screen to opt in. Reopening this guide preserves current capture, provider, notification and storage settings.",
    )),
)


class OnboardingDialog(QDialog):
    def __init__(self, coordinator: CapabilityCoordinator | None, finish: Callable[[], bool],
                 parent: QWidget | None = None, *, skip: Callable[[], bool] | None = None,
                 config: AppConfig | None = None,
                 credential_available: bool | None = None,
                 actions: Mapping[str, Callable[[], object]] | None = None) -> None:
        super().__init__(parent)
        self._finish, self._skip = finish, skip
        self.completed = False
        self.skipped = False
        self.setWindowTitle("NetSentinel — First-run & Privacy guide")
        self.setAccessibleName("NetSentinel first-run onboarding")
        self.resize(740, 600)
        outer = QVBoxLayout(self)
        self.progress = QLabel(self)
        self.progress.setAccessibleName("Guide page and title")
        self.progress.setWordWrap(True)
        self.progress.setStyleSheet("font-size: 20px; font-weight: 700;")
        outer.addWidget(self.progress)
        self.pages = QStackedWidget(self)
        outer.addWidget(self.pages, 1)
        self.diagnostics = DiagnosticsView(coordinator, self)
        self.diagnostics.set_preferences(config or AppConfig(), credential_available=credential_available)
        for index, (title, paragraphs) in enumerate(GUIDE_PAGES):
            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            body = QWidget(scroll)
            content = QVBoxLayout(body)
            for paragraph in paragraphs:
                label = QLabel(paragraph, body)
                label.setWordWrap(True)
                label.setTextFormat(Qt.TextFormat.PlainText)
                label.setAccessibleName(f"Guide explanation: {title}")
                content.addWidget(label)
            if index == len(GUIDE_PAGES) - 1:
                content.addWidget(self.diagnostics)
            else:
                content.addStretch()
            scroll.setWidget(body)
            self.pages.addWidget(scroll)
        links = QHBoxLayout()
        self.links: dict[str, QPushButton] = {}
        for name, action in (actions or {}).items():
            button = QPushButton(name, self)
            button.setAccessibleName(f"Open {name} after leaving guide")
            button.setToolTip("Close the guide without saving and open this local screen.")
            button.clicked.connect(lambda _checked=False, callback=action: self._open_action(callback))
            self.links[name] = button
            links.addWidget(button)
        outer.addLayout(links)
        self.error = QLabel("", self)
        self.error.setWordWrap(True)
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setAccessibleName("Onboarding save status")
        outer.addWidget(self.error)
        row = QHBoxLayout()
        self.back_button = QPushButton("Back", self)
        self.next_button = QPushButton("Next", self)
        self.skip_button = QPushButton("Skip for now", self)
        self.cancel_button = QPushButton("Cancel", self)
        self.finish_button = QPushButton("Finish and open NetSentinel", self)
        for button in (self.back_button, self.next_button, self.skip_button, self.cancel_button, self.finish_button):
            button.setAccessibleName(button.text())
            button.setToolTip(button.text() + " — this guide does not grant consent.")
            button.setAutoDefault(False)
            row.addWidget(button)
        self.finish_button.setToolTip("Complete this guide version. No optional feature is enabled.")
        self.skip_button.setToolTip("Dismiss this guide version. No consent or feature setting changes.")
        self.skip_button.setVisible(skip is not None)
        self.back_button.clicked.connect(lambda: self._page(-1))
        self.next_button.clicked.connect(lambda: self._page(1))
        self.finish_button.clicked.connect(self._complete)
        self.skip_button.clicked.connect(self._dismiss)
        self.cancel_button.clicked.connect(self.reject)
        outer.addLayout(row)
        self.finished.connect(lambda _result: self.diagnostics.deactivate())
        self.diagnostics.retry()
        self._page(0)

    def _page(self, direction: int) -> None:
        index = max(0, min(self.pages.count() - 1, self.pages.currentIndex() + direction))
        self.pages.setCurrentIndex(index)
        self.progress.setText(f"{index + 1} / {self.pages.count()} — {GUIDE_PAGES[index][0]}")
        self.back_button.setEnabled(index > 0)
        self.next_button.setEnabled(index < self.pages.count() - 1)
        self.next_button.setDefault(index < self.pages.count() - 1)
        self.finish_button.setDefault(index == self.pages.count() - 1)

    def _open_action(self, action: Callable[[], object]) -> None:
        self.reject()
        action()

    def _save(self, callback: Callable[[], bool], *, skipped: bool) -> None:
        if self.completed or self.skipped:
            return
        self.finish_button.setEnabled(False)
        self.skip_button.setEnabled(False)
        try:
            saved = callback()
        except Exception:
            saved = False
        if not saved:
            self.error.setText("Settings could not be saved. Check local storage and try again.")
            self.finish_button.setEnabled(True)
            self.skip_button.setEnabled(True)
            return
        self.skipped, self.completed = skipped, not skipped
        self.accept()

    def _complete(self) -> None:
        self._save(self._finish, skipped=False)

    def _dismiss(self) -> None:
        if self._skip is not None:
            self._save(self._skip, skipped=True)


__all__ = ("GUIDE_PAGES", "OnboardingDialog")
