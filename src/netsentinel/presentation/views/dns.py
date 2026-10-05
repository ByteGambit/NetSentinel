"""Paged classic DNS history and bounded transaction evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID

from typing import cast
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QHeaderView
from PyQt6.QtCore import QDateTime, QModelIndex, QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDateTimeEdit,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QSplitter, QTableView, QTextEdit, QVBoxLayout, QWidget)

from netsentinel.presentation.theme import PAGE_TITLE
from netsentinel.application.ports import DnsHistoryQuery
from netsentinel.application.services.dns_history_query import DnsHistoryPage
from netsentinel.domain.dns import DnsHistoryRecord, DnsRecordType
from netsentinel.presentation.dns_query import DnsQueryCoordinator
from netsentinel.presentation.models.dns import (DnsTableModel, MISSING, STATUS_TEXT,
    answer_lines, event_time, format_dns_endpoint, format_latency, format_rcode, format_record_type)
from netsentinel.presentation.models.history import format_local_timestamp

PAGE_SIZE = 50


class DnsDetailsWidget(QGroupBox):
    FIELDS = (("id", "Record ID"), ("time", "Event time"), ("network", "Network"),
              ("status", "Status"), ("client", "Client"), ("server", "DNS server"),
              ("transport", "Transport"), ("transaction_id", "DNS transaction ID"),
              ("rcode", "Result"), ("latency", "Latency"), ("retries", "Retries"),
              ("truncated", "Truncated"), ("query_time", "Query time"),
              ("response_time", "Response time"))

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Selected DNS record", parent)
        self.setAccessibleName("DNS record details")
        self.status_label = QLabel("No DNS record selected.", self)
        self.values: dict[str, QLabel] = {}
        form = QFormLayout()
        for key, label in self.FIELDS:
            value = QLabel(MISSING, self)
            value.setObjectName(f"dnsDetail_{key}")
            value.setAccessibleName(f"DNS {label.lower()}")
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.values[key] = value
            form.addRow(f"{label}:", value)
        self.questions = QTextEdit(self)
        self.questions.setAccessibleName("DNS questions")
        self.questions.setReadOnly(True)
        self.questions.setMaximumHeight(85)
        self.answers = QTextEdit(self)
        self.answers.setAccessibleName("DNS answers")
        self.answers.setReadOnly(True)
        self.answers.setMaximumHeight(100)
        layout = QVBoxLayout(self)
        layout.addWidget(self.status_label)
        layout.addLayout(form)
        layout.addWidget(QLabel("Questions", self))
        layout.addWidget(self.questions)
        layout.addWidget(QLabel("Answers (up to 16 supported records)", self))
        layout.addWidget(self.answers)

    def clear(self) -> None:
        self.status_label.show()
        for value in self.values.values():
            value.setText(MISSING)
        self.questions.clear()
        self.answers.clear()

    def set_record(self, record: DnsHistoryRecord, network_label: str | None = None) -> None:
        tx = record.transaction
        self.status_label.hide()
        values = {"id": str(record.id), "time": format_local_timestamp(event_time(record)),
                  "network": network_label or "Previously observed network",
                  "status": STATUS_TEXT[tx.status],
                  "client": format_dns_endpoint(tx.client_ip, tx.client_port),
                  "server": format_dns_endpoint(tx.server_ip, tx.server_port),
                  "transport": tx.transport.value.upper(), "transaction_id": str(tx.transaction_id),
                  "rcode": format_rcode(tx.response_code), "latency": format_latency(tx.latency_seconds),
                  "retries": str(tx.retry_count), "truncated": "Yes" if tx.truncated else "No",
                  "query_time": format_local_timestamp(tx.query_at) if tx.query_at else MISSING,
                  "response_time": format_local_timestamp(tx.response_at) if tx.response_at else MISSING}
        for key, value in values.items():
            self.values[key].setText(value)
        self.questions.setPlainText("\n".join(f"{q.name} {format_record_type(q.record_type)}"
                                              for q in tx.questions[:4]) or MISSING)
        self.answers.setPlainText("\n".join(answer_lines(record)) or MISSING)


class DnsView(QWidget):
    config_alert_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None, *, coordinator: DnsQueryCoordinator | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("dnsView")
        self.setAccessibleName("DNS history page")
        self.coordinator = coordinator
        self.model = DnsTableModel(self)
        self._page_index = 0
        self._generation: int | None = None
        self._has_next = False
        self._loading = False
        self._initial_requested = False
        self._selected_id: UUID | None = None
        self._network_labels: dict[str, str] = {}
        self._capture_running = False
        self._writer_available = True

        title = QLabel("DNS", self)
        title.setStyleSheet(PAGE_TITLE)
        description = QLabel("Locally saved classic DNS metadata. Raw DNS packets and payloads are not stored.", self)
        description.setWordWrap(True)
        self.capability_label = QLabel("Classic UDP/TCP DNS on port 53 only. Encrypted DoH/DoT content is not visible; mDNS is not included.", self)
        self.capability_label.setAccessibleName("DNS capture capability and limitations")
        self.capability_label.setWordWrap(True)
        self.capture_label = QLabel("Capture is off. Saved DNS history remains available.", self)
        self.capture_label.setAccessibleName("DNS capture status")
        self.qname_filter = QLineEdit(self)
        self.qname_filter.setPlaceholderText("Exact query name")
        self.qname_filter.setAccessibleName("DNS query name filter")
        self.type_filter = QComboBox(self)
        self.type_filter.setAccessibleName("DNS query type filter")
        self.type_filter.addItem("All types", None)
        for kind in DnsRecordType:
            self.type_filter.addItem(kind.name, kind.value)
        self.server_filter = QLineEdit(self)
        self.server_filter.setPlaceholderText("DNS server IP")
        self.server_filter.setAccessibleName("DNS server IP filter")
        self.status_filter = QComboBox(self)
        self.status_filter.setAccessibleName("DNS status filter")
        self.status_filter.addItem("All statuses", None)
        for status, label in STATUS_TEXT.items():
            self.status_filter.addItem(label, status)

        now = QDateTime.currentDateTime()
        self.from_enabled = QCheckBox("From", self)
        self.from_enabled.setAccessibleName("Enable DNS start time filter")
        self.from_time = QDateTimeEdit(now.addDays(-1), self)
        self.from_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.from_time.setCalendarPopup(True)
        self.from_time.setAccessibleName("DNS start time")
        self.from_time.setEnabled(False)
        self.to_enabled = QCheckBox("To", self)
        self.to_enabled.setAccessibleName("Enable DNS end time filter")
        self.to_time = QDateTimeEdit(now, self)
        self.to_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.to_time.setCalendarPopup(True)
        self.to_time.setAccessibleName("DNS end time")
        self.to_time.setEnabled(False)
        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.setAccessibleName("Refresh DNS history")
        self.alert_button = QPushButton("DNS configuration alerts", self)
        self.alert_button.setAccessibleName("Show DNS configuration change alerts")
        self.validation_label = QLabel("", self)
        self.validation_label.setAccessibleName("DNS filter validation")
        self.validation_label.hide()
        self.state_label = QLabel("No DNS history yet." if coordinator else "DNS history is unavailable.", self)
        self.state_label.setAccessibleName("DNS history loading and result status")
        self.table = QTableView(self)
        self.table.setAccessibleName("DNS history records")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        cast(QHeaderView, self.table.verticalHeader()).setVisible(False)
        cast(QHeaderView, self.table.horizontalHeader()).setStretchLastSection(True)
        for column, width in enumerate((190, 145, 190, 65, 155, 155, 90, 100, 95)):
            self.table.setColumnWidth(column, width)
        self.previous_button = QPushButton("Previous", self)
        self.previous_button.setAccessibleName("Previous DNS page")
        self.next_button = QPushButton("Next", self)
        self.next_button.setAccessibleName("Next DNS page")
        self.page_label = QLabel("Page 1", self)
        self.page_label.setAccessibleName("DNS page number")
        self.details = DnsDetailsWidget(self)

        control: QWidget
        filters = QHBoxLayout()
        for control in (self.qname_filter, self.type_filter, self.server_filter,
                        self.status_filter):
            filters.addWidget(control)
        times = QHBoxLayout()
        for control in (self.from_enabled, self.from_time, self.to_enabled, self.to_time,
                        self.refresh_button, self.alert_button):
            times.addWidget(control)
        pagination = QHBoxLayout()
        pagination.addStretch()
        for control in (self.previous_button, self.page_label, self.next_button):
            pagination.addWidget(control)
        pagination.addStretch()
        table_panel = QWidget(self)
        table_layout = QVBoxLayout(table_panel)
        table_layout.addWidget(self.state_label)
        table_layout.addWidget(self.table, 1)
        table_layout.addLayout(pagination)
        splitter = QSplitter(Qt.Orientation.Vertical, self)
        splitter.addWidget(table_panel)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        for item in (title, description, self.capability_label, self.capture_label):
            layout.addWidget(item)
        layout.addLayout(filters)
        layout.addLayout(times)
        layout.addWidget(self.validation_label)
        layout.addWidget(splitter, 1)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self._filters_changed)
        for edit in (self.qname_filter, self.server_filter):
            edit.textChanged.connect(lambda _text: self._debounce.start())
        for combo in (self.type_filter, self.status_filter):
            combo.currentIndexChanged.connect(self._filters_changed)
        self.from_enabled.toggled.connect(self._toggle_from)
        self.to_enabled.toggled.connect(self._toggle_to)
        self.from_time.dateTimeChanged.connect(self._date_changed)
        self.to_time.dateTimeChanged.connect(self._date_changed)
        self.refresh_button.clicked.connect(self.refresh)
        self.alert_button.clicked.connect(self.config_alert_requested)
        self.previous_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)
        cast(QItemSelectionModel, self.table.selectionModel()).currentRowChanged.connect(self._selection_changed)
        if coordinator is not None:
            coordinator.page_ready.connect(self._page_ready)
            coordinator.query_failed.connect(self._query_failed)
        self._update_pagination()

    @property
    def page_index(self) -> int:
        return self._page_index

    def set_network_contexts(self, contexts) -> None:
        self._network_labels = {context.fingerprint: f"{context.interface_name} · {context.subnet}" for context in contexts}
        record = self._selected_record()
        if record is not None:
            self.details.set_record(record, self._network_labels.get(record.transaction.network_fingerprint))

    def set_capture_running(self, running: bool) -> None:
        self._capture_running = running
        self._update_capture_label()

    def set_writer_available(self, available: bool) -> None:
        self._writer_available = available
        self._update_capture_label()

    def _update_capture_label(self) -> None:
        if not self._writer_available:
            text = "DNS history writer is unavailable. Saved history remains readable."
        elif self._capture_running:
            text = "Passive capture is running. New DNS history appears after it is saved."
        else:
            text = "Capture is off. Saved DNS history remains available. Start passive capture on Devices."
        self.capture_label.setText(text)

    def load_initial(self) -> None:
        self._initial_requested = True
        self._page_index = 0
        self._request_page()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if not self._initial_requested and self.coordinator is not None:
            self.load_initial()

    def refresh(self) -> None:
        self._request_page()

    def next_page(self) -> None:
        if not self._loading and self._has_next:
            self._page_index += 1
            self._request_page()

    def previous_page(self) -> None:
        if not self._loading and self._page_index > 0:
            self._page_index -= 1
            self._request_page()

    def _toggle_from(self, enabled: bool) -> None:
        self.from_time.setEnabled(enabled)
        self._filters_changed()

    def _toggle_to(self, enabled: bool) -> None:
        self.to_time.setEnabled(enabled)
        self._filters_changed()

    def _date_changed(self) -> None:
        if self.sender() is self.from_time and not self.from_enabled.isChecked():
            return
        if self.sender() is self.to_time and not self.to_enabled.isChecked():
            return
        self._filters_changed()

    def _filters_changed(self) -> None:
        self._debounce.stop()
        self._page_index = 0
        self._selected_id = None
        self.table.clearSelection()
        self.details.clear()
        self._request_page()

    def _build_query(self) -> DnsHistoryQuery:
        server_text = self.server_filter.text().strip()
        if server_text:
            try:
                server_text = str(ip_address(server_text))
            except ValueError:
                raise ValueError("server_ip is invalid") from None
        start = datetime.fromtimestamp(self.from_time.dateTime().toMSecsSinceEpoch() / 1000, UTC) if self.from_enabled.isChecked() else None
        end = datetime.fromtimestamp(self.to_time.dateTime().toMSecsSinceEpoch() / 1000, UTC) if self.to_enabled.isChecked() else None
        return DnsHistoryQuery(limit=PAGE_SIZE, offset=self._page_index * PAGE_SIZE,
                               event_from=start, event_to=end,
                               qname=self.qname_filter.text().strip() or None,
                               qtype=self.type_filter.currentData(),
                               server_ip=server_text or None,
                               status=self.status_filter.currentData())

    def _request_page(self) -> None:
        if self.coordinator is None:
            return
        try:
            query = self._build_query()
        except (TypeError, ValueError) as error:
            self.coordinator.invalidate()
            self._generation = None
            self._loading = False
            self.state_label.setText("Check the DNS filters.")
            self.state_label.show()
            self._update_pagination()
            message = str(error)
            if "event_from" in message:
                message = "From time must not be after To time."
            elif "server_ip" in message:
                message = "Enter a valid DNS server IP address."
            else:
                message = "Enter a valid DNS query name."
            self.validation_label.setText(message)
            self.validation_label.show()
            return
        self.validation_label.hide()
        self._loading = True
        self.state_label.setText("Loading DNS history…")
        self.state_label.show()
        self._update_pagination()
        try:
            self._generation = self.coordinator.request(query)
        except RuntimeError:
            self._loading = False
            self.state_label.setText("DNS history is unavailable. Try Refresh.")
            self._update_pagination()

    def _page_ready(self, generation: int, page: object) -> None:
        if generation != self._generation or not isinstance(page, DnsHistoryPage):
            return
        if not page.records and self._page_index > 0:
            self._page_index -= 1
            self._request_page()
            return
        self._loading = False
        self._has_next = page.has_next
        previous = self._selected_id
        self.model.replace_records(page.records)
        row = self.model.row_for_id(previous) if previous is not None else None
        if row is not None:
            self.table.selectRow(row)
        else:
            self._selected_id = None
            self.details.clear()
        if page.records:
            self.state_label.hide()
        else:
            self.state_label.setText("No DNS records match these filters." if self._filters_active() else "No DNS history yet.")
            self.state_label.show()
        self._update_pagination()

    def _query_failed(self, generation: int) -> None:
        if generation != self._generation:
            return
        self._loading = False
        self._has_next = False
        self.model.replace_records(())
        self._selected_id = None
        self.details.clear()
        self.state_label.setText("DNS history is unavailable. Try Refresh.")
        self.state_label.show()
        self._update_pagination()

    def _selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        record = self.model.record_at(current.row()) if current.isValid() else None
        self._selected_id = record.id if record else None
        if record is None:
            self.details.clear()
        else:
            self.details.set_record(record, self._network_labels.get(record.transaction.network_fingerprint))

    def _selected_record(self) -> DnsHistoryRecord | None:
        row = self.model.row_for_id(self._selected_id) if self._selected_id else None
        return self.model.record_at(row) if row is not None else None

    def _filters_active(self) -> bool:
        return bool(self.qname_filter.text().strip() or self.server_filter.text().strip()
                    or self.type_filter.currentData() is not None or self.status_filter.currentData() is not None
                    or self.from_enabled.isChecked() or self.to_enabled.isChecked())

    def _update_pagination(self) -> None:
        self.page_label.setText(f"Page {self._page_index + 1}")
        self.previous_button.setEnabled(not self._loading and self._page_index > 0)
        self.next_button.setEnabled(not self._loading and self._has_next)
