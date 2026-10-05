"""Paged, filtered connection-history page."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from typing import cast
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QHeaderView
from PyQt6.QtCore import QDateTime, QModelIndex, QTimer, Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from netsentinel.application.ports import ConnectionHistoryQuery
from netsentinel.application.services.history_query import ConnectionHistoryPage
from netsentinel.domain.connections import TransportProtocol
from netsentinel.presentation.history_query import HistoryQueryCoordinator
from netsentinel.presentation.destination_query import DestinationQueryCoordinator
from netsentinel.application.services.destination_evidence import DestinationEvidenceRequest
from netsentinel.presentation.destination_context import DestinationEvidenceWidget
from netsentinel.presentation.models.history import HistoryRow, HistoryTableModel
from netsentinel.presentation.process_context import (
    PROCESS_CONTEXT_FIELDS,
    process_context_text,
)
from netsentinel.presentation.widgets.page_flow import EndpointTableView, MonitoringPageScroll
from netsentinel.presentation.theme import PAGE_TITLE, SECONDARY_TEXT
from netsentinel.presentation.viewmodels import MISSING_VALUE


HISTORY_PAGE_SIZE = 50
FILTER_DEBOUNCE_MS = 300


class HistoryDetailsWidget(QGroupBox):
    """Safe metadata detail for one selected persisted record."""

    _FIELDS = (
        ("process", "Process name"),
        ("pid", "PID"),
        *PROCESS_CONTEXT_FIELDS,
        ("protocol", "Protocol"),
        ("state", "State"),
        ("local", "Local endpoint"),
        ("remote", "Remote endpoint"),
        ("opened", "First seen"),
        ("last_seen", "Last seen"),
        ("closed", "Closed"),
        ("close_reason", "Close reason"),
        ("duration", "Observed duration"),
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Selected record", parent)
        self.setObjectName("historyDetails")
        self.setAccessibleName("History record details")
        self.status_label = QLabel(self)
        self.status_label.setAccessibleName("History details status")
        self.values: dict[str, QLabel] = {}
        content = QWidget(self)
        form = QFormLayout(content)
        for key, title in self._FIELDS:
            label = QLabel(MISSING_VALUE, self)
            label.setObjectName(f"historyDetail_{key}")
            label.setAccessibleName(f"{title} value")
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setWordWrap(key == "executable")
            self.values[key] = label
            form.addRow(f"{title}:", label)
        layout = QVBoxLayout(self)
        layout.addWidget(self.status_label)
        layout.addWidget(content)
        self.destination = DestinationEvidenceWidget(self)
        layout.addWidget(self.destination)
        self.clear()

    def clear(self) -> None:
        self.status_label.setText("No history record selected.")
        self.status_label.show()
        for label in self.values.values():
            label.setText(MISSING_VALUE)
        self.destination.clear()

    def set_row(self, row: HistoryRow) -> None:
        self.status_label.hide()
        values = {
            **process_context_text(row.process_info),
            "protocol": row.protocol_display,
            "state": row.state_display,
            "local": row.local_display,
            "remote": row.remote_display,
            "opened": row.opened_display,
            "last_seen": row.last_seen_display,
            "closed": row.closed_display,
            "close_reason": row.close_reason_display,
            "duration": row.duration_display,
        }
        for key, value in values.items():
            self.values[key].setText(value)


class HistoryView(QWidget):
    """Query persisted history without doing database work on the Qt thread."""

    def __init__(
        self,
        coordinator: HistoryQueryCoordinator | None = None,
        *,
        destination_queries: DestinationQueryCoordinator | None = None,
        model: HistoryTableModel | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("historyView")
        self.setAccessibleName("Connection history page")
        self.coordinator = coordinator
        self.destination_queries = destination_queries
        self._destination_generation: int | None = None
        self.model = HistoryTableModel(self) if model is None else model
        self._page_index = 0
        self._latest_generation: int | None = None
        self._loading = False
        self._has_next = False
        self._initial_requested = False
        self._restore_record_id: UUID | None = None

        title = QLabel("History", self)
        title.setObjectName("historyTitle")
        title.setStyleSheet(PAGE_TITLE)
        subtitle = QLabel(
            "Review bounded pages of locally stored connection metadata.", self
        )
        subtitle.setStyleSheet(SECONDARY_TEXT)

        self.process_filter = QLineEdit(self)
        self.process_filter.setPlaceholderText("Process name (exact)")
        self.process_filter.setAccessibleName("History process filter")
        self.pid_filter = QLineEdit(self)
        self.pid_filter.setPlaceholderText("PID")
        self.pid_filter.setAccessibleName("History PID filter")
        self.endpoint_filter = QLineEdit(self)
        self.endpoint_filter.setPlaceholderText("Local or remote IP")
        self.endpoint_filter.setAccessibleName("History endpoint filter")
        self.protocol_filter = QComboBox(self)
        self.protocol_filter.setAccessibleName("History protocol filter")
        self.protocol_filter.addItem("All protocols", None)
        self.protocol_filter.addItem("TCP", TransportProtocol.TCP)
        self.protocol_filter.addItem("UDP", TransportProtocol.UDP)

        now = QDateTime.currentDateTime()
        self.from_enabled = QCheckBox("From", self)
        self.from_enabled.setAccessibleName("Enable history start time filter")
        self.from_time = QDateTimeEdit(now.addDays(-1), self)
        self.from_time.setCalendarPopup(True)
        self.from_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.from_time.setAccessibleName("History start time")
        self.from_time.setEnabled(False)
        self.to_enabled = QCheckBox("To", self)
        self.to_enabled.setAccessibleName("Enable history end time filter")
        self.to_time = QDateTimeEdit(now, self)
        self.to_time.setCalendarPopup(True)
        self.to_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.to_time.setAccessibleName("History end time")
        self.to_time.setEnabled(False)

        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.setAccessibleName("Refresh connection history")
        self.validation_label = QLabel("", self)
        self.validation_label.setAccessibleName("History filter validation")
        self.validation_label.setStyleSheet("color: #9b2c2c;")
        self.validation_label.hide()

        first_filters = QHBoxLayout()
        first_filters.addWidget(self.process_filter, 2)
        first_filters.addWidget(self.pid_filter, 1)
        first_filters.addWidget(self.endpoint_filter, 2)
        first_filters.addWidget(self.protocol_filter, 1)
        first_filters.addWidget(self.refresh_button)
        time_filters = QHBoxLayout()
        time_filters.addWidget(self.from_enabled)
        time_filters.addWidget(self.from_time)
        time_filters.addWidget(self.to_enabled)
        time_filters.addWidget(self.to_time)
        time_filters.addStretch(1)

        self.state_label = QLabel("No history records found.", self)
        self.state_label.setObjectName("historyState")
        self.state_label.setAccessibleName("History loading and result status")
        self.state_label.setStyleSheet(SECONDARY_TEXT + " padding: 5px;")

        self.table = EndpointTableView(self)
        self.table.setObjectName("historyTable")
        self.table.setAccessibleName("Connection history records")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        cast(QHeaderView, self.table.verticalHeader()).setVisible(False)
        cast(QHeaderView, self.table.verticalHeader()).setDefaultSectionSize(30)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.configure_columns((14, 6, 8, 24, 24, 12, 25, 25, 25, 9), (1, 2, 5, 6, 7, 8, 9))

        self.previous_button = QPushButton("Previous", self)
        self.previous_button.setAccessibleName("Previous history page")
        self.next_button = QPushButton("Next", self)
        self.next_button.setAccessibleName("Next history page")
        self.page_label = QLabel("Page 1", self)
        self.page_label.setAccessibleName("History page number")
        pagination = QHBoxLayout()
        pagination.addStretch(1)
        pagination.addWidget(self.previous_button)
        pagination.addWidget(self.page_label)
        pagination.addWidget(self.next_button)
        pagination.addStretch(1)

        self.details = HistoryDetailsWidget(self)
        table_frame = QFrame(self)
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addWidget(self.state_label)
        table_layout.addWidget(self.table, 1)
        table_layout.addLayout(pagination)
        self.page_scroll = MonitoringPageScroll(self.table, self)
        layout = self.page_scroll.page_layout
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(first_filters)
        layout.addLayout(time_filters)
        layout.addWidget(self.validation_label)
        layout.addWidget(table_frame)
        layout.addWidget(self.details)
        layout.addStretch(1)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(FILTER_DEBOUNCE_MS)
        self._debounce.timeout.connect(self._filters_changed)
        for edit in (self.process_filter, self.pid_filter, self.endpoint_filter):
            edit.textChanged.connect(self._schedule_filter_change)
        self.protocol_filter.currentIndexChanged.connect(self._filters_changed)
        self.from_enabled.toggled.connect(self._toggle_from)
        self.to_enabled.toggled.connect(self._toggle_to)
        self.from_time.dateTimeChanged.connect(self._date_changed)
        self.to_time.dateTimeChanged.connect(self._date_changed)
        self.refresh_button.clicked.connect(self.refresh)
        self.previous_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)
        cast(QItemSelectionModel, self.table.selectionModel()).currentRowChanged.connect(self._selection_changed)
        if coordinator is not None:
            coordinator.page_ready.connect(self._page_ready)
            coordinator.query_failed.connect(self._query_failed)
        if destination_queries is not None:
            destination_queries.result_ready.connect(self._destination_ready)
            destination_queries.query_failed.connect(self._destination_failed)
        self._update_pagination()

    @property
    def page_index(self) -> int:
        return self._page_index

    def load_initial(self) -> None:
        if self.coordinator is not None:
            self._initial_requested = True
            self._page_index = 0
            self._request_page()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt API
        super().showEvent(event)
        if self.coordinator is not None and not self._initial_requested:
            self.load_initial()

    def refresh(self) -> None:
        self._request_page()

    def next_page(self) -> None:
        if self._loading or not self._has_next:
            return
        self._page_index += 1
        self._request_page()

    def previous_page(self) -> None:
        if self._loading or self._page_index == 0:
            return
        self._page_index -= 1
        self._request_page()

    def _schedule_filter_change(self) -> None:
        self._debounce.start()

    def _filters_changed(self) -> None:
        self._debounce.stop()
        self._page_index = 0
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

    def _request_page(self) -> None:
        if self.coordinator is None:
            return
        try:
            query = self._build_query()
        except (TypeError, ValueError) as error:
            message = str(error)
            if "first_seen_from" in message:
                message = "From time must not be after To time."
            elif "endpoint_address" in message:
                message = "Enter a valid local or remote IP address."
            elif "pid" in message.lower():
                message = "PID must be a non-negative whole number."
            else:
                message = "Check the history filters and try again."
            self.validation_label.setText(message)
            self.validation_label.show()
            return
        self.validation_label.hide()
        current = (
            self.model.row_at(self.table.currentIndex().row())
            if cast(QItemSelectionModel, self.table.selectionModel()).hasSelection()
            else None
        )
        self._restore_record_id = current.record_id if current is not None else None
        self.details.clear()
        self._destination_generation = None
        self.table.clearSelection()
        self._loading = True
        self.state_label.setText("Loading history…")
        self.state_label.show()
        self._update_pagination()
        try:
            self._latest_generation = self.coordinator.request(query)
        except RuntimeError:
            self._loading = False
            self.state_label.setText("Unable to load connection history.")
            self._update_pagination()

    def _build_query(self) -> ConnectionHistoryQuery:
        process_name = self.process_filter.text().strip() or None
        endpoint = self.endpoint_filter.text().strip() or None
        pid_text = self.pid_filter.text().strip()
        pid = None
        if pid_text:
            if not pid_text.isdecimal():
                raise ValueError("pid must be a non-negative whole number")
            pid = int(pid_text)
        first_seen_from = (
            _qdatetime_to_utc(self.from_time.dateTime())
            if self.from_enabled.isChecked()
            else None
        )
        first_seen_to = (
            _qdatetime_to_utc(self.to_time.dateTime())
            if self.to_enabled.isChecked()
            else None
        )
        return ConnectionHistoryQuery(
            limit=HISTORY_PAGE_SIZE,
            offset=self._page_index * HISTORY_PAGE_SIZE,
            first_seen_from=first_seen_from,
            first_seen_to=first_seen_to,
            protocol=self.protocol_filter.currentData(),
            process_name=process_name,
            pid=pid,
            endpoint_address=endpoint,
        )

    def _page_ready(self, generation: int, page: object) -> None:
        if generation != self._latest_generation or not isinstance(page, ConnectionHistoryPage):
            return
        if not page.records and self._page_index > 0:
            self._page_index -= 1
            self._request_page()
            return
        self._loading = False
        self._has_next = page.has_next
        self.model.replace_records(page.records)
        self.details.clear()
        self._destination_generation = None
        if self._restore_record_id is not None:
            for index, row in enumerate(self.model.rows):
                if row.record_id == self._restore_record_id:
                    self.table.selectRow(index)
                    break
        self._restore_record_id = None
        if page.records:
            self.state_label.hide()
        elif self._filters_active():
            self.state_label.setText("No records match the current filters.")
            self.state_label.show()
        else:
            self.state_label.setText("No history records found.")
            self.state_label.show()
        self._update_pagination()

    def _query_failed(self, generation: int) -> None:
        if generation != self._latest_generation:
            return
        self._loading = False
        self._has_next = False
        self.model.clear()
        self._restore_record_id = None
        self.details.clear()
        self.state_label.setText("Unable to load connection history.")
        self.state_label.show()
        self._update_pagination()

    def _selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        row = self.model.row_at(current.row()) if current.isValid() else None
        if row is None:
            self.details.clear()
            self._destination_generation = None
        else:
            self.details.set_row(row)
            self._request_destination(row)

    def _request_destination(self, row: HistoryRow) -> None:
        if row.remote_address is None:
            self.details.destination.clear("No remote destination.")
            self._destination_generation = None
            return
        if self.destination_queries is None:
            self.details.destination.clear("Destination evidence unavailable.")
            return
        self.details.destination.clear("Loading destination evidence…")
        try:
            self._destination_generation = self.destination_queries.request(
                DestinationEvidenceRequest(row.remote_address, row.local_address,
                                           row.network_scope, row.network_scope_since or row.last_seen,
                                           row.last_seen, historical=True)
            )
        except RuntimeError:
            self.details.destination.clear("Destination evidence unavailable.")

    def _destination_ready(self, generation: int, result: object) -> None:
        from netsentinel.application.services.destination_evidence import DestinationEvidenceResult

        if generation == self._destination_generation and isinstance(result, DestinationEvidenceResult):
            if cast(QItemSelectionModel, self.table.selectionModel()).hasSelection():
                self.details.destination.set_result(result)

    def _destination_failed(self, generation: int) -> None:
        if generation == self._destination_generation:
            self.details.destination.clear("Destination evidence unavailable.")

    def _filters_active(self) -> bool:
        return bool(
            self.process_filter.text().strip()
            or self.pid_filter.text().strip()
            or self.endpoint_filter.text().strip()
            or self.protocol_filter.currentData() is not None
            or self.from_enabled.isChecked()
            or self.to_enabled.isChecked()
        )

    def _update_pagination(self) -> None:
        self.page_label.setText(f"Page {self._page_index + 1}")
        self.previous_button.setEnabled(not self._loading and self._page_index > 0)
        self.next_button.setEnabled(not self._loading and self._has_next)


def _qdatetime_to_utc(value: QDateTime) -> datetime:
    """Convert a Qt local instant to an aware UTC datetime."""

    return datetime.fromtimestamp(value.toMSecsSinceEpoch() / 1_000, tz=UTC)


__all__ = (
    "FILTER_DEBOUNCE_MS",
    "HISTORY_PAGE_SIZE",
    "HistoryDetailsWidget",
    "HistoryView",
)
