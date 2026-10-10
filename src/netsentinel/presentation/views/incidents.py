"""NS-091 local read-only incident list, detail and paginated timeline."""

from netsentinel.presentation.i18n.text import translate

from netsentinel.presentation.i18n.text import display_enum, format_text, render_join, render_text


from uuid import UUID

from PyQt6.QtCore import QModelIndex, QSignalBlocker, Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QLabel, QPushButton, QSplitter,
    QSizePolicy, QTableView, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from netsentinel.presentation.theme import PAGE_TITLE
from netsentinel.application.services.incident_timeline import (
    MAX_LOADED_ROWS, PAGE_SIZE, TimelineCursor, TimelinePage, TimelineRequest, TimelineStatus, SOURCE_TEXT,
)
from netsentinel.application.services.risk_explanation import RiskExplanationRequest
from netsentinel.domain.incident_persistence import IncidentPage
from netsentinel.presentation.incident_query import IncidentQueryCoordinator
from netsentinel.presentation.models.incidents import IncidentTableModel, TimelineTableModel
from netsentinel.presentation.models.history import format_local_timestamp
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget


class IncidentsView(QWidget):
    def __init__(self, parent=None, *, queries: tuple[IncidentQueryCoordinator, IncidentQueryCoordinator] | None = None,
                 risk_queries: RiskQueryCoordinator | None = None):
        super().__init__(parent)
        self.setObjectName("incidentsView")
        self.setAccessibleName(translate('Incidents', 'Local incident history'))
        self.queries = queries
        self.model = IncidentTableModel(self)
        self.timeline_model = TimelineTableModel(self)
        self._list_generation: int | None = None
        self._detail_generation: int | None = None
        self._list_request: TimelineRequest | None = None
        self._detail_request: TimelineRequest | None = None
        self._selected_id: UUID | None = None
        self._list_cursor: UUID | None = None
        self._next_list_cursor: UUID | None = None
        self._previous_cursors: list[UUID | None] = []
        self._timeline_cursor: TimelineCursor | None = None
        self._list_loading = self._detail_loading = False
        self._initial = False
        self._stopped = False
        self._append = False

        self.title = QLabel(translate('Incidents', 'Incidents'), self)
        self.title.setStyleSheet(PAGE_TITLE)
        self.help = QLabel(translate('Incidents', 'Timeline order shows recorded times and does not prove causality. Local application history is not a tamper-proof forensic record.'), self)
        self.help.setWordWrap(True)
        self.help.setTextFormat(Qt.TextFormat.PlainText)
        self.refresh_button = self._button(translate('Incidents', 'Refresh'), translate('Incidents', 'Refresh incident list and selected timeline'), self.refresh)
        self.cancel_button = self._button(translate('Incidents', 'Cancel queries'), translate('Incidents', 'Cancel pending incident queries'), self.cancel)
        self.state = self._label(translate('Incidents', 'No incidents loaded.'), translate('Incidents', 'Incident list loading status'))
        self.detail_state = self._label(translate('Incidents', 'No incident selected.'), translate('Incidents', 'Incident timeline loading status'))
        self.table = self._table(self.model, translate('Incidents', 'Persisted incident records'))
        self.timeline = self._table(self.timeline_model, translate('Incidents', 'Incident timeline; chronological order'))
        self.previous_button = self._button(translate('Incidents', 'Previous'), translate('Incidents', 'Previous incident list page'), self.previous_page)
        self.next_button = self._button(translate('Incidents', 'Next'), translate('Incidents', 'Next incident list page'), self.next_page)
        self.more_button = self._button(translate('Incidents', 'Load more'), translate('Incidents', 'Load next timeline page'), self.load_more)
        self.detail_refresh_button = self._button(translate('Incidents', 'Refresh timeline'), translate('Incidents', 'Refresh selected incident timeline'), self.refresh_detail)
        self.summary = self._text(translate('Incidents', 'Selected incident summary and limitations'))
        self.row_detail = self._text(translate('Incidents', 'Selected timeline entry semantic times and references'))
        self.risk = RiskExplanationWidget(risk_queries, self)
        self.tabs = QTabWidget(self)
        self.tabs.setAccessibleName(translate('Incidents', 'Incident detail sections'))
        self.tabs.addTab(self.summary, translate('Incidents', 'Summary / context'))
        self.tabs.addTab(self.row_detail, translate('Incidents', 'Selected timeline entry'))
        self.tabs.addTab(self.risk, translate('Incidents', 'Risk explanation'))
        self.tabs.setTabVisible(2, False)

        controls = QHBoxLayout()
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.cancel_button)
        controls.addStretch()
        pagination = QHBoxLayout()
        pagination.addWidget(self.previous_button)
        pagination.addWidget(self.next_button)
        pagination.addStretch()
        list_panel = QWidget(self)
        list_layout = QVBoxLayout(list_panel)
        list_layout.addWidget(self.state)
        list_layout.addWidget(self.table, 1)
        list_layout.addLayout(pagination)
        self.detail_panel = QWidget(self)
        detail_layout = QVBoxLayout(self.detail_panel)
        detail_layout.addWidget(self.detail_state)
        detail_layout.addWidget(self.timeline, 2)
        detail_controls = QHBoxLayout()
        detail_controls.addWidget(self.more_button)
        detail_controls.addWidget(self.detail_refresh_button)
        detail_controls.addStretch()
        self.detail_controls = QWidget(self.detail_panel)
        self.detail_controls.setLayout(detail_controls)
        detail_layout.addWidget(self.detail_controls)
        detail_layout.addWidget(self.tabs, 1)
        # Hidden risk tabs must not impose their full form height on the list.
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Ignored)
        tab_bar = self.tabs.tabBar()
        assert tab_bar is not None
        self.tabs.setMinimumHeight(tab_bar.sizeHint().height() + self.fontMetrics().height() * 4)
        row_height = max(self.table.verticalHeader().defaultSectionSize(), self.fontMetrics().height() + 10)
        self.table.verticalHeader().setDefaultSectionSize(row_height)
        self.table.setMinimumHeight(row_height * 5 + self.table.horizontalHeader().sizeHint().height()
                                    + self.table.horizontalScrollBar().sizeHint().height() + 2 * self.table.frameWidth())
        self.timeline.setMinimumHeight(row_height * 2 + self.timeline.horizontalHeader().sizeHint().height()
                                       + self.timeline.horizontalScrollBar().sizeHint().height())
        self.splitter = QSplitter(Qt.Orientation.Vertical, self)
        self.splitter.addWidget(list_panel)
        self.splitter.addWidget(self.detail_panel)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        self._show_detail(False)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.addWidget(self.title)
        layout.addWidget(self.help)
        layout.addLayout(controls)
        layout.addWidget(self.splitter, 1)
        self.table.selectionModel().currentRowChanged.connect(self._selected)
        self.timeline.selectionModel().currentRowChanged.connect(self._row_selected)
        if queries:
            queries[0].result_ready.connect(self._list_ready)
            queries[1].result_ready.connect(self._detail_ready)
            queries[0].query_failed.connect(self._list_failed)
            queries[1].query_failed.connect(self._detail_failed)
            for query in queries:
                query.stopped.connect(self._worker_stopped)
        else:
            self.state.setText(translate('Incidents', 'Incident queries unavailable. Try Refresh.'))
        self._controls()

    def _show_detail(self, selected: bool) -> None:
        was_empty = self.timeline.isHidden()
        for widget in (self.timeline, self.detail_controls, self.tabs):
            widget.setVisible(selected)
        self.detail_panel.setMaximumHeight(16777215 if selected else self.detail_panel.sizeHint().height())
        if selected and was_empty:
            height = self.splitter.height()
            self.splitter.setSizes([height * 3 // 5, height * 2 // 5])

    def _label(self, text, name):
        label = QLabel(text, self)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        label.setAccessibleName(render_text(name))
        return label

    def _button(self, text, name, callback):
        button = QPushButton(text, self)
        button.setAccessibleName(render_text(name))
        button.clicked.connect(callback)
        return button

    def _text(self, name):
        text = QTextEdit(self)
        text.setReadOnly(True)
        text.setAccessibleName(render_text(name))
        return text

    def _table(self, model, name):
        table = QTableView(self)
        table.setAccessibleName(render_text(name))
        table.setModel(model)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)
        vertical, horizontal = table.verticalHeader(), table.horizontalHeader()
        assert vertical is not None and horizontal is not None
        vertical.hide()
        horizontal.setStretchLastSection(True)
        widths = (260, 145, 200, 200, 230) if isinstance(model, TimelineTableModel) else (160, 110, 230, 230, 110, 220)
        for column, width in enumerate(widths):
            table.setColumnWidth(column, width)
        return table

    @property
    def selected_incident_id(self):
        return self._selected_id

    def _controls(self):
        available = self.queries is not None and not self._stopped
        self.refresh_button.setEnabled(available and not self._list_loading)
        self.cancel_button.setEnabled(available and (self._list_loading or self._detail_loading))
        self.previous_button.setEnabled(available and not self._list_loading and bool(self._previous_cursors))
        self.next_button.setEnabled(available and not self._list_loading and self._next_list_cursor is not None)
        self.detail_refresh_button.setEnabled(available and not self._detail_loading and self._selected_id is not None)
        self.more_button.setEnabled(available and not self._detail_loading and self._timeline_cursor is not None and self.timeline_model.rowCount() < MAX_LOADED_ROWS)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._initial and self.queries and not self._stopped:
            self._initial = True
            self.refresh()

    def hideEvent(self, event):
        self.cancel()
        self._initial = False
        super().hideEvent(event)

    def cancel(self):
        if self.queries:
            for query in self.queries:
                query.invalidate()
        if self._list_loading:
            self.state.setText(translate('Incidents', 'Incident list query cancelled. Refresh to retry.'))
        if self._detail_loading:
            self.detail_state.setText(translate('Incidents', 'Timeline query cancelled. Refresh to retry.'))
            self._timeline_cursor = None
        self._list_generation = self._detail_generation = None
        self._list_loading = self._detail_loading = False
        self.risk.clear(translate('Incidents', 'Incident query cancelled.'))
        self.tabs.setTabVisible(2, False)
        self._controls()

    def _worker_stopped(self):
        self._stopped = True
        self.cancel()

    def refresh(self):
        if not self.queries or self._stopped:
            return
        self._previous_cursors.clear()
        self._list_cursor = None
        self._request_list()
        self.refresh_detail()

    def _request_list(self):
        if not self.queries or self._stopped:
            return
        request = TimelineRequest(after_id=self._list_cursor)
        try:
            self._list_generation = self.queries[0].request(request)
        except RuntimeError:
            self.state.setText(translate('Incidents', 'Incident queries unavailable. Try Refresh.'))
            return
        self._list_request = request
        self._list_loading = True
        self.state.setText(translate('Incidents', 'Loading incidents…'))
        self._controls()

    def next_page(self):
        if self._list_loading or self._next_list_cursor is None:
            return
        self._previous_cursors.append(self._list_cursor)
        self._list_cursor = self._next_list_cursor
        self._request_list()

    def previous_page(self):
        if self._list_loading or not self._previous_cursors:
            return
        self._list_cursor = self._previous_cursors.pop()
        self._request_list()

    def _list_ready(self, generation, page):
        if self._stopped or generation != self._list_generation or not isinstance(page, IncidentPage):
            return
        self._list_loading = False
        self._next_list_cursor = page.after_id if page.has_more else None
        with QSignalBlocker(self.table.selectionModel()):
            self.model.set_entries(page.entries)
            for row, entry in enumerate(page.entries):
                if entry.record is not None and entry.record.incident_id == self._selected_id:
                    self.table.selectRow(row)
                    break
        self.state.setText(render_text(translate('Incidents', 'No incidents yet.') if not page.entries else format_text(translate('Incidents', '{value1} incident records on this page; ordered by stable ID.'), value1=len(page.entries))))
        if any(e.record is None for e in page.entries):
            self.state.setText(render_text(self.state.text() + translate('Incidents', ' Some incident records are unavailable; see row status.')))
        self._controls()

    def _selected(self, current: QModelIndex, previous: QModelIndex):
        if not current.isValid():
            return
        record = self.model.entries[current.row()].record
        self.select_incident(record.incident_id if record else None)

    def select_incident(self, incident_id):
        if incident_id == self._selected_id and self._detail_generation is not None:
            return
        self._selected_id = incident_id
        self.refresh_detail()

    def refresh_detail(self):
        self._show_detail(self._selected_id is not None)
        if self.queries:
            self.queries[1].invalidate()
        self._detail_generation = None
        self._timeline_cursor = None
        self._detail_loading = False
        self.timeline_model.set_entries(())
        self.summary.clear()
        self.row_detail.clear()
        self.risk.clear(translate('Incidents', 'No assessment selected.'))
        self.tabs.setTabVisible(2, False)
        self.detail_state.setText(translate('Incidents', 'No incident selected.'))
        if self._selected_id is not None:
            self._request_detail(False)
        self._controls()

    def load_more(self):
        if not self._detail_loading and self._timeline_cursor is not None and self.timeline_model.rowCount() < MAX_LOADED_ROWS:
            self._request_detail(True)

    def _request_detail(self, append):
        if not self.queries or self._stopped or self._selected_id is None:
            return
        limit = min(PAGE_SIZE, MAX_LOADED_ROWS - self.timeline_model.rowCount()) if append else PAGE_SIZE
        request = TimelineRequest(self._selected_id, cursor=self._timeline_cursor if append else None, limit=limit)
        try:
            self._detail_generation = self.queries[1].request(request)
        except RuntimeError:
            self.detail_state.setText(translate('Incidents', 'Incident timeline unavailable. Try Refresh.'))
            return
        self._detail_request = request
        self._detail_loading = True
        self._append = append
        self.detail_state.setText(translate('Incidents', 'Loading timeline…'))
        self._controls()

    def _detail_ready(self, generation, page):
        if self._stopped or generation != self._detail_generation or not isinstance(page, TimelinePage):
            return
        self._detail_loading = False
        if page.status is not TimelineStatus.FOUND or page.record is None:
            self._timeline_cursor = None
            self.detail_state.setText(render_text(page.message or translate('Incidents', 'Incident timeline unavailable. Try Refresh.')))
            self._controls()
            return
        if page.record.incident_id != self._selected_id:
            return
        entries = self.timeline_model.entries + page.entries if self._append else page.entries
        self.timeline_model.set_entries(entries)
        self._timeline_cursor = page.next_cursor
        r, s = page.record, page.record.snapshot
        def stamp(t):
            return format_local_timestamp(t) if t else translate('Incidents', 'Unknown / not recorded')
        self.summary.setPlainText(render_join('\n', (format_text(translate('Incidents', 'Incident ID: {value1}'), value1=r.incident_id), format_text(translate('Incidents', 'Incident state: {value1}; incident revision: {value2}'), value1=display_enum(r.state), value2=r.revision), format_text(translate('Incidents', 'First observed (local): {value1}'), value1=stamp(s.first_observed_at)), format_text(translate('Incidents', 'Last observed (local): {value1}'), value1=stamp(s.last_observed_at)), format_text(translate('Incidents', 'Acknowledged (local): {value1}'), value1=stamp(r.acknowledged_at)), format_text(translate('Incidents', 'Resolved (local): {value1}'), value1=stamp(r.resolved_at)), format_text(translate('Incidents', 'Reopened (local): {value1}'), value1=stamp(r.reopened_at)), format_text(translate('Incidents', 'Persistence created / updated (local): {value1} / {value2}'), value1=stamp(r.created_at), value2=stamp(r.updated_at)), format_text(translate('Incidents', 'Correlation policy version: {value1}; fixed UTC bucket: {value2}; window: {value3}'), value1=r.correlation_version, value2=s.cohort.isoformat(), value3=r.correlation_policy.window), format_text(translate('Incidents', 'Observation relations: {value1}; evidence refs: {value2}; assessment refs: {value3}; alert refs: {value4} (separate lifecycle)'), value1=len(s.relations), value2=len(s.evidence), value3=len(s.assessments), value4=len(s.alerts)), translate('Incidents', 'Limitations: ') + (render_join('; ', page.limitations) or translate('Incidents', 'No additional persisted limitations; source/attribution uncertainty still applies.')), *page.context)))
        self.detail_state.setText(format_text(translate('Incidents', '{value1} timeline rows loaded; oldest first.'), value1=len(entries)))
        if len(entries) >= MAX_LOADED_ROWS and page.next_cursor is not None:
            self.detail_state.setText(format_text(translate('Incidents', 'Display limit reached ({value1} rows). Further retained entries are not displayed; refresh starts the bounded view again.'), value1=MAX_LOADED_ROWS))
        self._controls()

    def _row_selected(self, current, previous):
        self.risk.clear(translate('Incidents', 'No assessment selected.'))
        self.tabs.setTabVisible(2, False)
        if not current.isValid():
            self.row_detail.clear()
            return
        e = self.timeline_model.entries[current.row()]
        def stamp(t):
            return t.isoformat(timespec="microseconds") + " (UTC)" if t else translate('Incidents', 'Unknown / not recorded')
        self.row_detail.setPlainText(render_join('\n', (e.title, display_enum(e.kind), e.explanation, format_text(translate('Incidents', 'Primary ordering time: {value1}; {value2}'), value1=stamp(e.primary_time), value2=e.time_semantics), format_text(translate('Incidents', 'Observation time: {value1}'), value1=stamp(e.observation_time)), format_text(translate('Incidents', 'Assessment time: {value1}'), value1=stamp(e.assessment_time)), format_text(translate('Incidents', 'Action time: {value1}'), value1=stamp(e.action_time)), format_text(translate('Incidents', 'Source kind: {value1}; reference: {value2}'), value1=e.source_kind, value2=e.source_id), SOURCE_TEXT[e.source_status], format_text(translate('Incidents', 'Entry revision (assessment or incident action): {value1}'), value1=e.revision or translate('Incidents', 'Not applicable')))))
        self.tabs.setCurrentIndex(1)
        if e.assessment:
            self.tabs.setTabVisible(2, True)
            self.risk.select(RiskExplanationRequest(reference=e.assessment))

    def _list_failed(self, generation):
        if generation == self._list_generation:
            self._list_loading = False
            self.state.setText(translate('Incidents', 'Incident list unavailable. Try Refresh.'))
            self._controls()

    def _detail_failed(self, generation):
        if generation == self._detail_generation:
            self._detail_loading = False
            self._timeline_cursor = None
            self.detail_state.setText(translate('Incidents', 'Incident timeline unavailable. Try Refresh.'))
            self._controls()
