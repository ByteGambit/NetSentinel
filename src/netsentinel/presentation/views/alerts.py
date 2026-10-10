"""Bounded persisted-alert browser and acknowledge command."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import TranslationSequence, display_enum

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import translate
from uuid import UUID

from typing import cast
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QHeaderView, QLayout
from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QPushButton, QSplitter, QTableView,
    QTextEdit, QVBoxLayout, QWidget, QTabWidget, QScrollArea)
from PyQt6.QtCore import QSignalBlocker, pyqtSignal

from netsentinel.presentation.theme import PAGE_TITLE, SECONDARY_TEXT
from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alert_query import AlertPage
from netsentinel.domain.alerts import Alert, AlertStatus
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.models.alerts import (AlertsTableModel, RULE_EXPLANATIONS,
    RULE_TITLES, SCORE_EXPLANATIONS, entity_text)
from netsentinel.presentation.models.history import format_local_timestamp
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget
from netsentinel.application.services.risk_explanation import RiskExplanationRequest


ALERT_PAGE_SIZE = 50


class AlertDetailsWidget(QGroupBox):
    FIELDS = TranslationSequence(lambda: (("type", translate('Alerts', 'Type')), ("rule", translate('Alerts', 'Rule ID')), ("status", translate('Alerts', 'Status')),
              ("severity", translate('Alerts', 'Severity')), ("confidence", translate('Alerts', 'Confidence')),
              ("entity", translate('Alerts', 'Affected entity')), ("network", translate('Alerts', 'Network context')),
              ("expected", translate('Alerts', 'Expected MAC')), ("observed", translate('Alerts', 'Observed MAC')),
              ("first", translate('Alerts', 'First seen')), ("last", translate('Alerts', 'Last seen')),
              ("count", translate('Alerts', 'Occurrences')), ("updated", translate('Alerts', 'Lifecycle updated'))))

    def __init__(self, parent: QWidget | None = None, *, risk_queries: RiskQueryCoordinator | None = None) -> None:
        super().__init__(translate('Alerts', 'Selected alert'), parent)
        self.setAccessibleName(translate('Alerts', 'Alert details'))
        self.status_label = QLabel(translate('Alerts', 'No alert selected.'), self)
        self.status_label.setAccessibleName(translate('Alerts', 'Alert detail status'))
        self.values: dict[str, QLabel] = {}
        form = QFormLayout()
        for key, title in self.FIELDS:
            value = QLabel("—", self)
            value.setObjectName(f"alertDetail_{key}")
            value.setAccessibleName(format_text(translate('Alerts', 'Alert {value1}'), value1=title.lower()))
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.values[key] = value
            form.addRow(f"{title}:", value)
        self.explanation = QLabel("", self)
        self.explanation.setAccessibleName(translate('Alerts', 'Alert rule explanation'))
        self.explanation.setTextFormat(Qt.TextFormat.PlainText)
        self.explanation.setWordWrap(True)
        self.evidence = QTextEdit(self)
        self.evidence.setAccessibleName(translate('Alerts', 'Alert evidence and score breakdown'))
        self.evidence.setReadOnly(True)
        self.evidence.setMaximumHeight(145)
        legacy = QWidget(self)
        layout = QVBoxLayout(legacy)
        layout.addWidget(self.status_label)
        layout.addLayout(form)
        layout.addWidget(self.explanation)
        layout.addWidget(self.evidence)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setWidget(legacy)
        self.tabs = QTabWidget(self)
        self.tabs.setAccessibleName(translate('Alerts', 'Selected alert detail sections'))
        self.tabs.addTab(scroll, translate('Alerts', 'Alert evidence'))
        self.risk = RiskExplanationWidget(risk_queries, self)
        self.tabs.addTab(self.risk, translate('Alerts', 'Risk explanation'))
        self.tabs.setTabVisible(1, False)
        outer = QVBoxLayout(self)
        outer.addWidget(self.tabs)

    def clear(self) -> None:
        self.status_label.setText(translate('Alerts', 'No alert selected.'))
        self.status_label.show()
        for value in self.values.values():
            value.setText("—")
        self.explanation.clear()
        self.evidence.clear()
        self.risk.clear(translate('Alerts', 'No alert selected.'))
        self.tabs.setTabVisible(1, False)

    def set_alert(self, alert: Alert, network_label: str | None = None) -> None:
        request = RiskExplanationRequest.for_alert(alert)
        self.tabs.setTabVisible(1, request is not None)
        self.risk.select(request, empty=translate('Alerts', 'Generic assessment not available for this legacy alert.'))
        self.status_label.hide()
        latest = alert.evidence[-1]
        values = {"type": RULE_TITLES.get(alert.rule_id, alert.rule_id.replace("_", " ")),
                  "rule": alert.rule_id, "status": alert.status.value,
                  "severity": alert.severity, "confidence": alert.confidence,
                  "entity": entity_text(alert),
                  "network": network_label or (format_text(translate('Alerts', 'Previously observed network (scope {value1})'), value1=alert.network_fingerprint[:8])
                      if alert.network_fingerprint is not None else translate('Alerts', 'Network scope unavailable')),
                  "expected": str(latest.expected_mac) if latest.expected_mac else "—",
                  "observed": str(latest.observed_mac) if latest.observed_mac else "—",
                  "first": format_local_timestamp(alert.first_seen),
                  "last": format_local_timestamp(alert.last_seen),
                  "count": str(alert.occurrence_count),
                  "updated": format_local_timestamp(alert.updated_at)}
        for key, value in values.items():
            self.values[key].setText(render_text(value))
        self.explanation.setText(render_text(RULE_EXPLANATIONS.get(alert.rule_id, translate('Alerts', 'Review this observation in its network context.'))))
        lines: list[str] = []
        for evidence in alert.evidence:
            lines.append(format_text(translate('Alerts', 'Observed {value1}'), value1=format_local_timestamp(evidence.observed_at)))
            if evidence.ip_address:
                lines.append(f"  IP: {evidence.ip_address}")
            if evidence.expected_mac:
                lines.append(format_text(translate('Alerts', '  Expected MAC: {value1}'), value1=evidence.expected_mac))
            if evidence.observed_mac:
                lines.append(format_text(translate('Alerts', '  Observed MAC: {value1}'), value1=evidence.observed_mac))
            if evidence.expected_last_seen_at:
                lines.append(format_text(translate('Alerts', '  Expected identity last seen: {value1}'), value1=format_local_timestamp(evidence.expected_last_seen_at)))
            if evidence.baseline_status:
                lines.append(format_text(translate('Alerts', '  Gateway baseline: {value1}'), value1=evidence.baseline_status.value))
            if evidence.score is not None:
                lines.append(format_text(translate('Alerts', '  Correlation score: {value1}; observations: {value2}'), value1=evidence.score, value2=evidence.observation_count))
            for part in evidence.breakdown:
                lines.append(f"  {SCORE_EXPLANATIONS.get(part.rule.value, part.rule.value)}: {part.points}")
            for key, value in evidence.details:
                if key == "visibility" and value == "capture_filter_and_nic_offload_limited":
                    display_value = translate('Alerts', 'NIC/driver offload and capture filtering can hide VLAN tags.')
                elif key == "baseline" and value == "verified_observed":
                    display_value = translate('Alerts', 'User-accepted observed reference; switch configuration is not verified.')
                elif key == "confidence_basis":
                    display_value = value.replace("_", " ")
                else:
                    display_value = value
                lines.append(f"  {key.replace('_', ' ')}: {display_value}")
        self.evidence.setPlainText(render_join('\n', lines))


class AlertsView(QWidget):
    notification_navigation_finished = pyqtSignal(bool)
    def __init__(self, parent: QWidget | None = None, *, coordinator: AlertQueryCoordinator | None = None,
                 risk_queries: RiskQueryCoordinator | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("alertsView")
        self.setAccessibleName(translate('Alerts', 'Persisted security alerts'))
        self.coordinator = coordinator
        self.model = AlertsTableModel(self)
        self._page_index = 0
        self._generation: int | None = None
        self._has_next = False
        self._loading = False
        self._initial_requested = False
        self._selected_id: UUID | None = None
        self._ack_pending = False
        self._notification_target: UUID | None = None
        self._network_labels: dict[str, str] = {}
        self._linked_profile: tuple[str, str] | None = None

        title = QLabel(translate('Alerts', 'Alerts'), self)
        title.setStyleSheet(PAGE_TITLE)
        subtitle = QLabel(translate('Alerts', 'Review locally stored security observations and their supporting evidence.'), self)
        subtitle.setStyleSheet(SECONDARY_TEXT)
        self.status_filter = QComboBox(self)
        self.status_filter.setAccessibleName(translate('Alerts', 'Alert status filter'))
        self.status_filter.addItem(translate('Alerts', 'All statuses'), None)
        for status in AlertStatus:
            self.status_filter.addItem(display_enum(status, 'title'), status)
        self.severity_filter = QComboBox(self)
        self.severity_filter.setAccessibleName(translate('Alerts', 'Alert severity filter'))
        self.severity_filter.addItem(translate('Alerts', 'All severities'), None)
        for value in ("info", "low", "medium", "high"):
            self.severity_filter.addItem(value.title(), value)
        self.confidence_filter = QComboBox(self)
        self.confidence_filter.setAccessibleName(translate('Alerts', 'Alert confidence filter'))
        self.confidence_filter.addItem(translate('Alerts', 'All confidence levels'), None)
        for value in ("passive_observation", "low", "moderate", "high"):
            self.confidence_filter.addItem(value.replace("_", " ").title(), value)
        self.rule_filter = QComboBox(self)
        self.rule_filter.setAccessibleName(translate('Alerts', 'Alert rule filter'))
        self.rule_filter.addItem(translate('Alerts', 'All types'), None)
        for rule, label in RULE_TITLES.items():
            self.rule_filter.addItem(label, rule)
        self.refresh_button = QPushButton(translate('Alerts', 'Refresh'), self)
        self.refresh_button.setAccessibleName(translate('Alerts', 'Refresh alerts'))
        self.linked_profile_label = QLabel(translate('Alerts', 'Showing alerts for the selected device profile and network.'), self)
        self.linked_profile_label.setAccessibleName(translate('Alerts', 'Related profile alert scope'))
        self.linked_profile_label.hide()
        self.clear_profile_button = QPushButton(translate('Alerts', 'Show all alerts'), self)
        self.clear_profile_button.setAccessibleName(translate('Alerts', 'Clear related profile alert scope'))
        self.clear_profile_button.hide()
        filters = QHBoxLayout()
        control: QWidget
        for control in (self.status_filter, self.severity_filter, self.confidence_filter, self.rule_filter, self.refresh_button):
            filters.addWidget(control)

        self.state_label = QLabel(translate('Alerts', 'No alerts yet.') if coordinator is not None else translate('Alerts', 'Alerts are unavailable. Try Refresh.'), self)
        self.state_label.setAccessibleName(translate('Alerts', 'Alert loading and result status'))
        self.table = QTableView(self)
        self.table.setAccessibleName(translate('Alerts', 'Persisted alert records'))
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        cast(QHeaderView, self.table.verticalHeader()).setVisible(False)
        cast(QHeaderView, self.table.horizontalHeader()).setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.previous_button = QPushButton(translate('Alerts', 'Previous'), self)
        self.previous_button.setAccessibleName(translate('Alerts', 'Previous alert page'))
        self.next_button = QPushButton(translate('Alerts', 'Next'), self)
        self.next_button.setAccessibleName(translate('Alerts', 'Next alert page'))
        self.page_label = QLabel(translate('Alerts', 'Page 1'), self)
        self.page_label.setAccessibleName(translate('Alerts', 'Alert page number'))
        pagination = QHBoxLayout()
        pagination.addStretch()
        for control in (self.previous_button, self.page_label, self.next_button):
            pagination.addWidget(control)
        pagination.addStretch()
        self.details = AlertDetailsWidget(self, risk_queries=risk_queries)
        self.acknowledge_button = QPushButton(translate('Alerts', 'Acknowledge'), self)
        self.acknowledge_button.setAccessibleName(translate('Alerts', 'Acknowledge selected alert'))
        cast(QLayout, self.details.layout()).addWidget(self.acknowledge_button)
        table_panel = QWidget(self)
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(0, 0, 0, 0)
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
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(filters)
        link_controls = QHBoxLayout()
        link_controls.addWidget(self.linked_profile_label)
        link_controls.addWidget(self.clear_profile_button)
        link_controls.addStretch()
        layout.addLayout(link_controls)
        layout.addWidget(splitter, 1)
        for control in (self.status_filter, self.severity_filter, self.confidence_filter, self.rule_filter):
            control.currentIndexChanged.connect(self._filters_changed)
        self.refresh_button.clicked.connect(self.refresh)
        self.clear_profile_button.clicked.connect(self._clear_profile_link)
        self.previous_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)
        self.acknowledge_button.clicked.connect(self.acknowledge_selected)
        cast(QItemSelectionModel, self.table.selectionModel()).currentRowChanged.connect(self._selection_changed)
        if coordinator is not None:
            coordinator.page_ready.connect(self._page_ready)
            coordinator.detail_ready.connect(self._detail_ready)
            coordinator.query_failed.connect(self._query_failed)
            coordinator.acknowledged.connect(self._acknowledged)
            coordinator.action_failed.connect(self._action_failed)
        self._update_controls()

    @property
    def page_index(self) -> int:
        return self._page_index

    @property
    def selected_alert_id(self):
        return self._selected_id

    def set_network_contexts(self, contexts) -> None:
        self._network_labels = {context.fingerprint: f"{context.interface_name} · {context.subnet}" for context in contexts}
        alert = self._selected_alert()
        if alert is not None:
            self.details.set_alert(alert, self._network_labels.get(alert.network_fingerprint or ""))

    def load_initial(self) -> None:
        if self.coordinator is not None:
            self._initial_requested = True
            self._page_index = 0
            self._request_page()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if self.coordinator is not None and not self._initial_requested:
            self.load_initial()

    def refresh(self) -> None:
        self._notification_target = None
        self._request_page()

    def open_notification_alert(self, alert_id: UUID) -> None:
        """Reveal an exact record in a single-row view, using the existing worker."""
        self._initial_requested = True
        self._notification_target = alert_id
        self._selected_id = None
        self._page_index = 0
        self._linked_profile = None
        self._has_next = False
        for control in (self.status_filter, self.severity_filter, self.confidence_filter, self.rule_filter):
            blocker = QSignalBlocker(control)
            control.setCurrentIndex(0)
            del blocker
        self.linked_profile_label.hide()
        self.clear_profile_button.hide()
        self.model.replace_alerts(())
        self.details.clear()
        self._loading = True
        self.state_label.setText(translate('Alerts', 'Loading notification alert…'))
        self.state_label.show()
        self._update_controls()
        try:
            if self.coordinator is None:
                raise RuntimeError("alert worker unavailable")
            self._generation = self.coordinator.request(alert_id)
        except RuntimeError:
            self._generation = -1
            self._query_failed(-1)

    def _detail_ready(self, generation: int, alert: object) -> None:
        if generation != self._generation or self._notification_target is None:
            return
        self._loading = False
        target = self._notification_target
        self._notification_target = None
        if isinstance(alert, Alert) and alert.id == target:
            self.model.replace_alerts((alert,))
            self.table.selectRow(0)
            self.state_label.setText(translate('Alerts', 'Notification alert. Refresh to browse all alerts.'))
            self.notification_navigation_finished.emit(True)
        else:
            self.model.replace_alerts(())
            self.details.clear()
            self.state_label.setText(translate('Alerts', 'Alert is no longer available.'))
            self.notification_navigation_finished.emit(False)
        self.state_label.show()
        self._update_controls()

    def show_profile_identity_alerts(self, profile_id, network_fingerprint: str) -> None:
        """Browse alerts emitted for one user profile by NS-040."""
        self._linked_profile = (str(profile_id), network_fingerprint)
        self._initial_requested = True
        self.linked_profile_label.show()
        self.clear_profile_button.show()
        self._page_index = 0
        self._selected_id = None
        self.details.clear()
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

    def _filters_changed(self) -> None:
        self._notification_target = None
        self._linked_profile = None
        self.linked_profile_label.hide()
        self.clear_profile_button.hide()
        self._page_index = 0
        self._selected_id = None
        self.details.clear()
        self._request_page()

    def _clear_profile_link(self) -> None:
        self._linked_profile = None
        self.linked_profile_label.hide()
        self.clear_profile_button.hide()
        self._page_index = 0
        self._selected_id = None
        self.details.clear()
        self._request_page()

    def _request_page(self) -> None:
        if self.coordinator is None:
            return
        query = AlertQuery(limit=ALERT_PAGE_SIZE, offset=self._page_index * ALERT_PAGE_SIZE,
                           status=self.status_filter.currentData(), severity=self.severity_filter.currentData(),
                           confidence=self.confidence_filter.currentData(), rule_id=self.rule_filter.currentData(),
                           network_fingerprint=self._linked_profile[1] if self._linked_profile else None,
                           entity_id=self._linked_profile[0] if self._linked_profile else None)
        self._loading = True
        self.state_label.setText(translate('Alerts', 'Loading alerts…'))
        self.state_label.show()
        self._update_controls()
        try:
            self._generation = self.coordinator.request(query)
        except RuntimeError:
            self._loading = False
            self.state_label.setText(translate('Alerts', 'Alerts are unavailable. Try Refresh.'))
            self._update_controls()

    def _page_ready(self, generation: int, page: object) -> None:
        if generation != self._generation or not isinstance(page, AlertPage):
            return
        if not page.alerts and self._page_index > 0:
            self._page_index -= 1
            self._request_page()
            return
        self._loading = False
        self._has_next = page.has_next
        previous_id = self._selected_id
        # Reset selection signals must not discard a pending identical risk read.
        blocker = QSignalBlocker(cast(QItemSelectionModel, self.table.selectionModel()))
        self.model.replace_alerts(page.alerts)
        row = self.model.row_for_id(previous_id) if previous_id is not None else None
        if row is not None:
            self.table.selectRow(row)
        else:
            self._selected_id = None
            self.details.clear()
        del blocker
        if row is not None:
            alert = self.model.alert_at(row)
            if alert is not None:
                self._selected_id = alert.id
                self.details.set_alert(alert, self._network_labels.get(alert.network_fingerprint or ""))
        if page.alerts:
            self.state_label.hide()
        else:
            self.state_label.setText(render_text(translate('Alerts', 'No identity alerts for this profile.') if self._linked_profile else translate('Alerts', 'No alerts match the current filters.') if self._filters_active() else translate('Alerts', 'No alerts yet.')))
            self.state_label.show()
        self._update_controls()

    def _query_failed(self, generation: int) -> None:
        if generation != self._generation:
            return
        self._loading = False
        if self._notification_target is not None:
            self._notification_target = None
            self.notification_navigation_finished.emit(False)
        self._has_next = False
        self.model.replace_alerts(())
        self._selected_id = None
        self.details.clear()
        self.state_label.setText(translate('Alerts', 'Alerts are unavailable. Try Refresh.'))
        self.state_label.show()
        self._update_controls()

    def _selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        alert = self.model.alert_at(current.row()) if current.isValid() else None
        if alert is None:
            self._selected_id = None
            self.details.clear()
        else:
            self._selected_id = alert.id
            self.details.set_alert(alert, self._network_labels.get(alert.network_fingerprint or ""))
        self._update_controls()

    def _selected_alert(self) -> Alert | None:
        row = self.model.row_for_id(self._selected_id) if self._selected_id is not None else None
        return self.model.alert_at(row) if row is not None else None

    def acknowledge_selected(self) -> None:
        alert = self._selected_alert()
        if alert is None or alert.status is not AlertStatus.OPEN or self._ack_pending or self.coordinator is None:
            return
        self._ack_pending = True
        self._update_controls()
        if not self.coordinator.acknowledge(alert.id):
            self._action_failed(alert.id)

    def _acknowledged(self, alert: object) -> None:
        if not isinstance(alert, Alert):
            return
        self._ack_pending = False
        self.refresh()

    def _action_failed(self, _alert_id: object) -> None:
        self._ack_pending = False
        self.state_label.setText(translate('Alerts', 'Unable to acknowledge alert. Try again.'))
        self.state_label.show()
        self._update_controls()

    def _filters_active(self) -> bool:
        return any(control.currentData() is not None for control in
                   (self.status_filter, self.severity_filter, self.confidence_filter, self.rule_filter))

    def _update_controls(self) -> None:
        self.page_label.setText(format_text(translate('Alerts', 'Page {value1}'), value1=self._page_index + 1))
        self.previous_button.setEnabled(not self._loading and self._page_index > 0)
        self.next_button.setEnabled(not self._loading and self._has_next)
        alert = self._selected_alert()
        self.acknowledge_button.setEnabled(not self._loading and not self._ack_pending and
                                           alert is not None and alert.status is AlertStatus.OPEN)


__all__ = ("ALERT_PAGE_SIZE", "AlertDetailsWidget", "AlertsView")
