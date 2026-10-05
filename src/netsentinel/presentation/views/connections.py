"""Live Connections page backed by the incremental NS-010 model."""

from __future__ import annotations

from collections.abc import Callable

from typing import cast
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QHeaderView
from PyQt6.QtCore import (
    QModelIndex,
    QSignalBlocker,
    QTimer,
    Qt,
    pyqtSlot,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from netsentinel.domain.connections import ConnectionState, TransportProtocol
from netsentinel.domain.connections import ProcessInfo
from netsentinel.application.services.executable_signer import ExecutableSignerService, SignerSubmission
from netsentinel.domain.connections import ConnectionNetworkScope
from netsentinel.application.services.destination_evidence import live_request, DestinationEvidenceResult
from netsentinel.presentation.destination_query import DestinationQueryCoordinator
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator
from netsentinel.application.services.baseline_detail import baseline_detail_request
from netsentinel.presentation.bridge import BridgeHealthSnapshot
from netsentinel.presentation.models.connection_filter import (
    ConnectionsFilterProxyModel,
)
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
    ConnectionsTableModel,
)
from netsentinel.presentation.viewmodels import ConnectionRowId
from netsentinel.presentation.widgets.connection_details import (
    ConnectionDetailsWidget,
)
from netsentinel.presentation.widgets.page_flow import EndpointTableView, MonitoringPageScroll
from netsentinel.presentation.theme import PAGE_TITLE, SECONDARY_TEXT
from netsentinel.shared.diagnostics import CapabilityStatus, EngineState
from netsentinel.presentation.widgets.threat_intel_lookup import ThreatIntelLookupWidget


class ConnectionsView(QWidget):
    """Searchable, sortable active connections with stable-ID details."""

    def __init__(
        self,
        model: ConnectionsTableModel | None = None,
        parent: QWidget | None = None,
        *, destination_queries: DestinationQueryCoordinator | None = None,
        signer_service: ExecutableSignerService | None = None,
        baseline_queries: BaselineQueryCoordinator | None = None,
        risk_queries: RiskQueryCoordinator | None = None,
        preference_commands: PreferenceCommandCoordinator | None = None,
        threat_intel: ThreatIntelLookupWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("connectionsPage")
        self.setAccessibleName("Connections")

        self.source_model = (
            ConnectionsTableModel(self) if model is None else model
        )
        self.proxy_model = ConnectionsFilterProxyModel(self)
        self._selected_row_id: ConnectionRowId | None = None
        self.destination_queries = destination_queries
        self.signer_service = signer_service
        self._signer_submission: SignerSubmission | None = None
        self._signer_timer = QTimer(self)
        self._signer_timer.setInterval(100)
        self._signer_timer.timeout.connect(self._poll_signer)
        self._destination_generation: int | None = None
        self._selection_syncing = False
        self._selected_row_removing = False
        self._paused = False
        self._monitoring_unavailable = False
        # Register before the proxy so a selected identity is captured before
        # QItemSelectionModel reacts to proxy row removal and selects a neighbor.
        self.source_model.rowsAboutToBeRemoved.connect(
            self._on_source_rows_about_to_be_removed
        )
        self.proxy_model.setSourceModel(self.source_model)

        self.title_label = QLabel("Connections", self)
        self.title_label.setObjectName("pageTitle")
        self.title_label.setStyleSheet(PAGE_TITLE)
        self.subtitle_label = QLabel(
            "Active TCP and UDP connections observed by NetSentinel.", self
        )
        self.subtitle_label.setObjectName("pageDescription")
        self.subtitle_label.setStyleSheet(SECONDARY_TEXT)

        self.health_label = QLabel("Waiting for monitoring status…", self)
        self.health_label.setObjectName("connectionsHealth")
        self.health_label.setAccessibleName("Connection monitoring status")
        self.health_label.setWordWrap(True)
        self.health_label.setStyleSheet(
            "background: #eef4fb; color: #334e68; border-radius: 4px; padding: 7px;"
        )

        self.search_edit = QLineEdit(self)
        self.search_edit.setObjectName("connectionSearch")
        self.search_edit.setPlaceholderText(
            "Search process, PID, local or remote endpoint"
        )
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setAccessibleName("Search connections")

        self.protocol_filter = QComboBox(self)
        self.protocol_filter.setObjectName("protocolFilter")
        self.protocol_filter.setAccessibleName("Protocol filter")
        self.protocol_filter.addItem("All protocols", None)
        self.protocol_filter.addItem("TCP", TransportProtocol.TCP.value)
        self.protocol_filter.addItem("UDP", TransportProtocol.UDP.value)

        self.state_filter = QComboBox(self)
        self.state_filter.setObjectName("stateFilter")
        self.state_filter.setAccessibleName("Connection state filter")
        self.state_filter.addItem("All states", None)
        for state in ConnectionState:
            self.state_filter.addItem(_state_label(state), state.value)

        self.pause_button = QPushButton("Pause view", self)
        self.pause_button.setObjectName("pauseConnectionsView")
        self.pause_button.setAccessibleName("Pause connection updates")
        self.pause_button.setCheckable(True)
        self.pause_button.setToolTip(
            "Freeze painting while monitoring continues in the background"
        )
        self.pause_notice = QLabel(
            "View paused; monitoring continues in the background.", self
        )
        self.pause_notice.setObjectName("connectionsPauseNotice")
        self.pause_notice.setStyleSheet("color: #8d5b00;")
        self.pause_notice.hide()

        self.table = EndpointTableView(self)
        self.table.setObjectName("connectionsTable")
        self.table.setAccessibleName("Active connections")
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(
            int(ConnectionColumn.PROCESS),
            Qt.SortOrder.AscendingOrder,
        )
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        cast(QHeaderView, self.table.verticalHeader()).setVisible(False)
        cast(QHeaderView, self.table.verticalHeader()).setDefaultSectionSize(
            max(28, self.table.fontMetrics().height() + 10)
        )
        self.table.configure_columns((14, 6, 8, 24, 24, 12, 9), (1, 2, 5, 6))

        self.empty_label = QLabel("No active connections.", self)
        self.empty_label.setObjectName("connectionsEmptyState")
        self.empty_label.setAccessibleName("Connections empty state")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet("color: #829ab1; padding: 10px;")

        self.details = ConnectionDetailsWidget(self, baseline_queries=baseline_queries, preference_commands=preference_commands, risk_queries=risk_queries, threat_intel=threat_intel)
        self.details.signer_button.clicked.connect(self._request_signer)
        self.details.signer_button.setEnabled(signer_service is not None)

        table_frame = QFrame(self)
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(4)
        table_layout.addWidget(self.empty_label)
        table_layout.addWidget(self.table, 1)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        toolbar.addWidget(self.search_edit, 1)
        toolbar.addWidget(self.protocol_filter)
        toolbar.addWidget(self.state_filter)
        toolbar.addWidget(self.pause_button)

        self.page_scroll = MonitoringPageScroll(self.table, self)
        layout = self.page_scroll.page_layout
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addWidget(self.health_label)
        layout.addLayout(toolbar)
        layout.addWidget(self.pause_notice)
        layout.addWidget(table_frame)
        layout.addWidget(self.details)
        layout.addStretch(1)

        self.search_edit.textChanged.connect(self._set_search_filter)
        self.protocol_filter.currentIndexChanged.connect(self._set_protocol_filter)
        self.state_filter.currentIndexChanged.connect(self._set_state_filter)
        self.pause_button.toggled.connect(self.set_paused)
        cast(QItemSelectionModel, self.table.selectionModel()).currentRowChanged.connect(
            self._on_current_row_changed
        )
        self.proxy_model.dataChanged.connect(self._on_proxy_data_changed)
        self.proxy_model.rowsInserted.connect(self._on_proxy_structure_changed)
        self.proxy_model.rowsRemoved.connect(self._on_proxy_structure_changed)
        self.proxy_model.modelReset.connect(self._on_proxy_structure_changed)
        self.proxy_model.layoutChanged.connect(self._on_proxy_structure_changed)
        self._update_empty_state()
        if destination_queries is not None:
            destination_queries.result_ready.connect(self._destination_ready)
            destination_queries.query_failed.connect(self._destination_failed)

    @property
    def selected_row_id(self) -> ConnectionRowId | None:
        return self._selected_row_id

    @property
    def paused(self) -> bool:
        return self._paused

    @pyqtSlot(BridgeHealthSnapshot)
    def set_health(self, health: BridgeHealthSnapshot) -> None:
        """Present portable engine/bridge health without engine access."""

        connection_status = health.engine.capabilities.connection_monitoring
        process_status = health.engine.capabilities.process_metadata
        self._monitoring_unavailable = (
            connection_status is CapabilityStatus.UNAVAILABLE
        )

        if health.engine.state is EngineState.STOPPING:
            message = "Connection monitoring is stopping."
            severity = "warning"
        elif health.engine.state is EngineState.STOPPED:
            message = "Connection monitoring is stopped."
            severity = "warning"
        elif connection_status is CapabilityStatus.UNAVAILABLE:
            message = (
                "Connection monitoring is unavailable. Check Windows permissions "
                "and monitoring diagnostics."
            )
            severity = "error"
        elif connection_status is CapabilityStatus.DEGRADED:
            message = (
                "Connection monitoring is degraded; some active connections may "
                "be unavailable."
            )
            severity = "warning"
        elif health.engine.last_error is not None:
            message = (
                "Connection monitoring reported an error; displayed data may be "
                "incomplete. Review monitoring diagnostics."
            )
            severity = "error"
        elif process_status is not CapabilityStatus.AVAILABLE:
            message = (
                "Process metadata is limited; unavailable process values are "
                "shown as —."
            )
            severity = "warning"
        else:
            message = "Connection monitoring is active."
            severity = "normal"

        if health.dropped_events:
            message += (
                f" {health.dropped_events} UI update event(s) were dropped; "
                "the view may be incomplete."
            )
            severity = "error"

        colors = {
            "normal": ("#edf8f0", "#276749"),
            "warning": ("#fff8e6", "#8d5b00"),
            "error": ("#fff0f0", "#9b2c2c"),
        }
        background, foreground = colors[severity]
        self.health_label.setText(message)
        self.health_label.setStyleSheet(
            f"background: {background}; color: {foreground}; "
            "border-radius: 4px; padding: 7px;"
        )
        self._update_empty_state()

    @pyqtSlot(bool)
    def set_paused(self, paused: bool) -> None:
        """Freeze visible painting while retaining every source-model event."""

        paused = bool(paused)
        if paused == self._paused:
            return
        self._paused = paused
        if self.pause_button.isChecked() != paused:
            self.pause_button.setChecked(paused)
        self.pause_button.setText("Resume view" if paused else "Pause view")
        self.pause_notice.setVisible(paused)
        self.search_edit.setEnabled(not paused)
        self.protocol_filter.setEnabled(not paused)
        self.state_filter.setEnabled(not paused)
        self.table.setEnabled(not paused)
        cast(QWidget, self.table.viewport()).setUpdatesEnabled(not paused)
        if not paused:
            self._restore_selected_row()
            cast(QWidget, self.table.viewport()).update()

    def clear_filters(self) -> None:
        """Restore all connection rows without mutating the source model."""

        selected = self._selected_row_id
        self._selection_syncing = True
        blockers = (
            QSignalBlocker(self.search_edit),
            QSignalBlocker(self.protocol_filter),
            QSignalBlocker(self.state_filter),
        )
        try:
            self.search_edit.clear()
            self.protocol_filter.setCurrentIndex(0)
            self.state_filter.setCurrentIndex(0)
            self.proxy_model.set_search_text("")
            self.proxy_model.set_protocol_filter(None)
            self.proxy_model.set_state_filter(None)
        finally:
            del blockers
            self._selection_syncing = False
        self._selected_row_id = selected
        self._restore_selected_row()
        self._update_empty_state()

    def _set_search_filter(self, text: str) -> None:
        self._apply_filter_change(lambda: self.proxy_model.set_search_text(text))

    def _set_protocol_filter(self) -> None:
        value = self.protocol_filter.currentData()
        self._apply_filter_change(
            lambda: self.proxy_model.set_protocol_filter(value)
        )

    def _set_state_filter(self) -> None:
        value = self.state_filter.currentData()
        self._apply_filter_change(lambda: self.proxy_model.set_state_filter(value))

    def _apply_filter_change(self, change: Callable[[], None]) -> None:
        selected = self._selected_row_id
        self._selection_syncing = True
        try:
            change()
        finally:
            self._selection_syncing = False
        self._selected_row_id = selected
        self._restore_selected_row()
        self._update_empty_state()

    def _on_current_row_changed(
        self,
        current: QModelIndex,
        _previous: QModelIndex,
    ) -> None:
        if self._selection_syncing:
            return
        self._signer_submission = None
        self._signer_timer.stop()
        if not current.isValid():
            self._selected_row_id = None
            self.details.clear()
            self._destination_generation = None
            return
        row_id = self.proxy_model.data(current, int(ConnectionRole.ROW_ID))
        if not isinstance(row_id, ConnectionRowId):
            self._selected_row_id = None
            self.details.clear()
            self._destination_generation = None
            return
        self._selected_row_id = row_id
        self.details.set_connection(current.siblingAtColumn(0))
        self._request_baseline(current)
        self._request_destination(current)

    def _request_signer(self) -> None:
        if self.signer_service is None or self._selected_row_id is None:
            return
        row = self._find_proxy_row(self._selected_row_id)
        if row is None:
            return
        process = self.proxy_model.data(self.proxy_model.index(row, 0), int(ConnectionRole.PROCESS_INFO))
        if not isinstance(process, ProcessInfo):
            return
        self._signer_submission = self.signer_service.request(process)
        self.details.signer_text.setText("Checking local disk file…")
        self._signer_timer.start()
        self._poll_signer()

    def _poll_signer(self) -> None:
        submission = self._signer_submission
        if submission is None or not submission.future.done():
            return
        self._signer_timer.stop()
        self._signer_submission = None
        if self._selected_row_id is None:
            return
        row = self._find_proxy_row(self._selected_row_id)
        if row is None:
            return
        process = self.proxy_model.data(self.proxy_model.index(row, 0), int(ConnectionRole.PROCESS_INFO))
        if isinstance(process, ProcessInfo) and submission.matches(process):
            self.details.set_signer_result(submission.future.result())

    def _on_proxy_data_changed(
        self,
        _top_left: QModelIndex,
        _bottom_right: QModelIndex,
        _roles: list[int],
    ) -> None:
        if not self._paused:
            self._restore_selected_row()

    def _on_proxy_structure_changed(self, *_args: object) -> None:
        if self._selected_row_removing:
            self._selected_row_removing = False
            self._selection_syncing = False
            self._selected_row_id = None
            cast(QItemSelectionModel, self.table.selectionModel()).clear()
            self.details.clear()
            self._destination_generation = None
            self._update_empty_state()
            return
        if not self._selection_syncing:
            self._restore_selected_row()
        self._update_empty_state()

    def _on_source_rows_about_to_be_removed(
        self,
        _parent: QModelIndex,
        first: int,
        last: int,
    ) -> None:
        if self._selected_row_id is None:
            return
        for row in range(first, last + 1):
            index = self.source_model.index(row, 0)
            if (
                self.source_model.data(index, int(ConnectionRole.ROW_ID))
                == self._selected_row_id
            ):
                self._selected_row_removing = True
                self._selection_syncing = True
                return

    def _restore_selected_row(self) -> None:
        if self._selected_row_id is None:
            cast(QItemSelectionModel, self.table.selectionModel()).clearSelection()
            self.details.clear()
            self._destination_generation = None
            return

        row = self._find_proxy_row(self._selected_row_id)
        if row is None:
            self._selection_syncing = True
            try:
                cast(QItemSelectionModel, self.table.selectionModel()).clear()
            finally:
                self._selection_syncing = False
            self._selected_row_id = None
            self.details.clear()
            self._destination_generation = None
            return

        index = self.proxy_model.index(row, 0)
        self._selection_syncing = True
        try:
            cast(QItemSelectionModel, self.table.selectionModel()).setCurrentIndex(
                index,
                QItemSelectionModel.SelectionFlag.ClearAndSelect
                | QItemSelectionModel.SelectionFlag.Rows,
            )
        finally:
            self._selection_syncing = False
        if not self._paused:
            self.details.set_connection(index)
            self._request_baseline(index)
            self._request_destination(index)

    def _request_baseline(self, index: QModelIndex) -> None:
        first = index.siblingAtColumn(0)
        process = self.proxy_model.data(first, int(ConnectionRole.PROCESS_INFO))
        network = self.proxy_model.data(first, int(ConnectionRole.NETWORK_SCOPE))
        remote = self.proxy_model.data(first, int(ConnectionRole.RAW_REMOTE_ADDRESS))
        remote_port = self.proxy_model.data(first, int(ConnectionRole.RAW_REMOTE_PORT))
        protocol = self.proxy_model.data(first, int(ConnectionRole.RAW_PROTOCOL))
        if not isinstance(process, ProcessInfo):
            self.details.baseline.clear()
            return
        if not isinstance(network, ConnectionNetworkScope):
            network = ConnectionNetworkScope.unknown()
        self.details.baseline.select(baseline_detail_request(process, network, remote if isinstance(remote, str) else None,
                                     remote_port if isinstance(remote_port, int) else None,
                                     TransportProtocol(protocol) if isinstance(protocol, str) else None),
                                     self._selected_row_id)

    def _request_destination(self, index: QModelIndex) -> None:
        first = index.siblingAtColumn(0)
        remote = self.proxy_model.data(first, int(ConnectionRole.RAW_REMOTE_ADDRESS))
        if not isinstance(remote, str):
            self.details.destination.clear("No remote destination.")
            self._destination_generation = None
            return
        if self.destination_queries is None:
            self.details.destination.clear("Destination evidence unavailable.")
            return
        local = self.proxy_model.data(first, int(ConnectionRole.RAW_LOCAL_ADDRESS))
        scope = self.proxy_model.data(first, int(ConnectionRole.NETWORK_SCOPE))
        if not isinstance(scope, ConnectionNetworkScope):
            scope = ConnectionNetworkScope.unknown()
        self.details.destination.clear("Loading destination evidence…")
        try:
            self._destination_generation = self.destination_queries.request(
                live_request(remote, local if isinstance(local, str) else None, scope)
            )
        except RuntimeError:
            self.details.destination.clear("Destination evidence unavailable.")

    def _destination_ready(self, generation: int, result: object) -> None:
        if (generation == self._destination_generation and self._selected_row_id is not None
                and isinstance(result, DestinationEvidenceResult)):
            self.details.destination.set_result(result)

    def _destination_failed(self, generation: int) -> None:
        if generation == self._destination_generation:
            self.details.destination.clear("Destination evidence unavailable.")

    def _find_proxy_row(self, row_id: ConnectionRowId) -> int | None:
        for row in range(self.proxy_model.rowCount()):
            index = self.proxy_model.index(row, 0)
            if self.proxy_model.data(index, int(ConnectionRole.ROW_ID)) == row_id:
                return row
        return None

    def _update_empty_state(self) -> None:
        empty = self.proxy_model.rowCount() == 0
        if self._monitoring_unavailable:
            text = "Connection monitoring is unavailable."
        elif self.source_model.rowCount() and empty:
            text = "No connections match the current filters."
        else:
            text = "No active connections."
        self.empty_label.setText(text)
        self.empty_label.setVisible(empty)


def _state_label(state: ConnectionState) -> str:
    if state is ConnectionState.NONE:
        return "Not applicable (UDP)"
    return state.value.replace("_", " ").title()


__all__ = ("ConnectionsView",)
