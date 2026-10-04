"""Incremental Qt table model for active network connections."""

from __future__ import annotations

from enum import IntEnum

from PyQt6.QtCore import (
    QByteArray,
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QThread,
    Qt,
    pyqtSlot,
)

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionUpdated,
)
from netsentinel.presentation.bridge import ConnectionEventBatch
from netsentinel.presentation.viewmodels import (
    ConnectionRow,
    ConnectionRowId,
    connection_row_from_snapshot,
    connection_row_id,
)


class ConnectionColumn(IntEnum):
    PROCESS = 0
    PID = 1
    PROTOCOL = 2
    LOCAL_ENDPOINT = 3
    REMOTE_ENDPOINT = 4
    STATE = 5
    DURATION = 6


HEADERS: tuple[str, ...] = (
    "Process",
    "PID",
    "Protocol",
    "Local endpoint",
    "Remote endpoint",
    "State",
    "Duration",
)


class ConnectionRole(IntEnum):
    """Raw roles required by the NS-011 proxy/detail layers."""

    ROW_ID = int(Qt.ItemDataRole.UserRole) + 1
    RAW_PROTOCOL = ROW_ID + 1
    RAW_STATE = ROW_ID + 2
    RAW_PROCESS = ROW_ID + 3
    RAW_PID = ROW_ID + 4
    RAW_LOCAL_ADDRESS = ROW_ID + 5
    RAW_LOCAL_PORT = ROW_ID + 6
    RAW_REMOTE_ADDRESS = ROW_ID + 7
    RAW_REMOTE_PORT = ROW_ID + 8
    DURATION = ROW_ID + 9
    PROCESS_INFO = ROW_ID + 10
    NETWORK_SCOPE = ROW_ID + 11
    LIFECYCLE_ID = ROW_ID + 12


_DISPLAY_FIELDS = (
    "process_display",
    "pid_display",
    "protocol_display",
    "local_endpoint_display",
    "remote_endpoint_display",
    "state_display",
    "duration_display",
)

_RAW_ROLE_FIELDS = {
    ConnectionRole.ROW_ID: "row_id",
    ConnectionRole.RAW_PROTOCOL: "protocol",
    ConnectionRole.RAW_STATE: "state",
    ConnectionRole.RAW_PROCESS: "process_name",
    ConnectionRole.RAW_PID: "pid",
    ConnectionRole.RAW_LOCAL_ADDRESS: "local_address",
    ConnectionRole.RAW_LOCAL_PORT: "local_port",
    ConnectionRole.RAW_REMOTE_ADDRESS: "remote_address",
    ConnectionRole.RAW_REMOTE_PORT: "remote_port",
    ConnectionRole.DURATION: "duration_seconds",
    ConnectionRole.PROCESS_INFO: "process_info",
    ConnectionRole.NETWORK_SCOPE: "network_scope",
    ConnectionRole.LIFECYCLE_ID: "lifecycle_id",
}

_CHANGED_ROLES = [
    int(Qt.ItemDataRole.DisplayRole),
    *(int(role) for role in ConnectionRole),
]


class ConnectionsTableModel(QAbstractTableModel):
    """Active connections with O(1) identity lookup and stable row ordering.

    Every mutation must run in the model's Qt thread.  ``QtEngineBridge``
    provides that boundary; consumers may connect either its batched signal to
    ``handle_events`` or its individual signals to the matching handlers.

    Unknown updates are inserted using the event's previous observation as the
    first-seen time, allowing recovery after a missed OPENED event.  Unknown
    closes and stale events are ignored.  Duplicate opens update in place only
    when they carry a newer observation.
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ConnectionRow] = []
        self._row_by_id: dict[ConnectionRowId, int] = {}

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(  # noqa: N802
        self,
        parent: QModelIndex = QModelIndex(),
    ) -> int:
        if parent.isValid():
            return 0
        return len(HEADERS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ) -> object | None:
        if (
            role == int(Qt.ItemDataRole.DisplayRole)
            and orientation is Qt.Orientation.Horizontal
            and 0 <= section < len(HEADERS)
        ):
            return HEADERS[section]
        return None

    def data(
        self,
        index: QModelIndex,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ) -> object | None:
        if not index.isValid():
            return None
        row_number = index.row()
        column = index.column()
        if not 0 <= row_number < len(self._rows) or not 0 <= column < len(HEADERS):
            return None

        row = self._rows[row_number]
        if role == int(Qt.ItemDataRole.DisplayRole):
            return getattr(row, _DISPLAY_FIELDS[column])
        try:
            raw_role = ConnectionRole(role)
        except ValueError:
            return None
        return getattr(row, _RAW_ROLE_FIELDS[raw_role])

    def roleNames(self) -> dict[int, bytes]:  # noqa: N802
        names = super().roleNames()
        names.update(
            {
                int(ConnectionRole.ROW_ID): b"rowId",
                int(ConnectionRole.RAW_PROTOCOL): b"rawProtocol",
                int(ConnectionRole.RAW_STATE): b"rawState",
                int(ConnectionRole.RAW_PROCESS): b"rawProcess",
                int(ConnectionRole.RAW_PID): b"rawPid",
                int(ConnectionRole.RAW_LOCAL_ADDRESS): b"rawLocalAddress",
                int(ConnectionRole.RAW_LOCAL_PORT): b"rawLocalPort",
                int(ConnectionRole.RAW_REMOTE_ADDRESS): b"rawRemoteAddress",
                int(ConnectionRole.RAW_REMOTE_PORT): b"rawRemotePort",
                int(ConnectionRole.DURATION): b"duration",
                int(ConnectionRole.PROCESS_INFO): b"processInfo",
                int(ConnectionRole.NETWORK_SCOPE): b"networkScope",
                int(ConnectionRole.LIFECYCLE_ID): QByteArray(b"lifecycleId"),
            }
        )
        return names

    def rows_snapshot(self) -> tuple[ConnectionRow, ...]:
        """Return immutable presentation rows for same-thread summaries."""

        self._require_model_thread()
        return tuple(self._rows)

    @pyqtSlot(ConnectionOpened)
    def handle_connection_opened(self, event: ConnectionOpened) -> None:
        self._apply_event(event)

    @pyqtSlot(ConnectionUpdated)
    def handle_connection_updated(self, event: ConnectionUpdated) -> None:
        self._apply_event(event)

    @pyqtSlot(ConnectionClosed)
    def handle_connection_closed(self, event: ConnectionClosed) -> None:
        self._apply_event(event)

    @pyqtSlot(ConnectionEventBatch)
    def handle_events(self, batch: ConnectionEventBatch) -> None:
        """Apply one ordered bridge batch without rebuilding the table."""

        self._require_model_thread()
        if not isinstance(batch, ConnectionEventBatch):
            raise TypeError("batch must be a ConnectionEventBatch")
        for event in batch.events:
            self._apply_event(event)

    def _apply_event(self, event: ConnectionLifecycleEvent) -> None:
        self._require_model_thread()
        if isinstance(event, ConnectionOpened):
            self._open(event)
        elif isinstance(event, ConnectionUpdated):
            self._update(event)
        elif isinstance(event, ConnectionClosed):
            self._close(event)
        else:
            raise TypeError("event must be a connection lifecycle event")

    def _open(self, event: ConnectionOpened) -> None:
        row_id = connection_row_id(event.key)
        existing_index = self._row_by_id.get(row_id)
        if existing_index is None:
            self._insert_row(connection_row_from_snapshot(event.snapshot, lifecycle_id=event.lifecycle_id))
            return

        existing = self._rows[existing_index]
        if event.snapshot.observed_at <= existing.observed_at:
            return
        replacement = connection_row_from_snapshot(
            event.snapshot,
            first_seen=existing.first_seen,
            lifecycle_id=event.lifecycle_id,
        )
        self._replace_row(existing_index, replacement)

    def _update(self, event: ConnectionUpdated) -> None:
        row_id = connection_row_id(event.key)
        existing_index = self._row_by_id.get(row_id)
        if existing_index is None:
            self._insert_row(
                connection_row_from_snapshot(
                    event.current,
                    first_seen=event.previous.observed_at,
                    lifecycle_id=event.lifecycle_id,
                )
            )
            return

        existing = self._rows[existing_index]
        if event.current.observed_at < existing.observed_at:
            return
        replacement = connection_row_from_snapshot(
            event.current,
            first_seen=existing.first_seen,
            lifecycle_id=event.lifecycle_id,
        )
        self._replace_row(existing_index, replacement)

    def _close(self, event: ConnectionClosed) -> None:
        row_id = connection_row_id(event.key)
        row_number = self._row_by_id.get(row_id)
        if row_number is None:
            return
        if self._rows[row_number].observed_at > event.last_snapshot.observed_at:
            return

        self.beginRemoveRows(QModelIndex(), row_number, row_number)
        self._rows.pop(row_number)
        del self._row_by_id[row_id]
        for index in range(row_number, len(self._rows)):
            self._row_by_id[self._rows[index].row_id] = index
        self.endRemoveRows()

    def _insert_row(self, row: ConnectionRow) -> None:
        row_number = len(self._rows)
        self.beginInsertRows(QModelIndex(), row_number, row_number)
        self._rows.append(row)
        self._row_by_id[row.row_id] = row_number
        self.endInsertRows()

    def _replace_row(self, row_number: int, replacement: ConnectionRow) -> None:
        if replacement == self._rows[row_number]:
            return
        self._rows[row_number] = replacement
        left = self.index(row_number, 0)
        right = self.index(row_number, len(HEADERS) - 1)
        self.dataChanged.emit(left, right, _CHANGED_ROLES)

    def _require_model_thread(self) -> None:
        if QThread.currentThread() is not self.thread():
            raise RuntimeError(
                "ConnectionsTableModel mutations must run in its Qt thread"
            )


__all__ = (
    "ConnectionColumn",
    "ConnectionRole",
    "ConnectionsTableModel",
    "HEADERS",
)
