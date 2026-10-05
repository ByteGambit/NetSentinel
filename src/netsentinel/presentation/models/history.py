"""Atomic page model and formatting for persisted connection history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from uuid import UUID

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt

from netsentinel.domain.connections import (
    ConnectionClosureReason,
    ConnectionHistoryRecord,
    ConnectionNetworkScope,
    ProcessInfo,
)
from netsentinel.presentation.viewmodels import (
    MISSING_VALUE,
    format_duration,
    format_endpoint,
    format_state,
)
from netsentinel.presentation.process_context import format_process_created


class HistoryColumn(IntEnum):
    PROCESS = 0
    PID = 1
    PROTOCOL = 2
    LOCAL = 3
    REMOTE = 4
    STATE = 5
    OPENED = 6
    LAST_SEEN = 7
    CLOSED = 8
    DURATION = 9


HEADERS = (
    "Process",
    "PID",
    "Protocol",
    "Local",
    "Remote",
    "State",
    "First seen",
    "Last seen",
    "Closed",
    "Observed duration",
)


@dataclass(frozen=True, slots=True)
class HistoryRow:
    record_id: UUID
    process_display: str
    pid_display: str
    protocol_display: str
    local_display: str
    remote_display: str
    state_display: str
    opened_display: str
    last_seen_display: str
    closed_display: str
    duration_display: str
    process_create_time_display: str
    close_reason_display: str
    process_info: ProcessInfo
    remote_address: str | None
    local_address: str
    network_scope: ConnectionNetworkScope
    first_seen: datetime
    last_seen: datetime
    network_scope_since: datetime | None


def history_row_from_record(record: ConnectionHistoryRecord) -> HistoryRow:
    """Map portable history metadata into safe, local-time UI text."""

    if not isinstance(record, ConnectionHistoryRecord):
        raise TypeError("record must be a ConnectionHistoryRecord")
    snapshot = record.snapshot
    identity = snapshot.process.identity
    remote = snapshot.remote_endpoint
    duration_end = record.closed_at if record.closed_at is not None else record.last_seen
    duration = max(0.0, (duration_end - record.first_seen).total_seconds())
    if record.observation_gap:
        observation_status = "Last observed before monitoring gap"
    elif record.close_reason is not None:
        observation_status = format_close_reason(record.close_reason)
    elif record.session_id is not None:
        observation_status = "Currently observed / open"
    else:
        observation_status = "Historical status unknown"
    return HistoryRow(
        record_id=record.record_id,
        process_display=snapshot.process.name or MISSING_VALUE,
        pid_display=str(identity.pid) if identity is not None else MISSING_VALUE,
        protocol_display=snapshot.protocol.value.upper(),
        local_display=format_endpoint(snapshot.local_endpoint),
        remote_display=format_endpoint(remote) if remote is not None else MISSING_VALUE,
        state_display=format_state(snapshot.state),
        opened_display=format_local_timestamp(record.first_seen),
        last_seen_display=format_local_timestamp(record.last_seen),
        closed_display=(
            format_local_timestamp(record.closed_at)
            if record.closed_at is not None
            else "Unknown (monitoring gap)" if record.observation_gap else MISSING_VALUE
        ),
        duration_display=format_duration(duration),
        process_create_time_display=format_process_created(
            identity.create_time if identity is not None else None,
            snapshot.process.create_time_status,
        ),
        close_reason_display=observation_status,
        process_info=snapshot.process,
        remote_address=remote.address if remote is not None else None,
        local_address=snapshot.local_endpoint.address,
        network_scope=snapshot.network_scope,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        network_scope_since=record.network_scope_since,
    )


def format_local_timestamp(value: datetime) -> str:
    """Render an aware UTC value in the machine's local timezone."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z")


def format_close_reason(reason: ConnectionClosureReason | None) -> str:
    if reason is None:
        return MISSING_VALUE
    if reason is ConnectionClosureReason.NOT_OBSERVED:
        return "No longer observed"
    return MISSING_VALUE


class HistoryTableModel(QAbstractTableModel):
    """One bounded page replaced atomically after a successful query."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: tuple[HistoryRow, ...] = ()

    @property
    def rows(self) -> tuple[HistoryRow, ...]:
        return self._rows

    def replace_records(self, records: tuple[ConnectionHistoryRecord, ...]) -> None:
        rows = tuple(history_row_from_record(record) for record in records)
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def clear(self) -> None:
        self.replace_records(())

    def row_at(self, row: int) -> HistoryRow | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(HEADERS):
                return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        row = self._rows[index.row()]
        values = (
            row.process_display,
            row.pid_display,
            row.protocol_display,
            row.local_display,
            row.remote_display,
            row.state_display,
            row.opened_display,
            row.last_seen_display,
            row.closed_display,
            row.duration_display,
        )
        return values[index.column()]


__all__ = (
    "HistoryColumn",
    "HistoryRow",
    "HistoryTableModel",
    "format_close_reason",
    "format_local_timestamp",
    "history_row_from_record",
)
