"""Qt main-thread presentation model for network-scoped device identities."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import display_timestamp

from netsentinel.presentation.i18n.text import TranslationSequence, translate

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from uuid import UUID

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QThread, Qt

from netsentinel.application.services.device_inventory import DeviceInventoryEntry
from netsentinel.domain.devices import IdentityBinding
from netsentinel.presentation.viewmodels import MISSING_VALUE


def format_seen(value: datetime) -> str:
    return display_timestamp(value)


@dataclass(frozen=True, slots=True)
class DeviceRow:
    row_id: UUID
    network_fingerprint: str
    mac: str
    ip_address: str | None
    first_seen: datetime
    last_seen: datetime
    interface_name: str
    subnet: str
    locally_administered: bool
    bindings: tuple[IdentityBinding, ...]

    @property
    def current_ip_display(self) -> str:
        return self.ip_address or MISSING_VALUE


def entry_to_row(entry: DeviceInventoryEntry) -> DeviceRow:
    device = entry.device
    bindings = tuple(sorted(entry.bindings, key=lambda b: (b.last_seen, b.ip_address), reverse=True))
    return DeviceRow(
        row_id=device.device_id,
        network_fingerprint=device.network_fingerprint,
        mac=str(device.mac),
        ip_address=bindings[0].ip_address if bindings else None,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        interface_name=entry.interface_name,
        subnet=entry.subnet,
        locally_administered=device.mac.is_locally_administered,
        bindings=bindings,
    )


class DeviceColumn(IntEnum):
    MAC = 0
    IP = 1
    FIRST_SEEN = 2
    LAST_SEEN = 3
    NETWORK = 4


HEADERS = TranslationSequence(lambda: (translate('DevicesModel', 'MAC'), translate('DevicesModel', 'Last observed IPv4'), translate('DevicesModel', 'First seen'), translate('DevicesModel', 'Last seen'), translate('DevicesModel', 'Network / interface')))
ROW_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 1
SEARCH_ROLE = ROW_ID_ROLE + 1


class DevicesTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._fingerprint: str | None = None
        self._rows: list[DeviceRow] = []
        self._by_id: dict[UUID, int] = {}

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=int(Qt.ItemDataRole.DisplayRole)):  # noqa: N802
        if role == int(Qt.ItemDataRole.DisplayRole) and orientation == Qt.Orientation.Horizontal and 0 <= section < len(HEADERS):
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = int(Qt.ItemDataRole.DisplayRole)):
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        row = self._rows[index.row()]
        if role == ROW_ID_ROLE:
            return row.row_id
        if role == SEARCH_ROLE:
            return (row.mac, *(binding.ip_address for binding in row.bindings), row.interface_name)
        if role == int(Qt.ItemDataRole.DisplayRole):
            return (
                row.mac, row.current_ip_display, format_seen(row.first_seen),
                format_seen(row.last_seen), f"{row.interface_name} · {row.subnet}",
            )[index.column()]
        return None

    def row_for_id(self, row_id: UUID) -> DeviceRow | None:
        index = self._by_id.get(row_id)
        return self._rows[index] if index is not None else None

    def row_at(self, index: int) -> DeviceRow | None:
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def apply(self, fingerprint: str | None, entries: tuple[DeviceInventoryEntry, ...]) -> None:
        if QThread.currentThread() is not self.thread():
            raise RuntimeError("DevicesTableModel mutations must run in its Qt thread")
        if fingerprint != self._fingerprint:
            self.beginResetModel()
            self._fingerprint = fingerprint
            self._rows.clear()
            self._by_id.clear()
            self.endResetModel()
        incoming: dict[UUID, DeviceRow] = {}
        for entry in entries:
            if entry.device.network_fingerprint != fingerprint:
                continue
            candidate = entry_to_row(entry)
            previous_candidate = incoming.get(candidate.row_id)
            if previous_candidate is None or candidate.last_seen >= previous_candidate.last_seen:
                incoming[candidate.row_id] = candidate
        for index in range(len(self._rows) - 1, -1, -1):
            if self._rows[index].row_id not in incoming:
                self.beginRemoveRows(QModelIndex(), index, index)
                self._rows.pop(index)
                self.endRemoveRows()
        self._by_id = {row.row_id: i for i, row in enumerate(self._rows)}
        for row_id, candidate in incoming.items():
            index = self._by_id.get(row_id)
            if index is None:
                index = len(self._rows)
                self.beginInsertRows(QModelIndex(), index, index)
                self._rows.append(candidate)
                self._by_id[row_id] = index
                self.endInsertRows()
                continue
            previous = self._rows[index]
            if candidate.last_seen < previous.last_seen:
                continue
            if candidate != previous:
                self._rows[index] = candidate
                self.dataChanged.emit(self.index(index, 0), self.index(index, len(HEADERS) - 1))


__all__ = ("DeviceColumn", "DeviceRow", "DevicesTableModel", "HEADERS", "ROW_ID_ROLE", "SEARCH_ROLE", "format_seen")
