"""Raw-role filtering and semantic sorting for active connections."""

from __future__ import annotations

from ipaddress import ip_address

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt

from netsentinel.domain.connections import ConnectionState, TransportProtocol
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
)
from netsentinel.presentation.viewmodels import ConnectionRowId


_PROTOCOL_ORDER = {
    TransportProtocol.TCP.value: 0,
    TransportProtocol.UDP.value: 1,
}
_STATE_ORDER = {state.value: index for index, state in enumerate(ConnectionState)}


class ConnectionsFilterProxyModel(QSortFilterProxyModel):
    """Combine connection search/filtering and raw-value sorting.

    Filtering never parses display strings.  It reads the NS-010 raw roles and
    composes searchable endpoint text from the raw address and port values.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._search_terms: tuple[str, ...] = ()
        self._protocol: str | None = None
        self._state: str | None = None
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    @property
    def search_text(self) -> str:
        return " ".join(self._search_terms)

    @property
    def protocol_filter(self) -> str | None:
        return self._protocol

    @property
    def state_filter(self) -> str | None:
        return self._state

    def set_search_text(self, text: str) -> None:
        if not isinstance(text, str):
            raise TypeError("search text must be a string")
        terms = tuple(part.casefold() for part in text.split() if part)
        if terms == self._search_terms:
            return
        self._search_terms = terms
        self.invalidateFilter()

    def set_protocol_filter(self, protocol: str | None) -> None:
        if protocol is not None and protocol not in _PROTOCOL_ORDER:
            raise ValueError("protocol filter must be tcp, udp, or None")
        if protocol == self._protocol:
            return
        self._protocol = protocol
        self.invalidateFilter()

    def set_state_filter(self, state: str | None) -> None:
        if state is not None and state not in _STATE_ORDER:
            raise ValueError("state filter must be a portable state or None")
        if state == self._state:
            return
        self._state = state
        self.invalidateFilter()

    def filterAcceptsRow(  # noqa: N802 - Qt API
        self,
        source_row: int,
        source_parent: QModelIndex,
    ) -> bool:
        model = self.sourceModel()
        if model is None:
            return False
        index = model.index(source_row, 0, source_parent)

        protocol = model.data(index, int(ConnectionRole.RAW_PROTOCOL))
        if self._protocol is not None and protocol != self._protocol:
            return False

        state = model.data(index, int(ConnectionRole.RAW_STATE))
        if self._state is not None and state != self._state:
            return False

        if not self._search_terms:
            return True

        process = model.data(index, int(ConnectionRole.RAW_PROCESS))
        pid = model.data(index, int(ConnectionRole.RAW_PID))
        local_address = model.data(index, int(ConnectionRole.RAW_LOCAL_ADDRESS))
        local_port = model.data(index, int(ConnectionRole.RAW_LOCAL_PORT))
        remote_address = model.data(index, int(ConnectionRole.RAW_REMOTE_ADDRESS))
        remote_port = model.data(index, int(ConnectionRole.RAW_REMOTE_PORT))

        searchable = " ".join(
            value
            for value in (
                _search_value(process),
                _search_value(pid),
                _search_value(local_address),
                _search_value(local_port),
                _endpoint_search_value(local_address, local_port),
                _search_value(remote_address),
                _search_value(remote_port),
                _endpoint_search_value(remote_address, remote_port),
            )
            if value
        ).casefold()
        return all(term in searchable for term in self._search_terms)

    def lessThan(  # noqa: N802 - Qt API
        self,
        source_left: QModelIndex,
        source_right: QModelIndex,
    ) -> bool:
        return self._sort_key(source_left) < self._sort_key(source_right)

    def _sort_key(self, index: QModelIndex) -> tuple[object, ...]:
        model = self.sourceModel()
        if model is None:
            return ()

        column = ConnectionColumn(index.column())
        if column is ConnectionColumn.PROCESS:
            primary = _optional_text_key(
                model.data(index, int(ConnectionRole.RAW_PROCESS))
            )
        elif column is ConnectionColumn.PID:
            primary = _optional_number_key(
                model.data(index, int(ConnectionRole.RAW_PID))
            )
        elif column is ConnectionColumn.PROTOCOL:
            value = model.data(index, int(ConnectionRole.RAW_PROTOCOL))
            primary = (_PROTOCOL_ORDER.get(value, len(_PROTOCOL_ORDER)), str(value))
        elif column is ConnectionColumn.LOCAL_ENDPOINT:
            primary = _endpoint_sort_key(
                model.data(index, int(ConnectionRole.RAW_LOCAL_ADDRESS)),
                model.data(index, int(ConnectionRole.RAW_LOCAL_PORT)),
            )
        elif column is ConnectionColumn.REMOTE_ENDPOINT:
            primary = _endpoint_sort_key(
                model.data(index, int(ConnectionRole.RAW_REMOTE_ADDRESS)),
                model.data(index, int(ConnectionRole.RAW_REMOTE_PORT)),
            )
        elif column is ConnectionColumn.STATE:
            value = model.data(index, int(ConnectionRole.RAW_STATE))
            primary = (_STATE_ORDER.get(value, len(_STATE_ORDER)), str(value))
        else:
            primary = _optional_number_key(
                model.data(index, int(ConnectionRole.DURATION))
            )

        row_id = model.data(index, int(ConnectionRole.ROW_ID))
        return (*primary, *_row_id_sort_key(row_id))


def _search_value(value: object | None) -> str:
    return "" if value is None else str(value)


def _endpoint_search_value(address: object | None, port: object | None) -> str:
    if address is None or port is None:
        return ""
    address_text = str(address)
    if ":" in address_text:
        return f"[{address_text}]:{port}"
    return f"{address_text}:{port}"


def _optional_text_key(value: object | None) -> tuple[object, ...]:
    if value is None:
        return (1, "")
    return (0, str(value).casefold())


def _optional_number_key(value: object | None) -> tuple[object, ...]:
    if value is None:
        return (1, 0)
    return (0, float(value))


def _endpoint_sort_key(
    address: object | None,
    port: object | None,
) -> tuple[object, ...]:
    if address is None:
        return (1, 0, 0, 0)
    parsed = ip_address(str(address))
    return (0, parsed.version, int(parsed), -1 if port is None else int(port))


def _row_id_sort_key(value: object | None) -> tuple[object, ...]:
    if not isinstance(value, ConnectionRowId):
        return ("", "", -1, "", -1, -1, "")
    return (
        value.protocol,
        value.local_address,
        value.local_port,
        value.remote_address or "",
        -1 if value.remote_port is None else value.remote_port,
        -1 if value.pid is None else value.pid,
        value.process_create_time.isoformat() if value.process_create_time else "",
    )


__all__ = ("ConnectionsFilterProxyModel",)
