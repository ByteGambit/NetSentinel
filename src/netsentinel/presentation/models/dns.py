"""Stable-ID rows and safe formatting for persisted classic DNS metadata."""

from __future__ import annotations

from ipaddress import ip_address
from uuid import UUID

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt

from netsentinel.domain.dns import DnsHistoryRecord, DnsTransactionStatus, DnsRecordType
from netsentinel.presentation.models.history import format_local_timestamp

MISSING = "—"
HEADERS = ("Time", "Status", "Query name", "Type", "Client", "DNS server",
           "Transport", "Result", "Latency", "Answers")
STATUS_TEXT = {
    DnsTransactionStatus.COMPLETED: "Response matched",
    DnsTransactionStatus.TIMED_OUT: "Timed out",
    DnsTransactionStatus.EVICTED: "Query evicted",
    DnsTransactionStatus.UNMATCHED_RESPONSE: "Unmatched response",
}
RCODE_TEXT = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


def format_record_type(value: int) -> str:
    try:
        return DnsRecordType(value).name
    except ValueError:
        return f"TYPE {value}"


def format_rcode(value: int | None) -> str:
    return MISSING if value is None else RCODE_TEXT.get(value, f"RCODE {value}")


def format_latency(value: float | None) -> str:
    return MISSING if value is None else f"{max(0.0, value) * 1000:.1f} ms"


def format_dns_endpoint(ip: str | None, port: int | None) -> str:
    if ip is None or port is None:
        return MISSING
    address = ip_address(ip)
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def event_time(record: DnsHistoryRecord):
    transaction = record.transaction
    return transaction.query_at or transaction.response_at


def answer_lines(record: DnsHistoryRecord) -> tuple[str, ...]:
    return tuple(f"{answer.name} {answer.record_type.name} {answer.value} (TTL {answer.ttl}s)"
                 for answer in record.transaction.answers[:16])


class DnsTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._records: tuple[DnsHistoryRecord, ...] = ()
        self._by_id: dict[UUID, int] = {}

    @property
    def records(self) -> tuple[DnsHistoryRecord, ...]:
        return self._records

    def replace_records(self, records: tuple[DnsHistoryRecord, ...]) -> None:
        self.beginResetModel()
        self._records = tuple(dict((record.id, record) for record in records).values())
        self._by_id = {record.id: i for i, record in enumerate(self._records)}
        self.endResetModel()

    def record_at(self, row: int) -> DnsHistoryRecord | None:
        return self._records[row] if 0 <= row < len(self._records) else None

    def row_for_id(self, record_id: UUID) -> int | None:
        return self._by_id.get(record_id)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return HEADERS[section] if 0 <= section < len(HEADERS) else None
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        record = self.record_at(index.row()) if index.isValid() else None
        if record is None:
            return None
        if role == Qt.ItemDataRole.UserRole:
            return record.id
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        tx = record.transaction
        answers = answer_lines(record)
        values = (
            format_local_timestamp(event_time(record)), STATUS_TEXT[tx.status],
            tx.questions[0].name if tx.questions else MISSING,
            format_record_type(tx.questions[0].record_type) if tx.questions else MISSING,
            format_dns_endpoint(tx.client_ip, tx.client_port),
            format_dns_endpoint(tx.server_ip, tx.server_port), tx.transport.value.upper(),
            format_rcode(tx.response_code), format_latency(tx.latency_seconds),
            "; ".join(answers) if answers else MISSING,
        )
        return values[index.column()]
