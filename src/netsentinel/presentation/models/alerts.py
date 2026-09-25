"""Safe, stable-ID presentation rows for persisted alerts."""

from __future__ import annotations

from enum import IntEnum
from uuid import UUID

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt

from netsentinel.domain.alerts import Alert
from netsentinel.presentation.models.history import format_local_timestamp


class AlertColumn(IntEnum):
    LAST_SEEN = 0
    STATUS = 1
    SEVERITY = 2
    CONFIDENCE = 3
    TYPE = 4
    ENTITY = 5
    OCCURRENCES = 6


HEADERS = ("Last seen", "Status", "Severity", "Confidence", "Type", "Entity", "Occurrences")
RULE_TITLES = {
    "ip_mac_conflict": "IP-MAC identity conflict observed",
    "gateway_mac_change": "Gateway MAC differs from expected baseline",
    "new_device": "New device observed",
    "dns_server_set_change": "DNS server configuration changed",
}
RULE_EXPLANATIONS = {
    "ip_mac_conflict": "A different sender MAC was observed for an IP recently associated with another MAC. Normal network changes can also cause this signal.",
    "gateway_mac_change": "A gateway sender MAC differs from the stored expected baseline. Review the network and baseline context before drawing conclusions.",
    "new_device": "A device identity was first observed after the initial learning period. Its trust has not been verified.",
    "dns_server_set_change": "The Windows DNS server set changed after repeated consistent readings. Review the previous and current configuration; this alone does not imply an attack.",
}
SCORE_EXPLANATIONS = {
    "identity_conflict": "Identity conflict",
    "repeated_observation": "Repeated observation",
    "verified_gateway": "Verified gateway baseline",
    "combined_targets": "Multiple affected targets",
}


def entity_text(alert: Alert) -> str:
    latest = alert.evidence[-1]
    if latest.ip_address:
        return latest.ip_address
    if latest.observed_mac is not None:
        return str(latest.observed_mac)
    return "Other observed entity"


class AlertsTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._alerts: tuple[Alert, ...] = ()
        self._by_id: dict[UUID, int] = {}

    @property
    def alerts(self) -> tuple[Alert, ...]:
        return self._alerts

    def replace_alerts(self, alerts: tuple[Alert, ...]) -> None:
        unique = tuple(dict((alert.id, alert) for alert in alerts).values())
        self.beginResetModel()
        self._alerts = unique
        self._by_id = {alert.id: i for i, alert in enumerate(unique)}
        self.endResetModel()

    def alert_at(self, row: int) -> Alert | None:
        return self._alerts[row] if 0 <= row < len(self._alerts) else None

    def row_for_id(self, alert_id: UUID) -> int | None:
        return self._by_id.get(alert_id)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._alerts)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(HEADERS):
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        alert = self.alert_at(index.row()) if index.isValid() else None
        if alert is None:
            return None
        if role == Qt.ItemDataRole.UserRole:
            return alert.id
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        values = (format_local_timestamp(alert.last_seen), alert.status.value,
                  alert.severity, alert.confidence, RULE_TITLES.get(alert.rule_id, alert.rule_id.replace("_", " ")),
                  entity_text(alert), str(alert.occurrence_count))
        return values[index.column()]


__all__ = ("AlertColumn", "AlertsTableModel", "HEADERS", "RULE_TITLES", "RULE_EXPLANATIONS", "SCORE_EXPLANATIONS", "entity_text")
