"""Bounded portable alert reads for NS-029."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from uuid import UUID

from netsentinel.application.ports import AlertQuery, MAX_ALERT_QUERY_LIMIT
from netsentinel.application.services.alerts import AlertService
from netsentinel.domain.alerts import Alert


@dataclass(frozen=True, slots=True)
class AlertPage:
    alerts: tuple[Alert, ...]
    offset: int
    page_size: int
    has_previous: bool
    has_next: bool


class AlertQueryService:
    def __init__(self, alerts: AlertService) -> None:
        self._alerts = alerts

    def load_page(self, query: AlertQuery, *, is_cancelled: Callable[[], bool] | None = None) -> AlertPage:
        if not isinstance(query, AlertQuery) or query.limit >= MAX_ALERT_QUERY_LIMIT:
            raise ValueError("alert page must leave one look-ahead row")
        larger = replace(query, limit=query.limit + 1)
        if is_cancelled is None:
            rows = self._alerts.query(larger)
        else:
            rows = self._alerts.query(larger, is_cancelled=is_cancelled)
        return AlertPage(rows[:query.limit], query.offset, query.limit, query.offset > 0, len(rows) > query.limit)

    def acknowledge(self, alert_id: UUID) -> Alert | None:
        return self._alerts.acknowledge(alert_id)

    def get(self, alert_id: UUID) -> Alert | None:
        """Exact read independent of pagination and filters; no mutation."""
        return self._alerts.get(alert_id)


__all__ = ("AlertPage", "AlertQueryService")
