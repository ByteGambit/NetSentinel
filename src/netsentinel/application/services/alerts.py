"""NS-028 portable alert lifecycle over existing detector outputs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Callable
from uuid import UUID

from netsentinel.application.ports import AlertQuery, AlertRepository
from netsentinel.domain.alerts import (
    Alert, AlertCandidate, AlertEvidence, AlertStatus, ArpRiskAssessment,
    NewDeviceDetected,
)
from netsentinel.domain.alert_risk import AlertWriteIntent
from dataclasses import replace


DEFAULT_RATE_WINDOW = timedelta(seconds=120)


class AlertService:
    """Store meaningful detector output; rate limit outward notifications."""

    def __init__(self, repository: AlertRepository, *, clock: Callable[[], datetime] | None = None,
                 rate_window: timedelta = DEFAULT_RATE_WINDOW) -> None:
        if not isinstance(rate_window, timedelta) or rate_window <= timedelta(0):
            raise ValueError("rate_window must be positive")
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._rate_window = rate_window

    def record(self, event: ArpRiskAssessment | NewDeviceDetected | AlertCandidate) -> tuple[Alert, bool]:
        """Return persisted state and whether a new notification is warranted."""

        return self._repository.record(self._candidate(event), self._now(), self._rate_window)

    def acknowledge(self, alert_id: UUID) -> Alert | None:
        return self._repository.set_status(alert_id, AlertStatus.ACKNOWLEDGED, self._now())

    def update_assessment(self, candidate: AlertCandidate) -> tuple[Alert, bool]:
        """Refresh explanation without inventing a new observation or reopening."""
        return self.record(replace(candidate, intent=AlertWriteIntent.REASSESSMENT))

    def resolve(self, alert_id: UUID) -> Alert | None:
        return self._repository.set_status(alert_id, AlertStatus.RESOLVED, self._now())

    def get(self, alert_id: UUID) -> Alert | None:
        return self._repository.get(alert_id)

    def query(self, query: AlertQuery, *, is_cancelled: Callable[[], bool] | None = None) -> tuple[Alert, ...]:
        if is_cancelled is None:
            return self._repository.query(query)
        return self._repository.query(query, is_cancelled=is_cancelled)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("clock must return a UTC-aware datetime")
        return value.astimezone(UTC)

    @staticmethod
    def _candidate(event: ArpRiskAssessment | NewDeviceDetected | AlertCandidate) -> AlertCandidate:
        if isinstance(event, AlertCandidate):
            return event
        if isinstance(event, ArpRiskAssessment):
            source = event.source
            evidence = source.evidence
            return AlertCandidate(
                event.event_fingerprint, source.rule_id.value, evidence.network_fingerprint,
                source.entity_id, event.severity, event.confidence,
                AlertEvidence(
                    event.last_observed_at, evidence.ip_address, evidence.observed_mac,
                    evidence.expected_mac, evidence.expected_last_seen_at,
                    evidence.baseline_status, event.score, event.breakdown,
                    event.observation_count,
                ),
            )
        if isinstance(event, NewDeviceDetected):
            return AlertCandidate(
                event.event_fingerprint, event.rule_id, event.device.network_fingerprint,
                str(event.entity_id), event.severity, event.confidence,
                AlertEvidence(event.observed_at, event.binding.ip_address, event.device.mac),
            )
        raise TypeError("event must be a supported portable detector output")


__all__ = ("AlertService", "DEFAULT_RATE_WINDOW")
