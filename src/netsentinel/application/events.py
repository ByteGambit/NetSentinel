"""Thread-safe, process-local typed event dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Generic, TypeVar, cast
from datetime import datetime
from uuid import UUID

from netsentinel.domain.alert_risk import AlertAssessmentReference, AlertWriteIntent


EventT = TypeVar("EventT")
EventSubscriber = Callable[[EventT], None]


@dataclass(frozen=True, slots=True)
class AlertNotificationIntent:
    """Process-local eligibility after both commits; never delivery proof."""

    alert_id: UUID
    fingerprint: str
    assessment: AlertAssessmentReference
    severity: str
    intent: AlertWriteIntent
    persisted_at: datetime


@dataclass(frozen=True, slots=True)
class Subscription(Generic[EventT]):
    """Opaque handle identifying one exact event subscription."""

    event_type: type[EventT]
    token: int


@dataclass(frozen=True, slots=True)
class PublishReport:
    """Bounded dispatch outcome; subscriber exceptions never escape publish."""

    delivered: int
    failed: int


class EventDispatcher:
    """Dispatch events synchronously in deterministic subscription order.

    Mutations made while an event is being published apply to the next publish;
    the current publish uses a stable subscriber snapshot. Each subscription is
    invoked at most once for an event, and exceptions from one subscriber do not
    prevent later subscribers from receiving it.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._next_token = 1
        self._subscribers: dict[
            type[object], list[tuple[int, Callable[[object], None]]]
        ] = {}

    def subscribe(
        self,
        event_type: type[EventT],
        subscriber: EventSubscriber[EventT],
    ) -> Subscription[EventT]:
        if not isinstance(event_type, type):
            raise TypeError("event_type must be a type")
        if not callable(subscriber):
            raise TypeError("subscriber must be callable")

        with self._lock:
            token = self._next_token
            self._next_token += 1
            entry = (token, cast(Callable[[object], None], subscriber))
            self._subscribers.setdefault(
                cast(type[object], event_type), []
            ).append(entry)
        return Subscription(event_type=event_type, token=token)

    def unsubscribe(self, subscription: Subscription[EventT]) -> bool:
        """Remove one subscription; return whether it was still registered."""

        if not isinstance(subscription, Subscription):
            raise TypeError("subscription must be a Subscription")

        event_type = cast(type[object], subscription.event_type)
        with self._lock:
            entries = self._subscribers.get(event_type)
            if entries is None:
                return False
            remaining = [entry for entry in entries if entry[0] != subscription.token]
            if len(remaining) == len(entries):
                return False
            if remaining:
                self._subscribers[event_type] = remaining
            else:
                del self._subscribers[event_type]
            return True

    def publish(self, event: object) -> PublishReport:
        """Publish once to exact-type subscribers, isolating callback failures."""

        with self._lock:
            entries = tuple(self._subscribers.get(type(event), ()))

        delivered = 0
        failed = 0
        for _, subscriber in entries:
            try:
                subscriber(event)
            except Exception:
                failed += 1
            else:
                delivered += 1
        return PublishReport(delivered=delivered, failed=failed)


__all__ = (
    "AlertNotificationIntent",
    "EventDispatcher",
    "EventSubscriber",
    "PublishReport",
    "Subscription",
)
