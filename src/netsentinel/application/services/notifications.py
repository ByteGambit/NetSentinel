"""NS-094 portable, bounded delivery of committed alert intents; no I/O or Qt."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from threading import RLock
from time import monotonic
from typing import Protocol
from uuid import UUID

from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.domain.alerts import Alert, AlertStatus
from netsentinel.domain.risk_scoring import RiskSeverity


class NotificationDeliveryOutcome(str, Enum):
    POLICY_SKIPPED = "policy_skipped"
    SUBMITTED_TO_SINK = "submitted_to_sink"
    SINK_UNAVAILABLE = "sink_unavailable"
    SINK_FAILED = "sink_failed"
    QUEUED = "queued"
    QUEUE_COALESCED = "queue_coalesced"
    QUEUE_FULL = "queue_full"


@dataclass(frozen=True, slots=True)
class PersistedNotificationIntent:
    alert_id: UUID
    severity: str
    status: AlertStatus
    previous_severity: str | None
    previous_status: AlertStatus | None
    observed_at: datetime
    occurrence_count: int
    write_intent: AlertWriteIntent
    eligible: bool
    suppressed: bool = False

    def __post_init__(self) -> None:
        if (not isinstance(self.alert_id, UUID) or not isinstance(self.status, AlertStatus)
                or not isinstance(self.write_intent, AlertWriteIntent)
                or type(self.eligible) is not bool or type(self.suppressed) is not bool):
            raise ValueError("notification intent must use typed fields")
        RiskSeverity(self.severity)
        if self.previous_severity is not None:
            RiskSeverity(self.previous_severity)
        if self.previous_status is not None and not isinstance(self.previous_status, AlertStatus):
            raise ValueError("invalid previous alert status")
        if (not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None
                or self.observed_at.utcoffset() != timedelta(0)
                or type(self.occurrence_count) is not int or not 1 <= self.occurrence_count <= 1_000_000_000):
            raise ValueError("invalid persisted occurrence identity")

    @classmethod
    def from_alert(cls, alert: Alert, previous: Alert | None, *, eligible: bool,
                   write_intent: AlertWriteIntent = AlertWriteIntent.OCCURRENCE,
                   suppressed: bool = False) -> PersistedNotificationIntent:
        return cls(alert.id, alert.severity, alert.status,
                   previous.severity if previous else None, previous.status if previous else None,
                   alert.last_seen, alert.occurrence_count, write_intent, eligible, suppressed)

    @property
    def identity(self) -> tuple[UUID, int, datetime, int, str]:
        # Revision/score/confidence changes within a severity are not new popups.
        return self.alert_id, 1, self.observed_at, self.occurrence_count, self.severity


@dataclass(frozen=True, slots=True)
class DesktopNotificationRequest:
    alert_id: UUID
    severity: RiskSeverity
    title: str
    body: str

    def __post_init__(self) -> None:
        if not isinstance(self.alert_id, UUID) or not isinstance(self.severity, RiskSeverity):
            raise ValueError("invalid notification target")
        # Only allow the fixed privacy mapper output, even at the adapter seam.
        if self.title != "NetSentinel security alert" or self.body != preview_body(self.severity):
            raise ValueError("notification preview must be limited")


def preview_body(severity: RiskSeverity) -> str:
    return (f"{severity.value.title()} severity network security alert detected. "
            "Open NetSentinel to review details.")


class DesktopNotificationSink(Protocol):
    def submit(self, request: DesktopNotificationRequest) -> NotificationDeliveryOutcome: ...
    def set_click_handler(self, handler: Callable[[UUID], None]) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class NotificationDeliveryPolicy:
    version: int = 1
    cooldown_seconds: float = 120.0
    state_capacity: int = 512
    queue_capacity: int = 32
    body_max: int = 160

    def __post_init__(self) -> None:
        # V1 is an immutable frozen product policy, not an arbitrary runtime knob.
        if (self.version, self.cooldown_seconds, self.state_capacity,
                self.queue_capacity, self.body_max) != (1, 120.0, 512, 32, 160):
            raise ValueError("unsupported notification policy")


@dataclass(frozen=True, slots=True)
class NotificationDiagnostics:
    intents_seen: int = 0
    submitted_to_sink: int = 0
    duplicate_skipped: int = 0
    cooldown_skipped: int = 0
    escalation_notifications: int = 0
    suppression_skipped: int = 0
    disabled_skipped: int = 0
    sink_unavailable: int = 0
    sink_failure: int = 0
    queue_coalesced: int = 0
    queue_dropped: int = 0
    lifecycle_skipped: int = 0
    hysteresis_skipped: int = 0
    capacity_skipped: int = 0
    shutdown_skipped: int = 0
    clicks: int = 0
    navigation_success: int = 0
    navigation_failure: int = 0


@dataclass(frozen=True, slots=True)
class _State:
    identity: tuple[UUID, int, datetime, int, str]
    highest: int
    submitted_at: float | None


_RANK = {RiskSeverity.LOW: 1, RiskSeverity.MEDIUM: 2, RiskSeverity.HIGH: 3}


class NotificationDeliveryService:
    """Producer only enqueues; the GUI thread drains and owns the sink.

    State never evicts into a replay: new subjects above the session budget are
    rejected. Each subject retains one attempted identity and successful high
    watermark. Neither failure nor a policy skip is successful delivery proof.
    """

    def __init__(self, sink: DesktopNotificationSink, *, enabled: bool = False,
                 clock: Callable[[], float] = monotonic,
                 policy: NotificationDeliveryPolicy = NotificationDeliveryPolicy()) -> None:
        self.sink, self.policy, self._clock = sink, policy, clock
        self._enabled = enabled
        self._closed = False
        self._lock = RLock()
        self._queue: OrderedDict[UUID, PersistedNotificationIntent] = OrderedDict()
        self._states: dict[UUID, _State] = {}
        self._diagnostics = NotificationDiagnostics()

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @property
    def sizes(self) -> tuple[int, int]:
        with self._lock:
            return len(self._queue), len(self._states)

    def diagnostics(self) -> NotificationDiagnostics:
        with self._lock:
            return self._diagnostics

    def count(self, field: str) -> None:
        with self._lock:
            self._diagnostics = replace(self._diagnostics, **{
                field: min(2**63 - 1, getattr(self._diagnostics, field) + 1)})

    def set_enabled(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise ValueError("notification preference must be boolean")
        with self._lock:
            self._enabled = enabled
            self._queue.clear()  # Enable never replays disabled-time intents.

    def enqueue(self, intent: PersistedNotificationIntent) -> NotificationDeliveryOutcome:
        with self._lock:
            self.count("intents_seen")
            if self._closed:
                self.count("shutdown_skipped")
                return NotificationDeliveryOutcome.POLICY_SKIPPED
            if not self._enabled:
                self.count("disabled_skipped")
                return NotificationDeliveryOutcome.POLICY_SKIPPED
            if intent.suppressed or not intent.eligible or intent.status is not AlertStatus.OPEN:
                self._queue.pop(intent.alert_id, None)
                self.count("suppression_skipped" if intent.suppressed else "lifecycle_skipped")
                return NotificationDeliveryOutcome.POLICY_SKIPPED
            old = self._queue.get(intent.alert_id)
            if old is not None:
                # Preserve the initial lifecycle baseline across a pending burst.
                if (intent.observed_at, intent.occurrence_count) >= (old.observed_at, old.occurrence_count):
                    self._queue[intent.alert_id] = replace(intent,
                        previous_severity=old.previous_severity, previous_status=old.previous_status)
                self.count("queue_coalesced")
                return NotificationDeliveryOutcome.QUEUE_COALESCED
            if len(self._queue) >= self.policy.queue_capacity:
                self.count("queue_dropped")
                return NotificationDeliveryOutcome.QUEUE_FULL
            self._queue[intent.alert_id] = intent
            return NotificationDeliveryOutcome.QUEUED

    def drain_one(self) -> NotificationDeliveryOutcome | None:
        with self._lock:
            if self._closed or not self._queue:
                return None
            _, intent = self._queue.popitem(last=False)
            return self._deliver(intent)

    def _deliver(self, intent: PersistedNotificationIntent) -> NotificationDeliveryOutcome:
        skip = NotificationDeliveryOutcome.POLICY_SKIPPED
        if intent.severity == "info":
            self.count("hysteresis_skipped")
            return skip
        severity = RiskSeverity(intent.severity)
        rank = _RANK[severity]
        previous = _RANK.get(RiskSeverity(intent.previous_severity), 0) if intent.previous_severity in {"low", "medium", "high"} else 0
        state = self._states.get(intent.alert_id)
        reopened = intent.previous_status is AlertStatus.RESOLVED
        if state is not None and (state.identity == intent.identity or
                (intent.observed_at, intent.occurrence_count) < (state.identity[2], state.identity[3])):
            self.count("duplicate_skipped")
            return skip
        if state is None and len(self._states) >= self.policy.state_capacity:
            self.count("capacity_skipped")
            return skip
        highest = 0 if reopened else max(previous, state.highest if state else 0)
        submitted_at = None if reopened else state.submitted_at if state else None
        self._states[intent.alert_id] = _State(intent.identity, highest, submitted_at)
        if not reopened and (rank < highest or (
                intent.write_intent is AlertWriteIntent.REASSESSMENT and rank <= highest)):
            self.count("hysteresis_skipped")
            return skip
        escalation = not reopened and highest > 0 and rank > highest
        now = self._clock()
        if not escalation and submitted_at is not None and now - submitted_at < self.policy.cooldown_seconds:
            self.count("cooldown_skipped")
            return skip
        request = DesktopNotificationRequest(intent.alert_id, severity,
                                            "NetSentinel security alert", preview_body(severity))
        try:
            outcome = self.sink.submit(request)
        except Exception:
            outcome = NotificationDeliveryOutcome.SINK_FAILED
        if outcome is NotificationDeliveryOutcome.SUBMITTED_TO_SINK:
            self._states[intent.alert_id] = _State(intent.identity, max(highest, rank), now)
            self.count("submitted_to_sink")
            if escalation:
                self.count("escalation_notifications")
        elif outcome is NotificationDeliveryOutcome.SINK_UNAVAILABLE:
            self.count("sink_unavailable")
        else:
            outcome = NotificationDeliveryOutcome.SINK_FAILED
            self.count("sink_failure")
        return outcome

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._queue.clear()
            self._states.clear()
            try:
                self.sink.close()
            except Exception:
                self.count("sink_failure")
