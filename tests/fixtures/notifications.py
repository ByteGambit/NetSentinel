"""NS-094 offline sink, clocks and committed alert fixtures."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from netsentinel.application.services.notifications import (
    NotificationDeliveryOutcome as Outcome, PersistedNotificationIntent, NotificationPlatformState,
)
from netsentinel.domain.alerts import Alert, AlertCandidate, AlertEvidence, AlertStatus, alert_id

NOW = datetime(2026, 10, 5, 10, tzinfo=UTC)


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeNotificationSink:
    def __init__(self):
        self.requests = []
        self.outcome = Outcome.SUBMITTED_TO_SINK
        self.exception = False
        self.closed = False
        self.handler = None
        self.on_submit = None
        self.attempts = 0
        self.platform_state = NotificationPlatformState.DELIVERY_UNKNOWN

    def policy_state(self):
        return self.platform_state

    def submit(self, request):
        self.attempts += 1
        if self.on_submit:
            self.on_submit(request)
        if self.exception:
            raise RuntimeError("private IP 192.0.2.1 secret.example C:/private/user")
        if self.outcome is Outcome.SUBMITTED_TO_SINK:
            self.requests.append(request)
        return self.outcome

    def set_click_handler(self, handler):
        self.handler = handler

    def click(self, index=0):
        if self.handler and not self.closed:
            self.handler(self.requests[index].alert_id)

    def close(self):
        self.closed = True


def candidate(index=1, *, seconds=0, severity="low"):
    fingerprint = sha256(str(index).encode()).hexdigest()
    return AlertCandidate(fingerprint, "ip_mac_conflict", "a" * 64, "private-user",
                          severity, "low", AlertEvidence(NOW + timedelta(seconds=seconds),
                          "192.0.2.123", details=(("path", "C:/private/user/tool.exe"),
                          ("domain", "private.example"))))


def alert(index=1, *, seconds=0, severity="low", status=AlertStatus.OPEN, count=1):
    c = candidate(index, seconds=seconds, severity=severity)
    return Alert(alert_id(c.fingerprint), c.fingerprint, c.rule_id, c.network_fingerprint,
                 c.entity_id, severity, "low", status, NOW, c.evidence.observed_at,
                 count, (c.evidence,), NOW, c.evidence.observed_at, c.evidence.observed_at)


def intent(index=1, *, previous=None, **kwargs):
    return PersistedNotificationIntent.from_alert(alert(index, **kwargs), previous, eligible=True)
