"""NS-027 bounded, passive correlation of NS-026 identity events."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityRule, ArpRiskAssessment,
    ArpScoreComponent, ArpScoreRule,
)
from netsentinel.domain.devices import GatewayBaselineStatus, NetworkContext
from netsentinel.domain.observations import PacketObservation


@dataclass(slots=True)
class _Signal:
    event: ArpIdentityConflictDetected
    # Three distinct observations are enough for the repeat rule. Saturating
    # here bounds memory even during an arbitrarily fast packet burst.
    received: deque[tuple[datetime, datetime]] = field(default_factory=lambda: deque(maxlen=3))
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    last_emitted_confidence: str | None = None


class ArpAnomalyCorrelator:
    """Assess repeat and cross-target evidence without retaining packet objects.

    The injected clock measures the rolling window and expiry. Observation UTC
    times order evidence; old or duplicate timestamps cannot advance a signal.
    One result is emitted for a new discrepancy and for a confidence transition.
    """

    def __init__(self, *, window: timedelta = timedelta(seconds=120), capacity: int = 512,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be positive")
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        self._window = window
        self._capacity = capacity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signals: OrderedDict[str, _Signal] = OrderedDict()
        self._last_now: datetime | None = None
        self._capacity_drops = 0

    @property
    def retained_signals(self) -> int:
        self._prune(self._now())
        return len(self._signals)

    @property
    def capacity_drops(self) -> int:
        return self._capacity_drops

    def observe(self, context: NetworkContext, observation: PacketObservation,
                events: Iterable[ArpIdentityConflictDetected] = ()) -> tuple[ArpRiskAssessment, ...]:
        if not isinstance(context, NetworkContext) or not isinstance(observation, PacketObservation):
            raise TypeError("context and observation must be portable models")
        now = self._now()
        self._prune(now)
        if (observation.network_fingerprint != context.fingerprint
                or observation.interface_id.casefold() != context.interface_id.casefold()
                or observation.interface_index != context.interface_index
                or observation.observed_at < context.observed_at or observation.arp is None):
            return ()

        incoming = tuple(events)
        for event in incoming:
            if not isinstance(event, ArpIdentityConflictDetected):
                raise TypeError("events must be NS-026 identity events")
            if (event.evidence.network_fingerprint != context.fingerprint
                    or event.observed_at != observation.observed_at
                    or event.evidence.ip_address != observation.arp.sender_ip
                    or event.evidence.observed_mac != observation.arp.sender_mac):
                raise ValueError("event must match the current ARP sender and context")

        changed: list[str] = []
        incoming_keys = {event.event_fingerprint for event in incoming}
        for event in incoming:
            key = event.event_fingerprint
            signal = self._signals.get(key)
            if any(
                other_key != key
                and other.event.evidence.network_fingerprint == context.fingerprint
                and other.event.evidence.ip_address == event.evidence.ip_address
                and other.last_observed_at >= event.observed_at
                for other_key, other in self._signals.items()
            ):
                continue
            if signal is None:
                if len(self._signals) >= self._capacity:
                    self._signals.popitem(last=False)
                    self._capacity_drops += 1
                signal = _Signal(event)
                self._signals[key] = signal
            elif observation.observed_at <= signal.last_observed_at:
                continue
            else:
                signal.event = event
                self._signals.move_to_end(key)
            self._record(signal, observation.observed_at, now)
            changed.append(key)

        # A detector may suppress a repeated discrepancy (for example a
        # pending gateway MAC). Repeated passive sender metadata still adds
        # evidence to an existing signal, but cannot create one on its own.
        for key, signal in self._signals.items():
            if key in incoming_keys or signal.event.evidence.network_fingerprint != context.fingerprint:
                continue
            evidence = signal.event.evidence
            if (evidence.ip_address == observation.arp.sender_ip
                    and evidence.observed_mac == observation.arp.sender_mac
                    and not any(
                        other_key != key
                        and other.event.evidence.network_fingerprint == context.fingerprint
                        and other.event.evidence.ip_address == evidence.ip_address
                        and other.last_observed_at >= observation.observed_at
                        for other_key, other in self._signals.items()
                    )
                    and observation.observed_at > signal.last_observed_at):
                self._record(signal, observation.observed_at, now)
                changed.append(key)

        results: list[ArpRiskAssessment] = []
        for key in changed:
            signal = self._signals[key]
            event = signal.event
            components = [ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2)]
            repeated = len(signal.received) >= 3
            if repeated:
                components.append(ArpScoreComponent(ArpScoreRule.REPEATED_OBSERVATION, 1))
            if (event.rule_id is ArpIdentityRule.GATEWAY_MAC_CHANGE
                    and event.evidence.baseline_status is GatewayBaselineStatus.VERIFIED):
                components.append(ArpScoreComponent(ArpScoreRule.VERIFIED_GATEWAY, 1))
            combined = any(
                other_key != key
                and other.event.evidence.network_fingerprint == event.evidence.network_fingerprint
                and other.event.evidence.ip_address != event.evidence.ip_address
                and other.event.rule_id != event.rule_id
                for other_key, other in self._signals.items()
            )
            if combined:
                components.append(ArpScoreComponent(ArpScoreRule.COMBINED_TARGETS, 2))
            score = sum(part.points for part in components)
            confidence = "moderate" if repeated or combined else "low"
            if signal.last_emitted_confidence == confidence:
                continue
            signal.last_emitted_confidence = confidence
            results.append(ArpRiskAssessment(
                event, signal.first_observed_at, signal.last_observed_at,
                len(signal.received), tuple(components), score, confidence,
            ))
        return tuple(results)

    def _record(self, signal: _Signal, observed_at: datetime, now: datetime) -> None:
        signal.received.append((now, observed_at))
        signal.first_observed_at = signal.received[0][1]
        signal.last_observed_at = observed_at

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._window
        for key, signal in tuple(self._signals.items()):
            while signal.received and signal.received[0][0] <= cutoff:
                signal.received.popleft()
            if not signal.received:
                del self._signals[key]
            else:
                signal.first_observed_at = signal.received[0][1]

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("clock must return a UTC-aware datetime")
        now = value.astimezone(UTC)
        if self._last_now is not None and now < self._last_now:
            now = self._last_now
        self._last_now = now
        return now


__all__ = ("ArpAnomalyCorrelator",)
