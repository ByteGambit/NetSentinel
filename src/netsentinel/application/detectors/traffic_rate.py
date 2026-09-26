"""NS-037 portable broadcast/ARP rate decisions over NS-036 snapshots."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from math import isfinite
from time import monotonic

from netsentinel.application.services.traffic_metrics import (
    BaselineState, MeasurementConfidence, ProtocolRateSnapshot,
    TrafficMetricsSnapshot, TrafficProtocol,
)
from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.shared.config import TrafficRateConfig


_RULES = {
    TrafficProtocol.BROADCAST: "broadcast_rate_anomaly",
    TrafficProtocol.ARP: "arp_rate_anomaly",
}
_Key = tuple[str, str, int, TrafficProtocol]


@dataclass(frozen=True, slots=True)
class TrafficRateDecision:
    """One alert candidate or recovery request; persistence stays in AlertService."""

    candidate: AlertCandidate | None = None
    resolved_fingerprint: str | None = None


@dataclass(slots=True)
class _State:
    last_seen_at: datetime
    last_tick: float
    high_samples: int = 0
    last_high_tick: float | None = None
    recovery_count: int = 0
    last_recovery_tick: float | None = None
    active: bool = False
    last_emitted_tick: float | None = None


class TrafficRateDetector:
    """Confirm high rolling rates across a full NS-036 window.

    No packet, bucket, baseline, repository, or worker is owned here. Sparse
    high snapshots must be separated by window/(minimum_samples-1); a single
    short burst cannot remain high for the whole confirmation span. Unknown
    measurement quality and learning baselines produce no decision.
    """

    def __init__(self, *, config: TrafficRateConfig | None = None,
                 clock: Callable[[], float] = monotonic) -> None:
        self._config = config or TrafficRateConfig()
        self._clock = clock
        self._states: dict[_Key, _State] = {}
        self._last_tick: float | None = None

    @property
    def tracked_states(self) -> int:
        return len(self._states)

    @property
    def config(self) -> TrafficRateConfig:
        """Portable policy for read-only UI explanation."""
        return self._config

    def retry_after_alert_failure(self, decision: TrafficRateDecision) -> None:
        """Release cooldown or recovery after a failed AlertService operation."""
        fingerprint = (decision.candidate.fingerprint if decision.candidate is not None
                       else decision.resolved_fingerprint)
        for key, state in self._states.items():
            if self._fingerprint(key) != fingerprint:
                continue
            if decision.candidate is not None:
                state.last_emitted_tick = None
            else:
                state.active = True
                state.recovery_count = 0
                state.last_recovery_tick = None
            return

    def assess(self, snapshot: TrafficMetricsSnapshot, observed_at: datetime) -> tuple[TrafficRateDecision, ...]:
        if not isinstance(snapshot, TrafficMetricsSnapshot):
            raise TypeError("snapshot must be TrafficMetricsSnapshot")
        if (not isinstance(observed_at, datetime) or observed_at.tzinfo is None
                or observed_at.utcoffset() != timedelta(0)):
            raise ValueError("observed_at must be UTC-aware")
        if (not isinstance(snapshot.confidence, MeasurementConfidence)
                or type(snapshot.window_seconds) is not int or snapshot.window_seconds <= 0
                or snapshot.arp.protocol is not TrafficProtocol.ARP
                or snapshot.broadcast.protocol is not TrafficProtocol.BROADCAST):
            raise ValueError("invalid traffic metrics snapshot")
        tick = self._now()
        self._expire(tick)
        if snapshot.confidence is MeasurementConfidence.UNKNOWN:
            return ()
        decisions: list[TrafficRateDecision] = []
        for rate in (snapshot.broadcast, snapshot.arp):
            decision = self._assess_rate(snapshot, rate, observed_at.astimezone(UTC), tick)
            if decision is not None:
                decisions.append(decision)
        return tuple(decisions)

    def _assess_rate(self, snapshot: TrafficMetricsSnapshot, rate: ProtocolRateSnapshot,
                     observed_at: datetime, tick: float) -> TrafficRateDecision | None:
        if (rate.baseline.state is not BaselineState.LEARNED
                or rate.baseline.packets_per_second is None):
            return None
        baseline = rate.baseline.packets_per_second
        current = rate.packets_per_second
        if (not isfinite(baseline) or baseline < 0 or not isfinite(current) or current < 0
                or type(rate.packet_count) is not int or rate.packet_count < 0):
            raise ValueError("rate and baseline must be finite and nonnegative")
        key = (snapshot.network_fingerprint, snapshot.interface_id.casefold(),
               snapshot.interface_index, rate.protocol)
        state = self._states.get(key)
        if state is not None and observed_at <= state.last_seen_at:
            return None
        if state is None:
            floor = (self._config.arp_floor_pps if rate.protocol is TrafficProtocol.ARP
                     else self._config.broadcast_floor_pps)
            if current <= max(floor, baseline * self._config.baseline_multiplier):
                return None
            if len(self._states) >= self._config.max_states:
                victim = min(self._states, key=lambda item: (self._states[item].last_tick,
                                                              item[0], item[1], item[2], item[3].value))
                del self._states[victim]
            state = _State(observed_at, tick)
            self._states[key] = state
        state.last_seen_at = observed_at
        state.last_tick = tick
        floor = (self._config.arp_floor_pps if rate.protocol is TrafficProtocol.ARP
                 else self._config.broadcast_floor_pps)
        threshold = max(floor, baseline * self._config.baseline_multiplier)
        interval = snapshot.window_seconds / (self._config.minimum_samples - 1)
        if current > threshold:
            state.recovery_count = 0
            state.last_recovery_tick = None
            if state.last_high_tick is None or tick - state.last_high_tick >= interval:
                state.high_samples += 1
                state.last_high_tick = tick
            if not state.active and state.high_samples < self._config.minimum_samples:
                return None
            if (state.active and state.last_emitted_tick is not None
                    and tick - state.last_emitted_tick < self._config.cooldown_seconds):
                return None
            state.active = True
            state.last_emitted_tick = tick
            return TrafficRateDecision(candidate=self._candidate(snapshot, rate, observed_at, threshold))
        state.high_samples = 0
        state.last_high_tick = None
        if not state.active:
            return None
        # Loss can undercount the rate. Never resolve from incomplete data.
        if (snapshot.confidence is not MeasurementConfidence.COMPLETE
                or current > threshold * self._config.recovery_fraction):
            state.recovery_count = 0
            state.last_recovery_tick = None
            return None
        recovery_interval = snapshot.window_seconds / self._config.recovery_samples
        if state.last_recovery_tick is None or tick - state.last_recovery_tick >= recovery_interval:
            state.recovery_count += 1
            state.last_recovery_tick = tick
        if state.recovery_count < self._config.recovery_samples:
            return None
        state.active = False
        state.recovery_count = 0
        state.last_recovery_tick = None
        return TrafficRateDecision(resolved_fingerprint=self._fingerprint(key))

    def _candidate(self, snapshot: TrafficMetricsSnapshot, rate: ProtocolRateSnapshot,
                   observed_at: datetime, threshold: float) -> AlertCandidate:
        key = (snapshot.network_fingerprint, snapshot.interface_id.casefold(),
               snapshot.interface_index, rate.protocol)
        entity = sha256("\0".join((key[0], key[1], str(key[2]))).encode("utf-8")).hexdigest()
        baseline = rate.baseline.packets_per_second
        assert baseline is not None
        interface = f"{snapshot.interface_id.casefold()}#{snapshot.interface_index}"
        if len(interface) > 128 or not interface.isascii() or not interface.isprintable():
            interface = f"sha256:{sha256(interface.encode('utf-8')).hexdigest()}"
        return AlertCandidate(
            self._fingerprint(key), _RULES[rate.protocol], snapshot.network_fingerprint,
            entity, "medium" if rate.packets_per_second > 2 * threshold else "low",
            "low" if snapshot.confidence is MeasurementConfidence.REDUCED else "moderate",
            AlertEvidence(
                observed_at, observation_count=self._config.minimum_samples,
                details=(
                    ("interface", interface),
                    ("current_pps", f"{rate.packets_per_second:.3f}"),
                    ("traffic_count", str(rate.packet_count)),
                    ("baseline", f"learned:{baseline:.3f}pps"),
                    ("threshold_pps", f"{threshold:.3f}"),
                    ("multiplier", f"{rate.packets_per_second / baseline:.2f}x" if baseline > 0 else "undefined"),
                    ("window_seconds", str(snapshot.window_seconds)),
                    ("quality", snapshot.confidence.value),
                ),
            ),
        )

    @staticmethod
    def _fingerprint(key: _Key) -> str:
        return sha256("\0".join((_RULES[key[3]], key[0], key[1], str(key[2]))).encode("utf-8")).hexdigest()

    def _expire(self, tick: float) -> None:
        for key, state in tuple(self._states.items()):
            if tick - state.last_tick >= self._config.idle_expiry_seconds:
                del self._states[key]

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
            raise ValueError("monotonic clock must be finite")
        self._last_tick = float(value) if self._last_tick is None else max(self._last_tick, float(value))
        return self._last_tick


__all__ = ("TrafficRateDecision", "TrafficRateDetector")
