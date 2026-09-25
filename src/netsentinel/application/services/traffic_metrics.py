"""NS-036 bounded, memory-only broadcast and ARP rate measurements.

The exclusive NS-035 ``PacketObservation.broadcast`` class is the only traffic
classification input. All elapsed time comes from an injected monotonic clock;
packet UTC timestamps are deliberately irrelevant to counting and expiry.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from math import floor, isfinite
from statistics import median
from time import monotonic

from netsentinel.domain.devices import NetworkContext
from netsentinel.domain.observations import BroadcastKind, BroadcastObservation, PacketObservation
from netsentinel.shared.diagnostics import CaptureHealthSnapshot, CaptureState


class TrafficProtocol(str, Enum):
    ARP = "arp"
    BROADCAST = "broadcast"


class BaselineState(str, Enum):
    LEARNING = "learning"
    LEARNED = "learned"


class MeasurementConfidence(str, Enum):
    UNKNOWN = "unknown"  # capture drop counters have not been sampled
    COMPLETE = "complete"  # no known queue drops in the rolling window
    REDUCED = "reduced"  # the capture queue dropped observations


@dataclass(frozen=True, slots=True)
class TrafficBaselineSnapshot:
    state: BaselineState
    packets_per_second: float | None
    completed_windows: int
    observed_packets: int


@dataclass(frozen=True, slots=True)
class ProtocolRateSnapshot:
    protocol: TrafficProtocol
    packet_count: int
    packets_per_second: float
    baseline: TrafficBaselineSnapshot


@dataclass(frozen=True, slots=True)
class TrafficMetricsSnapshot:
    network_fingerprint: str
    interface_id: str
    interface_index: int
    window_seconds: int
    bucket_seconds: int
    arp: ProtocolRateSnapshot
    broadcast: ProtocolRateSnapshot
    dropped_observations: int
    confidence: MeasurementConfidence


@dataclass(slots=True)
class _Bucket:
    arp: int = 0
    broadcast: int = 0
    dropped: int = 0


@dataclass(slots=True)
class _Learning:
    counts: deque[int]
    baseline_rate: float | None = None


@dataclass(slots=True)
class _Scope:
    origin_tick: float
    last_observation_tick: float
    current_window: int
    buckets: dict[int, _Bucket] = field(default_factory=dict)
    window_arp: int = 0
    window_broadcast: int = 0
    window_dropped: bool = False
    arp_learning: _Learning | None = None
    broadcast_learning: _Learning | None = None
    health_known: bool = False


_ScopeKey = tuple[str, str, int]
_BROADCAST_KINDS = frozenset((
    BroadcastKind.ETHERNET_BROADCAST,
    BroadcastKind.IPV4_LIMITED_BROADCAST,
    BroadcastKind.IPV4_DIRECTED_BROADCAST,
))


class TrafficMetricsService:
    """Synchronous state owned by one capture consumer.

    Rates divide the count in the last ``window_seconds`` of fixed buckets by
    the full window duration, including the first and idle windows. Baselines
    use three *completed*, non-overlapping, loss-free windows by default.
    Learning also requires at least three packets in at least two nonempty
    windows. The median rate is then frozen until the idle context expires;
    a later spike cannot immediately move the reference used by NS-037.

    One scope is fingerprint + case-insensitive interface ID + interface index.
    At most ``max_contexts`` scopes and ``window_seconds / bucket_seconds``
    buckets per scope are retained. On capacity, the least recently observed
    scope is evicted, with the scope key as a deterministic tie-breaker.
    """

    def __init__(
        self, *, clock: Callable[[], float] = monotonic,
        window_seconds: int = 60, bucket_seconds: int = 1,
        max_contexts: int = 64, idle_expiry_seconds: float = 600.0,
        baseline_windows: int = 3,
    ) -> None:
        if (type(window_seconds) is not int or type(bucket_seconds) is not int
                or not 1 <= window_seconds <= 3600 or not 1 <= bucket_seconds <= window_seconds
                or window_seconds % bucket_seconds or window_seconds // bucket_seconds > 3600):
            raise ValueError("window and bucket must be positive, bounded, and divisible")
        if type(max_contexts) is not int or not 1 <= max_contexts <= 4096:
            raise ValueError("max_contexts must be between 1 and 4096")
        if type(baseline_windows) is not int or not 2 <= baseline_windows <= 32:
            raise ValueError("baseline_windows must be between 2 and 32")
        if (isinstance(idle_expiry_seconds, bool)
                or not isinstance(idle_expiry_seconds, (int, float))
                or not isfinite(idle_expiry_seconds)
                or idle_expiry_seconds <= window_seconds):
            raise ValueError("idle expiry must exceed the measurement window")
        self._clock = clock
        self._window = window_seconds
        self._bucket = bucket_seconds
        self._bucket_count = window_seconds // bucket_seconds
        self._max_contexts = max_contexts
        self._idle_expiry = float(idle_expiry_seconds)
        self._baseline_windows = baseline_windows
        self._scopes: dict[_ScopeKey, _Scope] = {}
        self._last_tick: float | None = None
        self._health_scope: _ScopeKey | None = None
        self._last_dropped_total: int | None = None

    @property
    def tracked_contexts(self) -> int:
        return len(self._scopes)

    @property
    def retained_buckets(self) -> int:
        return sum(len(scope.buckets) for scope in self._scopes.values())

    def observe(self, context: NetworkContext, packet: PacketObservation) -> bool:
        """Count one delivered packet; equal values still mean two captured frames."""
        if not isinstance(context, NetworkContext) or not isinstance(packet, PacketObservation):
            return False
        key = self._key(context)
        if not self._matches(context, packet):
            return False
        classification = packet.broadcast
        if not isinstance(classification, BroadcastObservation):
            return False
        if classification.kind is BroadcastKind.ARP:
            protocol = TrafficProtocol.ARP
        elif classification.kind in _BROADCAST_KINDS:
            protocol = TrafficProtocol.BROADCAST
        else:
            return False
        now = self._now()
        self._expire(now)
        scope = self._get_or_create(key, now)
        self._advance(scope, now)
        bucket = scope.buckets.setdefault(floor(now / self._bucket), _Bucket())
        if protocol is TrafficProtocol.ARP:
            bucket.arp += 1
            scope.window_arp += 1
        else:
            bucket.broadcast += 1
            scope.window_broadcast += 1
        scope.last_observation_tick = now
        self._prune_buckets(scope, now)
        return True

    def record_capture_health(self, context: NetworkContext, health: CaptureHealthSnapshot) -> bool:
        """Convert cumulative queue drops to a scoped, rolling loss indicator.

        The initial reading conservatively attributes existing drops to this
        scope. A reading after a context switch only establishes a new cursor;
        drops accumulated on the previous network cannot be attributed here.
        Read health before and after each consumer drain to observe new drops.
        """
        if (not isinstance(context, NetworkContext)
                or not isinstance(health, CaptureHealthSnapshot)
                or health.state is not CaptureState.RUNNING
                or health.network_fingerprint != context.fingerprint
                or health.selected_interface_id is None
                or health.selected_interface_id.casefold() != context.interface_id.casefold()):
            return False
        now = self._now()
        self._expire(now)
        key = self._key(context)
        total = health.counters.dropped_observations
        delta = 0
        if self._health_scope is None:
            delta = total
        elif self._health_scope == key and self._last_dropped_total is not None and total >= self._last_dropped_total:
            delta = total - self._last_dropped_total
        self._health_scope = key
        self._last_dropped_total = total
        scope = self._get_or_create(key, now)
        if delta and floor((now - scope.origin_tick) / self._window) > scope.current_window:
            # A health read cannot timestamp individual dropped frames. If the
            # interval crossed a boundary, do not learn from the prior window.
            scope.window_dropped = True
        self._advance(scope, now)
        scope.health_known = True
        if delta:
            scope.buckets.setdefault(floor(now / self._bucket), _Bucket()).dropped += delta
            scope.window_dropped = True
            self._prune_buckets(scope, now)
        return True

    def snapshot(self, context: NetworkContext) -> TrafficMetricsSnapshot:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        now = self._now()
        self._expire(now)
        key = self._key(context)
        scope = self._scopes.get(key)
        if scope is not None:
            self._advance(scope, now)
            self._prune_buckets(scope, now)
        buckets = () if scope is None else tuple(scope.buckets.values())
        arp_count = sum(bucket.arp for bucket in buckets)
        broadcast_count = sum(bucket.broadcast for bucket in buckets)
        dropped = sum(bucket.dropped for bucket in buckets)
        confidence = (MeasurementConfidence.REDUCED if dropped else
                      MeasurementConfidence.COMPLETE if scope is not None and scope.health_known else
                      MeasurementConfidence.UNKNOWN)
        return TrafficMetricsSnapshot(
            context.fingerprint, context.interface_id, context.interface_index,
            self._window, self._bucket,
            self._protocol_snapshot(TrafficProtocol.ARP, arp_count, None if scope is None else scope.arp_learning),
            self._protocol_snapshot(TrafficProtocol.BROADCAST, broadcast_count,
                                    None if scope is None else scope.broadcast_learning),
            dropped, confidence,
        )

    def _protocol_snapshot(self, protocol: TrafficProtocol, count: int,
                           learning: _Learning | None) -> ProtocolRateSnapshot:
        counts = () if learning is None else tuple(learning.counts)
        baseline = TrafficBaselineSnapshot(
            BaselineState.LEARNED if learning is not None and learning.baseline_rate is not None else BaselineState.LEARNING,
            None if learning is None else learning.baseline_rate,
            len(counts), sum(counts),
        )
        return ProtocolRateSnapshot(protocol, count, count / self._window, baseline)

    def _get_or_create(self, key: _ScopeKey, now: float) -> _Scope:
        scope = self._scopes.get(key)
        if scope is not None:
            return scope
        if len(self._scopes) >= self._max_contexts:
            victim = min(self._scopes, key=lambda item: (self._scopes[item].last_observation_tick, item))
            del self._scopes[victim]
        scope = _Scope(now, now, 0,
                       arp_learning=_Learning(deque(maxlen=self._baseline_windows)),
                       broadcast_learning=_Learning(deque(maxlen=self._baseline_windows)),
                       health_known=self._health_scope == key)
        self._scopes[key] = scope
        return scope

    def _advance(self, scope: _Scope, now: float) -> None:
        window = floor((now - scope.origin_tick) / self._window)
        if window <= scope.current_window:
            return
        if not scope.window_dropped:
            self._complete(scope.arp_learning, scope.window_arp)
            self._complete(scope.broadcast_learning, scope.window_broadcast)
        # Add at most the learning capacity; long clock jumps allocate nothing.
        for _ in range(min(window - scope.current_window - 1, self._baseline_windows)):
            self._complete(scope.arp_learning, 0)
            self._complete(scope.broadcast_learning, 0)
        scope.current_window = window
        scope.window_arp = 0
        scope.window_broadcast = 0
        scope.window_dropped = False

    def _complete(self, learning: _Learning | None, count: int) -> None:
        if learning is None or learning.baseline_rate is not None:
            return
        learning.counts.append(count)
        counts = learning.counts
        if (len(counts) >= self._baseline_windows and sum(counts) >= 3
                and sum(value > 0 for value in counts) >= 2):
            learning.baseline_rate = float(median(counts)) / self._window

    def _prune_buckets(self, scope: _Scope, now: float) -> None:
        cutoff = floor(now / self._bucket) - self._bucket_count + 1
        for index in tuple(scope.buckets):
            if index < cutoff:
                del scope.buckets[index]

    def _expire(self, now: float) -> None:
        for key, scope in tuple(self._scopes.items()):
            if now - scope.last_observation_tick >= self._idle_expiry:
                del self._scopes[key]

    def _now(self) -> float:
        tick = self._clock()
        if isinstance(tick, bool) or not isinstance(tick, (int, float)) or not isfinite(tick):
            raise ValueError("monotonic clock must return a finite number")
        now = float(tick)
        self._last_tick = now if self._last_tick is None else max(self._last_tick, now)
        return self._last_tick

    @staticmethod
    def _key(context: NetworkContext) -> _ScopeKey:
        return context.fingerprint, context.interface_id.casefold(), context.interface_index

    @staticmethod
    def _matches(context: NetworkContext, packet: PacketObservation) -> bool:
        return (packet.network_fingerprint == context.fingerprint
                and packet.interface_id.casefold() == context.interface_id.casefold()
                and packet.interface_index == context.interface_index)


__all__ = ("BaselineState", "MeasurementConfidence", "ProtocolRateSnapshot",
           "TrafficBaselineSnapshot", "TrafficMetricsService", "TrafficMetricsSnapshot",
           "TrafficProtocol")
