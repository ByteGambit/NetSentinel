"""NS-031: bounded, synchronous correlation of portable DNS observations."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from heapq import heappop, heappush
from math import isfinite
from time import monotonic
from typing import Callable

from netsentinel.domain.dns import (
    DnsObservation, DnsQuestion, DnsTrafficKind, DnsTransaction,
    DnsTransactionStatus, DnsTransport,
)
from netsentinel.domain.observations import PacketObservation


_Key = tuple[str, DnsTransport, str, int, str, int, int, tuple[DnsQuestion, ...]]


@dataclass(slots=True)
class _Pending:
    query_at: datetime
    last_query_at: datetime
    started: float
    deadline: float
    generation: int
    retry_count: int = 0


class DnsTrackingService:
    """Single-consumer memory state. Call observe/expire on the same consumer.

    Equal or older query timestamps are duplicate observations. A newer query
    on a pending key is a retry; the original query time and latency origin are
    retained. Recent completions suppress exact/older packet replays. A query
    observed after the completed response starts a new logical transaction.
    """

    def __init__(
        self, *, timeout_seconds: float = 5.0, max_pending: int = 1024,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if not isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending <= 0:
            raise ValueError("max_pending must be a positive integer")
        self._timeout = timeout_seconds
        self._limit = max_pending
        self._clock = clock
        self._last_now = 0.0
        self._pending: OrderedDict[_Key, _Pending] = OrderedDict()
        self._deadlines: list[tuple[float, int, _Key]] = []
        self._next_generation = 0
        self._recent: OrderedDict[_Key, tuple[float, datetime]] = OrderedDict()

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def recent_count(self) -> int:
        return len(self._recent)

    def observe(self, packet: PacketObservation) -> tuple[DnsTransaction, ...]:
        """Consume one NS-030 envelope; return zero or more portable outcomes."""
        if not isinstance(packet, PacketObservation):
            return ()
        now = self._now()
        outcomes = list(self._expire(now))
        dns = packet.dns
        if dns is None or dns.traffic_kind is not DnsTrafficKind.CLASSIC:
            return tuple(outcomes)
        try:
            key = self._key(packet.network_fingerprint, dns)
            if not dns.questions:
                if dns.is_response:
                    outcomes.append(self._result(key, DnsTransactionStatus.UNMATCHED_RESPONSE,
                                                 response_at=packet.observed_at, dns=dns))
                return tuple(outcomes)
            if dns.is_response:
                pending = self._pending.get(key)
                if pending is None or packet.observed_at < pending.query_at:
                    recent = self._recent.get(key)
                    if recent is None or packet.observed_at > recent[1]:
                        outcomes.append(self._result(key, DnsTransactionStatus.UNMATCHED_RESPONSE,
                                                     response_at=packet.observed_at, dns=dns))
                    return tuple(outcomes)
                del self._pending[key]
                self._remember(key, now, packet.observed_at)
                outcomes.append(self._result(
                    key, DnsTransactionStatus.COMPLETED, pending=pending,
                    response_at=packet.observed_at, dns=dns,
                    latency=max(0.0, now - pending.started),
                ))
                return tuple(outcomes)

            pending = self._pending.get(key)
            if pending is not None:
                if packet.observed_at > pending.last_query_at:
                    pending.last_query_at = packet.observed_at
                    pending.retry_count = min(65535, pending.retry_count + 1)
                    self._schedule(key, pending, now)
                return tuple(outcomes)
            recent = self._recent.get(key)
            if recent is not None and packet.observed_at <= recent[1]:
                return tuple(outcomes)
            if recent is not None:
                del self._recent[key]
            if len(self._pending) >= self._limit:
                oldest_key, oldest = self._pending.popitem(last=False)
                outcomes.append(self._result(oldest_key, DnsTransactionStatus.EVICTED, pending=oldest))
            pending = _Pending(packet.observed_at, packet.observed_at, now, now + self._timeout, 0)
            self._pending[key] = pending
            self._schedule(key, pending, now)
            return tuple(outcomes)
        except (AttributeError, TypeError, ValueError):
            # A damaged/unexpected observation cannot corrupt a prior key.
            return tuple(outcomes)

    def expire(self) -> tuple[DnsTransaction, ...]:
        """Advance idle timeout cleanup without requiring another packet."""
        return self._expire(self._now())

    def _now(self) -> float:
        value = self._clock()
        if not isinstance(value, (float, int)) or not isfinite(value):
            raise ValueError("monotonic clock must return a finite number")
        self._last_now = max(self._last_now, float(value))
        return self._last_now

    @staticmethod
    def _key(network: str, dns: DnsObservation) -> _Key:
        if dns.is_response:
            return (network, dns.transport, dns.destination_ip, dns.destination_port,
                    dns.source_ip, dns.source_port, dns.transaction_id, dns.questions)
        return (network, dns.transport, dns.source_ip, dns.source_port,
                dns.destination_ip, dns.destination_port, dns.transaction_id, dns.questions)

    def _schedule(self, key: _Key, pending: _Pending, now: float) -> None:
        self._next_generation += 1
        pending.generation = self._next_generation
        pending.deadline = now + self._timeout
        heappush(self._deadlines, (pending.deadline, pending.generation, key))
        # Retries leave stale heap nodes. Rebuild so they cannot grow forever.
        if len(self._deadlines) > 2 * self._limit:
            self._deadlines = sorted(
                (item.deadline, item.generation, item_key)
                for item_key, item in self._pending.items()
            )

    def _expire(self, now: float) -> tuple[DnsTransaction, ...]:
        outcomes: list[DnsTransaction] = []
        while self._deadlines and self._deadlines[0][0] <= now:
            _, generation, key = heappop(self._deadlines)
            pending = self._pending.get(key)
            if pending is not None and pending.generation == generation:
                del self._pending[key]
                outcomes.append(self._result(key, DnsTransactionStatus.TIMED_OUT, pending=pending))
        while self._recent and next(iter(self._recent.values()))[0] + self._timeout <= now:
            self._recent.popitem(last=False)
        return tuple(outcomes)

    def _remember(self, key: _Key, now: float, response_at: datetime) -> None:
        self._recent[key] = (now, response_at)
        self._recent.move_to_end(key)
        if len(self._recent) > self._limit:
            self._recent.popitem(last=False)

    @staticmethod
    def _result(
        key: _Key, status: DnsTransactionStatus, *, pending: _Pending | None = None,
        response_at: datetime | None = None, dns: DnsObservation | None = None,
        latency: float | None = None,
    ) -> DnsTransaction:
        network, transport, client_ip, client_port, server_ip, server_port, txid, questions = key
        return DnsTransaction(
            status=status, network_fingerprint=network, transport=transport,
            client_ip=client_ip, client_port=client_port, server_ip=server_ip,
            server_port=server_port, transaction_id=txid, questions=questions,
            query_at=pending.query_at if pending is not None else None,
            response_at=response_at, latency_seconds=latency,
            response_code=dns.response_code if dns is not None else None,
            truncated=dns.truncated if dns is not None else False,
            answers=dns.answers if dns is not None else (),
            retry_count=pending.retry_count if pending is not None else 0,
        )


__all__ = ("DnsTrackingService",)
