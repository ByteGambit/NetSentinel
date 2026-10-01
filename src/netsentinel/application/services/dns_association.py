"""NS-062: bounded, in-memory evidence from matched classic DNS responses."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import ip_address
from math import isfinite
from threading import RLock
from time import monotonic
from typing import Callable

from netsentinel.domain.connections import ConnectionNetworkScope, NetworkScopeStatus
from netsentinel.domain.dns import (
    MAX_DNS_ANSWERS, DnsAssociationLookup, DnsAssociationProvenance,
    DnsAssociationStatus, DnsAnswer, DnsRecordType, DnsTransaction,
    DnsTransactionStatus, DomainAssociation,
)


_Key = tuple[str, str, str, str, DnsAssociationProvenance, tuple[str, ...]]
MAX_CNAME_STATES = 64
MAX_CNAME_RESULTS = 64


@dataclass(frozen=True, slots=True)
class DnsAssociationStats:
    active: int
    expired: int
    evicted: int
    capacity_loss: bool


class DnsAssociationService:
    """Retain scoped DNS candidates; a lookup never asserts hostname causality.

    All public operations are locked for a capture worker and a separate read
    worker. State is bounded without an auxiliary, duplicate-growing heap.
    """

    def __init__(
        self, *, max_associations: int = 2048, max_per_ip: int = 32,
        max_per_domain: int = 32, max_retention_seconds: int = 3600,
        max_cname_depth: int = 8, clock: Callable[[], float] = monotonic,
    ) -> None:
        for name, value in (
            ("max_associations", max_associations), ("max_per_ip", max_per_ip),
            ("max_per_domain", max_per_domain),
            ("max_retention_seconds", max_retention_seconds),
            ("max_cname_depth", max_cname_depth),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_cname_depth > MAX_DNS_ANSWERS:
            raise ValueError("max_cname_depth exceeds the parsed answer bound")
        self._global_limit = max_associations
        self._ip_limit = min(max_per_ip, max_associations)
        self._domain_limit = min(max_per_domain, max_associations)
        self._retention_limit = max_retention_seconds
        self._cname_depth = max_cname_depth
        self._clock = clock
        self._lock = RLock()
        self._items: OrderedDict[_Key, tuple[DomainAssociation, float]] = OrderedDict()
        self._last_now = 0.0
        self._expired = 0
        self._evicted = 0

    def observe(self, transaction: DnsTransaction) -> tuple[DomainAssociation, ...]:
        """Accept only matched, successful, complete response answer evidence."""
        if not isinstance(transaction, DnsTransaction):
            raise TypeError("transaction must be a DnsTransaction")
        with self._lock:
            now = self._now()
            self._expire(now)
            if (
                transaction.status is not DnsTransactionStatus.COMPLETED
                or transaction.response_code != 0 or transaction.truncated
                or not transaction.answers or transaction.response_at is None
                or transaction.query_at is None
            ):
                return ()
            result: list[DomainAssociation] = []
            for question in transaction.questions:
                # PTR and unrelated query types cannot provide forward evidence.
                if question.record_type not in (DnsRecordType.A, DnsRecordType.AAAA):
                    continue
                for path, chain_ttl, answer in self._reachable(question.name, transaction.answers):
                    retention = min(chain_ttl, self._retention_limit)
                    association = DomainAssociation(
                        domain=question.name if len(path) > 1 else answer.name,
                        ip=answer.value, record_type=answer.record_type,
                        provenance=(DnsAssociationProvenance.CNAME_DERIVED if len(path) > 1
                                    else DnsAssociationProvenance.DIRECT_ANSWER),
                        queried_domain=question.name, answer_name=answer.name,
                        cname_chain=path if len(path) > 1 else (),
                        observed_at=transaction.response_at, ttl=chain_ttl,
                        answer_ttl=answer.ttl, retention_seconds=retention,
                        network_fingerprint=transaction.network_fingerprint,
                        client_ip=transaction.client_ip, server_ip=transaction.server_ip,
                        transport=transaction.transport, transaction_id=transaction.transaction_id,
                        query_at=transaction.query_at,
                    )
                    result.append(association)
                    self._retain(association, now)
                    # The address RR at the CNAME target is directly observed too.
                    if len(path) > 1:
                        direct = DomainAssociation(
                            domain=answer.name, ip=answer.value, record_type=answer.record_type,
                            provenance=DnsAssociationProvenance.DIRECT_ANSWER,
                            queried_domain=question.name, answer_name=answer.name,
                            cname_chain=(), observed_at=transaction.response_at,
                            ttl=answer.ttl, answer_ttl=answer.ttl,
                            retention_seconds=min(answer.ttl, self._retention_limit),
                            network_fingerprint=transaction.network_fingerprint,
                            client_ip=transaction.client_ip, server_ip=transaction.server_ip,
                            transport=transaction.transport, transaction_id=transaction.transaction_id,
                            query_at=transaction.query_at,
                        )
                        result.append(direct)
                        self._retain(direct, now)
            return tuple(result)

    def lookup_by_ip(
        self, ip: str, *, network_scope: ConnectionNetworkScope,
        client_ip: str | None,
    ) -> DnsAssociationLookup:
        """Return 0..N exact-scope candidates, never a singular hostname."""
        address = str(ip_address(ip))
        if not isinstance(network_scope, ConnectionNetworkScope):
            raise TypeError("network_scope must be a ConnectionNetworkScope")
        client = str(ip_address(client_ip)) if client_ip is not None else None
        with self._lock:
            self._expire(self._now())
            loss = self._evicted > 0
            if network_scope.status is not NetworkScopeStatus.RESOLVED or client is None:
                return DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, (), loss)
            candidates = tuple(
                item for item, _ in self._items.values()
                if item.ip == address and item.network_fingerprint == network_scope.fingerprint
                and item.client_ip == client
            )
            candidates = tuple(sorted(candidates, key=lambda item: (
                -item.observed_at.timestamp(),
                item.provenance is DnsAssociationProvenance.CNAME_DERIVED,
                item.domain, item.cname_chain, item.server_ip,
            )))
            domains = {item.domain for item in candidates}
            status = (DnsAssociationStatus.UNKNOWN if not candidates else
                      DnsAssociationStatus.AMBIGUOUS if len(domains) > 1 else
                      DnsAssociationStatus.CORRELATED)
            return DnsAssociationLookup(status, candidates, loss)

    def stats(self) -> DnsAssociationStats:
        with self._lock:
            self._expire(self._now())
            return DnsAssociationStats(len(self._items), self._expired, self._evicted, self._evicted > 0)

    def _reachable(
        self, origin: str, answers: tuple[DnsAnswer, ...],
    ) -> tuple[tuple[tuple[str, ...], int, DnsAnswer], ...]:
        edges: dict[str, list[DnsAnswer]] = {}
        addresses: dict[str, list[DnsAnswer]] = {}
        for answer in answers:
            if answer.record_type is DnsRecordType.CNAME:
                edges.setdefault(answer.name, []).append(answer)
            elif answer.record_type in (DnsRecordType.A, DnsRecordType.AAAA):
                addresses.setdefault(answer.name, []).append(answer)
        for values in edges.values():
            values.sort(key=lambda item: (item.value, item.ttl), reverse=True)
        for values in addresses.values():
            values.sort(key=lambda item: (item.value, item.ttl))
        found: list[tuple[tuple[str, ...], int, DnsAnswer]] = []
        stack: list[tuple[str, tuple[str, ...], int]] = [(origin, (origin,), 0xFFFFFFFF)]
        visited_states = 0
        while stack and visited_states < MAX_CNAME_STATES and len(found) < MAX_CNAME_RESULTS:
            name, path, ttl = stack.pop()
            visited_states += 1
            for answer in addresses.get(name, ()):
                found.append((path, min(ttl, answer.ttl), answer))
                if len(found) >= MAX_CNAME_RESULTS:
                    break
            if len(path) > self._cname_depth:
                continue
            for edge in edges.get(name, ()):
                if edge.value not in path and len(stack) < MAX_CNAME_STATES:
                    stack.append((edge.value, (*path, edge.value), min(ttl, edge.ttl)))
        return tuple(found)

    def _retain(self, association: DomainAssociation, now: float) -> None:
        key: _Key = (
            association.network_fingerprint, association.client_ip,
            association.domain, association.ip, association.provenance,
            association.cname_chain,
        )
        old = self._items.get(key)
        if old is not None:
            if association.observed_at <= old[0].observed_at:
                return
            del self._items[key]
        if association.retention_seconds == 0:
            return
        for predicate, limit in (
            (lambda item: item.ip == association.ip and item.network_fingerprint == association.network_fingerprint
             and item.client_ip == association.client_ip, self._ip_limit),
            (lambda item: item.domain == association.domain and item.network_fingerprint == association.network_fingerprint
             and item.client_ip == association.client_ip, self._domain_limit),
            (lambda item: True, self._global_limit),
        ):
            while sum(predicate(item) for item, _ in self._items.values()) >= limit:
                victim = next(key for key, (item, _) in self._items.items() if predicate(item))
                del self._items[victim]
                self._evicted += 1
        self._items[key] = (association, now + association.retention_seconds)

    def _expire(self, now: float) -> None:
        for key, (_, deadline) in tuple(self._items.items()):
            if deadline <= now:
                del self._items[key]
                self._expired += 1

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not isfinite(value):
            raise ValueError("monotonic clock must return a finite number")
        self._last_now = max(self._last_now, float(value))
        return self._last_now
