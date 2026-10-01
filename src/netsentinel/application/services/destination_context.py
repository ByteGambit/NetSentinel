"""Classify destinations before consulting a local context dataset."""

from __future__ import annotations

from collections import OrderedDict
from ipaddress import IPv4Network, IPv6Network, ip_address
from threading import RLock

from netsentinel.application.ports import DestinationContextProvider
from netsentinel.domain.destination_context import (
    DestinationAddressKind, DestinationContext, DestinationContextStatus,
)
from netsentinel.shared.diagnostics import DestinationDatasetDiagnostic


_PRIVATE_V4 = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_PRIVATE_V6 = IPv6Network("fc00::/7")
MAX_DESTINATION_CACHE_ENTRIES = 4096


class DestinationContextResolver:
    """Thread-safe, bounded public-IP lookup cache, separate from DNS evidence."""

    def __init__(self, provider: DestinationContextProvider, *, cache_capacity: int = MAX_DESTINATION_CACHE_ENTRIES) -> None:
        if type(cache_capacity) is not int or not 1 <= cache_capacity <= MAX_DESTINATION_CACHE_ENTRIES:
            raise ValueError("invalid cache capacity")
        self._provider = provider
        self._capacity = cache_capacity
        self._cache: OrderedDict[str, DestinationContext] = OrderedDict()
        self._generation = provider.generation
        self._lock = RLock()

    def resolve(self, ip: str) -> DestinationContext:
        if not isinstance(ip, str):
            raise TypeError("ip must be a string")
        address = ip_address(ip)
        canonical = str(address)
        if address.version == 4 and any(address in network for network in _PRIVATE_V4):
            kind = DestinationAddressKind.PRIVATE
        elif address.version == 6 and address in _PRIVATE_V6:
            kind = DestinationAddressKind.PRIVATE
        elif (not address.is_global or address.is_multicast
              or (address.version == 6 and address.ipv4_mapped is not None)):
            kind = DestinationAddressKind.SPECIAL
        else:
            kind = DestinationAddressKind.PUBLIC
        if kind is not DestinationAddressKind.PUBLIC:
            return DestinationContext(canonical, kind, DestinationContextStatus.NOT_APPLICABLE)
        with self._lock:
            generation = self._provider.generation
            if generation != self._generation:
                self._cache.clear()
                self._generation = generation
            cached = self._cache.get(canonical)
            if cached is not None:
                self._cache.move_to_end(canonical)
                return cached
            result = self._provider.lookup(canonical)
            if self._provider.generation == generation:
                self._cache[canonical] = result
                if len(self._cache) > self._capacity:
                    self._cache.popitem(last=False)
            return result

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def diagnostic(self) -> DestinationDatasetDiagnostic:
        return self._provider.diagnostic()
