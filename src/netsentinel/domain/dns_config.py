"""Portable evidence of a confirmed local DNS configuration change."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from netsentinel.domain.devices import NetworkInterfaceKind


@dataclass(frozen=True, slots=True)
class DnsServerChange:
    network_fingerprint: str
    interface_kind: NetworkInterfaceKind
    previous_servers: tuple[str, ...]
    current_servers: tuple[str, ...]
    first_observed_at: datetime
    confirmed_at: datetime
    confirmation_count: int

    def __post_init__(self) -> None:
        if len(self.network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.network_fingerprint):
            raise ValueError("invalid network fingerprint")
        if not isinstance(self.interface_kind, NetworkInterfaceKind):
            raise TypeError("invalid interface kind")
        for name in ("previous_servers", "current_servers"):
            servers = getattr(self, name)
            if not isinstance(servers, tuple) or not 1 <= len(servers) <= 8:
                raise ValueError("DNS server evidence must contain 1 to 8 addresses")
            canonical = tuple(sorted({str(IPv4Address(value)) for value in servers}, key=lambda value: int(IPv4Address(value))))
            if canonical != servers:
                raise ValueError("DNS server evidence must be canonical and sorted")
        if self.previous_servers == self.current_servers:
            raise ValueError("change requires distinct server sets")
        for name in ("first_observed_at", "confirmed_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
            object.__setattr__(self, name, value.astimezone(UTC))
        if self.confirmed_at <= self.first_observed_at or self.confirmation_count < 2:
            raise ValueError("change requires repeated, ordered confirmation")


__all__ = ("DnsServerChange",)
