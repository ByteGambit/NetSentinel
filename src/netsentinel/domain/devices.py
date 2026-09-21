"""Framework-independent network-context models for LAN device monitoring.

NS-019 deliberately models only the local Windows network context. Device,
ARP, discovery, and persistence concepts belong to later M4 tasks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network


class NetworkInterfaceKind(str, Enum):
    """Portable classification relevant to safe interface selection."""

    ETHERNET = "ethernet"
    WIFI = "wifi"
    VPN = "vpn"
    VIRTUAL = "virtual"
    LOOPBACK = "loopback"
    OTHER = "other"


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


def _canonical_ipv4(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    try:
        parsed = ip_address(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a valid IPv4 address") from error
    if not isinstance(parsed, IPv4Address):
        raise ValueError(f"{field_name} must be an IPv4 address")
    return str(parsed)


def _context_fingerprint(
    *,
    interface_id: str,
    subnet: str,
    gateway: str | None,
) -> str:
    """Return a versioned, non-secret stable identity for one network context.

    The current host address, display name, DNS servers, and observation time
    are intentionally excluded. DHCP address changes inside the same subnet,
    DNS reordering, and adapter renames therefore do not create a new context.
    A gateway or subnet change does create a new context for later baselines.
    """

    payload = "\0".join(
        (
            "netsentinel-network-context-v1",
            interface_id.casefold(),
            subnet,
            gateway or "",
        )
    )
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class NetworkContext:
    """One active IPv4 subnet observed on a local interface.

    A Windows adapter may have multiple IPv4 addresses; the infrastructure
    adapter emits one context per address/subnet pair. ``fingerprint`` remains
    stable when the address changes within that same interface/subnet.
    """

    interface_id: str
    interface_index: int
    interface_name: str
    interface_kind: NetworkInterfaceKind
    ipv4_address: str
    subnet: str
    gateway: str | None
    dns_servers: tuple[str, ...]
    observed_at: datetime
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        for field_name in ("interface_id", "interface_name"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")
            normalized = value.strip()
            if not normalized:
                raise ValueError(f"{field_name} must not be empty")
            if len(normalized) > 512:
                raise ValueError(f"{field_name} must not exceed 512 characters")
            object.__setattr__(self, field_name, normalized)

        if isinstance(self.interface_index, bool) or not isinstance(
            self.interface_index, int
        ):
            raise TypeError("interface_index must be an integer")
        if self.interface_index < 0:
            raise ValueError("interface_index must be zero or greater")
        if not isinstance(self.interface_kind, NetworkInterfaceKind):
            raise TypeError("interface_kind must be a NetworkInterfaceKind")

        canonical_address = _canonical_ipv4(self.ipv4_address, "ipv4_address")
        if not isinstance(self.subnet, str):
            raise TypeError("subnet must be a string")
        try:
            parsed_subnet = ip_network(self.subnet, strict=False)
        except ValueError as error:
            raise ValueError("subnet must be a valid IPv4 network") from error
        if not isinstance(parsed_subnet, IPv4Network):
            raise ValueError("subnet must be an IPv4 network")
        if IPv4Address(canonical_address) not in parsed_subnet:
            raise ValueError("ipv4_address must belong to subnet")
        canonical_subnet = str(parsed_subnet)

        canonical_gateway = None
        if self.gateway is not None:
            canonical_gateway = _canonical_ipv4(self.gateway, "gateway")

        if not isinstance(self.dns_servers, tuple):
            raise TypeError("dns_servers must be a tuple")
        canonical_dns = tuple(
            sorted(
                {
                    _canonical_ipv4(server, "dns_servers item")
                    for server in self.dns_servers
                },
                key=lambda server: int(IPv4Address(server)),
            )
        )

        observed_at = _require_utc(self.observed_at, "observed_at")
        object.__setattr__(self, "ipv4_address", canonical_address)
        object.__setattr__(self, "subnet", canonical_subnet)
        object.__setattr__(self, "gateway", canonical_gateway)
        object.__setattr__(self, "dns_servers", canonical_dns)
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(
            self,
            "fingerprint",
            _context_fingerprint(
                interface_id=self.interface_id,
                subnet=canonical_subnet,
                gateway=canonical_gateway,
            ),
        )

    @property
    def is_loopback(self) -> bool:
        """Whether this context represents a loopback interface/address."""

        return (
            self.interface_kind is NetworkInterfaceKind.LOOPBACK
            or IPv4Address(self.ipv4_address).is_loopback
        )

    @property
    def is_vpn(self) -> bool:
        return self.interface_kind is NetworkInterfaceKind.VPN

    @property
    def is_default_capture_candidate(self) -> bool:
        """Loopback is visible but never a default packet-capture candidate."""

        return not self.is_loopback


__all__ = (
    "NetworkContext",
    "NetworkInterfaceKind",
)
