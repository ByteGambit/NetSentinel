"""Framework-independent network-context and observed device models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from uuid import UUID, uuid5

from netsentinel.domain.observations import MacAddress


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


_DEVICE_NAMESPACE = UUID("81e629eb-470b-47a7-a275-2760424ff33d")
_BINDING_NAMESPACE = UUID("ce2de6e7-7468-4d74-b6ef-012386ed46a8")


def _require_fingerprint(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("network_fingerprint must be a string")
    canonical = value.lower()
    if len(canonical) != 64 or any(c not in "0123456789abcdef" for c in canonical):
        raise ValueError("network_fingerprint must be a SHA-256 hex digest")
    return canonical


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """One observed unicast MAC in one network fingerprint scope.

    The stable ID is derived from the scope and canonical MAC, never an IP.
    This is observed state, not a trusted user profile or security verdict.
    """

    network_fingerprint: str
    mac: MacAddress
    first_seen: datetime
    last_seen: datetime
    device_id: UUID = field(init=False)

    def __post_init__(self) -> None:
        fingerprint = _require_fingerprint(self.network_fingerprint)
        if not isinstance(self.mac, MacAddress):
            raise TypeError("mac must be a MacAddress")
        if self.mac.is_zero or self.mac.is_multicast or self.mac.is_broadcast:
            raise ValueError("mac must be a nonzero unicast address")
        first = _require_utc(self.first_seen, "first_seen")
        last = _require_utc(self.last_seen, "last_seen")
        if last < first:
            raise ValueError("last_seen cannot precede first_seen")
        object.__setattr__(self, "network_fingerprint", fingerprint)
        object.__setattr__(self, "first_seen", first)
        object.__setattr__(self, "last_seen", last)
        object.__setattr__(self, "device_id", uuid5(_DEVICE_NAMESPACE, f"{fingerprint}:{self.mac}"))


@dataclass(frozen=True, slots=True)
class IdentityBinding:
    """Observed sender IP/MAC pair and its first/last observation times."""

    network_fingerprint: str
    mac: MacAddress
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    binding_id: UUID = field(init=False)
    device_id: UUID = field(init=False)

    def __post_init__(self) -> None:
        identity = DeviceIdentity(
            self.network_fingerprint, self.mac, self.first_seen, self.last_seen
        )
        ip = _canonical_ipv4(self.ip_address, "ip_address")
        object.__setattr__(self, "network_fingerprint", identity.network_fingerprint)
        object.__setattr__(self, "ip_address", ip)
        object.__setattr__(self, "first_seen", identity.first_seen)
        object.__setattr__(self, "last_seen", identity.last_seen)
        object.__setattr__(self, "device_id", identity.device_id)
        object.__setattr__(
            self, "binding_id", uuid5(_BINDING_NAMESPACE, f"{identity.device_id}:{ip}")
        )


class GatewayBaselineStatus(str, Enum):
    LEARNING = "learning"
    LEARNED = "learned"
    VERIFIED = "verified"


@dataclass(frozen=True, slots=True)
class GatewayBaseline:
    """Expected gateway identity, distinct from observed device bindings."""

    network_fingerprint: str
    gateway_ip: str
    mac: MacAddress
    status: GatewayBaselineStatus
    first_seen: datetime
    last_seen: datetime
    learning_started_at: datetime
    observation_count: int
    conflicted: bool = False
    verified_at: datetime | None = None
    pending_mac: MacAddress | None = None
    pending_seen_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "network_fingerprint", _require_fingerprint(self.network_fingerprint))
        object.__setattr__(self, "gateway_ip", _canonical_ipv4(self.gateway_ip, "gateway_ip"))
        if not isinstance(self.mac, MacAddress) or self.mac.is_zero or self.mac.is_multicast:
            raise ValueError("mac must be a nonzero unicast MacAddress")
        if not isinstance(self.status, GatewayBaselineStatus):
            raise TypeError("status must be a GatewayBaselineStatus")
        for name in ("first_seen", "last_seen", "learning_started_at"):
            object.__setattr__(self, name, _require_utc(getattr(self, name), name))
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        if isinstance(self.observation_count, bool) or not isinstance(self.observation_count, int) or self.observation_count < 1:
            raise ValueError("observation_count must be positive")
        if not isinstance(self.conflicted, bool):
            raise TypeError("conflicted must be boolean")
        if self.verified_at is not None:
            object.__setattr__(self, "verified_at", _require_utc(self.verified_at, "verified_at"))
        if (self.status is GatewayBaselineStatus.VERIFIED) != (self.verified_at is not None):
            raise ValueError("verified_at must match verified status")
        if (self.pending_mac is None) != (self.pending_seen_at is None):
            raise ValueError("pending_mac and pending_seen_at must appear together")
        if self.pending_mac is not None:
            if not isinstance(self.pending_mac, MacAddress) or self.pending_mac.is_zero or self.pending_mac.is_multicast or self.pending_mac == self.mac:
                raise ValueError("pending_mac must be a distinct nonzero unicast MacAddress")
            object.__setattr__(self, "pending_seen_at", _require_utc(self.pending_seen_at, "pending_seen_at"))


@dataclass(frozen=True, slots=True)
class GatewayBaselineChange:
    """One retained expected-identity transition, never a security verdict."""

    network_fingerprint: str
    gateway_ip: str
    old_mac: MacAddress | None
    new_mac: MacAddress
    changed_at: datetime
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "network_fingerprint", _require_fingerprint(self.network_fingerprint))
        object.__setattr__(self, "gateway_ip", _canonical_ipv4(self.gateway_ip, "gateway_ip"))
        if self.old_mac is not None and not isinstance(self.old_mac, MacAddress):
            raise TypeError("old_mac must be a MacAddress or None")
        if not isinstance(self.new_mac, MacAddress) or self.new_mac.is_zero or self.new_mac.is_multicast:
            raise ValueError("new_mac must be a nonzero unicast MacAddress")
        object.__setattr__(self, "changed_at", _require_utc(self.changed_at, "changed_at"))
        if self.reason not in ("first_observation", "user_confirmation"):
            raise ValueError("unsupported baseline change reason")


__all__ = (
    "DeviceIdentity",
    "GatewayBaseline",
    "GatewayBaselineChange",
    "GatewayBaselineStatus",
    "IdentityBinding",
    "NetworkContext",
    "NetworkInterfaceKind",
)
