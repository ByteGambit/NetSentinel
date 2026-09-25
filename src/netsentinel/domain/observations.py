"""Portable packet-capture observations.

NS-020 deliberately carries only bounded capture metadata across the
infrastructure boundary.  Raw Scapy packets and packet payload bytes remain in
the capture adapter and are never retained by this model.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from ipaddress import IPv4Address, ip_address
import re

from netsentinel.domain.dns import DnsObservation


MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


class ObservationSource(str, Enum):
    """Portable origin of an observation."""

    PACKET_CAPTURE = "packet_capture"


class LinkLayerProtocol(str, Enum):
    """Small link-layer summary without exposing a packet-library type."""

    ETHERNET = "ethernet"
    LOOPBACK = "loopback"
    OTHER = "other"


class NetworkLayerProtocol(str, Enum):
    """Small network-layer summary used before protocol-specific parsing."""

    ARP = "arp"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    OTHER = "other"


class ArpOpcode(int, Enum):
    """ARP operations intentionally supported by the first passive parser."""

    REQUEST = 1
    REPLY = 2


class BroadcastKind(str, Enum):
    """Exclusive count class for one Ethernet frame (including ARP)."""

    ARP = "arp"
    ETHERNET_BROADCAST = "ethernet_broadcast"
    IPV4_LIMITED_BROADCAST = "ipv4_limited_broadcast"
    IPV4_DIRECTED_BROADCAST = "ipv4_directed_broadcast"
    MULTICAST = "multicast"
    UNICAST = "unicast"


@dataclass(frozen=True, slots=True)
class BroadcastObservation:
    """Payload-free traffic class; one frame contributes to exactly one class."""

    kind: BroadcastKind
    ethernet_broadcast: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, BroadcastKind):
            raise TypeError("kind must be a BroadcastKind")
        if not isinstance(self.ethernet_broadcast, bool):
            raise TypeError("ethernet_broadcast must be a bool")


@dataclass(frozen=True, slots=True)
class MacAddress:
    """Canonical, immutable 48-bit MAC address value.

    Colon- and hyphen-separated input is accepted, then normalized to lower-case
    colon notation.  The value object does not decide whether an address is a
    device identity; zero, broadcast, multicast, and locally administered
    addresses remain valid observations for later policy layers to interpret.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("value must be a string")
        value = self.value.strip()
        if not value:
            raise ValueError("value must not be empty")
        if ":" in value and "-" in value:
            raise ValueError("value must use one MAC address separator")
        canonical = value.replace("-", ":").lower()
        if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", canonical) is None:
            raise ValueError("value must be a six-octet MAC address")
        object.__setattr__(self, "value", canonical)

    def __str__(self) -> str:
        return self.value

    @property
    def is_zero(self) -> bool:
        return self.value == "00:00:00:00:00:00"

    @property
    def is_broadcast(self) -> bool:
        return self.value == "ff:ff:ff:ff:ff:ff"

    @property
    def is_multicast(self) -> bool:
        return bool(int(self.value[0:2], 16) & 0x01)

    @property
    def is_locally_administered(self) -> bool:
        return bool(int(self.value[0:2], 16) & 0x02)


def _canonical_ipv4(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    value = value.strip()
    if not value or len(value) > 15:
        raise ValueError(f"{field_name} must be a valid IPv4 address")
    try:
        parsed = ip_address(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a valid IPv4 address") from error
    if not isinstance(parsed, IPv4Address):
        raise ValueError(f"{field_name} must be an IPv4 address")
    return str(parsed)


@dataclass(frozen=True, slots=True)
class ArpObservation:
    """Validated ARP header values with no frame, payload, or library object."""

    opcode: ArpOpcode
    sender_mac: MacAddress
    sender_ip: str
    target_mac: MacAddress
    target_ip: str

    def __post_init__(self) -> None:
        if not isinstance(self.opcode, ArpOpcode):
            raise TypeError("opcode must be an ArpOpcode")
        if not isinstance(self.sender_mac, MacAddress):
            raise TypeError("sender_mac must be a MacAddress")
        if not isinstance(self.target_mac, MacAddress):
            raise TypeError("target_mac must be a MacAddress")
        object.__setattr__(
            self,
            "sender_ip",
            _canonical_ipv4(self.sender_ip, "sender_ip"),
        )
        object.__setattr__(
            self,
            "target_ip",
            _canonical_ipv4(self.target_ip, "target_ip"),
        )


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """Minimal metadata envelope for one passively captured packet.

    Equality intentionally describes an observation value, not a device or a
    packet identity.  Equal duplicate observations are retained by the capture
    queue because packet multiplicity matters to later traffic metrics.
    """

    interface_id: str
    interface_index: int
    network_fingerprint: str
    observed_at: datetime
    captured_length: int
    original_length: int
    link_layer: LinkLayerProtocol
    network_layer: NetworkLayerProtocol
    source: ObservationSource = ObservationSource.PACKET_CAPTURE
    arp: ArpObservation | None = None
    dns: DnsObservation | None = None
    broadcast: BroadcastObservation | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.interface_id, str):
            raise TypeError("interface_id must be a string")
        interface_id = self.interface_id.strip()
        if not interface_id:
            raise ValueError("interface_id must not be empty")
        if len(interface_id) > 512:
            raise ValueError("interface_id must not exceed 512 characters")

        if isinstance(self.interface_index, bool) or not isinstance(
            self.interface_index, int
        ):
            raise TypeError("interface_index must be an integer")
        if self.interface_index < 0:
            raise ValueError("interface_index must be zero or greater")

        if not isinstance(self.network_fingerprint, str):
            raise TypeError("network_fingerprint must be a string")
        fingerprint = self.network_fingerprint.strip().lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError("network_fingerprint must be a SHA-256 hex digest")

        for field_name in ("captured_length", "original_length"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if not 0 <= value <= MAX_CAPTURED_PACKET_BYTES:
                raise ValueError(
                    f"{field_name} must be between 0 and "
                    f"{MAX_CAPTURED_PACKET_BYTES}"
                )
        if self.original_length < self.captured_length:
            raise ValueError("original_length cannot be less than captured_length")

        if not isinstance(self.link_layer, LinkLayerProtocol):
            raise TypeError("link_layer must be a LinkLayerProtocol")
        if not isinstance(self.network_layer, NetworkLayerProtocol):
            raise TypeError("network_layer must be a NetworkLayerProtocol")
        if not isinstance(self.source, ObservationSource):
            raise TypeError("source must be an ObservationSource")
        if self.arp is not None:
            if not isinstance(self.arp, ArpObservation):
                raise TypeError("arp must be an ArpObservation or None")
            if self.network_layer is not NetworkLayerProtocol.ARP:
                raise ValueError("arp details require the ARP network layer")
        if self.dns is not None:
            if not isinstance(self.dns, DnsObservation):
                raise TypeError("dns must be a DnsObservation or None")
            if self.network_layer not in (NetworkLayerProtocol.IPV4, NetworkLayerProtocol.IPV6):
                raise ValueError("dns details require an IP network layer")
            if self.arp is not None:
                raise ValueError("a packet cannot contain both ARP and DNS details")
        if self.broadcast is not None:
            if not isinstance(self.broadcast, BroadcastObservation):
                raise TypeError("broadcast must be a BroadcastObservation or None")
            if self.link_layer is not LinkLayerProtocol.ETHERNET:
                raise ValueError("broadcast classification requires Ethernet")
            if (self.broadcast.kind is BroadcastKind.ARP) != (
                self.network_layer is NetworkLayerProtocol.ARP
            ):
                raise ValueError("ARP classification must match the network layer")

        object.__setattr__(self, "interface_id", interface_id)
        object.__setattr__(self, "network_fingerprint", fingerprint)
        object.__setattr__(
            self,
            "observed_at",
            _require_utc(self.observed_at, "observed_at"),
        )


__all__ = (
    "ArpObservation",
    "ArpOpcode",
    "BroadcastKind",
    "BroadcastObservation",
    "LinkLayerProtocol",
    "MacAddress",
    "MAX_CAPTURED_PACKET_BYTES",
    "NetworkLayerProtocol",
    "ObservationSource",
    "PacketObservation",
)
