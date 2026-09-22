"""Portable packet-capture observations.

NS-020 deliberately carries only bounded capture metadata across the
infrastructure boundary.  Raw Scapy packets and packet payload bytes remain in
the capture adapter and are never retained by this model.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum


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

        object.__setattr__(self, "interface_id", interface_id)
        object.__setattr__(self, "network_fingerprint", fingerprint)
        object.__setattr__(
            self,
            "observed_at",
            _require_utc(self.observed_at, "observed_at"),
        )


__all__ = (
    "LinkLayerProtocol",
    "MAX_CAPTURED_PACKET_BYTES",
    "NetworkLayerProtocol",
    "ObservationSource",
    "PacketObservation",
)
