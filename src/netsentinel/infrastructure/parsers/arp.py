"""Defensive ARP normalization for packets captured by the Scapy adapter.

The parser deliberately uses only Scapy's small packet/layer protocol surface
(``haslayer``/``getlayer`` and named fields).  It does not retain the packet,
serialize bytes, inspect payloads, discover interfaces, or make security
decisions.
"""

from __future__ import annotations

from typing import Final

from netsentinel.domain.observations import (
    ArpObservation,
    ArpOpcode,
    MacAddress,
    NetworkLayerProtocol,
    PacketObservation,
)


ARP_HARDWARE_ETHERNET: Final = 1
ARP_PROTOCOL_IPV4: Final = 0x0800
ETHERTYPE_ARP: Final = 0x0806
ETHERNET_ADDRESS_BYTES: Final = 6
IPV4_ADDRESS_BYTES: Final = 4
MAX_ARP_TEXT_FIELD: Final = 64


class ArpPacketMalformed(ValueError):
    """The packet claims to contain ARP but violates the supported contract."""


def parse_arp_packet(
    packet: object,
    metadata: PacketObservation,
) -> ArpObservation | None:
    """Return validated request/reply fields, or ``None`` for a non-ARP packet.

    All malformed packet-library behavior is collapsed to a sanitized exception;
    raw Scapy exception text and packet values never cross this module boundary.
    """

    if not isinstance(metadata, PacketObservation):
        raise TypeError("metadata must be a PacketObservation")

    try:
        arp_layer = _get_layer(packet, "ARP")
        if arp_layer is None:
            return None
        if metadata.network_layer is not NetworkLayerProtocol.ARP:
            raise ArpPacketMalformed("ARP metadata is inconsistent")

        ethernet_layer = _get_layer(packet, "Ether")
        if ethernet_layer is None:
            ethernet_layer = _get_layer(packet, "Ethernet")
        if ethernet_layer is None:
            raise ArpPacketMalformed("ARP requires an Ethernet frame")

        if _required_int(ethernet_layer, "type") != ETHERTYPE_ARP:
            raise ArpPacketMalformed("Ethernet type is not ARP")
        # Validate the frame addresses without treating a mismatch as a security
        # verdict. Proxy ARP and deliberately unusual traffic must remain observable.
        MacAddress(_required_text(ethernet_layer, "src"))
        MacAddress(_required_text(ethernet_layer, "dst"))

        if _required_int(arp_layer, "hwtype") != ARP_HARDWARE_ETHERNET:
            raise ArpPacketMalformed("ARP hardware type is unsupported")
        if _required_int(arp_layer, "ptype") != ARP_PROTOCOL_IPV4:
            raise ArpPacketMalformed("ARP protocol type is unsupported")
        _validate_optional_size(arp_layer, "hwlen", ETHERNET_ADDRESS_BYTES)
        _validate_optional_size(arp_layer, "plen", IPV4_ADDRESS_BYTES)

        try:
            opcode = ArpOpcode(_required_int(arp_layer, "op"))
        except ValueError as error:
            raise ArpPacketMalformed("ARP opcode is unsupported") from error

        return ArpObservation(
            opcode=opcode,
            sender_mac=MacAddress(_required_text(arp_layer, "hwsrc")),
            sender_ip=_required_text(arp_layer, "psrc"),
            target_mac=MacAddress(_required_text(arp_layer, "hwdst")),
            target_ip=_required_text(arp_layer, "pdst"),
        )
    except ArpPacketMalformed:
        raise
    except (AttributeError, LookupError, TypeError, ValueError, OverflowError) as error:
        raise ArpPacketMalformed("ARP packet fields are malformed") from error
    except Exception as error:
        raise ArpPacketMalformed("ARP packet could not be inspected") from error


def _get_layer(packet: object, name: str) -> object | None:
    haslayer = getattr(packet, "haslayer", None)
    getlayer = getattr(packet, "getlayer", None)
    if not callable(haslayer) or not callable(getlayer):
        return None
    if not bool(haslayer(name)):
        return None
    return getlayer(name)


def _required_text(layer: object, name: str) -> str:
    value = getattr(layer, name)
    if not isinstance(value, str):
        raise ArpPacketMalformed(f"ARP {name} is missing")
    value = value.strip()
    if not value or len(value) > MAX_ARP_TEXT_FIELD:
        raise ArpPacketMalformed(f"ARP {name} length is invalid")
    return value


def _required_int(layer: object, name: str) -> int:
    value = getattr(layer, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArpPacketMalformed(f"ARP {name} is missing")
    return value


def _validate_optional_size(layer: object, name: str, expected: int) -> None:
    value = getattr(layer, name)
    # Scapy leaves these derived fields as None on freshly constructed packets.
    # Decoded wire packets carry the explicit sizes and must match exactly.
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ArpPacketMalformed(f"ARP {name} is invalid")


__all__ = (
    "ArpPacketMalformed",
    "parse_arp_packet",
)
