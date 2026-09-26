"""Reduce a visible Ethernet 802.1Q header to portable metadata."""

from __future__ import annotations

from netsentinel.domain.observations import LinkLayerProtocol, PacketObservation
from netsentinel.domain.vlan import VlanObservation, VlanTagKind


class VlanPacketMalformed(ValueError):
    """A claimed VLAN header is missing, truncated, or inconsistent."""


def parse_vlan_packet(packet: object, metadata: PacketObservation) -> VlanObservation | None:
    """Return visible outer-tag metadata; None means non-Ethernet, not untagged."""
    if not isinstance(metadata, PacketObservation):
        raise TypeError("metadata must be a PacketObservation")
    if metadata.link_layer is not LinkLayerProtocol.ETHERNET:
        return None
    try:
        ether = _layer(packet, "Ether") or _layer(packet, "Ethernet")
        if ether is None:
            raise VlanPacketMalformed("Ethernet header is missing")
        outer_type = _number(ether, "type", 65535)
        tag = _layer(packet, "Dot1Q")
        provider_tag = _layer(packet, "Dot1AD")
        if outer_type not in (0x8100, 0x88A8):
            if tag is not None or provider_tag is not None:
                raise VlanPacketMalformed("VLAN header is inconsistent")
            return VlanObservation(VlanTagKind.UNTAGGED)
        if metadata.captured_length < 18:
            raise VlanPacketMalformed("VLAN header is truncated")
        if outer_type == 0x8100:
            if tag is None:
                raise VlanPacketMalformed("802.1Q header is missing or inconsistent")
        else:
            if provider_tag is None:
                raise VlanPacketMalformed("provider VLAN header is missing")
            tag = provider_tag
        vid = _number(tag, "vlan", 4095)
        pcp = _number(tag, "prio", 7)
        dei = _number(tag, "dei", 1)
        protocol = _number(tag, "type", 65535)
        inner = getattr(tag, "payload", None)
        inner_name = type(inner).__name__ if inner is not None else ""
        stacked = inner_name in ("Dot1Q", "Dot1AD")
        if protocol in (0x8100, 0x88A8):
            if not stacked:
                raise VlanPacketMalformed("inner VLAN header is missing")
            kind = VlanTagKind.STACKED
        elif stacked:
            raise VlanPacketMalformed("inner VLAN header is inconsistent")
        elif outer_type == 0x88A8:
            raise VlanPacketMalformed("single provider tag is outside 802.1Q scope")
        elif vid == 0:
            kind = VlanTagKind.PRIORITY_TAGGED
        elif vid == 4095:
            kind = VlanTagKind.RESERVED
        else:
            kind = VlanTagKind.TAGGED
        return VlanObservation(kind, vid, pcp, bool(dei), protocol)
    except VlanPacketMalformed:
        raise
    except Exception as error:
        raise VlanPacketMalformed("VLAN packet fields are malformed") from error


def _layer(packet: object, name: str) -> object | None:
    haslayer = getattr(packet, "haslayer", None)
    getlayer = getattr(packet, "getlayer", None)
    if not callable(haslayer) or not callable(getlayer) or not haslayer(name):
        return None
    return getlayer(name)


def _number(layer: object, field: str, maximum: int) -> int:
    value = getattr(layer, field)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise VlanPacketMalformed("VLAN numeric field is invalid")
    return value


__all__ = ("VlanPacketMalformed", "parse_vlan_packet")
