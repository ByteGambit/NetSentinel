"""Classify one captured Ethernet frame without retaining packet content.

The selected NetworkContext is authoritative for directed IPv4 broadcast. ARP
is an exclusive class even when its Ethernet destination is broadcast, so a
later rate counter must not count the same frame as both ARP and broadcast.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_network

from netsentinel.domain.devices import NetworkContext
from netsentinel.domain.observations import (
    BroadcastKind,
    BroadcastObservation,
    LinkLayerProtocol,
    MacAddress,
    NetworkLayerProtocol,
    PacketObservation,
)


class BroadcastPacketMalformed(ValueError):
    """A supported Ethernet/IPv4 header is inconsistent or malformed."""


def parse_broadcast_packet(
    packet: object,
    metadata: PacketObservation,
    context: NetworkContext,
) -> BroadcastObservation | None:
    """Return an exclusive traffic class, or None for non-Ethernet traffic.

    L3 directed broadcast is recognized only for the selected local subnet.
    Other-subnet directed broadcasts cannot be inferred from this context.
    """
    if not isinstance(metadata, PacketObservation):
        raise TypeError("metadata must be a PacketObservation")
    if (
        metadata.network_fingerprint != getattr(context, "fingerprint", None)
        or metadata.interface_id.casefold()
        != str(getattr(context, "interface_id", "")).casefold()
        or metadata.interface_index != getattr(context, "interface_index", None)
    ):
        raise BroadcastPacketMalformed("capture context is inconsistent")
    if metadata.link_layer is not LinkLayerProtocol.ETHERNET:
        return None

    try:
        ether = _layer(packet, "Ether")
        if ether is None:
            ether = _layer(packet, "Ethernet")
        if ether is None:
            raise BroadcastPacketMalformed("Ethernet header is missing")
        ether_type = _number(ether, "type", 0xFFFF)
        MacAddress(_text(ether, "src", 17))
        destination_mac = MacAddress(_text(ether, "dst", 17))
        l2_broadcast = destination_mac.is_broadcast

        if metadata.network_layer is NetworkLayerProtocol.ARP:
            if ether_type != 0x0806 or _layer(packet, "ARP") is None:
                raise BroadcastPacketMalformed("ARP header is inconsistent")
            kind = BroadcastKind.ARP
        elif metadata.network_layer is NetworkLayerProtocol.IPV4:
            if ether_type != 0x0800:
                raise BroadcastPacketMalformed("IPv4 EtherType is inconsistent")
            ip = _layer(packet, "IP")
            if ip is None or _number(ip, "version", 15) != 4:
                raise BroadcastPacketMalformed("IPv4 header is inconsistent")
            IPv4Address(_text(ip, "src", 15))
            destination_ip = IPv4Address(_text(ip, "dst", 15))
            subnet = getattr(context, "subnet", None)
            network = ip_network(subnet) if subnet is not None else None
            if network is not None and not isinstance(network, IPv4Network):
                raise BroadcastPacketMalformed("capture subnet is not IPv4")
            if destination_ip == IPv4Address("255.255.255.255"):
                kind = BroadcastKind.IPV4_LIMITED_BROADCAST
            elif (
                network is not None
                and network.prefixlen <= 30
                and destination_ip == network.broadcast_address
            ):
                kind = BroadcastKind.IPV4_DIRECTED_BROADCAST
            elif destination_ip.is_multicast or (
                destination_mac.is_multicast and not l2_broadcast
            ):
                kind = BroadcastKind.MULTICAST
            elif l2_broadcast:
                kind = BroadcastKind.ETHERNET_BROADCAST
            else:
                kind = BroadcastKind.UNICAST
        elif (
            ether_type in (0x0800, 0x0806)
            or _layer(packet, "ARP") is not None
            or _layer(packet, "IP") is not None
        ):
            raise BroadcastPacketMalformed("Ethernet protocol is inconsistent")
        elif l2_broadcast:
            kind = BroadcastKind.ETHERNET_BROADCAST
        elif destination_mac.is_multicast:
            kind = BroadcastKind.MULTICAST
        else:
            kind = BroadcastKind.UNICAST
        return BroadcastObservation(kind=kind, ethernet_broadcast=l2_broadcast)
    except BroadcastPacketMalformed:
        raise
    except Exception as error:
        raise BroadcastPacketMalformed("broadcast packet fields are malformed") from error


def _layer(packet: object, name: str) -> object | None:
    haslayer = getattr(packet, "haslayer", None)
    getlayer = getattr(packet, "getlayer", None)
    if not callable(haslayer) or not callable(getlayer) or not haslayer(name):
        return None
    return getlayer(name)


def _text(layer: object, field: str, limit: int) -> str:
    value = getattr(layer, field)
    if not isinstance(value, str) or not value or len(value) > limit:
        raise BroadcastPacketMalformed("header text field is invalid")
    return value


def _number(layer: object, field: str, maximum: int) -> int:
    value = getattr(layer, field)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise BroadcastPacketMalformed("header numeric field is invalid")
    return value


__all__ = ("BroadcastPacketMalformed", "parse_broadcast_packet")
