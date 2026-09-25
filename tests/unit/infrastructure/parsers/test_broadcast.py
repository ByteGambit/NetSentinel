"""NS-035 synthetic, offline Ethernet classification tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    BroadcastKind,
    LinkLayerProtocol,
    NetworkLayerProtocol,
    PacketObservation,
)
from netsentinel.infrastructure.parsers.broadcast import (
    BroadcastPacketMalformed,
    parse_broadcast_packet,
)
from netsentinel.infrastructure.scapy_capture import _packet_observation


NOW = datetime(2026, 9, 25, 8, tzinfo=UTC)


def context(**changes: object) -> NetworkContext:
    values: dict[str, object] = dict(
        interface_id="{WIFI}", interface_index=12, interface_name="Wi-Fi",
        interface_kind=NetworkInterfaceKind.WIFI, ipv4_address="192.168.50.25",
        subnet="192.168.50.0/24", gateway="192.168.50.1",
        dns_servers=(), observed_at=NOW,
    )
    values.update(changes)
    return NetworkContext(**values)  # type: ignore[arg-type]


def metadata(packet: object, ctx: NetworkContext | None = None) -> PacketObservation:
    selected = ctx or context()
    layer = (NetworkLayerProtocol.ARP if packet.haslayer("ARP") else
             NetworkLayerProtocol.IPV4 if packet.haslayer("IP") else
             NetworkLayerProtocol.OTHER)
    return PacketObservation(
        interface_id=selected.interface_id, interface_index=selected.interface_index,
        network_fingerprint=selected.fingerprint, observed_at=NOW,
        captured_length=len(packet), original_length=len(packet),
        link_layer=LinkLayerProtocol.ETHERNET, network_layer=layer,
    )


@pytest.mark.parametrize(
    ("packet", "kind", "l2_broadcast"),
    [
        (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(), BroadcastKind.ARP, True),
        (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff", type=0x88b5) / Raw(b"private"), BroadcastKind.ETHERNET_BROADCAST, True),
        (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255"), BroadcastKind.IPV4_LIMITED_BROADCAST, True),
        (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.50.255"), BroadcastKind.IPV4_DIRECTED_BROADCAST, True),
        (Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:01") / IP(dst="224.0.0.1"), BroadcastKind.MULTICAST, False),
        (Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:01", type=0x88b5), BroadcastKind.MULTICAST, False),
        (Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(dst="192.168.50.1"), BroadcastKind.UNICAST, False),
        (Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(dst="10.0.0.255"), BroadcastKind.UNICAST, False),
    ],
)
def test_exclusive_classification(packet: object, kind: BroadcastKind, l2_broadcast: bool) -> None:
    result = parse_broadcast_packet(packet, metadata(packet), context())
    assert result is not None
    assert result.kind is kind
    assert result.ethernet_broadcast is l2_broadcast
    assert not hasattr(result, "packet")
    assert not hasattr(result, "payload")
    with pytest.raises(FrozenInstanceError):
        result.kind = BroadcastKind.UNICAST  # type: ignore[misc]


def test_directed_broadcast_is_scoped_to_selected_network() -> None:
    packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.50.255")
    assert parse_broadcast_packet(packet, metadata(packet), context()).kind is BroadcastKind.IPV4_DIRECTED_BROADCAST
    other = context(subnet="192.168.51.0/24", ipv4_address="192.168.51.25", gateway="192.168.51.1")
    with pytest.raises(BroadcastPacketMalformed):
        parse_broadcast_packet(packet, metadata(packet), other)
    assert parse_broadcast_packet(packet, metadata(packet, other), other).kind is BroadcastKind.ETHERNET_BROADCAST


def test_prefix_31_has_no_directed_broadcast() -> None:
    ctx = context(subnet="192.168.50.24/31", ipv4_address="192.168.50.24", gateway=None)
    packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(dst="192.168.50.25")
    assert parse_broadcast_packet(packet, metadata(packet, ctx), ctx).kind is BroadcastKind.UNICAST


def test_non_ethernet_is_skipped() -> None:
    ctx = context()
    packet = IP(dst="255.255.255.255")
    meta = PacketObservation(
        interface_id=ctx.interface_id, interface_index=ctx.interface_index,
        network_fingerprint=ctx.fingerprint, observed_at=NOW, captured_length=len(packet),
        original_length=len(packet), link_layer=LinkLayerProtocol.OTHER,
        network_layer=NetworkLayerProtocol.IPV4,
    )
    assert parse_broadcast_packet(packet, meta, ctx) is None


class BrokenPacket:
    def __init__(self, ether: object, ip: object | None = None) -> None:
        self.ether, self.ip = ether, ip

    def haslayer(self, name: str) -> bool:
        return name == "Ether" or (name == "IP" and self.ip is not None)

    def getlayer(self, name: str) -> object | None:
        return self.ether if name == "Ether" else self.ip if name == "IP" else None


@pytest.mark.parametrize("ether,ip", [
    (SimpleNamespace(type=0x0800, src="bad", dst="ff:ff:ff:ff:ff:ff"), SimpleNamespace(version=4, src="192.168.50.1", dst="255.255.255.255")),
    (SimpleNamespace(type=0x0800, src="00:11:22:33:44:55", dst="bad"), SimpleNamespace(version=4, src="192.168.50.1", dst="255.255.255.255")),
    (SimpleNamespace(type=0x0800, src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff"), SimpleNamespace(version=6, src="192.168.50.1", dst="255.255.255.255")),
    (SimpleNamespace(type=0x0800, src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff"), SimpleNamespace(version=4, src="192.168.50.1", dst="999.1.1.1")),
    (SimpleNamespace(type=0x0800, src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff"), SimpleNamespace(version=4, src="999.1.1.1", dst="255.255.255.255")),
])
def test_malformed_header_is_sanitized(ether: object, ip: object) -> None:
    packet = BrokenPacket(ether, ip)
    valid = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255")
    with pytest.raises(BroadcastPacketMalformed):
        parse_broadcast_packet(packet, metadata(valid), context())


def test_capture_normalization_retains_only_metadata_and_existing_arp() -> None:
    ctx = context()
    arp = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.2",
        hwdst="00:00:00:00:00:00", pdst="192.168.50.1",
    ) / Raw(b"private secret")
    observation = _packet_observation(arp, ctx, NOW)
    assert observation.arp is not None
    assert observation.broadcast is not None
    assert observation.broadcast.kind is BroadcastKind.ARP
    assert observation.network_fingerprint == ctx.fingerprint
    assert b"private secret" not in repr(observation).encode()
    assert not hasattr(observation, "payload")
    unicast = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(dst="192.168.50.1") / UDP(sport=1000, dport=1001) / Raw(b"private secret")
    result = _packet_observation(unicast, ctx, NOW)
    assert result.broadcast is not None and result.broadcast.kind is BroadcastKind.UNICAST
    assert b"private secret" not in repr(result).encode()
