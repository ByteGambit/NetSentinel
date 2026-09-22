"""NS-021 defensive ARP parser tests using synthetic packets only."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from netsentinel.domain.observations import (
    ArpOpcode,
    LinkLayerProtocol,
    NetworkLayerProtocol,
    ObservationSource,
    PacketObservation,
)
from netsentinel.infrastructure.parsers.arp import (
    ArpPacketMalformed,
    parse_arp_packet,
)
from tests.fixtures.packets.arp import arp_reply, arp_request


NOW = datetime(2026, 9, 22, 8, 0, tzinfo=UTC)
FINGERPRINT = "c" * 64


def metadata(
    *, network_layer: NetworkLayerProtocol = NetworkLayerProtocol.ARP
) -> PacketObservation:
    return PacketObservation(
        interface_id="{WIFI-ADAPTER}",
        interface_index=12,
        network_fingerprint=FINGERPRINT,
        observed_at=NOW,
        captured_length=42,
        original_length=42,
        link_layer=LinkLayerProtocol.ETHERNET,
        network_layer=network_layer,
    )


@pytest.mark.parametrize(
    ("packet_factory", "opcode", "sender_ip", "sender_mac", "target_ip", "target_mac"),
    [
        (
            arp_request,
            ArpOpcode.REQUEST,
            "192.168.1.20",
            "aa:bb:cc:dd:ee:ff",
            "192.168.1.1",
            "00:00:00:00:00:00",
        ),
        (
            arp_reply,
            ArpOpcode.REPLY,
            "192.168.1.1",
            "00:11:22:33:44:55",
            "192.168.1.20",
            "aa:bb:cc:dd:ee:ff",
        ),
    ],
)
def test_request_and_reply_are_normalized_without_payload(
    packet_factory: object,
    opcode: ArpOpcode,
    sender_ip: str,
    sender_mac: str,
    target_ip: str,
    target_mac: str,
) -> None:
    packet = packet_factory()  # type: ignore[operator]

    observation = parse_arp_packet(packet, metadata())

    assert observation is not None
    assert observation.opcode is opcode
    assert observation.sender_ip == sender_ip
    assert str(observation.sender_mac) == sender_mac
    assert observation.target_ip == target_ip
    assert str(observation.target_mac) == target_mac
    assert not hasattr(observation, "packet")
    assert not hasattr(observation, "payload")
    with pytest.raises(FrozenInstanceError):
        observation.sender_ip = "192.168.1.99"  # type: ignore[misc]


def test_non_arp_packet_is_unsupported_not_malformed() -> None:
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1")

    assert (
        parse_arp_packet(
            packet,
            metadata(network_layer=NetworkLayerProtocol.IPV4),
        )
        is None
    )


@pytest.mark.parametrize(
    "packet",
    [
        ARP(),
        Ether(type=0x0800) / ARP(),
        Ether() / ARP(hwtype=2),
        Ether() / ARP(ptype=0x86DD),
        Ether() / ARP(hwlen=5),
        Ether() / ARP(plen=16),
        Ether() / ARP(op=3),
        Ether() / ARP(hwsrc="not-a-mac"),
        Ether() / ARP(hwdst="aa:bb:cc:dd:ee"),
        Ether() / ARP(psrc="999.1.1.1"),
        Ether() / ARP(pdst="2001:db8::1"),
    ],
)
def test_malformed_or_unsupported_arp_fields_are_rejected(packet: object) -> None:
    with pytest.raises(ArpPacketMalformed):
        parse_arp_packet(packet, metadata())


class SyntheticPacket:
    def __init__(self, *, arp: object, ether: object) -> None:
        self._arp = arp
        self._ether = ether

    def haslayer(self, name: str) -> bool:
        return name in {"ARP", "Ether"}

    def getlayer(self, name: str) -> object | None:
        return self._arp if name == "ARP" else self._ether if name == "Ether" else None


def valid_layers(**arp_overrides: object) -> SyntheticPacket:
    arp_values: dict[str, object] = {
        "hwtype": 1,
        "ptype": 0x0800,
        "hwlen": 6,
        "plen": 4,
        "op": 1,
        "hwsrc": "aa:bb:cc:dd:ee:ff",
        "psrc": "192.168.1.20",
        "hwdst": "00:00:00:00:00:00",
        "pdst": "192.168.1.1",
    }
    arp_values.update(arp_overrides)
    return SyntheticPacket(
        arp=SimpleNamespace(**arp_values),
        ether=SimpleNamespace(
            type=0x0806,
            src="aa:bb:cc:dd:ee:ff",
            dst="ff:ff:ff:ff:ff:ff",
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hwsrc", ""),
        ("hwsrc", "a" * 65),
        ("hwdst", None),
        ("psrc", "1" * 65),
        ("pdst", None),
        ("op", True),
        ("hwlen", True),
    ],
)
def test_missing_or_overlong_fuzz_like_fields_are_rejected(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ArpPacketMalformed):
        parse_arp_packet(valid_layers(**{field: value}), metadata())


def test_packet_metadata_context_time_and_source_remain_authoritative() -> None:
    packet_metadata = metadata()
    arp = parse_arp_packet(arp_request(), packet_metadata)

    assert arp is not None
    assert packet_metadata.interface_id == "{WIFI-ADAPTER}"
    assert packet_metadata.interface_index == 12
    assert packet_metadata.network_fingerprint == FINGERPRINT
    assert packet_metadata.observed_at == NOW
    assert packet_metadata.observed_at.utcoffset().total_seconds() == 0
    assert packet_metadata.source is ObservationSource.PACKET_CAPTURE


def test_parser_and_domain_layer_boundaries_exclude_scapy_from_core() -> None:
    root = Path(__file__).resolve().parents[4]
    for relative in ("src/netsentinel/domain", "src/netsentinel/application"):
        for source_path in (root / relative).rglob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            assert not any(name == "scapy" or name.startswith("scapy.") for name in imported)
