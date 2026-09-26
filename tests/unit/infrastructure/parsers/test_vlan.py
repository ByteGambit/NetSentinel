"""NS-043 single-tag parser boundaries and portable value semantics."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from netsentinel.domain.observations import LinkLayerProtocol, NetworkLayerProtocol, PacketObservation
from netsentinel.domain.vlan import VlanObservation, VlanTagKind
from netsentinel.infrastructure.parsers.vlan import VlanPacketMalformed, parse_vlan_packet
from netsentinel.infrastructure.scapy_capture import _packet_observation
from tests.fixtures.packets.vlan import stacked, tagged, untagged
from tests.unit.infrastructure.test_scapy_capture import context


AT = datetime(2026, 9, 26, tzinfo=UTC)


def metadata(packet: object, *, link: LinkLayerProtocol = LinkLayerProtocol.ETHERNET,
             length: int | None = None) -> PacketObservation:
    ctx = context()
    size = len(packet) if length is None else length
    return PacketObservation(ctx.interface_id, ctx.interface_index, ctx.fingerprint, AT,
                             size, size, link, NetworkLayerProtocol.OTHER)


@pytest.mark.parametrize(("vid", "kind"), [
    (0, VlanTagKind.PRIORITY_TAGGED),
    (1, VlanTagKind.TAGGED),
    (42, VlanTagKind.TAGGED),
    (4094, VlanTagKind.TAGGED),
    (4095, VlanTagKind.RESERVED),
])
def test_vid_semantics_and_fields(vid: int, kind: VlanTagKind) -> None:
    packet = tagged(vid)
    result = parse_vlan_packet(packet, metadata(packet))
    assert result == VlanObservation(kind, vid, 3, True, 0x0800)
    assert b"secret" not in repr(result).encode()
    with pytest.raises(FrozenInstanceError):
        result.vlan_id = 99  # type: ignore[misc]


def test_untagged_is_explicit_but_non_ethernet_is_not() -> None:
    packet = untagged()
    assert parse_vlan_packet(packet, metadata(packet)) == VlanObservation(VlanTagKind.UNTAGGED)
    assert parse_vlan_packet(packet, metadata(packet, link=LinkLayerProtocol.OTHER)) is None
    observation = _packet_observation(packet, context(), AT)
    assert observation.vlan == VlanObservation(VlanTagKind.UNTAGGED)
    assert observation.broadcast is not None


@pytest.mark.parametrize(("provider", "mixed", "protocol"), [
    (False, False, 0x8100), (True, False, 0x8100), (False, True, 0x88A8),
])
def test_qinq_is_marked_stacked_without_inner_tag_details(
    provider: bool, mixed: bool, protocol: int,
) -> None:
    packet = stacked(provider=provider, mixed=mixed)
    result = parse_vlan_packet(packet, metadata(packet))
    assert result.kind is VlanTagKind.STACKED
    assert result.vlan_id == 11
    assert result.encapsulated_protocol == protocol
    assert not hasattr(result, "inner_vlan_id")
    observation = _packet_observation(packet, context(), AT)
    assert observation.vlan == result
    assert observation.arp is None and observation.dns is None and observation.broadcast is None


class BrokenPacket:
    def __init__(self, outer_type: object, tag: object | None) -> None:
        self.ether = SimpleNamespace(type=outer_type)
        self.tag = tag

    def __len__(self) -> int:
        return 64

    def haslayer(self, name: str) -> bool:
        return name == "Ether" or (name == "Dot1Q" and self.tag is not None)

    def getlayer(self, name: str) -> object | None:
        return self.ether if name == "Ether" else self.tag if name == "Dot1Q" else None


@pytest.mark.parametrize(("outer_type", "tag"), [
    (0x8100, None),
    (0x0800, SimpleNamespace(vlan=3, prio=0, dei=0, type=0x0800)),
    (0x8100, SimpleNamespace(vlan=-1, prio=0, dei=0, type=0x0800)),
    (0x8100, SimpleNamespace(vlan=3, prio=8, dei=0, type=0x0800)),
    (0x8100, SimpleNamespace(vlan=3, prio=0, dei=2, type=0x0800)),
    (0x8100, SimpleNamespace(vlan=3, prio=0, dei=0, type=0x8100)),
    ("invalid", None),
])
def test_malformed_tag_is_sanitized(outer_type: object, tag: object | None) -> None:
    packet = BrokenPacket(outer_type, tag)
    with pytest.raises(VlanPacketMalformed) as error:
        parse_vlan_packet(packet, metadata(packet))
    assert "secret" not in str(error.value)


def test_truncated_tag_and_invalid_domain_values() -> None:
    packet = tagged()
    with pytest.raises(VlanPacketMalformed):
        parse_vlan_packet(packet, metadata(packet, length=17))
    with pytest.raises(ValueError):
        VlanObservation(VlanTagKind.TAGGED, 0, 1, False, 0x0800)
    with pytest.raises(ValueError):
        VlanObservation(VlanTagKind.UNTAGGED, 1)
    with pytest.raises(ValueError):
        VlanObservation(VlanTagKind.TAGGED, 1, True, False, 0x0800)


def test_capture_envelope_uses_existing_context_and_drops_payload() -> None:
    packet = tagged()
    ctx = context()
    result = _packet_observation(packet, ctx, AT)
    assert result.vlan == VlanObservation(VlanTagKind.TAGGED, 42, 3, True, 0x0800)
    assert result.network_fingerprint == ctx.fingerprint
    assert result.interface_id == ctx.interface_id
    assert result.observed_at == AT
    assert b"secret" not in repr(result).encode()
    assert not hasattr(result, "packet") and not hasattr(result, "payload")


def test_capture_copies_only_canonical_ethernet_source_identity() -> None:
    frame = tagged(10)
    frame.src = "02:AA:BB:CC:DD:EE"
    observation = _packet_observation(frame, context(), AT)
    assert str(observation.ethernet_source_mac) == "02:aa:bb:cc:dd:ee"
    assert observation.vlan.vlan_id == 10
    assert not hasattr(observation, "raw_frame")
    assert b"secret" not in repr(observation).encode()

    malformed = BrokenPacket(0x8100, SimpleNamespace(
        vlan=10, prio=0, dei=0, type=0x0800))
    malformed.ether.src = "not-a-mac"
    result = _packet_observation(malformed, context(), AT)
    assert result.ethernet_source_mac is None
    assert result.vlan.vlan_id == 10
