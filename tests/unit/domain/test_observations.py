"""NS-020 tests for the portable packet metadata envelope."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from netsentinel.domain.observations import (
    ArpObservation,
    ArpOpcode,
    LinkLayerProtocol,
    MacAddress,
    MAX_CAPTURED_PACKET_BYTES,
    NetworkLayerProtocol,
    ObservationSource,
    PacketObservation,
)


OBSERVED_AT = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
FINGERPRINT = "a" * 64


def observation(**overrides: object) -> PacketObservation:
    values: dict[str, object] = {
        "interface_id": "{WIFI-ADAPTER}",
        "interface_index": 12,
        "network_fingerprint": FINGERPRINT,
        "observed_at": OBSERVED_AT,
        "captured_length": 64,
        "original_length": 72,
        "link_layer": LinkLayerProtocol.ETHERNET,
        "network_layer": NetworkLayerProtocol.ARP,
    }
    values.update(overrides)
    return PacketObservation(**values)  # type: ignore[arg-type]


def test_packet_observation_is_immutable_hashable_and_contains_no_payload() -> None:
    item = observation(interface_id="  {WIFI-ADAPTER}  ")
    same = observation()

    assert item == same
    assert hash(item) == hash(same)
    assert item.source is ObservationSource.PACKET_CAPTURE
    assert not hasattr(item, "packet")
    assert not hasattr(item, "payload")
    with pytest.raises(FrozenInstanceError):
        item.captured_length = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "raw",
    [
        "AA-BB-CC-DD-EE-FF",
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "  aa:bb:cc:dd:ee:ff  ",
    ],
)
def test_mac_address_has_one_canonical_immutable_identity(raw: str) -> None:
    address = MacAddress(raw)

    assert address.value == "aa:bb:cc:dd:ee:ff"
    assert str(address) == "aa:bb:cc:dd:ee:ff"
    assert address == MacAddress("aa:bb:cc:dd:ee:ff")
    with pytest.raises(FrozenInstanceError):
        address.value = "00:00:00:00:00:00"  # type: ignore[misc]


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "gg:bb:cc:dd:ee:ff",
        "aa-bb:cc-dd:ee-ff",
        "aabbccddeeff",
    ],
)
def test_mac_address_rejects_missing_extra_or_invalid_octets(raw: str) -> None:
    with pytest.raises(ValueError):
        MacAddress(raw)


def test_mac_address_exposes_portable_bit_properties_without_identity_policy() -> None:
    assert MacAddress("00:00:00:00:00:00").is_zero
    broadcast = MacAddress("ff:ff:ff:ff:ff:ff")
    assert broadcast.is_broadcast and broadcast.is_multicast
    assert MacAddress("01:00:5e:00:00:01").is_multicast
    assert MacAddress("02:00:00:00:00:01").is_locally_administered


def test_arp_observation_normalizes_ipv4_and_contains_no_packet_or_payload() -> None:
    arp = ArpObservation(
        opcode=ArpOpcode.REPLY,
        sender_mac=MacAddress("AA-BB-CC-DD-EE-FF"),
        sender_ip=" 192.168.1.20 ",
        target_mac=MacAddress("00:11:22:33:44:55"),
        target_ip="192.168.1.1",
    )
    item = observation(arp=arp)

    assert arp.sender_ip == "192.168.1.20"
    assert item.arp == arp
    assert not hasattr(arp, "packet")
    assert not hasattr(arp, "payload")
    assert not hasattr(arp, "bytes")


@pytest.mark.parametrize(
    "value",
    ["", "999.1.1.1", "192.168.1.1.5", "2001:db8::1", "1" * 65],
)
def test_arp_observation_rejects_invalid_or_unbounded_ipv4(value: str) -> None:
    with pytest.raises(ValueError):
        ArpObservation(
            opcode=ArpOpcode.REQUEST,
            sender_mac=MacAddress("aa:bb:cc:dd:ee:ff"),
            sender_ip=value,
            target_mac=MacAddress("00:00:00:00:00:00"),
            target_ip="192.168.1.1",
        )


def test_arp_details_require_arp_packet_metadata() -> None:
    arp = ArpObservation(
        opcode=ArpOpcode.REQUEST,
        sender_mac=MacAddress("aa:bb:cc:dd:ee:ff"),
        sender_ip="192.168.1.20",
        target_mac=MacAddress("00:00:00:00:00:00"),
        target_ip="192.168.1.1",
    )

    with pytest.raises(ValueError):
        observation(network_layer=NetworkLayerProtocol.IPV4, arp=arp)


@pytest.mark.parametrize(
    ("overrides", "error_type"),
    [
        ({"interface_id": ""}, ValueError),
        ({"interface_index": -1}, ValueError),
        ({"interface_index": True}, TypeError),
        ({"network_fingerprint": "not-a-fingerprint"}, ValueError),
        ({"captured_length": -1}, ValueError),
        ({"captured_length": MAX_CAPTURED_PACKET_BYTES + 1}, ValueError),
        ({"original_length": 63}, ValueError),
        ({"link_layer": "ethernet"}, TypeError),
        ({"network_layer": "arp"}, TypeError),
        ({"source": "packet_capture"}, TypeError),
    ],
)
def test_packet_observation_rejects_invalid_values(
    overrides: dict[str, object],
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        observation(**overrides)


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 9, 21, 12, 0),
        datetime(2026, 9, 21, 15, 0, tzinfo=timezone(timedelta(hours=3))),
    ],
)
def test_packet_observation_requires_utc_timestamp(invalid_time: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        observation(observed_at=invalid_time)


def test_observation_domain_has_no_framework_or_io_dependencies() -> None:
    source_path = (
        Path(__file__).parents[3]
        / "src"
        / "netsentinel"
        / "domain"
        / "observations.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {"PyQt6", "psutil", "scapy", "sqlite3", "ctypes"}
    )
