"""NS-020 tests for the portable packet metadata envelope."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from netsentinel.domain.observations import (
    LinkLayerProtocol,
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
