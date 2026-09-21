"""NS-019 domain tests for portable Windows network contexts."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind


OBSERVED_AT = datetime(2026, 9, 21, 8, 0, tzinfo=UTC)


def context(**overrides: object) -> NetworkContext:
    values: dict[str, object] = {
        "interface_id": "{12345678-1234-1234-1234-123456789ABC}",
        "interface_index": 12,
        "interface_name": "Wi-Fi",
        "interface_kind": NetworkInterfaceKind.WIFI,
        "ipv4_address": "192.168.50.25",
        "subnet": "192.168.50.25/24",
        "gateway": "192.168.50.1",
        "dns_servers": ("1.1.1.1", "8.8.8.8"),
        "observed_at": OBSERVED_AT,
    }
    values.update(overrides)
    return NetworkContext(**values)  # type: ignore[arg-type]


def test_context_is_immutable_and_canonicalizes_ipv4_values() -> None:
    item = context(
        interface_id="  {12345678-1234-1234-1234-123456789ABC}  ",
        interface_name="  Wi-Fi  ",
        ipv4_address="192.168.50.25",
        subnet="192.168.50.25/24",
        dns_servers=("8.8.8.8", "1.1.1.1", "8.8.8.8"),
    )

    assert item.interface_name == "Wi-Fi"
    assert item.subnet == "192.168.50.0/24"
    assert item.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert len(item.fingerprint) == 64
    assert item.fingerprint == item.fingerprint.lower()
    with pytest.raises(FrozenInstanceError):
        item.gateway = None  # type: ignore[misc]


def test_context_equality_and_hash_are_deterministic() -> None:
    first = context()
    same = context()

    assert first == same
    assert hash(first) == hash(same)
    assert {first: "context"}[same] == "context"


def test_same_network_has_stable_fingerprint_across_dhcp_dns_and_name_changes() -> None:
    first = context()
    second = context(
        interface_name="Renamed Wi-Fi",
        ipv4_address="192.168.50.99",
        dns_servers=("9.9.9.9",),
        observed_at=OBSERVED_AT + timedelta(hours=1),
    )

    assert first != second
    assert first.fingerprint == second.fingerprint


@pytest.mark.parametrize(
    "change",
    [
        {"interface_id": "{AAAAAAAA-1234-1234-1234-123456789ABC}"},
        {"subnet": "192.168.60.0/24", "ipv4_address": "192.168.60.25"},
        {"gateway": "192.168.50.254"},
        {"gateway": None},
    ],
)
def test_fingerprint_changes_when_network_identity_changes(
    change: dict[str, object],
) -> None:
    assert context().fingerprint != context(**change).fingerprint


def test_gateway_and_dns_may_be_absent() -> None:
    item = context(gateway=None, dns_servers=())

    assert item.gateway is None
    assert item.dns_servers == ()


def test_loopback_is_never_a_default_capture_candidate() -> None:
    item = context(
        interface_id="loopback",
        interface_index=1,
        interface_name="Loopback",
        interface_kind=NetworkInterfaceKind.LOOPBACK,
        ipv4_address="127.0.0.1",
        subnet="127.0.0.0/8",
        gateway=None,
        dns_servers=(),
    )

    assert item.is_loopback is True
    assert item.is_default_capture_candidate is False


def test_loopback_address_is_safe_even_if_source_kind_is_wrong() -> None:
    item = context(
        ipv4_address="127.0.0.1",
        subnet="127.0.0.0/8",
        gateway=None,
        interface_kind=NetworkInterfaceKind.OTHER,
    )

    assert item.is_loopback is True
    assert item.is_default_capture_candidate is False


def test_vpn_is_explicit_without_being_silently_excluded() -> None:
    item = context(interface_kind=NetworkInterfaceKind.VPN)

    assert item.is_vpn is True
    assert item.is_default_capture_candidate is True


@pytest.mark.parametrize(
    ("overrides", "error_type"),
    [
        ({"interface_id": ""}, ValueError),
        ({"interface_index": -1}, ValueError),
        ({"interface_index": True}, TypeError),
        ({"interface_kind": "wifi"}, TypeError),
        ({"ipv4_address": "not-an-ip"}, ValueError),
        ({"ipv4_address": "2001:db8::1"}, ValueError),
        ({"subnet": "2001:db8::/64"}, ValueError),
        ({"subnet": "192.168.51.0/24"}, ValueError),
        ({"gateway": "2001:db8::1"}, ValueError),
        ({"dns_servers": ["1.1.1.1"]}, TypeError),
        ({"dns_servers": ("invalid",)}, ValueError),
    ],
)
def test_context_rejects_invalid_or_out_of_scope_values(
    overrides: dict[str, object],
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        context(**overrides)


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 9, 21, 8, 0),
        datetime(2026, 9, 21, 11, 0, tzinfo=timezone(timedelta(hours=3))),
    ],
)
def test_context_requires_utc_observation_time(invalid_time: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        context(observed_at=invalid_time)


def test_device_domain_has_no_framework_or_io_dependencies() -> None:
    source_path = (
        Path(__file__).parents[3] / "src" / "netsentinel" / "domain" / "devices.py"
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

    assert imported_roots.isdisjoint({"PyQt6", "psutil", "scapy", "sqlite3"})
