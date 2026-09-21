"""NS-019 fixture-based contract tests for the Windows network adapter."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone

import pytest

from netsentinel.application.ports import (
    NetworkContextPermissionDenied,
    NetworkContextProvider,
    NetworkContextUnavailable,
)
from netsentinel.bootstrap import create_network_context_provider
from netsentinel.domain.devices import NetworkInterfaceKind
from netsentinel.infrastructure.windows_network import (
    WindowsIPv4Address,
    WindowsNetworkAdapterSnapshot,
    WindowsNetworkContextProvider,
)


OBSERVED_AT = datetime(2026, 9, 21, 9, 30, tzinfo=UTC)


def adapter(**overrides: object) -> WindowsNetworkAdapterSnapshot:
    values: dict[str, object] = {
        "interface_id": "{WIFI-ADAPTER}",
        "interface_index": 12,
        "name": "Wi-Fi",
        "description": "Wireless adapter",
        "if_type": 71,
        "is_up": True,
        "ipv4_addresses": (WindowsIPv4Address("192.168.10.25", 24),),
        "gateways": ("192.168.10.1",),
        "dns_servers": ("8.8.8.8", "1.1.1.1"),
    }
    values.update(overrides)
    return WindowsNetworkAdapterSnapshot(**values)  # type: ignore[arg-type]


def provider_for(
    *snapshots: WindowsNetworkAdapterSnapshot,
) -> WindowsNetworkContextProvider:
    return WindowsNetworkContextProvider(
        snapshot_provider=lambda: snapshots,
        clock=lambda: OBSERVED_AT,
    )


def test_adapter_satisfies_application_port_and_normalizes_active_ipv4() -> None:
    provider: NetworkContextProvider = provider_for(adapter())

    contexts = provider.get_contexts()

    assert len(contexts) == 1
    context = contexts[0]
    assert context.interface_id == "{WIFI-ADAPTER}"
    assert context.interface_index == 12
    assert context.interface_name == "Wi-Fi"
    assert context.interface_kind is NetworkInterfaceKind.WIFI
    assert context.ipv4_address == "192.168.10.25"
    assert context.subnet == "192.168.10.0/24"
    assert context.gateway == "192.168.10.1"
    assert context.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert context.observed_at == OBSERVED_AT
    assert context.is_default_capture_candidate is True


def test_empty_snapshot_is_a_valid_empty_context_set() -> None:
    assert provider_for().get_contexts() == ()


def test_composition_root_creates_provider_without_reading_network_state() -> None:
    provider = create_network_context_provider()

    assert isinstance(provider, WindowsNetworkContextProvider)


def test_multiple_interfaces_are_kept_while_disconnected_adapter_is_excluded() -> None:
    disconnected = adapter(
        interface_id="{DOWN}",
        interface_index=30,
        name="Ethernet 2",
        if_type=6,
        is_up=False,
        ipv4_addresses=(WindowsIPv4Address("10.10.0.5", 16),),
    )
    ethernet = adapter(
        interface_id="{ETHERNET}",
        interface_index=4,
        name="Ethernet",
        if_type=6,
        ipv4_addresses=(WindowsIPv4Address("10.0.0.15", 8),),
        gateways=(),
        dns_servers=(),
    )

    contexts = provider_for(disconnected, adapter(), ethernet).get_contexts()

    assert {item.interface_id for item in contexts} == {
        "{WIFI-ADAPTER}",
        "{ETHERNET}",
    }
    assert all(item.interface_id != "{DOWN}" for item in contexts)


def test_loopback_is_visible_but_sorted_after_default_capture_candidates() -> None:
    loopback = adapter(
        interface_id="{LOOPBACK}",
        interface_index=1,
        name="Loopback Pseudo-Interface",
        description="Software Loopback Interface",
        if_type=24,
        ipv4_addresses=(WindowsIPv4Address("127.0.0.1", 8),),
        gateways=(),
        dns_servers=(),
    )

    contexts = provider_for(loopback, adapter()).get_contexts()

    assert [item.interface_id for item in contexts] == [
        "{WIFI-ADAPTER}",
        "{LOOPBACK}",
    ]
    assert contexts[1].interface_kind is NetworkInterfaceKind.LOOPBACK
    assert contexts[1].is_default_capture_candidate is False


@pytest.mark.parametrize(
    "snapshot",
    [
        adapter(if_type=131, name="Tunnel", description="Tunnel adapter"),
        adapter(if_type=23, name="PPP", description="PPP adapter"),
        adapter(if_type=6, name="WireGuard Tunnel", description="Adapter"),
    ],
)
def test_vpn_interfaces_are_explicitly_classified(
    snapshot: WindowsNetworkAdapterSnapshot,
) -> None:
    context = provider_for(snapshot).get_contexts()[0]

    assert context.interface_kind is NetworkInterfaceKind.VPN
    assert context.is_vpn is True


def test_virtual_interface_is_modelled_separately() -> None:
    context = provider_for(
        adapter(if_type=6, name="vEthernet (Default Switch)", description="Hyper-V")
    ).get_contexts()[0]

    assert context.interface_kind is NetworkInterfaceKind.VIRTUAL


def test_missing_gateway_and_dns_are_preserved_as_absent() -> None:
    context = provider_for(adapter(gateways=(), dns_servers=())).get_contexts()[0]

    assert context.gateway is None
    assert context.dns_servers == ()


def test_multiple_addresses_produce_one_context_per_ipv4_subnet() -> None:
    contexts = provider_for(
        adapter(
            ipv4_addresses=(
                WindowsIPv4Address("192.168.10.25", 24),
                WindowsIPv4Address("10.20.30.40", 16),
            )
        )
    ).get_contexts()

    assert {(item.ipv4_address, item.subnet) for item in contexts} == {
        ("192.168.10.25", "192.168.10.0/24"),
        ("10.20.30.40", "10.20.0.0/16"),
    }


def test_malformed_and_ipv6_addresses_do_not_break_valid_contexts() -> None:
    contexts = provider_for(
        adapter(
            ipv4_addresses=(
                WindowsIPv4Address("not-an-ip", 24),
                WindowsIPv4Address("2001:db8::1", 64),
                WindowsIPv4Address("192.168.10.25", 33),
                WindowsIPv4Address("192.168.10.26", 24),
            )
        )
    ).get_contexts()

    assert len(contexts) == 1
    assert contexts[0].ipv4_address == "192.168.10.26"


def test_one_malformed_adapter_does_not_discard_other_interfaces() -> None:
    malformed = adapter(interface_id="", interface_index=-1)
    valid = adapter(interface_id="{VALID}", interface_index=20)

    contexts = provider_for(malformed, valid).get_contexts()

    assert len(contexts) == 1
    assert contexts[0].interface_id == "{VALID}"


def test_gateway_dns_duplicates_and_invalid_values_are_safely_normalized() -> None:
    context = provider_for(
        adapter(
            gateways=("192.168.10.254", "invalid", "192.168.10.1"),
            dns_servers=("8.8.8.8", "invalid", "0.0.0.0", "8.8.8.8"),
        )
    ).get_contexts()[0]

    assert context.gateway == "192.168.10.1"
    assert context.dns_servers == ("8.8.8.8",)


def test_output_is_deterministic_and_duplicate_contexts_are_removed() -> None:
    first = adapter(interface_id="{B}", interface_index=20, name="B")
    second = adapter(interface_id="{A}", interface_index=10, name="A")
    richer_duplicate = adapter(
        interface_id="{B}",
        interface_index=20,
        name="Renamed B",
        dns_servers=("8.8.8.8", "1.1.1.1", "9.9.9.9"),
    )

    forward = provider_for(first, second, richer_duplicate).get_contexts()
    reverse = provider_for(richer_duplicate, second, first).get_contexts()

    assert forward == reverse
    assert [item.interface_id for item in forward] == ["{A}", "{B}"]
    assert forward[1].dns_servers == ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def test_provider_does_not_cache_and_models_network_change_by_fingerprint() -> None:
    rounds: list[tuple[WindowsNetworkAdapterSnapshot, ...]] = [
        (adapter(),),
        (
            adapter(
                ipv4_addresses=(WindowsIPv4Address("10.0.0.25", 8),),
                gateways=("10.0.0.1",),
            ),
        ),
    ]
    calls = 0

    def snapshots() -> Iterable[WindowsNetworkAdapterSnapshot]:
        nonlocal calls
        result = rounds[min(calls, len(rounds) - 1)]
        calls += 1
        return result

    provider = WindowsNetworkContextProvider(
        snapshot_provider=snapshots,
        clock=lambda: OBSERVED_AT,
    )

    first = provider.get_contexts()[0]
    second = provider.get_contexts()[0]

    assert calls == 2
    assert first.fingerprint != second.fingerprint


def test_same_network_fingerprint_is_stable_across_reordered_dns_and_new_time() -> None:
    times = iter((OBSERVED_AT, OBSERVED_AT + timedelta(minutes=5)))
    rounds = iter(
        (
            (adapter(dns_servers=("8.8.8.8", "1.1.1.1")),),
            (
                adapter(
                    name="Renamed Wi-Fi",
                    ipv4_addresses=(WindowsIPv4Address("192.168.10.99", 24),),
                    dns_servers=("1.1.1.1", "8.8.8.8"),
                ),
            ),
        )
    )
    provider = WindowsNetworkContextProvider(
        snapshot_provider=lambda: next(rounds),
        clock=lambda: next(times),
    )

    first = provider.get_contexts()[0]
    second = provider.get_contexts()[0]

    assert first.fingerprint == second.fingerprint
    assert first.observed_at != second.observed_at


def test_all_contexts_in_one_read_share_one_normalized_utc_timestamp() -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return datetime(
            2026,
            9,
            21,
            12,
            30,
            tzinfo=timezone(timedelta(hours=3)),
        )

    provider = WindowsNetworkContextProvider(
        snapshot_provider=lambda: (
            adapter(interface_id="{ONE}"),
            adapter(interface_id="{TWO}", interface_index=13),
        ),
        clock=clock,
    )

    contexts = provider.get_contexts()

    assert calls == 1
    assert {item.observed_at for item in contexts} == {OBSERVED_AT}
    assert all(item.observed_at.tzinfo is UTC for item in contexts)


def test_whole_read_permission_failure_is_typed() -> None:
    def denied() -> tuple[WindowsNetworkAdapterSnapshot, ...]:
        raise PermissionError("raw platform detail")

    provider = WindowsNetworkContextProvider(snapshot_provider=denied)

    with pytest.raises(NetworkContextPermissionDenied) as raised:
        provider.get_contexts()

    assert "raw platform detail" not in str(raised.value)


def test_whole_read_os_failure_is_sanitized_and_typed() -> None:
    failure = OSError("localized command or platform output")

    def unavailable() -> tuple[WindowsNetworkAdapterSnapshot, ...]:
        raise failure

    provider = WindowsNetworkContextProvider(snapshot_provider=unavailable)

    with pytest.raises(NetworkContextUnavailable) as raised:
        provider.get_contexts()

    assert raised.value.__cause__ is failure
    assert "localized" not in str(raised.value)
