"""NS-057 local-address attribution and lifecycle regressions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.ports import ConnectionCollectionRound
from netsentinel.application.services.connection_network_scope import ConnectionNetworkScopeResolver
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionOpened, ConnectionSnapshot, ConnectionState,
    ConnectionUpdated, Endpoint, NetworkAttributionMethod, NetworkScopeStatus,
    ObservationQuality, ProcessIdentity, ProcessInfo, ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.infrastructure.windows_network import (
    WindowsIPv4Address, WindowsNetworkAdapterSnapshot, WindowsNetworkContextProvider,
)


T0 = datetime(2026, 10, 1, tzinfo=UTC)


def context(address: str, *, interface: str = "ethernet", index: int = 1,
            subnet: str = "192.168.1.0/24", kind: NetworkInterfaceKind = NetworkInterfaceKind.ETHERNET) -> NetworkContext:
    return NetworkContext(interface, index, interface, kind, address, subnet, None, (), T0)


def row(address: str, *, at: datetime = T0, create_time: datetime | None = None) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint(address, 50000), Endpoint("203.0.113.10" if ":" not in address else "2001:db8::10", 443),
        ConnectionState.ESTABLISHED,
        ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(42, create_time or T0 - timedelta(hours=1)), "app"),
        at,
    )


class Provider:
    def __init__(self, contexts: tuple[NetworkContext, ...]) -> None:
        self.contexts = contexts
        self.calls = 0

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        self.calls += 1
        return self.contexts


def test_unique_ipv4_and_vpn_choose_exact_assigned_address() -> None:
    ethernet = context("192.168.1.20")
    vpn = context("10.8.0.2", interface="vpn", index=2, subnet="10.8.0.0/24", kind=NetworkInterfaceKind.VPN)
    provider = Provider((ethernet, vpn))
    resolver = ConnectionNetworkScopeResolver(provider)  # type: ignore[arg-type]
    first, second = resolver.attribute((row("192.168.1.20"), row("10.8.0.2")))
    assert provider.calls == 1
    assert first.network_scope.status is NetworkScopeStatus.RESOLVED
    assert first.network_scope.fingerprint == ethernet.fingerprint
    assert first.network_scope.interface_id == "ethernet"
    assert first.network_scope.method is NetworkAttributionMethod.LOCAL_ADDRESS_MATCH
    assert first.key == row("192.168.1.20").key
    assert second.network_scope.status is NetworkScopeStatus.RESOLVED
    assert second.network_scope.fingerprint == vpn.fingerprint
    assert second.network_scope.fingerprint != ethernet.fingerprint


@pytest.mark.parametrize("address", ["192.168.1.25", "0.0.0.0", "::", "127.0.0.1", "::1", "2001:db8::20"])
def test_unmatched_wildcard_loopback_and_unsupported_ipv6_are_unknown(address: str) -> None:
    lan = context("192.168.1.20")
    loopback = context("127.0.0.1", interface="loopback", index=9, subnet="127.0.0.0/8", kind=NetworkInterfaceKind.LOOPBACK)
    scope = ConnectionNetworkScopeResolver(Provider((lan, loopback))).attribute((row(address),))[0].network_scope  # type: ignore[arg-type]
    assert scope.status is NetworkScopeStatus.UNKNOWN
    assert scope.fingerprint is None
    assert scope.interface_id is None


def test_same_subnet_is_not_evidence_and_multiple_exact_matches_are_ambiguous() -> None:
    first = context("192.168.1.20", interface="wifi", index=1)
    second = context("192.168.1.21", interface="ethernet", index=2)
    duplicate_address = context("192.168.1.20", interface="vpn", index=3)
    for inventory in ((first, second, duplicate_address), (duplicate_address, second, first)):
        resolver = ConnectionNetworkScopeResolver(Provider(inventory))  # type: ignore[arg-type]
        ambiguous = resolver.attribute((row("192.168.1.20"),))[0].network_scope
        assert ambiguous.status is NetworkScopeStatus.AMBIGUOUS
        assert ambiguous.fingerprint is None
        assert resolver.attribute((row("192.168.1.22"),))[0].network_scope.status is NetworkScopeStatus.UNKNOWN


def test_duplicate_logical_context_does_not_create_false_ambiguity() -> None:
    lan = context("192.168.1.20")
    scope = ConnectionNetworkScopeResolver(Provider((lan, lan))).attribute((row(lan.ipv4_address),))[0].network_scope  # type: ignore[arg-type]
    assert scope.status is NetworkScopeStatus.RESOLVED


def test_context_loss_and_bound_are_conservative(monkeypatch: pytest.MonkeyPatch) -> None:
    import netsentinel.application.services.connection_network_scope as module

    provider = Provider((context("192.168.1.20"), context("10.8.0.2", interface="vpn", index=2, subnet="10.8.0.0/24")))
    monkeypatch.setattr(module, "MAX_NETWORK_CONTEXTS", 1)
    resolver = ConnectionNetworkScopeResolver(provider)  # type: ignore[arg-type]
    assert resolver.attribute((row("192.168.1.20"),))[0].network_scope.status is NetworkScopeStatus.UNKNOWN

    class FailedProvider:
        def get_contexts(self) -> tuple[NetworkContext, ...]:
            raise PermissionError("private adapter data")

    assert ConnectionNetworkScopeResolver(FailedProvider()).attribute((row("192.168.1.20"),))[0].network_scope.status is NetworkScopeStatus.UNKNOWN  # type: ignore[arg-type]


def test_context_switch_enriches_same_lifecycle_without_fake_close_open() -> None:
    provider = Provider(())
    resolver = ConnectionNetworkScopeResolver(provider)  # type: ignore[arg-type]
    tracker = ConnectionTrackingService()
    original = row("192.168.1.20")
    opened = tracker.track(resolver.attribute((original,)))[0]
    assert isinstance(opened, ConnectionOpened)
    assert opened.snapshot.network_scope.status is NetworkScopeStatus.UNKNOWN
    lan = context("192.168.1.20")
    provider.contexts = (lan,)
    update = tracker.track(resolver.attribute((replace(original, observed_at=T0 + timedelta(seconds=1)),)))[0]
    assert isinstance(update, ConnectionUpdated)
    assert update.lifecycle_id == opened.lifecycle_id
    assert update.previous.network_scope.status is NetworkScopeStatus.UNKNOWN
    assert update.current.network_scope.fingerprint == lan.fingerprint
    provider.contexts = ()
    lost = tracker.track(resolver.attribute((replace(original, observed_at=T0 + timedelta(seconds=2)),)))[0]
    assert isinstance(lost, ConnectionUpdated)
    assert lost.lifecycle_id == opened.lifecycle_id
    assert lost.previous.network_scope.fingerprint == lan.fingerprint
    assert lost.current.network_scope.status is NetworkScopeStatus.UNKNOWN
    assert tracker.active_connections[0].lifecycle_id == opened.lifecycle_id
    assert not any(isinstance(event, (ConnectionOpened, ConnectionClosed)) for event in (update, lost))


def test_reduced_quality_and_pid_reuse_remain_independent_of_scope() -> None:
    resolver = ConnectionNetworkScopeResolver(Provider((context("192.168.1.20"),)))  # type: ignore[arg-type]
    tracker = ConnectionTrackingService()
    original = row("192.168.1.20")
    opened = tracker.track(resolver.attribute((original,)))[0]
    assert isinstance(opened, ConnectionOpened)
    assert tracker.track(resolver.attribute((replace(original, observed_at=T0 + timedelta(seconds=1)),)), quality=ObservationQuality.REDUCED) == ()
    assert tracker.last_round is not None and tracker.last_round.quality is ObservationQuality.REDUCED
    newer = row("192.168.1.20", at=T0 + timedelta(seconds=2), create_time=T0 - timedelta(minutes=1))
    events = tracker.track(resolver.attribute((newer,)))
    assert isinstance(events[0], ConnectionOpened)
    assert isinstance(events[1], ConnectionClosed)
    assert events[0].lifecycle_id != opened.lifecycle_id
    assert events[1].lifecycle_id == opened.lifecycle_id


def test_engine_uses_one_context_read_per_round_and_keeps_quality() -> None:
    provider = Provider((context("192.168.1.20"),))
    tracker = ConnectionTrackingService()

    class Collector:
        def collect_round(self) -> ConnectionCollectionRound:
            return ConnectionCollectionRound((row("192.168.1.20"),), ObservationQuality.REDUCED, 1)

    class Enricher:
        def enrich(self, snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[ConnectionSnapshot, ...]:
            return snapshots

    engine = MonitoringEngine(collector=Collector(), enricher=Enricher(), tracker=tracker,
                              network_context_provider=provider, clock=lambda: T0)  # type: ignore[arg-type]
    engine._poll_once()
    assert provider.calls == 1
    assert tracker.last_round is not None and tracker.last_round.quality is ObservationQuality.REDUCED
    assert tracker.active_connections[0].snapshot.network_scope.status is NetworkScopeStatus.RESOLVED


def test_windows_adapter_fixture_attribution_is_independent_of_interface_type() -> None:
    def adapter(name: str, index: int, address: str, if_type: int) -> WindowsNetworkAdapterSnapshot:
        return WindowsNetworkAdapterSnapshot(name, index, name, name, if_type, True,
                                             (WindowsIPv4Address(address, 24),))

    provider = WindowsNetworkContextProvider(
        snapshot_provider=lambda: (
            adapter("Ethernet", 1, "192.168.1.20", 6),
            adapter("Tunnel", 2, "10.8.0.2", 131),
        ), clock=lambda: T0,
    )
    scope = ConnectionNetworkScopeResolver(provider).attribute((row("10.8.0.2"),))[0].network_scope
    assert scope.status is NetworkScopeStatus.RESOLVED
    assert scope.interface_id == "Tunnel"
