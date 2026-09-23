"""NS-025 gateway identity learning using only portable fake inputs."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.baselines import (
    GatewayBaselineService, GatewayConfirmationUnavailable, GatewayContextChanged,
)
from netsentinel.domain.devices import GatewayBaselineStatus, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress,
    NetworkLayerProtocol, PacketObservation,
)


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)
MAC_A = MacAddress("02:11:22:33:44:55")
MAC_B = MacAddress("02:11:22:33:44:66")


def context(interface="wifi", gateway="192.168.1.1", subnet="192.168.1.0/24"):
    return NetworkContext(
        interface, 1 if interface == "wifi" else 2, interface,
        NetworkInterfaceKind.WIFI if interface == "wifi" else NetworkInterfaceKind.ETHERNET,
        "192.168.1.10" if subnet == "192.168.1.0/24" else "10.0.0.10",
        subnet, gateway, (), T0,
    )


def packet(ctx, *, mac=MAC_A, ip=None, at=T0, arp=True):
    return PacketObservation(
        ctx.interface_id, ctx.interface_index, ctx.fingerprint, at, 42, 42,
        LinkLayerProtocol.ETHERNET,
        NetworkLayerProtocol.ARP if arp else NetworkLayerProtocol.IPV4,
        arp=ArpObservation(
            ArpOpcode.REPLY, mac, ip or ctx.gateway or "192.168.1.1",
            MacAddress("ff:ff:ff:ff:ff:ff"), ctx.ipv4_address,
        ) if arp else None,
    )


class FakeContexts:
    def __init__(self, *contexts):
        self.contexts = contexts

    def get_contexts(self):
        return self.contexts


class FakeRepository:
    def __init__(self):
        self.items = {}
        self.history = {}

    def get(self, fingerprint):
        return self.items.get(fingerprint)

    def save(self, baseline, change=None):
        self.items[baseline.network_fingerprint] = baseline
        if change:
            self.history.setdefault(baseline.network_fingerprint, []).append(change)
        return baseline

    def changes(self, fingerprint):
        return tuple(self.history.get(fingerprint, ()))


def service(ctx, *, repo=None, source=None, clock=None):
    repo = repo or FakeRepository()
    source = source or FakeContexts(ctx)
    tick = [T0] if clock is None else clock
    return GatewayBaselineService(repo, source, clock=lambda: tick[0]), repo, source, tick


def test_empty_initial_learning_repeat_duplicate_and_out_of_order():
    ctx = context()
    svc, repo, _, tick = service(ctx)
    assert svc.get(ctx) is None
    first = svc.observe(ctx, packet(ctx))
    assert first.status is GatewayBaselineStatus.LEARNING
    assert first.observation_count == 1
    assert svc.observe(ctx, packet(ctx)) == first
    tick[0] += timedelta(seconds=59)
    second = svc.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=59)))
    assert second.status is GatewayBaselineStatus.LEARNING
    assert second.observation_count == 2
    tick[0] += timedelta(seconds=1)
    learned = svc.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=60)))
    assert learned.status is GatewayBaselineStatus.LEARNED
    assert learned.first_seen == T0
    assert learned.last_seen == T0 + timedelta(seconds=60)
    assert svc.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=10))) == learned
    assert len(repo.history[ctx.fingerprint]) == 1


def test_conflict_veto_and_verified_baseline_remains_stable():
    ctx = context()
    svc, _, _, tick = service(ctx)
    svc.observe(ctx, packet(ctx))
    conflict = svc.observe(ctx, packet(ctx, mac=MAC_B))
    assert conflict.conflicted and conflict.mac == MAC_A
    tick[0] += timedelta(seconds=61)
    assert svc.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=61))).status is GatewayBaselineStatus.LEARNING
    verified = svc.confirm(ctx, MAC_A)
    assert verified.status is GatewayBaselineStatus.VERIFIED
    assert verified.verified_at == tick[0]
    pending = svc.observe(ctx, packet(ctx, mac=MAC_B, at=T0 + timedelta(seconds=62)))
    assert pending.mac == MAC_A and pending.pending_mac == MAC_B
    assert svc.confirm(ctx, MAC_A) == pending
    tick[0] += timedelta(seconds=1)
    replacement = svc.confirm(ctx, MAC_B)
    assert replacement.mac == MAC_B and replacement.status is GatewayBaselineStatus.VERIFIED
    assert replacement.pending_mac is None
    changes = svc.changes(ctx)
    assert [change.reason for change in changes] == ["first_observation", "user_confirmation", "user_confirmation"]
    assert [change.changed_at for change in changes] == [T0, T0 + timedelta(seconds=61), T0 + timedelta(seconds=62)]
    assert changes[0].new_mac == changes[1].old_mac == MAC_A
    assert changes[2].old_mac == MAC_A and changes[2].new_mac == MAC_B


def test_network_fingerprint_gateway_and_current_context_isolation():
    a = context()
    b = context("ethernet", "10.0.0.1", "10.0.0.0/24")
    c = context(gateway="192.168.1.254")
    source = FakeContexts(a, b, c)
    repo = FakeRepository()
    svc = GatewayBaselineService(repo, source, clock=lambda: T0)
    assert svc.observe(a, packet(a)).network_fingerprint == a.fingerprint
    assert svc.observe(b, packet(b, mac=MAC_B)).network_fingerprint == b.fingerprint
    assert svc.observe(c, packet(c, mac=MAC_B)).network_fingerprint == c.fingerprint
    assert c.fingerprint != a.fingerprint
    assert svc.get(a).mac == MAC_A and svc.get(b).mac == MAC_B
    source.contexts = (b,)
    with pytest.raises(GatewayContextChanged):
        svc.observe(a, packet(a, at=T0 + timedelta(seconds=1)))
    with pytest.raises(GatewayContextChanged):
        svc.observe(b, packet(a))
    assert repo.items[a.fingerprint].mac == MAC_A


def test_out_of_order_conflict_does_not_replace_newer_pending_candidate():
    ctx = context()
    svc, _, _, tick = service(ctx)
    svc.observe(ctx, packet(ctx))
    tick[0] += timedelta(seconds=70)
    svc.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=70)))
    pending = svc.observe(ctx, packet(ctx, mac=MAC_B, at=T0 + timedelta(seconds=72)))
    assert pending.pending_seen_at == T0 + timedelta(seconds=72)
    assert svc.observe(ctx, packet(ctx, mac=MacAddress("02:11:22:33:44:77"), at=T0 + timedelta(seconds=71))) == pending


def test_only_gateway_sender_and_valid_unicast_arp_is_eligible():
    ctx = context()
    svc, _, _, _ = service(ctx)
    assert svc.observe(ctx, packet(ctx, ip="192.168.1.99")) is None
    assert svc.observe(ctx, packet(ctx, arp=False)) is None
    assert svc.observe(ctx, packet(ctx, mac=MacAddress("00:00:00:00:00:00"))) is None
    assert svc.observe(ctx, packet(ctx, mac=MacAddress("01:00:5e:00:00:01"))) is None
    assert svc.get(ctx) is None
    missing = context(gateway=None)
    svc2, _, _, _ = service(missing)
    assert svc2.observe(missing, packet(missing)) is None
    with pytest.raises(GatewayConfirmationUnavailable):
        svc.confirm(ctx, MAC_A)


def test_invalid_time_and_repository_failure_do_not_mutate_state():
    ctx = context()
    svc, repo, _, tick = service(ctx)
    with pytest.raises(ValueError):
        packet(ctx, at=T0.replace(tzinfo=None))
    tick[0] = T0.replace(tzinfo=None)
    with pytest.raises(ValueError):
        svc.observe(ctx, packet(ctx))
    assert repo.items == {}

    class FailingRepository(FakeRepository):
        def save(self, baseline, change=None):
            raise RuntimeError("storage unavailable")

    failed = GatewayBaselineService(FailingRepository(), FakeContexts(ctx), clock=lambda: T0)
    with pytest.raises(RuntimeError, match="storage unavailable"):
        failed.observe(ctx, packet(ctx))


def test_restart_restores_learning_and_verification_from_repository():
    ctx = context()
    repo = FakeRepository()
    source = FakeContexts(ctx)
    first = GatewayBaselineService(repo, source, clock=lambda: T0)
    first.observe(ctx, packet(ctx))
    later = T0 + timedelta(seconds=61)
    restarted = GatewayBaselineService(repo, source, clock=lambda: later)
    learned = restarted.observe(ctx, packet(ctx, at=later))
    assert learned.status is GatewayBaselineStatus.LEARNED
    restarted.confirm(ctx, MAC_A)
    again = GatewayBaselineService(repo, source, clock=lambda: later + timedelta(seconds=1))
    assert again.get(ctx).status is GatewayBaselineStatus.VERIFIED
    assert len(again.changes(ctx)) == 2
