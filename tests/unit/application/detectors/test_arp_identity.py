"""NS-026 deterministic detector rules; no LAN, capture driver, or GUI."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.detectors.arp_identity import GatewayMacChangeDetector, IpMacConflictDetector
from netsentinel.application.ports import DeviceRepositoryError, GatewayBaselineRepositoryError
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.domain.alerts import ArpIdentityReason, ArpIdentityRule
from netsentinel.domain.devices import GatewayBaselineStatus, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress, NetworkLayerProtocol, PacketObservation,
)


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)
A = MacAddress("00:11:22:33:44:55")
B = MacAddress("00:11:22:33:44:66")
C = MacAddress("02:11:22:33:44:77")


def context(interface="wifi", gateway="192.168.1.1"):
    return NetworkContext(interface, 1 if interface == "wifi" else 2, interface,
                          NetworkInterfaceKind.WIFI if interface == "wifi" else NetworkInterfaceKind.ETHERNET,
                          "192.168.1.10", "192.168.1.0/24", gateway, (), T0)


def packet(ctx, *, mac=A, ip="192.168.1.20", at=T0, target="192.168.1.10",
           opcode=ArpOpcode.REPLY):
    return PacketObservation(ctx.interface_id, ctx.interface_index, ctx.fingerprint, at,
                             42, 42, LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.ARP,
                             arp=ArpObservation(opcode, mac, ip, MacAddress("ff:ff:ff:ff:ff:ff"), target))


class Contexts:
    def __init__(self, *items):
        self.items = items

    def get_contexts(self):
        return self.items


class Devices:
    def __init__(self):
        self.bindings = {}
        self.fail = False

    def record_binding(self, device, binding):
        if self.fail:
            raise DeviceRepositoryError("offline")
        old = self.bindings.get(binding.binding_id)
        if old is not None:
            binding = replace(old, last_seen=max(old.last_seen, binding.last_seen))
        self.bindings[binding.binding_id] = binding
        return device, binding

    def latest_binding_for_ip(self, fingerprint, ip):
        if self.fail:
            raise DeviceRepositoryError("offline")
        values = [b for b in self.bindings.values() if b.network_fingerprint == fingerprint and b.ip_address == ip]
        return max(values, key=lambda b: (b.last_seen, b.first_seen, str(b.mac))) if values else None


class Baselines:
    def __init__(self):
        self.items = {}
        self.fail = False

    def get(self, fingerprint):
        if self.fail:
            raise GatewayBaselineRepositoryError("offline")
        return self.items.get(fingerprint)

    def save(self, baseline, change=None):
        if self.fail:
            raise GatewayBaselineRepositoryError("offline")
        self.items[baseline.network_fingerprint] = baseline
        return baseline

    def changes(self, fingerprint):
        return ()


def setup_gateway(ctx=None):
    ctx = ctx or context()
    source = Contexts(ctx)
    repo = Baselines()
    tick = [T0]
    service = GatewayBaselineService(repo, source, clock=lambda: tick[0])
    return ctx, source, repo, tick, service, GatewayMacChangeDetector(service)


def test_ip_conflict_recent_sender_transition_and_no_duplicate():
    ctx = context()
    repo = Devices()
    registry = DeviceRegistryService(repo)
    detector = IpMacConflictDetector(repo, Contexts(ctx))
    first = packet(ctx)
    assert detector.observe(ctx, first) is None
    registry.observe(ctx, first)
    same = packet(ctx, at=T0 + timedelta(seconds=61))
    assert detector.observe(ctx, same) is None
    registry.observe(ctx, same)
    changed = packet(ctx, mac=B, at=T0 + timedelta(seconds=62), opcode=ArpOpcode.REQUEST)
    event = detector.observe(ctx, changed)
    assert event.rule_id is ArpIdentityRule.IP_MAC_CONFLICT
    assert event.reason is ArpIdentityReason.RECENT_SENDER_CONFLICT
    assert (event.evidence.expected_mac, event.evidence.observed_mac) == (A, B)
    assert (event.evidence.expected_last_seen_at, event.observed_at) == (same.observed_at, changed.observed_at)
    assert event.entity_id == f"{ctx.fingerprint}:192.168.1.20"
    assert (event.severity, event.confidence) == ("low", "low")
    assert event == detector.observe(ctx, changed)
    registry.observe(ctx, changed)
    assert detector.observe(ctx, changed) is None
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=63))) is None
    assert detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=64))) is None
    registry.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=123)))
    restored = detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=124)))
    assert restored is not None and restored.evidence.expected_mac == B
    assert restored.event_fingerprint != event.event_fingerprint


def test_ip_conflict_warmup_dhcp_gap_gratuitous_stale_and_context_isolation():
    ctx = context()
    other = context("ethernet")
    source = Contexts(ctx, other)
    repo = Devices()
    registry = DeviceRegistryService(repo)
    detector = IpMacConflictDetector(repo, source)
    registry.observe(ctx, packet(ctx))
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=10))) is None
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=180))) is None
    registry.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=61)))
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=60))) is None
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=61), target="192.168.1.20")) is None
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 - timedelta(seconds=1))) is None
    assert detector.observe(other, packet(other, mac=B, at=T0 + timedelta(seconds=61))) is None
    assert detector.observe(ctx, packet(other, mac=B, at=T0 + timedelta(seconds=61))) is None
    assert detector.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=61))) is None
    assert detector.observe(ctx, packet(ctx, mac=B, ip="0.0.0.0", at=T0 + timedelta(seconds=61))) is None
    assert detector.observe(ctx, packet(ctx, mac=MacAddress("01:00:00:00:00:01"), at=T0 + timedelta(seconds=61))) is None
    source.items = (other,)
    assert detector.observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=61))) is None


def test_ip_conflict_repository_failure_does_not_create_local_state():
    ctx = context()
    repo = Devices()
    detector = IpMacConflictDetector(repo, Contexts(ctx))
    repo.fail = True
    with pytest.raises(DeviceRepositoryError):
        detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=61)))
    repo.fail = False
    assert detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=61))) is None


def test_gateway_learning_learned_verified_pending_and_recovery():
    ctx, _, repo, tick, service, detector = setup_gateway()
    assert detector.observe(ctx, packet(ctx, ip=ctx.gateway)) is None
    service.observe(ctx, packet(ctx, ip=ctx.gateway))
    assert detector.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=1))) is None
    tick[0] += timedelta(seconds=61)
    service.observe(ctx, packet(ctx, ip=ctx.gateway, at=T0 + timedelta(seconds=61)))
    assert repo.get(ctx.fingerprint).status is GatewayBaselineStatus.LEARNED
    changed = packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=62))
    event = detector.observe(ctx, changed)
    assert event.rule_id is ArpIdentityRule.GATEWAY_MAC_CHANGE
    assert event.reason is ArpIdentityReason.LEARNED_GATEWAY_CONFLICT
    assert event.evidence.baseline_status is GatewayBaselineStatus.LEARNED
    assert (event.severity, event.confidence) == ("low", "low")
    service.observe(ctx, changed)
    assert detector.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=63))) is None
    assert detector.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=64))) is not None
    service.observe(ctx, packet(ctx, ip=ctx.gateway, at=T0 + timedelta(seconds=65)))
    assert detector.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=66))) is not None
    tick[0] += timedelta(seconds=5)
    service.confirm(ctx, A)
    verified = detector.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=67)))
    assert verified.reason is ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT
    assert (verified.severity, verified.confidence) == ("medium", "low")
    local = detector.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=68)))
    assert local.severity == "low"


def test_gateway_restart_scope_gratuitous_special_and_repository_failure():
    ctx, source, repo, tick, service, detector = setup_gateway()
    service.observe(ctx, packet(ctx, ip=ctx.gateway))
    tick[0] += timedelta(seconds=61)
    service.observe(ctx, packet(ctx, ip=ctx.gateway, at=T0 + timedelta(seconds=61)))
    pending = packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=62))
    assert detector.observe(ctx, pending) is not None
    service.observe(ctx, pending)
    restarted = GatewayMacChangeDetector(GatewayBaselineService(repo, source, clock=lambda: tick[0]))
    assert restarted.observe(ctx, packet(ctx, mac=B, ip=ctx.gateway, at=T0 + timedelta(seconds=63))) is None
    assert restarted.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=64))) is not None
    assert restarted.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=61))) is None
    assert restarted.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=64), target=ctx.gateway)) is None
    assert restarted.observe(ctx, packet(ctx, mac=C, ip="192.168.1.20", at=T0 + timedelta(seconds=64))) is None
    assert restarted.observe(ctx, packet(ctx, mac=C, ip="0.0.0.0", at=T0 + timedelta(seconds=64))) is None
    other = context("ethernet")
    source.items = (other,)
    assert restarted.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=64))) is None
    source.items = (ctx,)
    repo.fail = True
    with pytest.raises(GatewayBaselineRepositoryError):
        restarted.observe(ctx, packet(ctx, mac=C, ip=ctx.gateway, at=T0 + timedelta(seconds=64)))


def test_event_is_immutable_and_contains_no_raw_packet_or_payload():
    ctx = context()
    repo = Devices()
    registry = DeviceRegistryService(repo)
    registry.observe(ctx, packet(ctx))
    event = IpMacConflictDetector(repo, Contexts(ctx)).observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=61)))
    with pytest.raises(AttributeError):
        event.evidence.observed_mac = A
    assert "packet" not in repr(event).lower()
    assert "payload" not in repr(event).lower()
    assert event.event_fingerprint == IpMacConflictDetector(repo, Contexts(ctx)).observe(ctx, packet(ctx, mac=B, at=T0 + timedelta(seconds=61))).event_fingerprint
