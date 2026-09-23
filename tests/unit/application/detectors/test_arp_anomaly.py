"""NS-027 deterministic rolling ARP correlation; no capture or database."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.detectors.arp_anomaly import ArpAnomalyCorrelator
from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityEvidence, ArpIdentityReason,
    ArpIdentityRule, ArpScoreRule,
)
from netsentinel.domain.devices import GatewayBaselineStatus, NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import (
    ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress, NetworkLayerProtocol, PacketObservation,
)


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)
A = MacAddress("00:11:22:33:44:55")
B = MacAddress("00:11:22:33:44:66")


def context(name="wifi"):
    return NetworkContext(name, 1 if name == "wifi" else 2, name,
                          NetworkInterfaceKind.WIFI if name == "wifi" else NetworkInterfaceKind.ETHERNET,
                          "192.168.1.10", "192.168.1.0/24", "192.168.1.1", (), T0)


def packet(ctx, ip="192.168.1.20", at=T0 + timedelta(seconds=61), mac=B):
    return PacketObservation(ctx.interface_id, ctx.interface_index, ctx.fingerprint, at,
                             42, 42, LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.ARP,
                             arp=ArpObservation(ArpOpcode.REPLY, mac, ip, A, ctx.ipv4_address))


def event(ctx, observation, *, gateway=False, verified=False):
    return ArpIdentityConflictDetected(
        ArpIdentityRule.GATEWAY_MAC_CHANGE if gateway else ArpIdentityRule.IP_MAC_CONFLICT,
        (ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT if verified else ArpIdentityReason.LEARNED_GATEWAY_CONFLICT)
        if gateway else ArpIdentityReason.RECENT_SENDER_CONFLICT,
        ArpIdentityEvidence(ctx.fingerprint, observation.arp.sender_ip, A, observation.arp.sender_mac,
                            T0 + timedelta(seconds=60), observation.observed_at,
                            (GatewayBaselineStatus.VERIFIED if verified else GatewayBaselineStatus.LEARNED)
                            if gateway else None),
        "medium" if verified else "low", "low",
    )


def test_single_repeated_burst_and_out_of_order_evidence():
    ctx = context()
    tick = [T0]
    detector = ArpAnomalyCorrelator(clock=lambda: tick[0])
    first = packet(ctx)
    source = event(ctx, first)
    result, = detector.observe(ctx, first, (source,))
    assert result.source is source
    assert (result.score, result.confidence, result.severity, result.observation_count) == (2, "low", "low", 1)
    assert [part.rule for part in result.breakdown] == [ArpScoreRule.IDENTITY_CONFLICT]
    assert detector.observe(ctx, first, (source,)) == ()
    tick[0] += timedelta(seconds=1)
    assert detector.observe(ctx, packet(ctx, at=first.observed_at + timedelta(seconds=1))) == ()
    tick[0] += timedelta(seconds=1)
    stronger, = detector.observe(ctx, packet(ctx, at=first.observed_at + timedelta(seconds=2)))
    assert (stronger.score, stronger.confidence, stronger.observation_count) == (3, "moderate", 3)
    assert [part.rule for part in stronger.breakdown] == [ArpScoreRule.IDENTITY_CONFLICT, ArpScoreRule.REPEATED_OBSERVATION]
    assert detector.observe(ctx, packet(ctx, at=first.observed_at + timedelta(seconds=1))) == ()
    assert detector.observe(ctx, packet(ctx, at=first.observed_at + timedelta(seconds=3))) == ()
    assert detector.retained_signals == 1


def test_combined_conflict_and_verified_gateway_are_scoped_and_explained():
    ctx = context()
    tick = [T0]
    detector = ArpAnomalyCorrelator(clock=lambda: tick[0])
    ordinary = packet(ctx)
    gateway = packet(ctx, ctx.gateway, ordinary.observed_at + timedelta(seconds=1))
    assert detector.observe(ctx, ordinary, (event(ctx, ordinary),))[0].confidence == "low"
    tick[0] += timedelta(seconds=1)
    assessment, = detector.observe(ctx, gateway, (event(ctx, gateway, gateway=True, verified=True),))
    assert (assessment.score, assessment.confidence, assessment.severity) == (5, "moderate", "medium")
    assert [part.rule for part in assessment.breakdown] == [
        ArpScoreRule.IDENTITY_CONFLICT, ArpScoreRule.VERIFIED_GATEWAY, ArpScoreRule.COMBINED_TARGETS,
    ]
    other = context("ethernet")
    different = packet(other, other.gateway)
    isolated, = detector.observe(other, different, (event(other, different, gateway=True, verified=True),))
    assert (isolated.score, isolated.confidence) == (3, "low")


def test_sparse_traffic_expiry_capacity_and_no_event_no_assessment():
    ctx = context()
    tick = [T0]
    detector = ArpAnomalyCorrelator(clock=lambda: tick[0], window=timedelta(seconds=10), capacity=2)
    assert detector.observe(ctx, packet(ctx)) == ()
    for index, ip in enumerate(("192.168.1.20", "192.168.1.21", "192.168.1.22")):
        item = packet(ctx, ip, T0 + timedelta(seconds=61 + index))
        assert detector.observe(ctx, item, (event(ctx, item),))[0].confidence == "low"
    assert detector.retained_signals == 2
    assert detector.capacity_drops == 1
    tick[0] += timedelta(seconds=11)
    assert detector.retained_signals == 0
    assert detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=70))) == ()


def test_invalid_clock_mismatched_event_and_no_raw_packet_model():
    ctx = context()
    other = context("ethernet")
    item = packet(ctx)
    with pytest.raises(ValueError, match="UTC-aware"):
        ArpAnomalyCorrelator(clock=lambda: datetime(2026, 9, 23)).observe(ctx, item)
    detector = ArpAnomalyCorrelator(clock=lambda: T0)
    with pytest.raises(ValueError, match="match"):
        detector.observe(ctx, item, (event(other, packet(other)),))
    assert detector.retained_signals == 0
    assert detector.observe(ctx, packet(other)) == ()
    assessment, = detector.observe(ctx, item, (event(ctx, item),))
    assert "payload" not in repr(assessment).lower()
    assert "PacketObservation" not in repr(assessment)


def test_late_conflict_cannot_replace_newer_identity_and_burst_is_bounded():
    ctx = context()
    tick = [T0]
    detector = ArpAnomalyCorrelator(clock=lambda: tick[0])
    newer = packet(ctx, at=T0 + timedelta(seconds=65))
    detector.observe(ctx, newer, (event(ctx, newer),))
    older = packet(ctx, at=T0 + timedelta(seconds=64), mac=MacAddress("00:11:22:33:44:77"))
    assert detector.observe(ctx, older, (event(ctx, older),)) == ()
    assert detector.retained_signals == 1
    for second in range(66, 106):
        tick[0] += timedelta(seconds=1)
        detector.observe(ctx, packet(ctx, at=T0 + timedelta(seconds=second)))
    assert detector.retained_signals == 1
    signal, = detector._signals.values()
    assert len(signal.received) == 3
    tick[0] += timedelta(seconds=121)
    assert detector.retained_signals == 0
