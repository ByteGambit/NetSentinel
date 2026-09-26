"""NS-044 portable baseline tests; no capture driver or live network."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.vlan import VlanBaselineNotReady, VlanContextChanged, VlanSummaryService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.observations import LinkLayerProtocol, NetworkLayerProtocol, PacketObservation
from netsentinel.domain.vlan import VlanObservation, VlanTagKind
from netsentinel.domain.vlan_summary import VlanBaselineState, VlanSummarySnapshot


AT = datetime(2026, 9, 26, tzinfo=UTC)


class Clock:
    at = AT

    def __call__(self) -> datetime:
        return self.at


class MemoryRepository:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, int], VlanSummarySnapshot] = {}

    def get(self, fingerprint: str, interface: str, index: int) -> VlanSummarySnapshot | None:
        return self.rows.get((fingerprint, interface, index))

    def save(self, snapshot: VlanSummarySnapshot) -> VlanSummarySnapshot:
        key = (snapshot.network_fingerprint, snapshot.interface_id, snapshot.interface_index)
        self.rows[key] = snapshot
        return snapshot

    def verify(self, fingerprint: str, interface: str, index: int,
               verified_at: datetime) -> VlanSummarySnapshot:
        key = (fingerprint, interface, index)
        current = self.rows[key]
        if current.baseline_state is VlanBaselineState.VERIFIED:
            return current
        assert current.baseline_state is VlanBaselineState.LEARNED
        verified = replace(current, baseline_state=VlanBaselineState.VERIFIED,
                           verified_at=verified_at)
        self.rows[key] = verified
        return verified


def context(interface: str = "WiFi", index: int = 1, subnet: str = "192.0.2.0/24") -> NetworkContext:
    return NetworkContext(interface, index, interface, NetworkInterfaceKind.ETHERNET,
                          "192.0.2.10" if subnet == "192.0.2.0/24" else "198.51.100.10",
                          subnet, None, (), AT)


def packet(ctx: NetworkContext, vid: int | None = None, *,
           kind: VlanTagKind | None = None, at: datetime = AT) -> PacketObservation:
    if kind is None:
        kind = (VlanTagKind.UNTAGGED if vid is None else
                VlanTagKind.PRIORITY_TAGGED if vid == 0 else
                VlanTagKind.RESERVED if vid == 4095 else VlanTagKind.TAGGED)
    vlan = (VlanObservation(kind) if kind is VlanTagKind.UNTAGGED else
            VlanObservation(kind, vid, 3, False,
                            0x8100 if kind is VlanTagKind.STACKED else 0x0800))
    return PacketObservation(ctx.interface_id, ctx.interface_index, ctx.fingerprint,
                             at, 64, 64, LinkLayerProtocol.ETHERNET,
                             NetworkLayerProtocol.IPV4, vlan=vlan)


def test_empty_counts_learning_and_frozen_baseline() -> None:
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock)
    ctx = context()
    assert service.get(ctx) is None
    first = service.observe(ctx, packet(ctx))
    assert first.untagged_count == 1 and first.tagged_count == 0
    assert first.baseline_state is VlanBaselineState.LEARNING
    clock.at += timedelta(seconds=60)
    second = service.observe(ctx, packet(ctx, 10))
    assert second.baseline_state is VlanBaselineState.LEARNING
    second = service.observe(ctx, packet(ctx, 10))
    assert second.baseline_state is VlanBaselineState.LEARNED
    assert second.learned_vlan_ids == (10,)
    assert second.total_count == 3
    later = service.observe(ctx, packet(ctx, 20))
    later = service.observe(ctx, packet(ctx, 10))
    assert later.tagged_count == 4 and later.untagged_count == 1
    assert later.learned_vlan_ids == (10,)
    assert [(entry.vlan_id, entry.count, entry.learned) for entry in later.vlan_ids] == [
        (10, 3, True), (20, 1, False),
    ]
    with pytest.raises(FrozenInstanceError):
        later.untagged_count = 0  # type: ignore[misc]


def test_one_observation_never_learns_and_vid_zero_reserved_stacked_are_distinct() -> None:
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock)
    ctx = context()
    service.observe(ctx, packet(ctx, 0))
    clock.at += timedelta(seconds=100)
    assert service.get(ctx).baseline_state is VlanBaselineState.LEARNING
    service.observe(ctx, packet(ctx, 4095))
    result = service.observe(ctx, packet(ctx, 11, kind=VlanTagKind.STACKED))
    assert (result.priority_tagged_count, result.reserved_count, result.stacked_count) == (1, 1, 1)
    assert result.vlan_ids == () and result.learned_vlan_ids == ()
    assert result.baseline_state is VlanBaselineState.LEARNING


def test_scope_casefold_duplicate_and_out_of_order_packet_times() -> None:
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock)
    a, b, c, d = (context(), context("Ethernet", 2), context("WiFi", 3),
                  context("WiFi", 1, "198.51.100.0/24"))
    first = packet(a, 10, at=AT + timedelta(seconds=10))
    service.observe(a, first)
    result = service.observe(a, first)
    result = service.observe(a, packet(a, 10, at=AT))
    assert result.vlan_ids[0].count == 3
    assert result.first_seen == AT and result.last_seen == AT + timedelta(seconds=10)
    assert service.get(b) is None and service.get(c) is None and service.get(d) is None
    with pytest.raises(VlanContextChanged):
        service.observe(b, first)
    assert service.get(b) is None


def test_distinct_singletons_do_not_establish_a_learned_vid() -> None:
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock)
    ctx = context()
    service.observe(ctx, packet(ctx, 10))
    clock.at += timedelta(seconds=60)
    assert service.observe(ctx, packet(ctx, 20)).baseline_state is VlanBaselineState.LEARNING
    result = service.observe(ctx, packet(ctx, 20))
    assert result.baseline_state is VlanBaselineState.LEARNED
    assert result.learned_vlan_ids == (20,)


def test_vid_capacity_is_bounded_and_excess_is_counted() -> None:
    service = VlanSummaryService(MemoryRepository(), clock=Clock())
    ctx = context()
    for vid in range(1, 131):
        service.observe(ctx, packet(ctx, vid))
    result = service.get(ctx)
    assert len(result.vlan_ids) == 128
    assert result.overflow_count == 2
    assert result.tagged_count == 130
    assert result.vlan_ids[0].vlan_id == 1


def test_explicit_verification_is_separate_from_passive_learning_and_stays_frozen() -> None:
    clock = Clock()
    service = VlanSummaryService(MemoryRepository(), clock=clock, warmup=timedelta(0))
    ctx = context()
    with pytest.raises(VlanBaselineNotReady):
        service.verify_baseline(ctx)
    service.observe(ctx, packet(ctx, 10, at=AT))
    with pytest.raises(VlanBaselineNotReady):
        service.verify_baseline(ctx)
    learned = service.observe(ctx, packet(ctx, 10, at=AT + timedelta(seconds=1)))
    assert learned.baseline_state is VlanBaselineState.LEARNED
    assert learned.verified_at is None
    clock.at += timedelta(seconds=2)
    verified = service.verify_baseline(ctx)
    assert verified.baseline_state is VlanBaselineState.VERIFIED
    assert verified.verified_at == clock.at
    clock.at += timedelta(seconds=1)
    assert service.verify_baseline(ctx).verified_at == verified.verified_at
    updated = service.observe(ctx, packet(ctx, 20, at=AT + timedelta(seconds=3)))
    assert updated.baseline_state is VlanBaselineState.VERIFIED
    assert updated.verified_at == verified.verified_at
    assert updated.learned_vlan_ids == (10,)
    with pytest.raises(VlanBaselineNotReady):
        service.verify_baseline(context("Other", 2))
