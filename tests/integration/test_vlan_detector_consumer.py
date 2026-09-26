"""NS-045 offline parser -> NS-044 summary -> portable detector result."""

from __future__ import annotations

from datetime import timedelta

from netsentinel.application.detectors.vlan_anomaly import DEVICE_SWITCH_RULE, NEW_VID_RULE, VlanAnomalyDetector
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from tests.fixtures.packets.vlan import tagged, untagged
from tests.integration.test_traffic_metrics_pipeline import Capture, Contexts
from tests.unit.application.test_vlan_baseline import Clock
from tests.unit.infrastructure.test_scapy_capture import context
from scapy.layers.l2 import ARP, Ether


def _tagged_from(vid: int, source: str):
    frame = tagged(vid)
    frame.src = source
    return Ether(bytes(frame))


def test_existing_consumer_emits_portable_candidate_without_alert_write(tmp_path):
    ctx = context()
    database = SQLiteDatabase(tmp_path / "vlan_detector.sqlite3")
    vlan = VlanSummaryService(SQLiteVlanSummaryRepository(database),
                              clock=Clock(), warmup=timedelta(0))
    for second in (0, 1):
        vlan.observe(ctx, _packet_observation(tagged(10), ctx,
                                              ctx.observed_at + timedelta(seconds=second)))
    vlan.verify_baseline(ctx)
    times = [ctx.observed_at + timedelta(seconds=i) for i in range(2, 5)]
    frames = (untagged(), tagged(30), tagged(30))
    observations = tuple(_packet_observation(frame, ctx, at)
                         for frame, at in zip(frames, times))
    capture = Capture(observations, ctx)
    inventory = DeviceInventoryService(Contexts(ctx), SQLiteDeviceRepository(database),
                                       capture, vlan_summary=vlan)
    try:
        result = inventory.refresh(start_capture=True)
        assert len(result.vlan_events) == 1
        assert result.vlan_events[0].rule_id == NEW_VID_RULE
        assert dict(result.vlan_events[0].evidence.details)["vid"] == "30"
        assert vlan.get(ctx).learned_vlan_ids == (10,)
        assert vlan.get(ctx).untagged_count == 1
    finally:
        assert inventory.close()


def test_repository_failure_skips_detector_and_keeps_capture_running(tmp_path):
    ctx = context()
    observation = _packet_observation(tagged(30), ctx, ctx.observed_at)
    capture = Capture((observation,), ctx)
    database = SQLiteDatabase(tmp_path / "failure.sqlite3")

    class FailedSummary:
        def observe(self, *_args):
            raise RuntimeError("private SQLite error")

    inventory = DeviceInventoryService(Contexts(ctx), SQLiteDeviceRepository(database),
                                       capture, vlan_summary=FailedSummary())
    try:
        result = inventory.refresh(start_capture=True)
        assert result.vlan_events == ()
        assert capture.health_snapshot().running
        assert "private SQLite error" not in repr(result)
    finally:
        assert inventory.close()


def test_persisted_baseline_survives_restart_but_pending_confirmation_does_not(tmp_path):
    ctx = context()
    database = SQLiteDatabase(tmp_path / "restart.sqlite3")
    def service():
        return VlanSummaryService(SQLiteVlanSummaryRepository(database),
                                  clock=Clock(), warmup=timedelta(0))
    first = service()
    for second in (0, 1):
        first.observe(ctx, _packet_observation(tagged(10), ctx,
                                               ctx.observed_at + timedelta(seconds=second)))
    first.verify_baseline(ctx)
    pending = VlanAnomalyDetector(clock=lambda: 2.0)
    unseen = _packet_observation(tagged(30), ctx, ctx.observed_at + timedelta(seconds=2))
    assert pending.observe(first.observe(ctx, unseen), unseen) == ()
    restored = service()
    fresh = VlanAnomalyDetector(clock=lambda: 3.0)
    known = _packet_observation(tagged(10), ctx, ctx.observed_at + timedelta(seconds=3))
    assert fresh.observe(restored.observe(ctx, known), known) == ()
    unseen_again = _packet_observation(tagged(30), ctx, ctx.observed_at + timedelta(seconds=4))
    assert fresh.observe(restored.observe(ctx, unseen_again), unseen_again) == ()
    third = _packet_observation(tagged(30), ctx, ctx.observed_at + timedelta(seconds=5))
    assert fresh.observe(restored.observe(ctx, third), third)[0].rule_id == NEW_VID_RULE
    assert restored.get(ctx).learned_vlan_ids == (10,)


def test_detector_failure_isolated_from_arp_pipeline(tmp_path):
    ctx = context()
    tagged_observation = _packet_observation(tagged(30), ctx, ctx.observed_at)
    arp_observation = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.2",
            hwdst="00:00:00:00:00:00", pdst="192.168.50.20"),
        ctx, ctx.observed_at + timedelta(seconds=1),
    )
    database = SQLiteDatabase(tmp_path / "detector_error.sqlite3")
    capture = Capture((tagged_observation, arp_observation), ctx)

    class FailedDetector:
        def observe(self, *_args):
            raise RuntimeError("private detector detail")

    inventory = DeviceInventoryService(
        Contexts(ctx), SQLiteDeviceRepository(database), capture,
        vlan_summary=VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=Clock()),
        vlan_detector=FailedDetector(),
    )
    try:
        result = inventory.refresh(start_capture=True)
        assert len(result.entries) == 1
        assert "private detector detail" not in repr(result)
        assert capture.health_snapshot().running
    finally:
        assert inventory.close()


def test_real_parser_consumer_detector_device_tag_change(tmp_path):
    ctx = context()
    database = SQLiteDatabase(tmp_path / "device_vlan.sqlite3")
    vlan = VlanSummaryService(SQLiteVlanSummaryRepository(database),
                              clock=Clock(), warmup=timedelta(0))
    for second in (0, 1):
        vlan.observe(ctx, _packet_observation(_tagged_from(10, "02:11:22:33:44:55"),
                                              ctx, ctx.observed_at + timedelta(seconds=second)))
    vlan.verify_baseline(ctx)
    frames = (
        _tagged_from(10, "02:11:22:33:44:55"),
        _tagged_from(20, "02:aa:bb:cc:dd:ee"),
        _tagged_from(20, "02:11:22:33:44:55"),
        _tagged_from(20, "02:11:22:33:44:55"),
    )
    observations = tuple(_packet_observation(frame, ctx, ctx.observed_at + timedelta(seconds=i))
                         for i, frame in enumerate(frames, start=2))
    assert str(observations[0].ethernet_source_mac) == "02:11:22:33:44:55"
    assert observations[0].vlan.vlan_id == 10
    assert observations[2].vlan.vlan_id == 20
    capture = Capture(observations, ctx)
    inventory = DeviceInventoryService(Contexts(ctx), SQLiteDeviceRepository(database),
                                       capture, vlan_summary=vlan)
    try:
        result = inventory.refresh(start_capture=True)
        changes = [event for event in result.vlan_events if event.rule_id == DEVICE_SWITCH_RULE]
        assert len(changes) == 1
        assert dict(changes[0].evidence.details)["vid"] == "20"
        assert b"secret" not in repr(result.vlan_events).encode()
        assert not hasattr(observations[0], "packet")
        assert vlan.get(ctx).learned_vlan_ids == (10,)
    finally:
        assert inventory.close()
