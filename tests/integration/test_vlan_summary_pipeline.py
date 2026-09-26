"""Offline NS-043 parser to NS-044 portable aggregate integration."""

from __future__ import annotations

from netsentinel.application.ports import PacketCaptureRequest
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.infrastructure.scapy_capture import _packet_observation
from tests.fixtures.packets.vlan import tagged, untagged
from tests.unit.application.test_vlan_baseline import Clock
from tests.unit.infrastructure.test_scapy_capture import context, worker_for
from tests.integration.test_traffic_metrics_pipeline import Capture, Contexts
from scapy.layers.l2 import ARP, Ether
from netsentinel.application.services.device_inventory import DeviceInventoryProblem


def test_parser_queue_summary_and_sqlite_without_live_capture(tmp_path) -> None:
    worker, _, backend = worker_for(queue_capacity=8)
    ctx = context()
    service = VlanSummaryService(
        SQLiteVlanSummaryRepository(SQLiteDatabase(tmp_path / "pipeline.sqlite3")),
        clock=Clock(),
    )
    assert worker.start(PacketCaptureRequest(ctx, "vlan or arp"))
    for frame in (untagged(), tagged(10), tagged(10), tagged(20)):
        backend.handles[0].emit(frame)
    for observation in worker.drain(8):
        service.observe(ctx, observation)
    summary = service.get(ctx)
    assert summary.baseline_state is VlanBaselineState.LEARNING
    assert summary.untagged_count == 1 and summary.tagged_count == 3
    assert [(entry.vlan_id, entry.count) for entry in summary.vlan_ids] == [(10, 2), (20, 1)]
    assert "secret" not in repr(summary)
    assert worker.stop()
    assert backend.handles[0].closed


def test_existing_inventory_consumer_persists_vlan_without_alert_or_ui(tmp_path) -> None:
    ctx = context()
    observations = tuple(_packet_observation(frame, ctx, ctx.observed_at)
                         for frame in (untagged(), tagged(10), tagged(20)))
    capture = Capture(observations, ctx)
    database = SQLiteDatabase(tmp_path / "consumer.sqlite3")
    vlan = VlanSummaryService(SQLiteVlanSummaryRepository(database), clock=Clock())
    inventory = DeviceInventoryService(
        Contexts(ctx), SQLiteDeviceRepository(database), capture, vlan_summary=vlan,
    )
    try:
        inventory.refresh(start_capture=True)
        summary = vlan.get(ctx)
        assert summary is not None
        assert summary.untagged_count == 1 and summary.tagged_count == 2
        assert "vlan" in capture.request.capture_filter
        assert summary.learned_vlan_ids == ()
    finally:
        assert inventory.close()


def test_vlan_repository_failure_does_not_stop_arp_consumer(tmp_path) -> None:
    ctx = context()
    arp = _packet_observation(
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.2",
            hwdst="00:00:00:00:00:00", pdst="192.168.50.20"),
        ctx, ctx.observed_at,
    )

    class BrokenVlanSummary:
        def observe(self, *_args):
            raise RuntimeError("private database detail")

    capture = Capture((_packet_observation(tagged(10), ctx, ctx.observed_at), arp), ctx)
    inventory = DeviceInventoryService(
        Contexts(ctx), SQLiteDeviceRepository(SQLiteDatabase(tmp_path / "isolated.sqlite3")),
        capture, vlan_summary=BrokenVlanSummary(),
    )
    try:
        result = inventory.refresh(start_capture=True)
        assert result.problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
        assert len(result.entries) == 1
        assert "private database detail" not in repr(result)
    finally:
        assert inventory.close()
