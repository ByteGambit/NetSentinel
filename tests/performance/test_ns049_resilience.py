"""NS-049 offline load contracts; these are resource checks, not throughput scores."""

from __future__ import annotations

import gc
import tracemalloc
from datetime import timedelta
from threading import Event, Thread, enumerate as threads
from time import monotonic

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.detectors.traffic_rate import TrafficRateDetector
from netsentinel.application.detectors.vlan_anomaly import VlanAnomalyDetector
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.application.services.dns_history import DnsHistoryWriter
from netsentinel.application.services.traffic_metrics import MeasurementConfidence, TrafficMetricsService
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_repository import SQLiteDnsHistorySessionFactory
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from netsentinel.shared.config import TrafficRateConfig
from netsentinel.shared.diagnostics import DiagnosticCode
from tests.fixtures.packets.dns import dns_query, dns_response
from tests.fixtures.packets.vlan import tagged, untagged
from tests.integration.sqlite.test_alert_repository import T0, assessment
from tests.unit.application.detectors.test_traffic_rate import metric
from tests.unit.application.test_vlan_baseline import Clock, MemoryRepository, packet as vlan_packet
from tests.unit.infrastructure.test_scapy_capture import FakeContextProvider, MalformedPacket, context, worker_for


@pytest.mark.performance
def test_mixed_packet_burst_backpressure_and_shutdown_under_load(tmp_path) -> None:
    ctx = context()
    owned_before = {t.ident for t in threads() if t.name.startswith("netsentinel-")}
    at = [ctx.observed_at]
    ticks = [0.0]
    worker, provider, backend = worker_for(
        FakeContextProvider((ctx,)), queue_capacity=32,
        shutdown_timeout=1.0, clock=lambda: at[0],
    )
    db = SQLiteDatabase(tmp_path / "mixed.sqlite3")
    writer = DnsHistoryWriter(SQLiteDnsHistorySessionFactory(db), queue_capacity=32,
                              batch_size=8, batch_interval=0, shutdown_timeout=2)
    metrics = TrafficMetricsService(clock=lambda: ticks[0])
    summary = VlanSummaryService(SQLiteVlanSummaryRepository(db), clock=lambda: at[0],
                                 warmup=timedelta(0))
    alerts = AlertService(SQLiteAlertRepository(db), clock=lambda: at[0])
    inventory = DeviceInventoryService(provider, SQLiteDeviceRepository(db), worker,
                                       alerts=alerts, dns_writer=writer,
                                       dns_tracking=DnsTrackingService(clock=lambda: ticks[0]),
                                       traffic_metrics=metrics, vlan_summary=summary)
    packet_mix = (
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.50.4", hwdst="00:00:00:00:00:00", pdst="192.168.50.1"),
        dns_query(), dns_response(),
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.50.4", dst="192.168.50.255"),
        tagged(10), untagged(),
    )
    try:
        assert inventory.refresh(start_capture=True).capture.running
        handle = backend.handles[0]
        # An exact full queue gives a deterministic loss count, independent of CPU speed.
        for index in range(320):
            handle.emit(packet_mix[index % len(packet_mix)])
            if index % 8 == 0:
                handle.emit(MalformedPacket())
        health = worker.health_snapshot()
        assert health.queue_depth == 32
        assert health.counters.dropped_observations == 288
        assert health.counters.malformed_packets == 40
        assert health.last_error is not None
        assert health.last_error.code is DiagnosticCode.CAPTURE_QUEUE_OVERFLOW
        assert "raw malformed" not in repr(health)
        snapshot = inventory.refresh()
        assert snapshot.traffic_metrics is not None
        assert snapshot.traffic_metrics.confidence is MeasurementConfidence.REDUCED
        assert snapshot.traffic_metrics.arp.packet_count > 0
        assert snapshot.traffic_metrics.broadcast.packet_count > 0
        assert snapshot.vlan_summary is not None and snapshot.vlan_summary.tagged_count > 0
        assert metrics.tracked_contexts == 1 and metrics.retained_buckets <= 60
        assert writer.health_snapshot().queue_depth <= 32
        assert len(alerts.query(AlertQuery(50))) <= 50

        reached, resume = Event(), Event()
        def producer() -> None:
            reached.set()
            assert resume.wait(5)
            for _ in range(320):
                handle.emit(packet_mix[0])
        active = Thread(target=producer, name="netsentinel-ns049-producer")
        active.start()
        assert reached.wait(5)
        before_stop = worker.health_snapshot().counters
        start = monotonic()
        assert inventory.close()
        elapsed = monotonic() - start
        resume.set()
        active.join(5)
        assert not active.is_alive()
        assert worker.health_snapshot().counters == before_stop
        assert worker.health_snapshot().queue_depth <= 32
        assert writer.health_snapshot().queue_depth == 0
        assert not writer.health_snapshot().running
        assert writer.health_snapshot().persisted >= 1
        assert elapsed < 3.5  # capture 1 s + DNS drain 2 s + generous scheduling slack
        assert handle.closed
    finally:
        inventory.close()
    assert {t.ident for t in threads() if t.name.startswith("netsentinel-")} == owned_before


@pytest.mark.performance
def test_accelerated_context_churn_has_structural_and_heap_bounds() -> None:
    at = context().observed_at
    ticks = [0.0]
    metrics = TrafficMetricsService(clock=lambda: ticks[0], max_contexts=8)
    dns = DnsTrackingService(clock=lambda: ticks[0], max_pending=16)
    frame = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(
        src="192.168.50.4", dst="192.168.50.255")
    contexts = tuple(context(interface_id=f"adapter-{i}", interface_index=i + 1)
                     for i in range(24))
    packets = tuple(_packet_observation(frame, ctx, at) for ctx in contexts)
    query = _packet_observation(dns_query(), contexts[0], at)
    assert query.dns is not None

    def cycle(iterations: int) -> None:
        for i in range(iterations):
            index = i % len(contexts)
            ticks[0] += 1.0
            metrics.observe(contexts[index], packets[index])
            dns.observe(query)
            if i % 7 == 0:
                dns.expire()
            assert metrics.tracked_contexts <= 8
            assert metrics.retained_buckets <= 8 * 60
            assert dns.pending_count <= 16 and dns.recent_count <= 16

    cycle(500)
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.take_snapshot()
        cycle(4_000)  # accelerated hours of synthetic one-second ticks
        gc.collect()
        after = tracemalloc.take_snapshot()
        growth = sum(stat.size_diff for stat in after.compare_to(before, "filename"))
    finally:
        tracemalloc.stop()
    # Heap guard is intentionally broad; exact allocator bytes are platform-dependent.
    assert growth < 1_000_000
    assert metrics.tracked_contexts == 8
    assert metrics.retained_buckets <= 8 * 60
    assert dns.pending_count <= 16 and dns.recent_count <= 16
    ticks[0] += 601.0
    metrics.snapshot(contexts[0])
    dns.expire()
    assert metrics.tracked_contexts == 0
    assert dns.pending_count == 0


@pytest.mark.performance
def test_alert_storm_uses_persistent_fingerprint_without_merging_distinct_issues(tmp_path) -> None:
    now = [T0]
    alerts = AlertService(SQLiteAlertRepository(SQLiteDatabase(tmp_path / "alerts.sqlite3")),
                          clock=lambda: now[0])
    first_id = None
    for i in range(256):
        now[0] += timedelta(seconds=1)
        row, _ = alerts.record(assessment(at=now[0]))
        first_id = first_id or row.id
        assert row.id == first_id
        assert len(row.evidence) <= 8
    rows = alerts.query(AlertQuery(10))
    assert len(rows) == 1
    assert rows[0].occurrence_count == 256
    other, _ = alerts.record(assessment(at=now[0] + timedelta(seconds=1), ip="192.168.1.21"))
    assert other.id != first_id
    assert len(alerts.query(AlertQuery(10))) == 2


@pytest.mark.performance
def test_detector_churn_keeps_rate_and_vlan_confirmation_state_bounded() -> None:
    ticks = [0.0]
    rate = TrafficRateDetector(config=TrafficRateConfig(max_states=8), clock=lambda: ticks[0])
    ctx = context()
    vlan_service = VlanSummaryService(MemoryRepository(), clock=Clock(), warmup=timedelta(0))
    for second in (0, 1):
        vlan_service.observe(ctx, vlan_packet(ctx, 10, at=ctx.observed_at + timedelta(seconds=second)))
    vlan_service.verify_baseline(ctx)
    vlan = VlanAnomalyDetector(clock=lambda: ticks[0], max_states=8)
    for i in range(500):
        ticks[0] = float(i)
        rate.assess(metric(broadcast=600, network=f"{i:064x}"),
                    ctx.observed_at + timedelta(seconds=i))
        sample = vlan_packet(ctx, 20 + i % 100,
                             at=ctx.observed_at + timedelta(seconds=i + 2))
        vlan.observe(vlan_service.observe(ctx, sample), sample)
        assert rate.tracked_states <= 8
        assert vlan.tracked_states <= 8
    ticks[0] += 601
    stale = vlan_packet(ctx, 0, at=ctx.observed_at + timedelta(seconds=1_200))
    vlan.observe(vlan_service.get(ctx), stale)
    assert vlan.tracked_states == 0
