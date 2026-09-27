"""NS-034 synthetic packet to live consumer, writer, SQLite and read model."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic, sleep

from netsentinel.application.ports import DnsHistoryQuery
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.application.services.dns_history import DnsHistoryWriter
from netsentinel.application.services.dns_history_query import DnsHistoryQueryService
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind
from netsentinel.domain.dns import DnsTransactionStatus
from netsentinel.infrastructure.scapy_capture import _packet_observation
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_repository import SQLiteDnsHistoryRepository, SQLiteDnsHistorySessionFactory
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.shared.diagnostics import (CaptureCapabilityReason, CaptureCapabilitySnapshot,
    CaptureCounters, CaptureHealthSnapshot, CaptureState, CapabilityStatus)
from tests.fixtures.packets.dns import dns_query, dns_response

AT = datetime(2026, 9, 23, 12, tzinfo=UTC)


class Contexts:
    def __init__(self, context):
        self.context = context

    def get_contexts(self):
        return (self.context,)


class Capture:
    def __init__(self, observations):
        self.observations = deque(observations)
        self.request = None
        self.snapshot = CaptureHealthSnapshot(
            CaptureState.STOPPED,
            CaptureCapabilitySnapshot(CapabilityStatus.AVAILABLE, CaptureCapabilityReason.NONE, AT),
            0, 128, CaptureCounters(),
        )

    def health_snapshot(self):
        return self.snapshot

    def probe(self, _context):
        return self.snapshot.capability

    def start(self, request):
        self.request = request
        self.snapshot = replace(self.snapshot, state=CaptureState.RUNNING,
                                selected_interface_id=request.context.interface_id,
                                network_fingerprint=request.context.fingerprint)
        return True

    def stop(self, timeout=None):
        self.snapshot = replace(self.snapshot, state=CaptureState.STOPPED)
        return True

    def drain(self, limit):
        values = []
        while self.observations and len(values) < limit:
            values.append(self.observations.popleft())
        return tuple(values)


def test_synthetic_dns_packet_live_consumer_writer_restart_read_model(tmp_path):
    context = NetworkContext("adapter", 1, "Ethernet", NetworkInterfaceKind.ETHERNET,
                             "192.0.2.20", "192.0.2.0/24", None, (), AT)
    query = _packet_observation(dns_query(), context, AT)
    response = _packet_observation(dns_response(), context, AT)
    assert query.dns is not None and response.dns is not None
    database = SQLiteDatabase(tmp_path / "dns-pipeline.sqlite3")
    writer = DnsHistoryWriter(SQLiteDnsHistorySessionFactory(database), batch_interval=0)
    capture = Capture((query, response, response))
    ticks = [0.0]
    service = DeviceInventoryService(Contexts(context), SQLiteDeviceRepository(database),
                                     capture, dns_writer=writer,
                                     dns_tracking=DnsTrackingService(clock=lambda: ticks[0]))
    try:
        snapshot = service.refresh(start_capture=True)
        assert snapshot.capture.running
        assert "port 53" in capture.request.capture_filter
        assert "arp" in capture.request.capture_filter
        deadline = monotonic() + 3
        while monotonic() < deadline and writer.health_snapshot().persisted < 1:
            sleep(.01)
        assert writer.health_snapshot().persisted == 1
        assert writer.health_snapshot().accepted == 1  # duplicate response is suppressed
        capture.observations.append(_packet_observation(dns_response(), context, AT + timedelta(seconds=1)))
        capture.observations.append(_packet_observation(dns_query(), context, AT + timedelta(seconds=2)))
        service.refresh()
        ticks[0] = 6.0
        service.refresh()  # idle timeout is persisted without another packet
        deadline = monotonic() + 3
        while monotonic() < deadline and writer.health_snapshot().persisted < 3:
            sleep(.01)
        assert writer.health_snapshot().persisted == 3
        assert service.close()
        rows = DnsHistoryQueryService(SQLiteDnsHistoryRepository(database)).load_page(DnsHistoryQuery(limit=50)).records
        assert len(rows) == 3
        assert {row.transaction.status for row in rows} == {
            DnsTransactionStatus.COMPLETED, DnsTransactionStatus.UNMATCHED_RESPONSE,
            DnsTransactionStatus.TIMED_OUT,
        }
        completed = next(row for row in rows if row.transaction.status is DnsTransactionStatus.COMPLETED)
        assert completed.transaction.questions[0].name == "example.com."
        assert len(completed.transaction.answers) == 4
        assert all(not hasattr(row.transaction, "payload") and not hasattr(row.transaction, "packet") for row in rows)
    finally:
        service.close()
