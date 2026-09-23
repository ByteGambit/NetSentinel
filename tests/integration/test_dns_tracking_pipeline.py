"""NS-030 packet metadata flows into NS-031 without a live capture backend."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.domain.dns import DnsTransactionStatus
from netsentinel.infrastructure.scapy_capture import _packet_observation
from tests.fixtures.packets.dns import dns_query, dns_response


def test_synthetic_udp_and_tcp_parser_to_correlation() -> None:
    now = datetime(2026, 9, 23, 12, tzinfo=UTC)
    context = SimpleNamespace(interface_id="{WIFI}", interface_index=12, fingerprint="a" * 64)
    ticks = [0.0]
    service = DnsTrackingService(clock=lambda: ticks[0])

    for tcp in (False, True):
        query = _packet_observation(dns_query(tcp=tcp), context, now)
        response = _packet_observation(dns_response(tcp=tcp), context, now)
        assert query.dns is not None and response.dns is not None
        assert service.observe(query) == ()
        ticks[0] += .125
        completed, = service.observe(response)
        assert completed.status is DnsTransactionStatus.COMPLETED
        assert completed.latency_seconds == .125
        assert completed.transaction_id == 42
        assert len(completed.answers) == 4
        assert completed.network_fingerprint == context.fingerprint
        assert not hasattr(completed, "payload") and not hasattr(completed, "packet")
