"""NS-031 deterministic DNS correlation, with no capture socket or worker."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.domain.dns import (
    DnsAnswer, DnsObservation, DnsQuestion, DnsRecordType,
    DnsTrafficKind, DnsTransactionStatus as Status, DnsTransport,
)
from netsentinel.domain.observations import LinkLayerProtocol, NetworkLayerProtocol, PacketObservation


BASE = datetime(2026, 9, 23, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def packet(*, response: bool = False, at: datetime = BASE, network: str = "a" * 64,
           transport: DnsTransport = DnsTransport.UDP, client: str = "192.0.2.20",
           server: str = "198.51.100.53", client_port: int = 53000,
           server_port: int = 53, txid: int = 42, name: str = "Example.COM",
           qtype: int = 1, rcode: int = 0, truncated: bool = False,
           kind: DnsTrafficKind = DnsTrafficKind.CLASSIC,
           answers: tuple[DnsAnswer, ...] = ()) -> PacketObservation:
    dns = DnsObservation(
        kind, transport, server if response else client, server_port if response else client_port,
        client if response else server, client_port if response else server_port,
        txid, response, rcode, truncated, (DnsQuestion(name, qtype),), answers,
    )
    return PacketObservation("{WIFI}", 12, network, at, 100, 100,
                             LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.IPV4, dns=dns)


def test_empty_udp_success_and_monotonic_latency() -> None:
    clock = Clock()
    service = DnsTrackingService(clock=clock)
    assert service.pending_count == 0 and service.expire() == ()
    assert service.observe(packet()) == ()
    clock.value = 0.25
    result, = service.observe(packet(response=True, at=BASE + timedelta(milliseconds=10)))
    assert result.status is Status.COMPLETED
    assert result.latency_seconds == .25
    assert result.query_at == BASE and result.response_at == BASE + timedelta(milliseconds=10)
    assert result.questions[0].name == "example.com."
    assert (result.client_ip, result.client_port, result.server_ip, result.server_port) == (
        "192.0.2.20", 53000, "198.51.100.53", 53)
    assert service.pending_count == 0
    with pytest.raises(FrozenInstanceError):
        result.retry_count = 5  # type: ignore[misc]


def test_tcp_and_udp_are_separate() -> None:
    service = DnsTrackingService(clock=Clock())
    service.observe(packet(transport=DnsTransport.TCP))
    unmatched, = service.observe(packet(response=True))
    assert unmatched.status is Status.UNMATCHED_RESPONSE
    completed, = service.observe(packet(response=True, transport=DnsTransport.TCP))
    assert completed.status is Status.COMPLETED and completed.transport is DnsTransport.TCP


@pytest.mark.parametrize("change", [
    {"txid": 43}, {"client": "192.0.2.21"}, {"server": "198.51.100.54"},
    {"client_port": 53001}, {"server_port": 5300}, {"name": "other.example"},
    {"qtype": 28}, {"network": "b" * 64}, {"transport": DnsTransport.TCP},
])
def test_collision_does_not_match_another_identity(change: dict[str, object]) -> None:
    service = DnsTrackingService(clock=Clock())
    service.observe(packet())
    unmatched, = service.observe(packet(response=True, **change))  # type: ignore[arg-type]
    assert unmatched.status is Status.UNMATCHED_RESPONSE
    assert service.pending_count == 1
    completed, = service.observe(packet(response=True))
    assert completed.status is Status.COMPLETED


def test_duplicate_retry_duplicate_response_and_new_transaction() -> None:
    clock = Clock()
    service = DnsTrackingService(clock=clock)
    assert service.observe(packet()) == ()
    assert service.observe(packet()) == ()
    clock.value = 1
    assert service.observe(packet(at=BASE + timedelta(milliseconds=1))) == ()
    assert service.pending_count == 1
    clock.value = 2
    result, = service.observe(packet(response=True, at=BASE + timedelta(seconds=2)))
    assert result.retry_count == 1 and result.latency_seconds == 2
    assert service.observe(packet(response=True, at=BASE + timedelta(seconds=2))) == ()
    assert service.observe(packet()) == ()  # captured query replay cannot reopen
    assert service.pending_count == 0
    service.observe(packet(at=BASE + timedelta(seconds=3)))
    assert service.pending_count == 1  # a later query can reuse the TCP/UDP ID


def test_unmatched_and_response_before_query_are_preserved_without_fabrication() -> None:
    service = DnsTrackingService(clock=Clock())
    unmatched, = service.observe(packet(response=True))
    assert unmatched.status is Status.UNMATCHED_RESPONSE
    assert unmatched.query_at is None and unmatched.response_at == BASE
    assert service.pending_count == 0
    service.observe(packet(at=BASE + timedelta(seconds=2)))
    older, = service.observe(packet(response=True, at=BASE + timedelta(seconds=1)))
    assert older.status is Status.UNMATCHED_RESPONSE
    assert service.pending_count == 1


def test_questionless_response_is_unmatched_and_older_query_cannot_rewind_retry() -> None:
    service = DnsTrackingService(clock=Clock())
    no_question = replace(packet(response=True).dns, questions=())
    unmatched, = service.observe(replace(packet(response=True), dns=no_question))
    assert unmatched.status is Status.UNMATCHED_RESPONSE and unmatched.questions == ()
    service.observe(packet(at=BASE + timedelta(seconds=2)))
    service.observe(packet(at=BASE + timedelta(seconds=3)))
    service.observe(packet(at=BASE + timedelta(seconds=1)))
    completed, = service.observe(packet(response=True, at=BASE + timedelta(seconds=4)))
    assert completed.query_at == BASE + timedelta(seconds=2)
    assert completed.retry_count == 1


def test_timeout_retry_expiry_and_oldest_capacity_eviction() -> None:
    clock = Clock()
    service = DnsTrackingService(clock=clock, timeout_seconds=3, max_pending=2)
    service.observe(packet(txid=1))
    clock.value = 1
    service.observe(packet(txid=2))
    clock.value = 2
    service.observe(packet(txid=1, at=BASE + timedelta(seconds=2)))
    evicted, = service.observe(packet(txid=3))
    assert evicted.status is Status.EVICTED and evicted.transaction_id == 1
    assert evicted.retry_count == 1 and service.pending_count == 2
    clock.value = 4
    timed_out, = service.expire()
    assert timed_out.status is Status.TIMED_OUT and timed_out.transaction_id == 2
    assert service.pending_count == 1
    clock.value = 5
    timed_out, = service.expire()
    assert timed_out.transaction_id == 3 and service.pending_count == 0


def test_retry_extends_timeout_and_heap_stays_bounded() -> None:
    clock = Clock()
    service = DnsTrackingService(clock=clock, timeout_seconds=2, max_pending=2)
    service.observe(packet())
    for i in range(1, 100):
        clock.value = i / 100
        service.observe(packet(at=BASE + timedelta(microseconds=i)))
    assert service.pending_count == 1
    assert len(service._deadlines) <= 4
    clock.value = 2.5
    assert service.expire() == ()
    clock.value = 3
    timed_out, = service.expire()
    assert timed_out.retry_count == 99


def test_recent_completion_cache_is_bounded() -> None:
    service = DnsTrackingService(clock=Clock(), max_pending=2)
    for txid in (1, 2, 3):
        service.observe(packet(txid=txid))
        service.observe(packet(response=True, txid=txid))
    assert service.recent_count == 2
    assert service.pending_count == 0


@pytest.mark.parametrize("rcode", [0, 2, 3, 5, 15])
def test_rcode_answers_and_truncation_are_metadata_not_verdict(rcode: int) -> None:
    service = DnsTrackingService(clock=Clock())
    answers = (DnsAnswer("example.com", DnsRecordType.A, "192.0.2.99", 30),
               DnsAnswer("example.com", DnsRecordType.AAAA, "2001:db8::99", 30))
    service.observe(packet())
    result, = service.observe(packet(response=True, rcode=rcode, truncated=True, answers=answers))
    assert result.status is Status.COMPLETED and result.response_code == rcode
    assert result.truncated and result.answers == answers
    assert not hasattr(result, "payload") and not hasattr(result, "packet")


def test_mdns_is_separate_and_out_of_order_clock_is_nonnegative() -> None:
    clock = Clock()
    service = DnsTrackingService(clock=clock)
    assert service.observe(packet(kind=DnsTrafficKind.MDNS, server_port=5353)) == ()
    assert service.pending_count == 0
    service.observe(packet())
    clock.value = 2
    service.observe(packet(kind=DnsTrafficKind.MDNS, response=True, server_port=5353))
    clock.value = 1  # defensive monotonic clamp
    result, = service.observe(packet(response=True))
    assert result.latency_seconds == 2


def test_bad_envelope_and_invalid_configuration_do_not_change_state() -> None:
    service = DnsTrackingService(clock=Clock())
    assert service.observe(object()) == ()  # type: ignore[arg-type]
    assert service.pending_count == 0
    with pytest.raises(ValueError):
        DnsTrackingService(max_pending=0)
    with pytest.raises(ValueError):
        DnsTrackingService(timeout_seconds=0)
    with pytest.raises(ValueError):
        replace(packet(), observed_at=datetime(2026, 9, 23))


def test_application_and_domain_have_no_framework_or_database_imports() -> None:
    root = Path(__file__).resolve().parents[3] / "src" / "netsentinel"
    for directory in (root / "domain", root / "application"):
        for path in directory.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
            names += [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module]
            assert not any(name.split(".")[0] in {"scapy", "sqlite3", "PyQt6"} for name in names)
