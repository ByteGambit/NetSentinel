"""NS-062 offline, deterministic DNS association contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

import pytest

from netsentinel.application.services.dns_association import DnsAssociationService
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkAttributionMethod, NetworkScopeStatus,
)
from netsentinel.domain.dns import (
    DnsAnswer, DnsAssociationProvenance as Provenance,
    DnsAssociationStatus as Status, DnsQuestion, DnsRecordType as Type,
    DnsTransaction, DnsTransactionStatus as TxStatus, DnsTransport,
)


AT = datetime(2026, 10, 1, tzinfo=UTC)
NET_A = "a" * 64
NET_B = "b" * 64


class Clock:
    value = 0.0

    def __call__(self) -> float:
        return self.value


def scope(fingerprint: str = NET_A) -> ConnectionNetworkScope:
    return ConnectionNetworkScope(
        NetworkScopeStatus.RESOLVED, fingerprint, "adapter", 1,
        NetworkAttributionMethod.LOCAL_ADDRESS_MATCH,
    )


def answer(name: str, ip: str, ttl: int = 60) -> DnsAnswer:
    record_type = Type.AAAA if ":" in ip else Type.A
    return DnsAnswer(name, record_type, ip, ttl)


def transaction(
    name: str = "Example.COM", *, answers: tuple[DnsAnswer, ...] | None = None,
    network: str = NET_A, client: str = "192.0.2.20", at: datetime = AT,
    status: TxStatus = TxStatus.COMPLETED, rcode: int = 0,
    truncated: bool = False, qtype: int = Type.A,
) -> DnsTransaction:
    if answers is None:
        answers = (answer(name, "1.2.3.4"),)
    return DnsTransaction(
        status, network, DnsTransport.UDP, client, 53000, "198.51.100.53", 53,
        42, (DnsQuestion(name, qtype),),
        at - timedelta(milliseconds=10) if status is not TxStatus.UNMATCHED_RESPONSE else None,
        at if status in (TxStatus.COMPLETED, TxStatus.UNMATCHED_RESPONSE) else None,
        .01 if status is TxStatus.COMPLETED else None,
        rcode if status is TxStatus.COMPLETED else None,
        truncated, answers, 0,
    )


def lookup(service: DnsAssociationService, ip: str = "1.2.3.4", *,
           network: str = NET_A, client: str | None = "192.0.2.20"):
    return service.lookup_by_ip(ip, network_scope=scope(network), client_ip=client)


def test_a_aaaa_many_to_many_and_order() -> None:
    service = DnsAssociationService(clock=Clock())
    service.observe(transaction(answers=(answer("example.com", "1.2.3.4"),
                                         answer("example.com", "1.2.3.5"))))
    service.observe(transaction("b.example", answers=(answer("b.example", "1.2.3.4"),)))
    service.observe(transaction("a.example", answers=(answer("a.example", "1.2.3.4"),)))
    assert [candidate.domain for candidate in lookup(service).candidates] == [
        "a.example.", "b.example.", "example.com."]
    assert lookup(service).status is Status.AMBIGUOUS
    assert [item.ip for item in lookup(service, "1.2.3.5").candidates] == ["1.2.3.5"]
    service.observe(transaction(answers=(answer("example.com", "2001:0db8::1"),), qtype=Type.AAAA))
    assert lookup(service, "2001:db8::1").candidates[0].ip == "2001:db8::1"
    with pytest.raises(FrozenInstanceError):
        lookup(service).candidates[0].domain = "changed"  # type: ignore[misc]


def test_cname_direct_derived_broken_cycle_and_ptr() -> None:
    service = DnsAssociationService(clock=Clock())
    records = (DnsAnswer("example.com", Type.CNAME, "edge.example", 20),
               answer("edge.example", "1.2.3.4", 60))
    observed = service.observe(transaction(answers=records))
    assert {(item.domain, item.provenance) for item in observed} == {
        ("example.com.", Provenance.CNAME_DERIVED),
        ("edge.example.", Provenance.DIRECT_ANSWER),
    }
    derived = next(item for item in observed if item.provenance is Provenance.CNAME_DERIVED)
    assert derived.cname_chain == ("example.com.", "edge.example.")
    assert (derived.ttl, derived.answer_ttl) == (20, 60)
    assert lookup(service).status is Status.AMBIGUOUS
    assert service.observe(transaction("broken.example", answers=(
        DnsAnswer("broken.example", Type.CNAME, "missing.example", 10),))) == ()
    assert service.observe(transaction("cycle.example", answers=(
        DnsAnswer("cycle.example", Type.CNAME, "other.example", 10),
        DnsAnswer("other.example", Type.CNAME, "cycle.example", 10),))) == ()
    assert service.observe(transaction("4.3.2.1.in-addr.arpa", qtype=Type.PTR,
        answers=(DnsAnswer("4.3.2.1.in-addr.arpa", Type.PTR, "example.com", 50),))) == ()


def test_ttl_zero_cap_monotonic_and_refresh() -> None:
    clock = Clock()
    service = DnsAssociationService(clock=clock, max_retention_seconds=10)
    seen, = service.observe(transaction(answers=(answer("example.com", "1.2.3.4", 0),)))
    assert seen.ttl == 0 and seen.retention_seconds == 0
    assert lookup(service).candidates == ()
    seen, = service.observe(transaction(answers=(answer("example.com", "1.2.3.4", 0xFFFFFFFF),)))
    assert seen.ttl == 0xFFFFFFFF and seen.retention_seconds == 10
    assert service.stats().active == 1
    clock.value = 9
    assert lookup(service).status is Status.CORRELATED
    clock.value = 9.5
    service.observe(transaction(at=AT + timedelta(seconds=1),
                                answers=(answer("example.com", "1.2.3.4", 3),)))
    assert service.stats().active == 1
    assert lookup(service).candidates[0].ttl == 3
    clock.value = 12.4
    assert lookup(service).candidates
    clock.value = 12.5
    assert lookup(service).candidates == ()
    assert service.stats().expired == 1
    # Old wall timestamps do not rewind a refreshed association.
    service.observe(transaction(at=AT + timedelta(seconds=2)))
    service.observe(transaction(at=AT + timedelta(seconds=1), answers=(answer("example.com", "1.2.3.4", 1),)))
    assert lookup(service).candidates[0].observed_at == AT + timedelta(seconds=2)
    service.observe(transaction(at=AT + timedelta(seconds=3),
                                answers=(answer("example.com", "1.2.3.4", 0),)))
    assert lookup(service).candidates == ()


def test_network_client_unknown_and_negative_quality() -> None:
    service = DnsAssociationService(clock=Clock())
    service.observe(transaction("a.example"))
    service.observe(transaction("b.example", network=NET_B))
    service.observe(transaction("c.example", client="192.0.2.21"))
    assert [item.domain for item in lookup(service).candidates] == ["a.example."]
    assert [item.domain for item in lookup(service, network=NET_B).candidates] == ["b.example."]
    assert [item.domain for item in lookup(service, client="192.0.2.21").candidates] == ["c.example."]
    assert service.lookup_by_ip("1.2.3.4", network_scope=ConnectionNetworkScope.unknown(),
                                client_ip="192.0.2.20").status is Status.UNKNOWN
    assert service.lookup_by_ip("1.2.3.4", network_scope=ConnectionNetworkScope.ambiguous(),
                                client_ip="192.0.2.20").candidates == ()
    assert lookup(service, client=None).candidates == ()
    for bad in (
        transaction("n.example", rcode=3), transaction("s.example", rcode=2),
        transaction("r.example", rcode=5), transaction("empty.example", answers=()),
        transaction("truncated.example", truncated=True),
        transaction("orphan.example", status=TxStatus.UNMATCHED_RESPONSE),
    ):
        assert service.observe(bad) == ()
    assert service.stats().active == 3


def test_capacity_eviction_and_no_process_or_persistence_fields() -> None:
    clock = Clock()
    service = DnsAssociationService(clock=clock, max_associations=2, max_per_ip=2,
                                    max_per_domain=2)
    for name in ("a.example", "b.example", "c.example"):
        service.observe(transaction(name))
    assert [item.domain for item in lookup(service).candidates] == ["b.example.", "c.example."]
    assert lookup(service).capacity_loss and service.stats().evicted == 1
    assert service.stats().active == 2
    service.observe(transaction("c.example", at=AT + timedelta(seconds=1)))
    assert service.stats().active == 2
    service.observe(transaction("a.example", at=AT + timedelta(seconds=2)))
    assert [item.domain for item in lookup(service).candidates] == ["a.example.", "c.example."]
    candidate = lookup(service).candidates[0]
    assert not any(hasattr(candidate, field) for field in (
        "pid", "process", "process_name", "process_identity", "repository_id"))
    assert service.stats().evicted == 2


def test_per_domain_capacity_and_invalid_config() -> None:
    service = DnsAssociationService(clock=Clock(), max_associations=10,
                                    max_per_ip=2, max_per_domain=2)
    for ip in ("1.2.3.4", "1.2.3.5", "1.2.3.6"):
        service.observe(transaction(answers=(answer("example.com", ip),)))
    assert lookup(service, "1.2.3.4").candidates == ()
    assert service.stats().active == 2
    for name in ("a.example", "b.example", "c.example"):
        service.observe(transaction(name, answers=(answer(name, "1.2.3.7"),)))
    assert [item.domain for item in lookup(service, "1.2.3.7").candidates] == [
        "b.example.", "c.example."]
    for invalid in ({"max_associations": 0}, {"max_per_ip": 0},
                    {"max_per_domain": 0}, {"max_retention_seconds": 0},
                    {"max_cname_depth": 17}):
        with pytest.raises(ValueError):
            DnsAssociationService(**invalid)


def test_response_replay_and_older_timestamp_do_not_refresh() -> None:
    clock = Clock()
    service = DnsAssociationService(clock=clock)
    service.observe(transaction())
    clock.value = 1
    service.observe(transaction())
    assert service.stats().active == 1
    assert lookup(service).candidates[0].observed_at == AT
    service.observe(replace(transaction(), response_at=AT - timedelta(seconds=1)))
    assert lookup(service).candidates[0].observed_at == AT


def test_concurrent_observe_and_lookup_stay_bounded() -> None:
    service = DnsAssociationService(clock=Clock(), max_associations=16,
                                    max_per_ip=4, max_per_domain=4)

    def worker(index: int) -> None:
        name = f"d{index}.example"
        service.observe(transaction(name, answers=(answer(name, "1.2.3.4"),)))
        lookup(service)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(100)))
    assert service.stats().active <= 4
    assert len(lookup(service).candidates) <= 4
