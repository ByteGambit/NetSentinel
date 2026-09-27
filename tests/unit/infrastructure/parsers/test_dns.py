"""NS-030 bounded DNS parser and capture-boundary tests."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, Raw, raw
from scapy.layers.dns import dns_compress

from netsentinel.domain.dns import (
    DnsObservation,
    DnsRecordType,
    DnsTrafficKind,
    DnsTransport,
    canonical_dns_name,
)
from netsentinel.domain.observations import (
    LinkLayerProtocol,
    NetworkLayerProtocol,
    PacketObservation,
)
from netsentinel.infrastructure.parsers.dns import DnsPacketMalformed, parse_dns_packet
from netsentinel.infrastructure.scapy_capture import _packet_observation
from tests.fixtures.packets.dns import dns_ether, dns_query, dns_response


NOW = datetime(2026, 9, 23, 9, tzinfo=UTC)


def test_dns_fixtures_do_not_resolve_host_interfaces() -> None:
    with patch("scapy.layers.l2.resolve_iface", side_effect=AssertionError("host interface lookup")):
        packets = (
            dns_query(), dns_query(tcp=True), dns_query(mdns=True),
            dns_query(mdns=True, ipv6=True), dns_response(), dns_response(tcp=True),
            Ether(raw(dns_ether() / IP() / UDP(dport=53) / Raw(b"malformed"))),
        )
        assert all(packet.src == "02:00:00:00:00:01" for packet in packets)
        assert packets[2].dst == "01:00:5e:00:00:fb"
        assert packets[3].dst == "33:33:00:00:00:fb"


def metadata(packet: object, *, ipv6: bool = False) -> PacketObservation:
    size = len(packet)  # type: ignore[arg-type]
    return PacketObservation(
        "{WIFI}", 12, "a" * 64, NOW, size, size,
        LinkLayerProtocol.ETHERNET,
        NetworkLayerProtocol.IPV6 if ipv6 else NetworkLayerProtocol.IPV4,
    )


@pytest.mark.parametrize("tcp", [False, True])
def test_udp_and_tcp_query_and_response(tcp: bool) -> None:
    query_packet = dns_query(tcp=tcp)
    response_packet = dns_response(tcp=tcp)
    query = parse_dns_packet(query_packet, metadata(query_packet))
    response = parse_dns_packet(response_packet, metadata(response_packet))

    assert query is not None and response is not None
    assert query.transport is (DnsTransport.TCP if tcp else DnsTransport.UDP)
    assert query.transaction_id == response.transaction_id == 42
    assert query.is_response is False and response.is_response is True
    assert query.questions[0].name == response.questions[0].name == "example.com."
    assert query.source_ip == "192.0.2.20" and query.destination_ip == "198.51.100.53"
    assert response.source_port == 53 and response.destination_port == 53000
    assert [answer.record_type for answer in response.answers] == [
        DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME, DnsRecordType.PTR
    ]
    assert [answer.value for answer in response.answers] == [
        "192.0.2.99", "2001:db8::99", "example.com.", "host.example.com."
    ]
    assert "private payload" not in repr(response)
    assert not hasattr(response, "payload")
    with pytest.raises(FrozenInstanceError):
        query.transaction_id = 99  # type: ignore[misc]


def test_mdns_ipv6_is_separate_and_network_scope_is_in_envelope() -> None:
    packet = dns_query(mdns=True, ipv6=True)
    observation = _packet_observation(packet, SimpleNamespace(
        interface_id="{WIFI}", interface_index=12, fingerprint="b" * 64
    ), NOW)

    assert observation.dns is not None
    assert observation.dns.traffic_kind is DnsTrafficKind.MDNS
    assert observation.dns.destination_ip == "ff02::fb"
    assert observation.network_fingerprint == "b" * 64
    assert observation.observed_at == NOW
    assert observation.arp is None
    assert not hasattr(observation, "packet")
    assert not hasattr(observation, "payload")


def test_truncation_flag_is_preserved_without_inventing_missing_answers() -> None:
    packet = dns_response(truncated=True)
    parsed = parse_dns_packet(packet, metadata(packet))
    assert parsed is not None and parsed.truncated is True
    assert len(parsed.answers) == 4


def test_compressed_question_name_is_decoded_safely() -> None:
    # Second answer owner uses the 0x0c compression pointer to the question.
    packet = Ether(raw(dns_compress(dns_response())))
    assert b"\xc0\x0c" in raw(packet)
    parsed = parse_dns_packet(packet, metadata(packet))
    assert parsed is not None
    assert parsed.answers[0].name == "example.com."


def test_malformed_compression_and_incomplete_message_are_isolated() -> None:
    bad_wire = b"\x00\x2a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
    packet = Ether(raw(dns_ether() / IP() / UDP(dport=53) / Raw(bad_wire)))
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(packet, metadata(packet))
    good = dns_query()
    assert parse_dns_packet(good, metadata(good)) is not None


def test_record_and_name_bounds_and_malformed_fields() -> None:
    many = dns_ether() / IP() / UDP(dport=53) / DNS(
        qd=DNSQR(qname="a.example"),
        an=[DNSRR(rrname="a.example", type="A", rdata="192.0.2.1") for _ in range(17)],
    )
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(many, metadata(many))
    for value in ("a" * 64 + ".example", "a" * 254, "a..example", "a\n.example", "é.example"):
        with pytest.raises((TypeError, ValueError)):
            canonical_dns_name(value)
    malformed = dns_ether() / IP() / UDP(dport=53) / DNS(qdcount=2, qd=DNSQR(qname="a.example"))
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(malformed, metadata(malformed))
    too_many_questions = dns_ether() / IP() / UDP(sport=53000, dport=53) / DNS(
        qd=[DNSQR(qname=f"q{index}.example") for index in range(5)]
    )
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(too_many_questions, metadata(too_many_questions))


def test_tcp_length_mismatch_is_dropped_and_next_packet_parses() -> None:
    bad = dns_query(tcp=True)
    dns_layer = bad.getlayer("DNS")
    dns_layer.original = b"\x00\x01" + dns_layer.original[2:]
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(bad, metadata(bad))
    good = dns_query(tcp=True)
    assert parse_dns_packet(good, metadata(good)) is not None


def test_parser_is_stateless_for_duplicate_out_of_order_and_context_switch() -> None:
    packet = dns_query()
    first = _packet_observation(packet, SimpleNamespace(
        interface_id="{WIFI}", interface_index=12, fingerprint="a" * 64
    ), NOW)
    duplicate = _packet_observation(packet, SimpleNamespace(
        interface_id="{WIFI}", interface_index=12, fingerprint="a" * 64
    ), NOW)
    older_other_network = _packet_observation(packet, SimpleNamespace(
        interface_id="{ETH}", interface_index=13, fingerprint="b" * 64
    ), datetime(2026, 9, 22, tzinfo=UTC))
    assert first == duplicate
    assert first.dns == older_other_network.dns
    assert first.network_fingerprint != older_other_network.network_fingerprint
    assert older_other_network.observed_at < first.observed_at


def test_non_dns_port_and_network_layer_mismatch() -> None:
    packet = dns_ether() / IP() / UDP(sport=12345, dport=1234) / DNS(qd=DNSQR(qname="example.com"))
    assert parse_dns_packet(packet, metadata(packet)) is None
    query = dns_query()
    with pytest.raises(DnsPacketMalformed):
        parse_dns_packet(query, metadata(query, ipv6=True))


def test_domain_rejects_unbounded_or_nonportable_metadata() -> None:
    packet = dns_query()
    parsed = parse_dns_packet(packet, metadata(packet))
    assert isinstance(parsed, DnsObservation)
    with pytest.raises(ValueError):
        DnsObservation(**{**{name: getattr(parsed, name) for name in parsed.__dataclass_fields__},
                          "questions": parsed.questions * 5})
    with pytest.raises(ValueError):
        PacketObservation("x", 1, "a" * 64, NOW, 1, 1,
                          LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.ARP, dns=parsed)
    with pytest.raises(ValueError):
        PacketObservation("x", 1, "a" * 64, datetime(2026, 9, 23), 1, 1,
                          LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.IPV4, dns=parsed)


def test_layer_boundaries_and_no_raw_packet_fields() -> None:
    root = Path(__file__).resolve().parents[4]
    for relative in ("src/netsentinel/domain", "src/netsentinel/application"):
        for source in (root / relative).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            imported = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                        for alias in node.names]
            imported += [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                         and node.module]
            assert not any(name == "scapy" or name.startswith("scapy.") for name in imported)
