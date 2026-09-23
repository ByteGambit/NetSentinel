"""Defensive classic DNS metadata extraction inside the capture boundary.

Only Scapy's decoded header fields are read.  No wire bytes, payload object,
packet reference, or unsupported resource-record data leaves this module.
"""

from __future__ import annotations

from netsentinel.domain.dns import (
    MAX_DNS_ANSWERS,
    MAX_DNS_QUESTIONS,
    DnsAnswer,
    DnsObservation,
    DnsQuestion,
    DnsRecordType,
    DnsTrafficKind,
    DnsTransport,
)
from netsentinel.domain.observations import NetworkLayerProtocol, PacketObservation


class DnsPacketMalformed(ValueError):
    """A claimed DNS message violates the supported bounded contract."""


MAX_DNS_PACKET_LENGTH = 65535


def parse_dns_packet(packet: object, metadata: PacketObservation) -> DnsObservation | None:
    """Return portable DNS metadata, or None for traffic outside ports 53/5353."""
    if not isinstance(metadata, PacketObservation):
        raise TypeError("metadata must be a PacketObservation")
    try:
        udp = _layer(packet, "UDP")
        tcp = _layer(packet, "TCP") if udp is None else None
        transport_layer = udp if udp is not None else tcp
        if transport_layer is None:
            return None
        source_port = _number(transport_layer, "sport", 65535)
        destination_port = _number(transport_layer, "dport", 65535)
        ports = {source_port, destination_port}
        if 53 not in ports and 5353 not in ports:
            return None
        if metadata.captured_length > MAX_DNS_PACKET_LENGTH:
            raise DnsPacketMalformed("DNS packet exceeds the supported bound")

        dns = _layer(packet, "DNS")
        if dns is None:
            raise DnsPacketMalformed("DNS header is missing or incomplete")
        _validate_wire(dns, tcp is not None)
        ipv4 = _layer(packet, "IP")
        ipv6 = _layer(packet, "IPv6") if ipv4 is None else None
        ip = ipv4 if ipv4 is not None else ipv6
        expected_layer = (
            NetworkLayerProtocol.IPV4 if ipv4 is not None else NetworkLayerProtocol.IPV6
        )
        if ip is None or metadata.network_layer is not expected_layer:
            raise DnsPacketMalformed("DNS IP metadata is inconsistent")

        if _number(dns, "opcode", 15) != 0:
            raise DnsPacketMalformed("DNS opcode is unsupported")
        questions = _records(dns, "qd", "qdcount", MAX_DNS_QUESTIONS)
        answer_records = _records(dns, "an", "ancount", MAX_DNS_ANSWERS)
        # Bound ignored sections as well; a huge authority/additional section
        # must not hide unbounded decoded records in a portable observation.
        _records(dns, "ns", "nscount", MAX_DNS_ANSWERS)
        _records(dns, "ar", "arcount", MAX_DNS_ANSWERS)

        parsed_questions = tuple(
            DnsQuestion(_name(item, "qname"), _number(item, "qtype", 65535))
            for item in questions
        )
        parsed_answers = []
        for item in answer_records:
            record_code = _number(item, "type", 65535)
            try:
                record_type = DnsRecordType(record_code)
            except ValueError:
                continue
            parsed_answers.append(
                DnsAnswer(
                    name=_name(item, "rrname"),
                    record_type=record_type,
                    value=_name(item, "rdata") if record_type in (DnsRecordType.CNAME, DnsRecordType.PTR)
                    else _ip_text(item),
                    ttl=_number(item, "ttl", 0xFFFFFFFF),
                )
            )

        return DnsObservation(
            traffic_kind=DnsTrafficKind.MDNS if 5353 in ports else DnsTrafficKind.CLASSIC,
            transport=DnsTransport.UDP if udp is not None else DnsTransport.TCP,
            source_ip=_ip_field(ip, "src"),
            source_port=source_port,
            destination_ip=_ip_field(ip, "dst"),
            destination_port=destination_port,
            transaction_id=_number(dns, "id", 65535),
            is_response=bool(_flag(dns, "qr")),
            response_code=_number(dns, "rcode", 15),
            truncated=bool(_flag(dns, "tc")),
            questions=parsed_questions,
            answers=tuple(parsed_answers),
        )
    except DnsPacketMalformed:
        raise
    except Exception as error:
        raise DnsPacketMalformed("DNS packet fields are malformed") from error


def _layer(packet: object, name: str) -> object | None:
    haslayer = getattr(packet, "haslayer", None)
    getlayer = getattr(packet, "getlayer", None)
    if not callable(haslayer) or not callable(getlayer) or not haslayer(name):
        return None
    return getlayer(name)


def _number(layer: object, field: str, maximum: int) -> int:
    value = getattr(layer, field)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DnsPacketMalformed(f"DNS {field} is invalid")
    return value


def _flag(layer: object, field: str) -> int:
    value = _number(layer, field, 1)
    return value


def _records(layer: object, field: str, count_field: str, limit: int) -> tuple[object, ...]:
    records = getattr(layer, field)
    if records is None:
        records = ()
    if not isinstance(records, (list, tuple)) or len(records) > limit:
        raise DnsPacketMalformed(f"DNS {field} record count exceeds the bound")
    count = getattr(layer, count_field)
    if count is not None and _number(layer, count_field, limit) != len(records):
        raise DnsPacketMalformed(f"DNS {field} record count is inconsistent")
    return tuple(records)


def _name(layer: object, field: str) -> str:
    value = getattr(layer, field)
    if isinstance(value, bytes):
        if len(value) > 255:
            raise DnsPacketMalformed(f"DNS {field} is too long")
        return value.decode("ascii")
    if isinstance(value, str) and len(value) <= 255:
        return value
    raise DnsPacketMalformed(f"DNS {field} is invalid")


def _ip_text(layer: object) -> str:
    value = getattr(layer, "rdata")
    if not isinstance(value, str) or len(value) > 45:
        raise DnsPacketMalformed("DNS IP answer is invalid")
    return value


def _ip_field(layer: object, field: str) -> str:
    value = getattr(layer, field)
    if not isinstance(value, str) or len(value) > 45:
        raise DnsPacketMalformed(f"DNS {field} is invalid")
    return value


def _validate_wire(dns: object, tcp: bool) -> None:
    """Check captured DNS lengths and compression links before trusting decoded fields."""
    original = getattr(dns, "original", None)
    if not original:
        return  # In-memory Scapy fixtures have no captured wire image.
    if not isinstance(original, bytes) or len(original) > MAX_DNS_PACKET_LENGTH + 2:
        raise DnsPacketMalformed("DNS wire image is invalid")
    wire = original
    if tcp:
        if len(wire) < 2 or int.from_bytes(wire[:2], "big") != len(wire) - 2:
            raise DnsPacketMalformed("DNS TCP length is inconsistent")
        wire = wire[2:]
    if len(wire) < 12:
        raise DnsPacketMalformed("DNS header is incomplete")
    counts = [int.from_bytes(wire[offset:offset + 2], "big") for offset in (4, 6, 8, 10)]
    if counts[0] > MAX_DNS_QUESTIONS or any(count > MAX_DNS_ANSWERS for count in counts[1:]):
        raise DnsPacketMalformed("DNS record count exceeds the bound")
    offset = 12
    for _ in range(counts[0]):
        offset = _skip_name(wire, offset)
        if offset + 4 > len(wire):
            raise DnsPacketMalformed("DNS question is incomplete")
        offset += 4
    for _ in range(sum(counts[1:])):
        offset = _skip_name(wire, offset)
        if offset + 10 > len(wire):
            raise DnsPacketMalformed("DNS resource record is incomplete")
        record_type = int.from_bytes(wire[offset:offset + 2], "big")
        data_length = int.from_bytes(wire[offset + 8:offset + 10], "big")
        offset += 10
        end = offset + data_length
        if end > len(wire):
            raise DnsPacketMalformed("DNS resource data is incomplete")
        if record_type in (DnsRecordType.CNAME, DnsRecordType.PTR):
            if _skip_name(wire, offset) != end:
                raise DnsPacketMalformed("DNS name resource data is malformed")
        offset = end


def _skip_name(wire: bytes, start: int) -> int:
    cursor = start
    end: int | None = None
    seen: set[int] = set()
    name_length = 0
    for _ in range(128):
        if cursor >= len(wire) or cursor in seen:
            raise DnsPacketMalformed("DNS name compression is malformed")
        seen.add(cursor)
        length = wire[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(wire):
                raise DnsPacketMalformed("DNS compression pointer is incomplete")
            target = ((length & 0x3F) << 8) | wire[cursor + 1]
            if target >= cursor or target < 12:
                raise DnsPacketMalformed("DNS compression pointer is invalid")
            if end is None:
                end = cursor + 2
            cursor = target
            continue
        if length & 0xC0 or length > 63:
            raise DnsPacketMalformed("DNS label length is invalid")
        cursor += 1
        if length == 0:
            return end if end is not None else cursor
        if cursor + length > len(wire):
            raise DnsPacketMalformed("DNS label is incomplete")
        name_length += length + 1
        if name_length > 254:
            raise DnsPacketMalformed("DNS name exceeds the bound")
        cursor += length
    raise DnsPacketMalformed("DNS compression depth exceeds the bound")


__all__ = ("DnsPacketMalformed", "parse_dns_packet")
