"""Bounded, immutable metadata for passively observed classic DNS messages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from ipaddress import ip_address
import re
from uuid import UUID


MAX_DNS_QUESTIONS = 4
MAX_DNS_ANSWERS = 16
MAX_DNS_NAME_LENGTH = 253


class DnsTransport(str, Enum):
    UDP = "udp"
    TCP = "tcp"


class DnsTrafficKind(str, Enum):
    CLASSIC = "classic"
    MDNS = "mdns"


class DnsRecordType(int, Enum):
    A = 1
    CNAME = 5
    PTR = 12
    AAAA = 28


class DnsTransactionStatus(str, Enum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    EVICTED = "evicted"
    UNMATCHED_RESPONSE = "unmatched_response"


def canonical_dns_name(value: str) -> str:
    """Keep a DNS name as bounded ASCII metadata, without expanding Unicode."""
    if not isinstance(value, str):
        raise TypeError("DNS name must be text")
    name = (value[:-1] if value.endswith(".") else value).lower()
    if name == "":
        if value == ".":
            return "."
        raise ValueError("DNS name is empty")
    if len(name) > MAX_DNS_NAME_LENGTH or not name.isascii():
        raise ValueError("DNS name exceeds the supported bound")
    labels = name.split(".")
    if any(
        not 1 <= len(label) <= 63 or re.fullmatch(r"[a-z0-9_-]+", label) is None
        for label in labels
    ):
        raise ValueError("DNS name contains an unsupported label")
    return name + "."


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    record_type: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonical_dns_name(self.name))
        if isinstance(self.record_type, bool) or not isinstance(self.record_type, int):
            raise TypeError("record_type must be an integer")
        if not 0 <= self.record_type <= 65535:
            raise ValueError("record_type is outside the DNS range")


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    name: str
    record_type: DnsRecordType
    value: str
    ttl: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonical_dns_name(self.name))
        if not isinstance(self.record_type, DnsRecordType):
            raise TypeError("record_type must be a supported DNS type")
        if self.record_type in (DnsRecordType.A, DnsRecordType.AAAA):
            if not isinstance(self.value, str) or len(self.value) > 45:
                raise ValueError("IP answer is invalid")
            parsed = ip_address(self.value)
            if parsed.version != (4 if self.record_type is DnsRecordType.A else 6):
                raise ValueError("IP answer family does not match record type")
            object.__setattr__(self, "value", str(parsed))
        else:
            object.__setattr__(self, "value", canonical_dns_name(self.value))
        if isinstance(self.ttl, bool) or not isinstance(self.ttl, int):
            raise TypeError("ttl must be an integer")
        if not 0 <= self.ttl <= 0xFFFFFFFF:
            raise ValueError("ttl is outside the DNS range")


@dataclass(frozen=True, slots=True)
class DnsObservation:
    """One DNS message; correlation and persistence are separate later tasks."""

    traffic_kind: DnsTrafficKind
    transport: DnsTransport
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    transaction_id: int
    is_response: bool
    response_code: int
    truncated: bool
    questions: tuple[DnsQuestion, ...]
    answers: tuple[DnsAnswer, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.traffic_kind, DnsTrafficKind):
            raise TypeError("traffic_kind must be a DnsTrafficKind")
        if not isinstance(self.transport, DnsTransport):
            raise TypeError("transport must be a DnsTransport")
        for field in ("source_ip", "destination_ip"):
            value = getattr(self, field)
            if not isinstance(value, str) or len(value) > 45:
                raise ValueError(f"{field} is invalid")
            object.__setattr__(self, field, str(ip_address(value)))
        for field in ("source_port", "destination_port", "transaction_id", "response_code"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field} must be an integer")
        if not 0 <= self.source_port <= 65535 or not 0 <= self.destination_port <= 65535:
            raise ValueError("DNS port is outside the transport range")
        if not 0 <= self.transaction_id <= 65535 or not 0 <= self.response_code <= 15:
            raise ValueError("DNS header field is outside its range")
        if not isinstance(self.is_response, bool) or not isinstance(self.truncated, bool):
            raise TypeError("DNS flags must be boolean")
        if not isinstance(self.questions, tuple) or not 0 <= len(self.questions) <= MAX_DNS_QUESTIONS:
            raise ValueError("DNS questions exceed the supported bound")
        if not all(isinstance(item, DnsQuestion) for item in self.questions):
            raise TypeError("questions must contain DnsQuestion values")
        if not isinstance(self.answers, tuple) or not 0 <= len(self.answers) <= MAX_DNS_ANSWERS:
            raise ValueError("DNS answers exceed the supported bound")
        if not all(isinstance(item, DnsAnswer) for item in self.answers):
            raise TypeError("answers must contain DnsAnswer values")


@dataclass(frozen=True, slots=True)
class DnsTransaction:
    """One bounded correlation outcome, with no packet or payload reference."""

    status: DnsTransactionStatus
    network_fingerprint: str
    transport: DnsTransport
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    transaction_id: int
    questions: tuple[DnsQuestion, ...]
    query_at: datetime | None
    response_at: datetime | None
    latency_seconds: float | None
    response_code: int | None
    truncated: bool
    answers: tuple[DnsAnswer, ...]
    retry_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.status, DnsTransactionStatus):
            raise TypeError("status must be a DnsTransactionStatus")
        if not isinstance(self.transport, DnsTransport):
            raise TypeError("transport must be a DnsTransport")
        if len(self.network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.network_fingerprint):
            raise ValueError("network_fingerprint must be a SHA-256 hex digest")
        for field in ("client_ip", "server_ip"):
            value = getattr(self, field)
            if not isinstance(value, str) or len(value) > 45:
                raise ValueError(f"{field} is invalid")
            object.__setattr__(self, field, str(ip_address(value)))
        for field in ("client_port", "server_port", "transaction_id", "retry_count"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                raise ValueError(f"{field} is outside its supported range")
        minimum_questions = 0 if self.status is DnsTransactionStatus.UNMATCHED_RESPONSE else 1
        if not isinstance(self.questions, tuple) or not minimum_questions <= len(self.questions) <= MAX_DNS_QUESTIONS or not all(isinstance(q, DnsQuestion) for q in self.questions):
            raise ValueError("questions must be a bounded DnsQuestion tuple")
        if not isinstance(self.answers, tuple) or len(self.answers) > MAX_DNS_ANSWERS or not all(isinstance(a, DnsAnswer) for a in self.answers):
            raise ValueError("answers must be a bounded DnsAnswer tuple")
        for field in ("query_at", "response_at"):
            value = getattr(self, field)
            if value is not None:
                if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                    raise ValueError(f"{field} must be UTC-aware")
                object.__setattr__(self, field, value.astimezone(UTC))
        if self.status is DnsTransactionStatus.UNMATCHED_RESPONSE:
            if self.query_at is not None or self.response_at is None:
                raise ValueError("unmatched response timestamps are inconsistent")
        elif self.query_at is None:
            raise ValueError("query timestamp is required")
        if self.status is DnsTransactionStatus.COMPLETED and self.response_at is None:
            raise ValueError("completed transaction requires a response")
        if self.latency_seconds is not None and (self.latency_seconds < 0 or self.status is not DnsTransactionStatus.COMPLETED):
            raise ValueError("latency is only valid for completed transactions")
        if self.response_code is not None and not 0 <= self.response_code <= 15:
            raise ValueError("response_code is outside the DNS range")


@dataclass(frozen=True, slots=True)
class DnsHistoryRecord:
    """Stable persistence identity for one portable correlation outcome."""

    id: UUID
    transaction: DnsTransaction

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise TypeError("id must be a UUID")
        if not isinstance(self.transaction, DnsTransaction):
            raise TypeError("transaction must be a DnsTransaction")
