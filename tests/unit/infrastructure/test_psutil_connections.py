"""Unit tests for the psutil connection collector adapter."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
import socket
from typing import Any

import psutil
import pytest

from netsentinel.application.ports import (
    ConnectionCollectionPermissionDenied,
    ConnectionCollectionTransientError,
    ConnectionCollector,
)
from netsentinel.domain.connections import (
    ConnectionState,
    ProcessIdentity,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.infrastructure.psutil_connections import PsutilConnectionCollector


OBSERVED_AT = datetime(2026, 9, 18, 9, 30, tzinfo=UTC)


@dataclass(frozen=True)
class FakeConnection:
    family: Any
    type: Any
    laddr: Any
    raddr: Any
    status: Any
    pid: Any = None


def connection(
    *,
    family: Any = socket.AF_INET,
    socket_type: Any = socket.SOCK_STREAM,
    laddr: Any = ("192.0.2.10", 50_000),
    raddr: Any = ("203.0.113.20", 443),
    status: Any = "ESTABLISHED",
    pid: Any = 321,
) -> FakeConnection:
    return FakeConnection(family, socket_type, laddr, raddr, status, pid)


def collector_for(*records: object) -> PsutilConnectionCollector:
    return PsutilConnectionCollector(
        connections_provider=lambda *, kind: records,
        clock=lambda: OBSERVED_AT,
    )


def test_collector_satisfies_application_port() -> None:
    collector: ConnectionCollector = collector_for()

    assert collector.collect() == ()


def test_collects_ipv4_tcp_established_connection_with_minimal_pid_identity() -> None:
    snapshot = collector_for(connection()).collect()[0]

    assert snapshot.protocol is TransportProtocol.TCP
    assert snapshot.local_endpoint.address == "192.0.2.10"
    assert snapshot.local_endpoint.port == 50_000
    assert snapshot.remote_endpoint is not None
    assert snapshot.remote_endpoint.address == "203.0.113.20"
    assert snapshot.remote_endpoint.port == 443
    assert snapshot.state is ConnectionState.ESTABLISHED
    assert snapshot.process.status is ProcessInfoStatus.UNAVAILABLE
    assert snapshot.process.identity == ProcessIdentity(pid=321)
    assert snapshot.process.name is None
    assert snapshot.observed_at == OBSERVED_AT


def test_collects_and_canonicalizes_ipv6_tcp_connection() -> None:
    snapshot = collector_for(
        connection(
            family=socket.AF_INET6,
            laddr=("2001:0db8:0:0:0:0:0:10", 50_001, 0, 0),
            raddr=("2001:0db8:0:0:0:0:0:20", 443, 0, 0),
        )
    ).collect()[0]

    assert snapshot.local_endpoint.address == "2001:db8::10"
    assert snapshot.local_endpoint.ip_version == 6
    assert snapshot.remote_endpoint is not None
    assert snapshot.remote_endpoint.address == "2001:db8::20"


def test_collects_listening_tcp_socket_without_remote_endpoint() -> None:
    snapshot = collector_for(
        connection(laddr=("0.0.0.0", 8080), raddr=(), status="LISTEN", pid=4)
    ).collect()[0]

    assert snapshot.state is ConnectionState.LISTEN
    assert snapshot.remote_endpoint is None
    assert snapshot.process.identity == ProcessIdentity(pid=4)


def test_collects_udp_local_only_socket() -> None:
    snapshot = collector_for(
        connection(
            socket_type=socket.SOCK_DGRAM,
            laddr=("0.0.0.0", 5353),
            raddr=(),
            status="NONE",
        )
    ).collect()[0]

    assert snapshot.protocol is TransportProtocol.UDP
    assert snapshot.state is ConnectionState.NONE
    assert snapshot.remote_endpoint is None


def test_collects_udp_socket_with_remote_endpoint() -> None:
    snapshot = collector_for(
        connection(
            socket_type=socket.SOCK_DGRAM,
            laddr=("192.0.2.10", 53_000),
            raddr=("198.51.100.53", 53),
            status="ESTABLISHED",
        )
    ).collect()[0]

    assert snapshot.protocol is TransportProtocol.UDP
    assert snapshot.state is ConnectionState.NONE
    assert snapshot.remote_endpoint is not None
    assert snapshot.remote_endpoint.address == "198.51.100.53"
    assert snapshot.remote_endpoint.port == 53


def test_connection_without_pid_has_explicitly_unavailable_process() -> None:
    snapshot = collector_for(connection(pid=None)).collect()[0]

    assert snapshot.process.status is ProcessInfoStatus.UNAVAILABLE
    assert snapshot.process.identity is None
    assert snapshot.process.name is None


@pytest.mark.parametrize(
    ("psutil_state", "domain_state"),
    [
        ("ESTABLISHED", ConnectionState.ESTABLISHED),
        ("SYN_SENT", ConnectionState.SYN_SENT),
        ("SYN_RECV", ConnectionState.SYN_RECEIVED),
        ("FIN_WAIT1", ConnectionState.FIN_WAIT_1),
        ("FIN_WAIT2", ConnectionState.FIN_WAIT_2),
        ("CLOSE_WAIT", ConnectionState.CLOSE_WAIT),
        ("CLOSING", ConnectionState.CLOSING),
        ("LAST_ACK", ConnectionState.LAST_ACK),
        ("TIME_WAIT", ConnectionState.TIME_WAIT),
        ("CLOSE", ConnectionState.CLOSED),
        ("LISTEN", ConnectionState.LISTEN),
    ],
)
def test_maps_psutil_tcp_states_to_portable_domain_states(
    psutil_state: str,
    domain_state: ConnectionState,
) -> None:
    remote = () if domain_state is ConnectionState.LISTEN else ("203.0.113.20", 443)

    snapshot = collector_for(
        connection(status=psutil_state, raddr=remote)
    ).collect()[0]

    assert snapshot.state is domain_state


@pytest.mark.parametrize("unknown_state", ["DELETE_TCB", "FUTURE_STATE", None, 7])
def test_unknown_tcp_state_is_preserved_as_domain_unknown(
    unknown_state: object,
) -> None:
    snapshot = collector_for(connection(status=unknown_state)).collect()[0]

    assert snapshot.state is ConnectionState.UNKNOWN


@pytest.mark.parametrize(
    "malformed",
    [
        object(),
        connection(laddr=()),
        connection(laddr=("not-an-ip", 80)),
        connection(laddr=("192.0.2.10", 70_000)),
        connection(family=-1),
        connection(socket_type=socket.SOCK_RAW),
        connection(
            family=socket.AF_INET,
            raddr=("2001:db8::20", 443),
        ),
        connection(pid=-1),
        connection(status="LISTEN", raddr=("203.0.113.20", 443)),
    ],
)
def test_malformed_or_unsupported_record_is_skipped(malformed: object) -> None:
    assert collector_for(malformed).collect() == ()


def test_one_bad_record_does_not_prevent_other_records_from_being_collected() -> None:
    valid = connection(pid=123)
    snapshots = collector_for(
        connection(laddr=("invalid", 80)),
        valid,
        connection(family=-1),
    ).collect()

    assert len(snapshots) == 1
    assert snapshots[0].process.identity == ProcessIdentity(pid=123)


class RacyConnection:
    @property
    def family(self) -> Any:
        raise psutil.NoSuchProcess(pid=999)


def test_process_race_in_one_record_is_skipped() -> None:
    snapshots = collector_for(RacyConnection(), connection(pid=123)).collect()

    assert len(snapshots) == 1
    assert snapshots[0].process.identity == ProcessIdentity(pid=123)


def test_collect_requests_combined_inet_table() -> None:
    requested_kinds: list[str] = []

    def provider(*, kind: str) -> tuple[FakeConnection, ...]:
        requested_kinds.append(kind)
        return ()

    PsutilConnectionCollector(
        connections_provider=provider,
        clock=lambda: OBSERVED_AT,
    ).collect()

    assert requested_kinds == ["inet"]


def test_all_rows_in_a_pass_share_one_utc_timestamp() -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return datetime(
            2026,
            9,
            18,
            12,
            30,
            tzinfo=timezone(timedelta(hours=3)),
        )

    snapshots = PsutilConnectionCollector(
        connections_provider=lambda *, kind: (
            connection(laddr=("192.0.2.11", 5001)),
            connection(laddr=("192.0.2.10", 5000)),
        ),
        clock=clock,
    ).collect()

    assert calls == 1
    assert {item.observed_at for item in snapshots} == {OBSERVED_AT}
    assert all(item.observed_at.tzinfo is UTC for item in snapshots)


def test_output_order_is_deterministic_independent_of_provider_order() -> None:
    first = connection(laddr=("192.0.2.20", 5000), pid=20)
    second = connection(laddr=("192.0.2.10", 5000), pid=10)

    forward = collector_for(first, second).collect()
    reverse = collector_for(second, first).collect()

    assert forward == reverse
    assert [item.local_endpoint.address for item in forward] == [
        "192.0.2.10",
        "192.0.2.20",
    ]


def test_access_denied_for_whole_collection_is_typed_permission_loss() -> None:
    def denied(*, kind: str) -> tuple[object, ...]:
        raise psutil.AccessDenied(pid=None, name=None)

    collector = PsutilConnectionCollector(connections_provider=denied)

    with pytest.raises(ConnectionCollectionPermissionDenied) as raised:
        collector.collect()

    assert isinstance(raised.value.__cause__, psutil.AccessDenied)


def test_native_permission_error_is_typed_permission_loss() -> None:
    def denied(*, kind: str) -> tuple[object, ...]:
        raise PermissionError("denied")

    with pytest.raises(ConnectionCollectionPermissionDenied):
        PsutilConnectionCollector(connections_provider=denied).collect()


@pytest.mark.parametrize(
    "error",
    [
        psutil.NoSuchProcess(pid=999),
        psutil.ZombieProcess(pid=999),
        OSError("connection table changed"),
    ],
)
def test_expected_collection_races_are_typed_transient_errors(
    error: BaseException,
) -> None:
    def failing(*, kind: str) -> tuple[object, ...]:
        raise error

    collector = PsutilConnectionCollector(connections_provider=failing)

    with pytest.raises(ConnectionCollectionTransientError) as raised:
        collector.collect()

    assert raised.value.__cause__ is error
