"""Unit tests for connection domain value objects and events."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
    ConnectionKey,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    MAX_EXECUTABLE_PATH_LENGTH,
    MAX_PARENT_NAME_LENGTH,
    ParentProcessInfo,
    ParentProcessStatus,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TrackedConnection,
    TransportProtocol,
)


def test_parent_context_validation_and_partial_availability() -> None:
    observed = datetime(2026, 9, 18, 9, 0, tzinfo=UTC)
    parent = ParentProcessInfo(
        status=ParentProcessStatus.OBSERVED,
        observed_at=observed,
        parent_pid=7,
        identity=ProcessIdentity(7, observed - timedelta(hours=2)),
        name_status=ProcessInfoStatus.ACCESS_DENIED,
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=ProcessInfoStatus.AVAILABLE,
    )
    assert parent.name is None
    assert parent.name_status is ProcessInfoStatus.ACCESS_DENIED
    with pytest.raises((TypeError, ValueError)):
        ParentProcessInfo(ParentProcessStatus.OBSERVED, observed, parent_pid=-1)
    with pytest.raises(ValueError):
        ParentProcessInfo(ParentProcessStatus.OBSERVED, observed, parent_pid=7)
    with pytest.raises(ValueError):
        ParentProcessInfo(
            ParentProcessStatus.OBSERVED,
            observed,
            parent_pid=7,
            identity=ProcessIdentity(8, observed),
            pid_status=ProcessInfoStatus.AVAILABLE,
            create_time_status=ProcessInfoStatus.AVAILABLE,
        )
    with pytest.raises(ValueError):
        ParentProcessInfo(
            ParentProcessStatus.OBSERVED,
            observed,
            parent_pid=7,
            identity=ProcessIdentity(7, observed),
            name="x" * (MAX_PARENT_NAME_LENGTH + 1),
            pid_status=ProcessInfoStatus.AVAILABLE,
            create_time_status=ProcessInfoStatus.AVAILABLE,
            name_status=ProcessInfoStatus.AVAILABLE,
        )
    with pytest.raises(ValueError):
        ParentProcessInfo(ParentProcessStatus.ABSENT, observed.replace(tzinfo=None))


OBSERVED_AT = datetime(2026, 9, 18, 8, 30, tzinfo=UTC)
PROCESS_STARTED_AT = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


def available_process(
    *, pid: int = 100, create_time: datetime = PROCESS_STARTED_AT
) -> ProcessInfo:
    return ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(pid=pid, create_time=create_time),
        name="example.exe",
    )


def tcp_snapshot(
    *,
    observed_at: datetime = OBSERVED_AT,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    remote_endpoint: Endpoint | None = Endpoint("203.0.113.10", 443),
    process: ProcessInfo | None = None,
) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.20", 50_000),
        remote_endpoint=remote_endpoint,
        state=state,
        process=process if process is not None else available_process(),
        observed_at=observed_at,
    )


@pytest.mark.parametrize(
    ("raw_address", "canonical_address", "version"),
    [
        ("192.0.2.1", "192.0.2.1", 4),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1", 6),
    ],
)
def test_endpoint_normalizes_ipv4_and_ipv6(
    raw_address: str, canonical_address: str, version: int
) -> None:
    endpoint = Endpoint(raw_address, 443)

    assert endpoint.address == canonical_address
    assert endpoint.port == 443
    assert endpoint.ip_version == version


@pytest.mark.parametrize("port", [0, 65_535])
def test_endpoint_accepts_port_boundaries(port: int) -> None:
    assert Endpoint("127.0.0.1", port).port == port


@pytest.mark.parametrize(
    ("address", "port", "error_type"),
    [
        ("not-an-ip", 80, ValueError),
        ("127.0.0.1", -1, ValueError),
        ("127.0.0.1", 65_536, ValueError),
        ("127.0.0.1", True, TypeError),
        ("127.0.0.1", 80.5, TypeError),
    ],
)
def test_endpoint_rejects_invalid_values(
    address: str, port: object, error_type: type[Exception]
) -> None:
    with pytest.raises(error_type):
        Endpoint(address, port)  # type: ignore[arg-type]


def test_endpoint_is_immutable() -> None:
    endpoint = Endpoint("127.0.0.1", 80)

    with pytest.raises(FrozenInstanceError):
        endpoint.port = 443  # type: ignore[misc]


@pytest.mark.parametrize(
    ("enum_type", "invalid_value"),
    [
        (TransportProtocol, "icmp"),
        (ConnectionState, "connected"),
        (ProcessInfoStatus, "hidden"),
    ],
)
def test_enums_reject_unknown_values(
    enum_type: type[TransportProtocol]
    | type[ConnectionState]
    | type[ProcessInfoStatus],
    invalid_value: str,
) -> None:
    with pytest.raises(ValueError):
        enum_type(invalid_value)


def test_process_identity_equality_and_hash_include_create_time() -> None:
    first = ProcessIdentity(pid=42, create_time=PROCESS_STARTED_AT)
    same = ProcessIdentity(pid=42, create_time=PROCESS_STARTED_AT)
    reused_pid = ProcessIdentity(
        pid=42,
        create_time=PROCESS_STARTED_AT + timedelta(minutes=5),
    )

    assert first == same
    assert hash(first) == hash(same)
    assert first != reused_pid
    assert len({first, same, reused_pid}) == 2


def test_process_identity_can_represent_unknown_create_time() -> None:
    assert ProcessIdentity(pid=42).create_time is None


@pytest.mark.parametrize("pid", [-1, True, 3.14])
def test_process_identity_rejects_invalid_pid(pid: object) -> None:
    error_type = ValueError if pid == -1 else TypeError

    with pytest.raises(error_type):
        ProcessIdentity(pid=pid)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 9, 18, 8, 0),
        datetime(2026, 9, 18, 11, 0, tzinfo=timezone(timedelta(hours=3))),
    ],
)
def test_process_identity_requires_utc_create_time(
    invalid_time: datetime,
) -> None:
    with pytest.raises(ValueError, match="UTC"):
        ProcessIdentity(pid=42, create_time=invalid_time)


def test_process_info_explicitly_represents_unavailable_metadata() -> None:
    unavailable = ProcessInfo.unavailable()
    denied = ProcessInfo(
        status=ProcessInfoStatus.ACCESS_DENIED,
        identity=ProcessIdentity(pid=4),
    )

    assert unavailable.identity is None
    assert unavailable.name is None
    assert denied.identity == ProcessIdentity(pid=4)
    assert denied.name is None


def test_process_info_legacy_constructor_defaults_field_availability() -> None:
    process = available_process()

    assert process.name_status is ProcessInfoStatus.AVAILABLE
    assert process.create_time_status is ProcessInfoStatus.AVAILABLE
    assert process.executable_path is None
    assert process.executable_path_status is ProcessInfoStatus.UNAVAILABLE


def test_process_info_accepts_independent_path_denial() -> None:
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(42, PROCESS_STARTED_AT),
        name="visible.exe",
        executable_path_status=ProcessInfoStatus.ACCESS_DENIED,
    )

    assert process.identity == ProcessIdentity(42, PROCESS_STARTED_AT)
    assert process.name_status is ProcessInfoStatus.AVAILABLE
    assert process.create_time_status is ProcessInfoStatus.AVAILABLE
    assert process.executable_path_status is ProcessInfoStatus.ACCESS_DENIED


def test_executable_path_is_omitted_from_process_repr() -> None:
    process = ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(42),
        name="visible.exe",
        executable_path="C:\\Users\\private\\visible.exe",
    )

    assert "C:\\Users\\private" not in repr(process)


@pytest.mark.parametrize(
    "path", ["", " ", "x\x00y", "x" * (MAX_EXECUTABLE_PATH_LENGTH + 1)]
)
def test_process_info_rejects_invalid_executable_path(path: str) -> None:
    with pytest.raises(ValueError, match="executable_path"):
        ProcessInfo(
            status=ProcessInfoStatus.AVAILABLE,
            identity=ProcessIdentity(42),
            name="visible.exe",
            executable_path=path,
        )


def test_process_info_rejects_inconsistent_path_availability() -> None:
    with pytest.raises(ValueError, match="executable_path_status"):
        ProcessInfo(
            status=ProcessInfoStatus.AVAILABLE,
            identity=ProcessIdentity(42),
            name="visible.exe",
            executable_path="C:\\Apps\\visible.exe",
            executable_path_status=ProcessInfoStatus.ACCESS_DENIED,
        )


@pytest.mark.parametrize(
    "process_info",
    [
        ProcessInfoStatus.AVAILABLE,
        ProcessInfoStatus.ACCESS_DENIED,
        ProcessInfoStatus.NOT_FOUND,
    ],
)
def test_process_info_rejects_incomplete_status_combinations(
    process_info: ProcessInfoStatus,
) -> None:
    with pytest.raises(ValueError):
        ProcessInfo(status=process_info)


def test_connection_key_equality_and_hash_are_stable() -> None:
    process = ProcessIdentity(pid=100, create_time=PROCESS_STARTED_AT)
    first = ConnectionKey(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.20", 50_000),
        remote_endpoint=Endpoint("203.0.113.10", 443),
        process_identity=process,
    )
    same = ConnectionKey(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.20", 50_000),
        remote_endpoint=Endpoint("203.0.113.10", 443),
        process_identity=ProcessIdentity(
            pid=100,
            create_time=PROCESS_STARTED_AT,
        ),
    )

    assert first == same
    assert hash(first) == hash(same)
    assert {first: "connection"}[same] == "connection"


def test_connection_key_distinguishes_process_instances_after_pid_reuse() -> None:
    common_fields = {
        "protocol": TransportProtocol.TCP,
        "local_endpoint": Endpoint("192.0.2.20", 50_000),
        "remote_endpoint": Endpoint("203.0.113.10", 443),
    }
    old_process = ProcessIdentity(pid=100, create_time=PROCESS_STARTED_AT)
    new_process = ProcessIdentity(
        pid=100,
        create_time=PROCESS_STARTED_AT + timedelta(hours=1),
    )

    old_key = ConnectionKey(**common_fields, process_identity=old_process)
    new_key = ConnectionKey(**common_fields, process_identity=new_process)

    assert old_key != new_key


def test_connection_key_distinguishes_tcp_and_udp() -> None:
    common_fields = {
        "local_endpoint": Endpoint("192.0.2.20", 50_000),
        "remote_endpoint": Endpoint("203.0.113.10", 443),
        "process_identity": ProcessIdentity(
            pid=100,
            create_time=PROCESS_STARTED_AT,
        ),
    }

    tcp_key = ConnectionKey(protocol=TransportProtocol.TCP, **common_fields)
    udp_key = ConnectionKey(protocol=TransportProtocol.UDP, **common_fields)

    assert tcp_key != udp_key


def test_connection_key_rejects_mixed_ip_versions() -> None:
    with pytest.raises(ValueError, match="same IP version"):
        ConnectionKey(
            protocol=TransportProtocol.TCP,
            local_endpoint=Endpoint("192.0.2.20", 50_000),
            remote_endpoint=Endpoint("2001:db8::1", 443),
            process_identity=None,
        )


def test_udp_snapshot_can_have_no_remote_endpoint() -> None:
    snapshot = ConnectionSnapshot(
        protocol=TransportProtocol.UDP,
        local_endpoint=Endpoint("0.0.0.0", 53),
        remote_endpoint=None,
        state=ConnectionState.NONE,
        process=ProcessInfo.unavailable(),
        observed_at=OBSERVED_AT,
    )

    assert snapshot.remote_endpoint is None
    assert snapshot.key.remote_endpoint is None
    assert snapshot.key.process_identity is None


def test_connected_udp_snapshot_can_have_remote_endpoint() -> None:
    snapshot = ConnectionSnapshot(
        protocol=TransportProtocol.UDP,
        local_endpoint=Endpoint("2001:db8::10", 53_000),
        remote_endpoint=Endpoint("2001:4860:4860::8888", 53),
        state=ConnectionState.NONE,
        process=available_process(),
        observed_at=OBSERVED_AT,
    )

    assert snapshot.remote_endpoint is not None
    assert snapshot.remote_endpoint.ip_version == 6


def test_tcp_listening_snapshot_has_no_remote_endpoint() -> None:
    snapshot = tcp_snapshot(
        state=ConnectionState.LISTEN,
        remote_endpoint=None,
    )

    assert snapshot.state is ConnectionState.LISTEN
    assert snapshot.remote_endpoint is None


@pytest.mark.parametrize(
    ("protocol", "state"),
    [
        (TransportProtocol.UDP, ConnectionState.ESTABLISHED),
        (TransportProtocol.TCP, ConnectionState.NONE),
    ],
)
def test_snapshot_rejects_protocol_state_mismatch(
    protocol: TransportProtocol, state: ConnectionState
) -> None:
    with pytest.raises(ValueError):
        ConnectionSnapshot(
            protocol=protocol,
            local_endpoint=Endpoint("192.0.2.20", 50_000),
            remote_endpoint=Endpoint("203.0.113.10", 443),
            state=state,
            process=ProcessInfo.unavailable(),
            observed_at=OBSERVED_AT,
        )


def test_listening_snapshot_rejects_remote_endpoint() -> None:
    with pytest.raises(ValueError, match="listening"):
        tcp_snapshot(state=ConnectionState.LISTEN)


def test_snapshot_rejects_non_enum_protocol_and_state() -> None:
    with pytest.raises(TypeError, match="protocol"):
        ConnectionSnapshot(
            protocol="tcp",  # type: ignore[arg-type]
            local_endpoint=Endpoint("127.0.0.1", 80),
            remote_endpoint=None,
            state=ConnectionState.LISTEN,
            process=ProcessInfo.unavailable(),
            observed_at=OBSERVED_AT,
        )

    with pytest.raises(TypeError, match="state"):
        ConnectionSnapshot(
            protocol=TransportProtocol.TCP,
            local_endpoint=Endpoint("127.0.0.1", 80),
            remote_endpoint=None,
            state="listen",  # type: ignore[arg-type]
            process=ProcessInfo.unavailable(),
            observed_at=OBSERVED_AT,
        )


def test_snapshot_rejects_naive_observation_time() -> None:
    with pytest.raises(ValueError, match="UTC"):
        tcp_snapshot(observed_at=datetime(2026, 9, 18, 8, 30))


def test_snapshot_is_immutable() -> None:
    snapshot = tcp_snapshot()

    with pytest.raises(FrozenInstanceError):
        snapshot.state = ConnectionState.CLOSED  # type: ignore[misc]


def test_snapshot_fields_use_serialization_friendly_values() -> None:
    snapshot = tcp_snapshot()

    assert isinstance(snapshot.local_endpoint.address, str)
    assert isinstance(snapshot.protocol.value, str)
    assert isinstance(snapshot.state.value, str)
    assert snapshot.observed_at.tzinfo is UTC


def test_connection_lifecycle_events_expose_key_and_time() -> None:
    opened_snapshot = tcp_snapshot()
    updated_snapshot = tcp_snapshot(
        observed_at=OBSERVED_AT + timedelta(seconds=1),
        state=ConnectionState.CLOSE_WAIT,
    )
    opened = ConnectionOpened(snapshot=opened_snapshot)
    updated = ConnectionUpdated(
        previous=opened_snapshot,
        current=updated_snapshot,
    )
    closed = ConnectionClosed(
        last_snapshot=updated_snapshot,
        occurred_at=OBSERVED_AT + timedelta(seconds=2),
    )

    assert opened.key == updated.key == closed.key
    assert opened.occurred_at == OBSERVED_AT
    assert updated.occurred_at == OBSERVED_AT + timedelta(seconds=1)
    assert closed.occurred_at == OBSERVED_AT + timedelta(seconds=2)
    assert closed.reason is ConnectionClosureReason.NOT_OBSERVED


def test_updated_event_rejects_different_connection_keys() -> None:
    previous = tcp_snapshot()
    current = ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.20", 50_001),
        remote_endpoint=Endpoint("203.0.113.10", 443),
        state=ConnectionState.ESTABLISHED,
        process=available_process(),
        observed_at=OBSERVED_AT + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="same connection key"):
        ConnectionUpdated(previous=previous, current=current)


def test_updated_event_rejects_time_regression() -> None:
    newer = tcp_snapshot(observed_at=OBSERVED_AT + timedelta(seconds=1))
    older = tcp_snapshot(observed_at=OBSERVED_AT)

    with pytest.raises(ValueError, match="cannot precede"):
        ConnectionUpdated(previous=newer, current=older)


def test_closed_event_rejects_time_before_last_observation() -> None:
    with pytest.raises(ValueError, match="cannot precede"):
        ConnectionClosed(
            last_snapshot=tcp_snapshot(),
            occurred_at=OBSERVED_AT - timedelta(seconds=1),
        )


def test_lifecycle_events_are_immutable() -> None:
    event = ConnectionOpened(snapshot=tcp_snapshot())

    with pytest.raises(FrozenInstanceError):
        event.snapshot = tcp_snapshot()  # type: ignore[misc]


def test_tracked_connection_exposes_first_last_seen_and_current_metadata() -> None:
    snapshot = tcp_snapshot()
    tracked = TrackedConnection(
        first_seen=OBSERVED_AT - timedelta(seconds=1),
        last_seen=OBSERVED_AT,
        snapshot=snapshot,
    )

    assert tracked.key == snapshot.key
    assert tracked.state is snapshot.state
    assert tracked.process is snapshot.process


def test_tracked_connection_requires_snapshot_time_to_match_last_seen() -> None:
    with pytest.raises(ValueError, match="must equal last_seen"):
        TrackedConnection(
            first_seen=OBSERVED_AT,
            last_seen=OBSERVED_AT + timedelta(seconds=1),
            snapshot=tcp_snapshot(),
        )
