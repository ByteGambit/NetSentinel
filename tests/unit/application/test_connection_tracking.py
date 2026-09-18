"""Unit tests for deterministic connection snapshot lifecycle tracking."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta, timezone

import pytest

from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services import connections as tracking_module
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionClosureReason,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)


T0 = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
T1 = T0 + timedelta(seconds=1)
T2 = T0 + timedelta(seconds=2)
T3 = T0 + timedelta(seconds=3)
PROCESS_STARTED = T0 - timedelta(hours=1)


def process(
    *,
    pid: int = 100,
    create_time: datetime | None = PROCESS_STARTED,
    name: str = "browser.exe",
    status: ProcessInfoStatus = ProcessInfoStatus.AVAILABLE,
) -> ProcessInfo:
    identity = ProcessIdentity(pid=pid, create_time=create_time)
    if status is ProcessInfoStatus.AVAILABLE:
        return ProcessInfo(status=status, identity=identity, name=name)
    return ProcessInfo(status=status, identity=identity)


def connection(
    *,
    observed_at: datetime = T0,
    protocol: TransportProtocol = TransportProtocol.TCP,
    local_address: str = "192.0.2.10",
    local_port: int = 50_000,
    remote_address: str | None = "203.0.113.20",
    remote_port: int = 443,
    state: ConnectionState | None = None,
    process_info: ProcessInfo | None = None,
) -> ConnectionSnapshot:
    if state is None:
        state = (
            ConnectionState.NONE
            if protocol is TransportProtocol.UDP
            else ConnectionState.ESTABLISHED
        )
    remote = (
        None
        if remote_address is None
        else Endpoint(remote_address, remote_port)
    )
    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local_address, local_port),
        remote_endpoint=remote,
        state=state,
        process=process_info if process_info is not None else process(),
        observed_at=observed_at,
    )


def test_empty_then_one_connection_emits_opened() -> None:
    tracker = ConnectionTrackingService(clock=lambda: T0)
    assert tracker.track((), observed_at=T0) == ()

    snapshot = connection(observed_at=T1)
    events = tracker.track((snapshot,))

    assert events == (ConnectionOpened(snapshot),)
    assert tracker.active_connections[0].first_seen == T1
    assert tracker.active_connections[0].last_seen == T1


def test_one_connection_then_empty_emits_not_observed_close() -> None:
    tracker = ConnectionTrackingService(clock=lambda: T1)
    snapshot = connection()
    tracker.track((snapshot,))

    events = tracker.track(())

    assert events == (
        ConnectionClosed(last_snapshot=snapshot, occurred_at=T1),
    )
    closed = events[0]
    assert isinstance(closed, ConnectionClosed)
    assert closed.reason is ConnectionClosureReason.NOT_OBSERVED
    assert tracker.active_connections == ()


def test_same_observable_snapshot_emits_no_event_but_advances_last_seen() -> None:
    tracker = ConnectionTrackingService()
    first = connection(observed_at=T0)
    second = connection(observed_at=T1)
    tracker.track((first,))

    assert tracker.track((second,)) == ()

    tracked = tracker.active_connections[0]
    assert tracked.first_seen == T0
    assert tracked.last_seen == T1
    assert tracked.snapshot is second


def test_tcp_state_change_emits_updated() -> None:
    tracker = ConnectionTrackingService()
    first = connection(observed_at=T0)
    second = connection(observed_at=T1, state=ConnectionState.CLOSE_WAIT)
    tracker.track((first,))

    assert tracker.track((second,)) == (
        ConnectionUpdated(previous=first, current=second),
    )


@pytest.mark.parametrize(
    "updated_process",
    [
        process(name="renamed.exe"),
        process(status=ProcessInfoStatus.ACCESS_DENIED),
    ],
)
def test_process_metadata_change_with_same_identity_emits_updated(
    updated_process: ProcessInfo,
) -> None:
    tracker = ConnectionTrackingService()
    first = connection(observed_at=T0)
    second = connection(observed_at=T1, process_info=updated_process)
    assert first.key == second.key
    tracker.track((first,))

    events = tracker.track((second,))

    assert events == (ConnectionUpdated(previous=first, current=second),)


def test_different_remote_endpoint_is_a_different_connection() -> None:
    tracker = ConnectionTrackingService()
    first = connection(observed_at=T0, remote_address="203.0.113.20")
    second = connection(observed_at=T1, remote_address="203.0.113.21")
    tracker.track((first,))

    events = tracker.track((second,))

    assert events == (
        ConnectionOpened(second),
        ConnectionClosed(last_snapshot=first, occurred_at=T1),
    )


@pytest.mark.parametrize(
    "snapshot",
    [
        connection(),
        connection(
            local_address="2001:db8::10",
            remote_address="2001:db8::20",
        ),
        connection(
            protocol=TransportProtocol.UDP,
            local_port=53_000,
            remote_address="198.51.100.53",
            remote_port=53,
        ),
        connection(
            local_address="0.0.0.0",
            local_port=8080,
            remote_address=None,
            state=ConnectionState.LISTEN,
        ),
    ],
    ids=["ipv4", "ipv6", "udp", "tcp-listener"],
)
def test_supported_connection_shapes_are_tracked(snapshot: ConnectionSnapshot) -> None:
    tracker = ConnectionTrackingService(clock=lambda: T1)

    assert tracker.track((snapshot,)) == (ConnectionOpened(snapshot),)
    events = tracker.track(())

    assert len(events) == 1
    assert isinstance(events[0], ConnectionClosed)
    assert events[0].reason is ConnectionClosureReason.NOT_OBSERVED


def test_same_pid_with_different_create_time_is_close_and_open() -> None:
    tracker = ConnectionTrackingService()
    old_process = process(create_time=PROCESS_STARTED)
    new_process = process(create_time=PROCESS_STARTED + timedelta(minutes=5))
    old = connection(observed_at=T0, process_info=old_process)
    new = connection(observed_at=T1, process_info=new_process)
    assert old.key != new.key
    tracker.track((old,))

    events = tracker.track((new,))

    assert events == (
        ConnectionOpened(new),
        ConnectionClosed(last_snapshot=old, occurred_at=T1),
    )


def test_input_order_does_not_change_output_order() -> None:
    first = connection(local_port=50_002)
    second = connection(local_port=50_000)
    third = connection(local_port=50_001)

    forward = ConnectionTrackingService().track((first, second, third))
    reverse = ConnectionTrackingService().track((third, second, first))

    assert forward == reverse
    assert [event.key.local_endpoint.port for event in forward] == [
        50_000,
        50_001,
        50_002,
    ]


def test_one_round_can_emit_opened_updated_and_closed_in_stable_groups() -> None:
    tracker = ConnectionTrackingService()
    closing = connection(local_port=50_002, observed_at=T0)
    updating = connection(local_port=50_003, observed_at=T0)
    unchanged = connection(local_port=50_004, observed_at=T0)
    tracker.track((closing, updating, unchanged))

    opened = connection(local_port=50_001, observed_at=T1)
    updated = connection(
        local_port=50_003,
        observed_at=T1,
        state=ConnectionState.CLOSE_WAIT,
    )
    same = connection(local_port=50_004, observed_at=T1)
    events = tracker.track((same, opened, updated))

    assert events == (
        ConnectionOpened(opened),
        ConnectionUpdated(previous=updating, current=updated),
        ConnectionClosed(last_snapshot=closing, occurred_at=T1),
    )


def test_exact_duplicate_records_collapse_to_one_event() -> None:
    snapshot = connection()

    events = ConnectionTrackingService().track((snapshot, snapshot, snapshot))

    assert events == (ConnectionOpened(snapshot),)


def test_conflicting_duplicates_are_resolved_independent_of_input_order() -> None:
    unavailable = connection(
        process_info=process(status=ProcessInfoStatus.ACCESS_DENIED),
        state=ConnectionState.CLOSE_WAIT,
    )
    available = connection(process_info=process(name="visible.exe"))
    assert unavailable.key == available.key

    forward = ConnectionTrackingService().track((unavailable, available))
    reverse = ConnectionTrackingService().track((available, unavailable))

    assert forward == reverse == (ConnectionOpened(available),)


def test_latest_timestamp_wins_for_duplicate_key() -> None:
    older = connection(observed_at=T0, state=ConnectionState.CLOSE_WAIT)
    newer = connection(observed_at=T1)

    events = ConnectionTrackingService().track((newer, older))

    assert events == (ConnectionOpened(newer),)


def test_observation_timestamps_are_preserved_for_all_event_types() -> None:
    tracker = ConnectionTrackingService()
    opening = connection(local_port=50_000, observed_at=T0)
    updating = connection(local_port=50_001, observed_at=T0)
    initial_events = tracker.track((updating, opening))
    assert [event.occurred_at for event in initial_events] == [T0, T0]

    updated = connection(
        local_port=50_001,
        observed_at=T1,
        state=ConnectionState.CLOSE_WAIT,
    )
    events = tracker.track((updated,), observed_at=T2)

    assert events == (
        ConnectionUpdated(previous=updating, current=updated),
        ConnectionClosed(last_snapshot=opening, occurred_at=T2),
    )
    assert events[0].occurred_at == T1
    assert events[1].occurred_at == T2


def test_empty_round_uses_fake_clock_for_close_timestamp() -> None:
    clock_values = iter((T1, T2))
    tracker = ConnectionTrackingService(clock=lambda: next(clock_values))
    snapshot = connection(observed_at=T0)
    tracker.track((snapshot,))

    first_close = tracker.track(())
    repeated_empty = tracker.track(())

    assert first_close[0].occurred_at == T1
    assert repeated_empty == ()


def test_tracker_state_progresses_across_multiple_rounds() -> None:
    tracker = ConnectionTrackingService()
    first = connection(observed_at=T0)
    same = connection(observed_at=T1)
    changed = connection(observed_at=T2, state=ConnectionState.CLOSE_WAIT)

    assert tracker.track((first,)) == (ConnectionOpened(first),)
    assert tracker.track((same,)) == ()
    assert tracker.track((changed,)) == (
        ConnectionUpdated(previous=same, current=changed),
    )
    assert tracker.track((), observed_at=T3) == (
        ConnectionClosed(last_snapshot=changed, occurred_at=T3),
    )
    assert tracker.track((), observed_at=T3) == ()


def test_time_regression_is_rejected_without_mutating_state() -> None:
    tracker = ConnectionTrackingService()
    latest = connection(observed_at=T1)
    tracker.track((latest,))

    with pytest.raises(ValueError, match="cannot precede"):
        tracker.track((connection(observed_at=T0),), observed_at=T1)

    assert tracker.active_connections[0].snapshot is latest


def test_non_snapshot_input_is_rejected() -> None:
    tracker = ConnectionTrackingService()

    with pytest.raises(TypeError, match="ConnectionSnapshot"):
        tracker.track((object(),))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 9, 18, 8, 0),
        datetime(
            2026,
            9,
            18,
            11,
            0,
            tzinfo=timezone(timedelta(hours=3)),
        ),
    ],
)
def test_round_timestamp_must_be_utc(invalid_time: datetime) -> None:
    tracker = ConnectionTrackingService()

    with pytest.raises(ValueError, match="UTC"):
        tracker.track((), observed_at=invalid_time)


def test_tracking_service_has_no_infrastructure_dependency() -> None:
    source = inspect.getsource(tracking_module)

    assert "psutil" not in source
    assert "netsentinel.infrastructure" not in source
