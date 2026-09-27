"""NS-007 integration and opt-in Windows smoke coverage for M1."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import os
import socket
import sys
from threading import Event, Lock, enumerate as enumerate_threads
from time import monotonic

import pytest

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.ports import (
    ConnectionCollectionPermissionDenied,
    ConnectionCollectionTransientError,
)
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.bootstrap import create_monitoring_engine
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
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
from netsentinel.infrastructure.psutil_connections import PsutilConnectionCollector
from netsentinel.infrastructure.psutil_processes import PsutilProcessMetadataResolver
from netsentinel.shared.diagnostics import CapabilityStatus, EngineState
from tests.fixtures.connections import LocalTcpConnection


T0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
PROCESS_STARTED = T0 - timedelta(hours=1)


def wait_until(predicate: Callable[[], bool], *, timeout: float = 2.0) -> bool:
    """Wait in bounded, interruptible steps instead of using fixed sleeps."""

    deadline = monotonic() + timeout
    wake = Event()
    while monotonic() < deadline:
        if predicate():
            return True
        wake.wait(0.005)
    return predicate()


def raw_snapshot(
    *,
    observed_at: datetime,
    state: ConnectionState = ConnectionState.ESTABLISHED,
) -> ConnectionSnapshot:
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("127.0.0.1", 51_000),
        remote_endpoint=Endpoint("127.0.0.1", 51_001),
        state=state,
        process=ProcessInfo(
            status=ProcessInfoStatus.UNAVAILABLE,
            identity=ProcessIdentity(321),
        ),
        observed_at=observed_at,
    )


class SequenceCollector:
    def __init__(self, rounds: Iterable[tuple[ConnectionSnapshot, ...]]) -> None:
        self._rounds = tuple(rounds)
        self._lock = Lock()
        self.calls = 0

    def collect(self) -> tuple[ConnectionSnapshot, ...]:
        with self._lock:
            index = min(self.calls, len(self._rounds) - 1)
            self.calls += 1
            return self._rounds[index]


class FakeProcessResolver:
    def resolve(self, pid: int) -> ProcessInfo:
        return ProcessInfo(
            status=ProcessInfoStatus.AVAILABLE,
            identity=ProcessIdentity(pid, PROCESS_STARTED),
            name="fixture.exe",
        )


@dataclass(frozen=True)
class FakeConnectionRecord:
    family: socket.AddressFamily
    type: socket.SocketKind
    laddr: tuple[str, int]
    raddr: tuple[str, int]
    status: str
    pid: int


class FakeProcess:
    def create_time(self) -> float:
        return PROCESS_STARTED.timestamp()

    def name(self) -> str:
        return "fixture.exe"


def test_bootstrap_composes_the_real_m1_dependencies_without_starting_them() -> None:
    engine = create_monitoring_engine(polling_interval=0.05)

    assert isinstance(engine, MonitoringEngine)
    assert isinstance(engine.dispatcher, EventDispatcher)
    assert isinstance(engine._collector, PsutilConnectionCollector)
    assert isinstance(engine._enricher, ProcessMetadataEnricher)
    assert isinstance(engine._enricher._resolver, PsutilProcessMetadataResolver)
    assert isinstance(engine._tracker, ConnectionTrackingService)
    assert engine.health.state is EngineState.STOPPED
    assert engine.health.worker_alive is False


def test_psutil_adapter_contract_flows_into_enrichment_and_tracking() -> None:
    record = FakeConnectionRecord(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 51_000),
        raddr=("127.0.0.1", 51_001),
        status="ESTABLISHED",
        pid=321,
    )
    collector = PsutilConnectionCollector(
        connections_provider=lambda **kwargs: (record,),
        clock=lambda: T0,
    )
    resolver = PsutilProcessMetadataResolver(
        process_factory=lambda pid: FakeProcess()
    )

    collected = collector.collect()
    enriched = ProcessMetadataEnricher(resolver).enrich(collected)
    events = ConnectionTrackingService(clock=lambda: T0).track(enriched)

    assert len(events) == 1
    assert isinstance(events[0], ConnectionOpened)
    snapshot = events[0].snapshot
    assert snapshot.protocol is TransportProtocol.TCP
    assert snapshot.local_endpoint == Endpoint("127.0.0.1", 51_000)
    assert snapshot.remote_endpoint == Endpoint("127.0.0.1", 51_001)
    assert snapshot.process == ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(321, PROCESS_STARTED),
        name="fixture.exe",
    )


def test_fake_pipeline_repeated_polling_dispatches_lifecycle_and_stops_cleanly() -> None:
    first = raw_snapshot(observed_at=T0)
    updated = raw_snapshot(
        observed_at=T0 + timedelta(seconds=1),
        state=ConnectionState.CLOSE_WAIT,
    )
    collector = SequenceCollector(((first,), (updated,), ()))
    dispatcher = EventDispatcher()
    received: list[ConnectionLifecycleEvent] = []
    closed = Event()

    dispatcher.subscribe(ConnectionOpened, received.append)
    dispatcher.subscribe(ConnectionUpdated, received.append)

    def on_closed(event: ConnectionClosed) -> None:
        received.append(event)
        closed.set()

    dispatcher.subscribe(ConnectionClosed, on_closed)
    thread_name = "netsentinel-ns007-integration-poller"
    engine = MonitoringEngine(
        collector=collector,
        enricher=ProcessMetadataEnricher(FakeProcessResolver()),
        tracker=ConnectionTrackingService(clock=lambda: T0 + timedelta(seconds=2)),
        dispatcher=dispatcher,
        polling_interval=0.01,
        shutdown_timeout=0.5,
        thread_name=thread_name,
    )

    assert engine.start() is True
    assert closed.wait(2.0)
    stop_started = monotonic()
    assert engine.stop() is True
    assert monotonic() - stop_started < 0.5

    assert collector.calls >= 3
    assert [type(event) for event in received[:3]] == [
        ConnectionOpened,
        ConnectionUpdated,
        ConnectionClosed,
    ]
    opened = received[0]
    assert isinstance(opened, ConnectionOpened)
    assert opened.snapshot.process.status is ProcessInfoStatus.AVAILABLE
    assert opened.snapshot.process.name == "fixture.exe"
    assert engine.health.state is EngineState.STOPPED
    assert engine.health.worker_alive is False
    assert not any(
        thread.name == thread_name and thread.is_alive()
        for thread in enumerate_threads()
    )


def test_permission_denial_is_degraded_without_breaking_shutdown() -> None:
    class DeniedCollector:
        def collect(self) -> tuple[ConnectionSnapshot, ...]:
            raise ConnectionCollectionPermissionDenied("permission denied")

    engine = MonitoringEngine(
        collector=DeniedCollector(),
        enricher=ProcessMetadataEnricher(FakeProcessResolver()),
        tracker=ConnectionTrackingService(),
        polling_interval=0.01,
        shutdown_timeout=0.5,
        thread_name="netsentinel-ns007-permission-poller",
    )

    engine.start()
    assert wait_until(lambda: engine.health.counters.failed_rounds >= 1)
    assert engine.health.capabilities.connection_monitoring is (
        CapabilityStatus.UNAVAILABLE
    )
    assert engine.health.worker_alive is True
    assert engine.stop() is True
    assert engine.health.worker_alive is False


def _matches_client_connection(
    snapshot: ConnectionSnapshot,
    connection: LocalTcpConnection,
) -> bool:
    return (
        snapshot.protocol is TransportProtocol.TCP
        and snapshot.local_endpoint == Endpoint(*connection.client_endpoint)
        and snapshot.remote_endpoint == Endpoint(*connection.listener_endpoint)
        and snapshot.state is ConnectionState.ESTABLISHED
    )


def _matches_listener(
    snapshot: ConnectionSnapshot,
    connection: LocalTcpConnection,
) -> bool:
    return (
        snapshot.protocol is TransportProtocol.TCP
        and snapshot.local_endpoint == Endpoint(*connection.listener_endpoint)
        and snapshot.remote_endpoint is None
        and snapshot.state is ConnectionState.LISTEN
    )


def _collect_visible_loopback_sockets(
    collector: PsutilConnectionCollector,
    connection: LocalTcpConnection,
    *,
    timeout: float,
) -> tuple[ConnectionSnapshot, ConnectionSnapshot]:
    found: tuple[ConnectionSnapshot, ConnectionSnapshot] | None = None

    def collect_once() -> bool:
        nonlocal found
        try:
            snapshots = collector.collect()
        except ConnectionCollectionPermissionDenied:
            pytest.skip(
                "Windows denied psutil system connection enumeration; "
                "administrator rights are intentionally not required"
            )
        except ConnectionCollectionTransientError:
            return False
        client = next(
            (item for item in snapshots if _matches_client_connection(item, connection)),
            None,
        )
        listener = next(
            (item for item in snapshots if _matches_listener(item, connection)),
            None,
        )
        if client is not None and listener is not None:
            found = client, listener
            return True
        return False

    assert wait_until(collect_once, timeout=timeout), (
        "real psutil adapter did not expose the controlled loopback listener "
        "and established connection within the bounded timeout"
    )
    assert found is not None
    return found


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only psutil smoke test")
def test_windows_live_loopback_connection_flows_through_real_engine(
    local_tcp_connection: LocalTcpConnection,
) -> None:
    """Exercise psutil -> enrichment -> tracking -> engine without internet/admin.

    psutil may restrict unrelated system rows for a normal user. The controlled
    sockets belong to this Python process, so endpoint/PID assertions remain
    strict; process name/create-time may still degrade when Windows denies an
    individual metadata field.
    """

    connection = local_tcp_connection
    assert connection.connected.is_set()
    assert connection.closed is False

    raw_client, raw_listener = _collect_visible_loopback_sockets(
        PsutilConnectionCollector(),
        connection,
        timeout=5.0,
    )
    assert raw_client.local_endpoint.port == connection.client_endpoint[1]
    assert raw_client.remote_endpoint is not None
    assert raw_client.remote_endpoint.port == connection.listener_endpoint[1]
    assert raw_listener.local_endpoint.port == connection.listener_endpoint[1]
    assert raw_client.process.identity == ProcessIdentity(os.getpid())
    assert raw_listener.process.identity == ProcessIdentity(os.getpid())

    engine = create_monitoring_engine(
        polling_interval=0.05,
        shutdown_timeout=1.0,
    )
    received: list[ConnectionOpened] = []
    observed = Event()
    received_lock = Lock()

    def on_opened(event: ConnectionOpened) -> None:
        if _matches_client_connection(event.snapshot, connection):
            with received_lock:
                received.append(event)
            observed.set()

    engine.dispatcher.subscribe(ConnectionOpened, on_opened)
    stop_result = False
    try:
        assert engine.start() is True
        assert observed.wait(5.0), (
            "MonitoringEngine did not emit OPENED for the controlled loopback "
            "connection within the bounded timeout"
        )
        assert wait_until(
            lambda: engine.health.counters.successful_rounds >= 2,
            timeout=5.0,
        )
    finally:
        stop_result = engine.stop(timeout=1.0)

    assert stop_result is True
    with received_lock:
        event = received[0]
    snapshot = event.snapshot
    assert snapshot.protocol is TransportProtocol.TCP
    assert snapshot.local_endpoint == Endpoint(*connection.client_endpoint)
    assert snapshot.remote_endpoint == Endpoint(*connection.listener_endpoint)
    assert snapshot.process.identity is not None
    assert snapshot.process.identity.pid == os.getpid()
    if snapshot.process.status is ProcessInfoStatus.AVAILABLE:
        assert snapshot.process.name
    else:
        assert snapshot.process.status in {
            ProcessInfoStatus.ACCESS_DENIED,
            ProcessInfoStatus.UNAVAILABLE,
        }
        assert snapshot.process.name is None
    assert engine.health.state is EngineState.STOPPED
    assert engine.health.worker_alive is False
    assert not any(
        thread.name == "netsentinel-connection-poller" and thread.is_alive()
        for thread in enumerate_threads()
    )
