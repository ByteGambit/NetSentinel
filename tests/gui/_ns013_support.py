"""Small deterministic fakes shared by the NS-013 GUI hardening tests."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Event, Thread

from netsentinel.application.events import EventDispatcher
from netsentinel.domain.connections import (
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    ProcessInfo,
    TransportProtocol,
)
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    CapabilityStatus,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
)


BASE_TIME = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def snapshot(
    index: int = 0,
    *,
    remote: bool = True,
    state: ConnectionState = ConnectionState.ESTABLISHED,
) -> ConnectionSnapshot:
    """Return a unique, portable connection without OS/network access."""

    local_port = 10_000 + (index % 50_000)
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", local_port),
        remote_endpoint=Endpoint("198.51.100.7", 443) if remote else None,
        state=state,
        process=ProcessInfo.unavailable(),
        observed_at=BASE_TIME,
    )


class FakeEngine:
    """Narrow bridge/lifecycle fake whose state is always inspectable."""

    def __init__(self, *, running: bool = False) -> None:
        self.dispatcher = EventDispatcher()
        self.running = running
        self.start_calls = 0
        self.stop_calls = 0
        self.connection_status = CapabilityStatus.AVAILABLE
        self.process_status = CapabilityStatus.AVAILABLE

    def start(self) -> bool:
        self.start_calls += 1
        if self.running:
            return False
        self.running = True
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.stop_calls += 1
        self.running = False
        return True

    def health_snapshot(self) -> EngineHealthSnapshot:
        return EngineHealthSnapshot(
            state=EngineState.RUNNING if self.running else EngineState.STOPPED,
            capabilities=CapabilitySnapshot(
                connection_monitoring=self.connection_status,
                process_metadata=self.process_status,
            ),
            counters=EngineCounters(),
            worker_alive=self.running,
        )


class BurstEngine(FakeEngine):
    """One bounded-lifecycle publisher used only for shutdown regression."""

    def __init__(self) -> None:
        super().__init__()
        self.cancel = Event()
        self.publisher_started = Event()
        self.worker: Thread | None = None

    def start(self) -> bool:
        started = super().start()
        if not started:
            return False
        self.cancel.clear()
        self.worker = Thread(
            target=self._publish_until_stopped,
            name="netsentinel-ns013-burst-worker",
        )
        self.worker.start()
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.stop_calls += 1
        self.cancel.set()
        worker = self.worker
        if worker is not None:
            worker.join(1.0 if timeout is None else timeout)
        self.running = False
        return worker is None or not worker.is_alive()

    def _publish_until_stopped(self) -> None:
        self.publisher_started.set()
        index = 0
        while not self.cancel.is_set():
            self.dispatcher.publish(ConnectionOpened(snapshot(index)))
            index += 1


__all__ = ("BASE_TIME", "BurstEngine", "FakeEngine", "snapshot")
