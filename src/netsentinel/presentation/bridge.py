"""Thread-safe handoff from application events to the Qt main thread.

The dispatcher invokes subscribers synchronously on the publishing thread.  A
``QtEngineBridge`` subscriber therefore performs only a bounded queue append
and emits one coalesced queued signal.  Queue draining and every public signal
emission happen in the bridge object's Qt thread (the GUI thread in the
application composition root).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import RLock
from typing import Protocol, cast
from weakref import ReferenceType, finalize, ref

from PyQt6.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal, pyqtSlot

from netsentinel.application.events import EventDispatcher, Subscription
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionUpdated,
)
from netsentinel.shared.diagnostics import EngineHealthSnapshot


class EngineEventSource(Protocol):
    """Narrow, portable engine surface consumed by the presentation bridge."""

    @property
    def dispatcher(self) -> EventDispatcher: ...

    def health_snapshot(self) -> EngineHealthSnapshot: ...


@dataclass(frozen=True, slots=True)
class ConnectionEventBatch:
    """Immutable, ordered events drained during one Qt event-loop turn."""

    events: tuple[ConnectionLifecycleEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.events, tuple):
            raise TypeError("events must be a tuple")
        if not all(
            isinstance(event, (ConnectionOpened, ConnectionUpdated, ConnectionClosed))
            for event in self.events
        ):
            raise TypeError("events must contain connection lifecycle events")


@dataclass(frozen=True, slots=True)
class BridgeHealthSnapshot:
    """Existing engine health plus bounded bridge transport diagnostics."""

    engine: EngineHealthSnapshot
    queued_events: int
    dropped_events: int
    queue_capacity: int

    def __post_init__(self) -> None:
        if not isinstance(self.engine, EngineHealthSnapshot):
            raise TypeError("engine must be an EngineHealthSnapshot")
        if self.queued_events < 0:
            raise ValueError("queued_events must not be negative")
        if self.dropped_events < 0:
            raise ValueError("dropped_events must not be negative")
        if self.queue_capacity <= 0:
            raise ValueError("queue_capacity must be greater than zero")
        if self.queued_events > self.queue_capacity:
            raise ValueError("queued_events cannot exceed queue_capacity")

    @property
    def overflowed(self) -> bool:
        """Return whether any event was dropped during this attachment lifetime."""

        return self.dropped_events > 0


class _BridgeState:
    """Non-QObject state shared with dispatcher callbacks.

    Dispatcher callbacks retain this state, not the bridge.  This prevents the
    dispatcher from keeping a deleted QObject alive and lets the QObject's
    ``destroyed`` signal detach subscriptions without touching a deleted Qt
    wrapper.
    """

    def __init__(self, source: EngineEventSource, queue_capacity: int) -> None:
        self.source = source
        self.queue_capacity = queue_capacity
        self.lock = RLock()
        self.queue: deque[ConnectionLifecycleEvent] = deque()
        self.subscriptions: list[Subscription[object]] = []
        self.active = False
        self.drain_scheduled = False
        self.generation = 0
        self.dropped_events = 0

    def attach(self, bridge_reference: ReferenceType[QtEngineBridge]) -> int | None:
        """Subscribe exactly once and return the new attachment generation."""

        with self.lock:
            if self.active:
                return None

            self.active = True
            self.drain_scheduled = False
            self.queue.clear()
            self.dropped_events = 0
            self.generation += 1
            generation = self.generation

            def enqueue(event: object) -> None:
                bridge = bridge_reference()
                if bridge is None:
                    self.detach()
                    return
                scheduled_generation = self.enqueue(
                    cast(ConnectionLifecycleEvent, event)
                )
                if scheduled_generation is None:
                    return
                try:
                    bridge._drain_requested.emit(scheduled_generation)
                except RuntimeError:
                    # The C++ QObject may already have been deleted while a
                    # dispatcher publish snapshot still contains this callback.
                    self.detach()

            created: list[Subscription[object]] = []
            try:
                for event_type in (
                    ConnectionOpened,
                    ConnectionUpdated,
                    ConnectionClosed,
                ):
                    subscription = self.source.dispatcher.subscribe(
                        event_type,
                        enqueue,
                    )
                    created.append(cast(Subscription[object], subscription))
            except BaseException:
                self.active = False
                self.generation += 1
                for subscription in created:
                    self.source.dispatcher.unsubscribe(subscription)
                raise

            self.subscriptions = created
            return generation

    def detach(self) -> bool:
        """Deactivate callbacks, clear pending work, and unsubscribe idempotently."""

        with self.lock:
            if not self.active and not self.subscriptions:
                return False
            self.active = False
            self.generation += 1
            self.queue.clear()
            self.drain_scheduled = False
            subscriptions = tuple(self.subscriptions)
            self.subscriptions.clear()

        for subscription in subscriptions:
            self.source.dispatcher.unsubscribe(subscription)
        return True

    def enqueue(self, event: ConnectionLifecycleEvent) -> int | None:
        """Append without blocking; newest events are dropped on overflow."""

        with self.lock:
            if not self.active:
                return None
            if len(self.queue) >= self.queue_capacity:
                self.dropped_events += 1
            else:
                self.queue.append(event)
            if self.drain_scheduled:
                return None
            self.drain_scheduled = True
            return self.generation

    def take_batch(
        self,
        generation: int,
        batch_size: int,
    ) -> tuple[tuple[ConnectionLifecycleEvent, ...], bool] | None:
        """Remove one ordered batch when the queued request is still current."""

        with self.lock:
            if not self.active or generation != self.generation:
                return None
            count = min(batch_size, len(self.queue))
            events = tuple(self.queue.popleft() for _ in range(count))
            has_more = bool(self.queue)
            self.drain_scheduled = has_more
            return events, has_more

    def is_current(self, generation: int) -> bool:
        with self.lock:
            return self.active and generation == self.generation

    def transport_snapshot(self) -> tuple[int, int]:
        with self.lock:
            return len(self.queue), self.dropped_events


class QtEngineBridge(QObject):
    """Translate engine lifecycle events into GUI-thread Qt signals.

    Public signal contracts carry only immutable domain/application or
    presentation values.  ``events_ready`` is the preferred batching surface;
    the three event-specific signals support consumers that need one lifecycle
    kind.  All four are emitted in the bridge's Qt thread.
    """

    connection_opened = pyqtSignal(ConnectionOpened)
    connection_updated = pyqtSignal(ConnectionUpdated)
    connection_closed = pyqtSignal(ConnectionClosed)
    events_ready = pyqtSignal(ConnectionEventBatch)
    health_changed = pyqtSignal(BridgeHealthSnapshot)

    _drain_requested = pyqtSignal(int)

    def __init__(
        self,
        source: EngineEventSource,
        *,
        queue_capacity: int = 1_024,
        batch_size: int = 128,
        health_poll_interval_ms: int = 250,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        for name, value in (
            ("queue_capacity", queue_capacity),
            ("batch_size", batch_size),
            ("health_poll_interval_ms", health_poll_interval_ms),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        if not hasattr(source, "dispatcher") or not callable(
            getattr(source, "health_snapshot", None)
        ):
            raise TypeError("source must expose dispatcher and health_snapshot()")

        self._state = _BridgeState(source, queue_capacity)
        self._batch_size = batch_size
        self._last_health: BridgeHealthSnapshot | None = None
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(health_poll_interval_ms)
        self._health_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._health_timer.timeout.connect(self._publish_health_if_changed)
        self._drain_requested.connect(
            self._drain,
            Qt.ConnectionType.QueuedConnection,
        )

        # The cleanup target has no strong reference to this QObject.  The Qt
        # destruction hook covers deleteLater(); finalize covers Python GC.
        state = self._state
        self.destroyed.connect(state.detach)
        self._finalizer = finalize(self, state.detach)

    @property
    def attached(self) -> bool:
        with self._state.lock:
            return self._state.active

    @property
    def dropped_events(self) -> int:
        return self._state.transport_snapshot()[1]

    def start(self) -> bool:
        """Attach to the dispatcher once and begin presentation health polling."""

        self._require_object_thread("start")
        generation = self._state.attach(ref(self))
        if generation is None:
            return False
        self._last_health = None
        self._health_timer.start()
        # A queued initial drain publishes health after control returns to Qt.
        self._drain_requested.emit(generation)
        return True

    def stop(self) -> bool:
        """Detach once; queued stale drains are generation-guarded no-ops."""

        self._require_object_thread("stop")
        detached = self._state.detach()
        self._health_timer.stop()
        self._last_health = None
        return detached

    attach = start
    detach = stop

    @pyqtSlot(int)
    def _drain(self, generation: int) -> None:
        """Drain and emit one bounded batch in the bridge's Qt thread."""

        result = self._state.take_batch(generation, self._batch_size)
        if result is None:
            return
        events, has_more = result

        if events:
            self.events_ready.emit(ConnectionEventBatch(events))
            for event in events:
                if not self._state.is_current(generation):
                    break
                if isinstance(event, ConnectionOpened):
                    self.connection_opened.emit(event)
                elif isinstance(event, ConnectionUpdated):
                    self.connection_updated.emit(event)
                else:
                    self.connection_closed.emit(event)

        self._publish_health_if_changed()
        if has_more and self._state.is_current(generation):
            # Queued even on the GUI thread so one burst cannot monopolize an
            # event-loop turn.  No worker or thread is created per event.
            self._drain_requested.emit(generation)

    @pyqtSlot()
    def _publish_health_if_changed(self) -> None:
        if not self.attached:
            return
        try:
            engine_health = self._state.source.health_snapshot()
        except Exception:
            # Health is observational; a source defect must not destabilize Qt
            # or reach the monitoring worker through the timer callback.
            return
        queued_events, dropped_events = self._state.transport_snapshot()
        health = BridgeHealthSnapshot(
            engine=engine_health,
            queued_events=queued_events,
            dropped_events=dropped_events,
            queue_capacity=self._state.queue_capacity,
        )
        if health != self._last_health:
            self._last_health = health
            self.health_changed.emit(health)

    def _require_object_thread(self, operation: str) -> None:
        if QThread.currentThread() is not self.thread():
            raise RuntimeError(f"{operation} must run in the bridge's Qt thread")


__all__ = (
    "BridgeHealthSnapshot",
    "ConnectionEventBatch",
    "EngineEventSource",
    "QtEngineBridge",
)
