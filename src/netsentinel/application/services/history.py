"""Bounded, single-writer connection-history persistence pipeline."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from math import isfinite
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread, current_thread
from time import monotonic
from typing import Callable, cast

from netsentinel.application.events import EventDispatcher, Subscription
from netsentinel.application.ports import (
    ConnectionHistoryWriteSession,
    ConnectionHistoryWriteSessionFactory,
    HistoryRepositoryError,
)
from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionLifecycleEvent,
    ConnectionOpened,
    ConnectionUpdated,
)
from netsentinel.shared.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    DiagnosticComponent,
    DiagnosticSeverity,
    PersistenceCounters,
    PersistenceHealthSnapshot,
    PersistenceState,
)


DEFAULT_QUEUE_CAPACITY = 2_048
DEFAULT_BATCH_SIZE = 64
DEFAULT_BATCH_INTERVAL = 0.1
DEFAULT_RETRY_LIMIT = 2
DEFAULT_RETRY_BACKOFF = 0.05
DEFAULT_SHUTDOWN_TIMEOUT = 2.0

WallClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


class HistoryWriterLifecycleError(RuntimeError):
    """Raised when the writer tries to join itself."""


class ConnectionHistoryPersistence:
    """Attach one writer subscriber set to a lifecycle dispatcher."""

    def __init__(
        self,
        dispatcher: EventDispatcher,
        writer: ConnectionHistoryWriter,
    ) -> None:
        if not isinstance(dispatcher, EventDispatcher):
            raise TypeError("dispatcher must be an EventDispatcher")
        if not isinstance(writer, ConnectionHistoryWriter):
            raise TypeError("writer must be a ConnectionHistoryWriter")
        self._dispatcher = dispatcher
        self._writer = writer
        self._lock = RLock()
        self._subscriptions: list[Subscription[object]] = []

    def start(self) -> bool:
        """Start the writer, then attach each lifecycle type exactly once."""

        with self._lock:
            if self._subscriptions:
                return False
            if not self._writer.start():
                return False
            try:
                subscriptions = [
                    cast(
                        Subscription[object],
                        self._dispatcher.subscribe(
                            ConnectionOpened,
                            self._writer.submit,
                        ),
                    ),
                    cast(
                        Subscription[object],
                        self._dispatcher.subscribe(
                            ConnectionUpdated,
                            self._writer.submit,
                        ),
                    ),
                    cast(
                        Subscription[object],
                        self._dispatcher.subscribe(
                            ConnectionClosed,
                            self._writer.submit,
                        ),
                    ),
                ]
            except BaseException:
                self._writer.stop()
                raise
            self._subscriptions = subscriptions
            return True

    def stop(self, timeout: float | None = None) -> bool:
        """Detach producers first, then bounded-drain the writer."""

        with self._lock:
            subscriptions = tuple(self._subscriptions)
            self._subscriptions.clear()
        for subscription in subscriptions:
            self._dispatcher.unsubscribe(subscription)
        return self._writer.stop(timeout)

    def health_snapshot(self) -> PersistenceHealthSnapshot:
        return self._writer.health_snapshot()


class ConnectionHistoryWriter:
    """Persist lifecycle events on one worker without blocking producers.

    ``submit`` performs only validation, a short state lock, and
    ``put_nowait``.  Accepted events retain FIFO order.  The worker creates its
    repository session inside its own thread and reuses that session until it
    stops, allowing SQLite adapters to retain strict connection ownership.
    """

    def __init__(
        self,
        repository_factory: ConnectionHistoryWriteSessionFactory,
        *,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_interval: float = DEFAULT_BATCH_INTERVAL,
        retry_limit: int = DEFAULT_RETRY_LIMIT,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT,
        clock: WallClock | None = None,
        monotonic_clock: MonotonicClock | None = None,
        thread_name: str = "netsentinel-history-writer",
    ) -> None:
        if not callable(repository_factory):
            raise TypeError("repository_factory must be callable")
        _require_positive_int(queue_capacity, "queue_capacity")
        _require_positive_int(batch_size, "batch_size")
        if batch_size > queue_capacity:
            raise ValueError("batch_size cannot exceed queue_capacity")
        _require_non_negative_float(batch_interval, "batch_interval")
        if isinstance(retry_limit, bool) or not isinstance(retry_limit, int):
            raise TypeError("retry_limit must be an integer")
        if retry_limit < 0:
            raise ValueError("retry_limit must be zero or greater")
        _require_non_negative_float(retry_backoff, "retry_backoff")
        _require_non_negative_float(shutdown_timeout, "shutdown_timeout")
        if not isinstance(thread_name, str):
            raise TypeError("thread_name must be a string")
        if not thread_name.strip():
            raise ValueError("thread_name must not be empty")

        self._repository_factory = repository_factory
        self._queue: Queue[ConnectionLifecycleEvent] = Queue(maxsize=queue_capacity)
        self._batch_size = batch_size
        self._batch_interval = float(batch_interval)
        self._retry_limit = retry_limit
        self._retry_backoff = float(retry_backoff)
        self._shutdown_timeout = float(shutdown_timeout)
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock if monotonic_clock is not None else monotonic
        self._thread_name = thread_name

        self._lock = RLock()
        self._stop_requested = Event()
        self._abandon_requested = Event()
        self._worker: Thread | None = None
        self._accepting = False
        self._health = PersistenceHealthSnapshot(
            state=PersistenceState.STOPPED,
            queue_depth=0,
            queue_capacity=queue_capacity,
            counters=PersistenceCounters(),
        )

    @property
    def health(self) -> PersistenceHealthSnapshot:
        """Return an immutable, internally consistent concurrent snapshot."""

        with self._lock:
            worker_alive = self._worker is not None and self._worker.is_alive()
            return replace(
                self._health,
                queue_depth=self._queue.qsize(),
                worker_alive=worker_alive,
            )

    def health_snapshot(self) -> PersistenceHealthSnapshot:
        return self.health

    def start(self) -> bool:
        """Start exactly one worker; cleanly stopped instances are restartable."""

        with self._lock:
            self._reject_worker_lifecycle_control()
            if self._worker is not None and self._worker.is_alive():
                return False
            if not self._queue.empty():
                self._discard_queued_locked()
            self._stop_requested = Event()
            self._abandon_requested = Event()
            worker = Thread(
                target=self._run,
                name=self._thread_name,
                daemon=True,
            )
            self._worker = worker
            self._accepting = True
            self._health = replace(
                self._health,
                state=PersistenceState.RUNNING,
                queue_depth=0,
                worker_alive=True,
            )
            worker.start()
            return True

    def submit(self, event: ConnectionLifecycleEvent) -> bool:
        """Try to enqueue one event immediately; never wait for queue capacity."""

        if not isinstance(event, (ConnectionOpened, ConnectionUpdated, ConnectionClosed)):
            raise TypeError("event must be a connection lifecycle event")

        with self._lock:
            if not self._accepting or self._health.state is not PersistenceState.RUNNING:
                self._record_drop_locked(DiagnosticCode.PERSISTENCE_NOT_RUNNING)
                return False
            try:
                self._queue.put_nowait(event)
            except Full:
                self._record_drop_locked(DiagnosticCode.PERSISTENCE_OVERFLOW)
                return False

            self._health = replace(
                self._health,
                queue_depth=self._queue.qsize(),
                counters=replace(
                    self._health.counters,
                    accepted_events=self._health.counters.accepted_events + 1,
                ),
            )
            return True

    def stop(self, timeout: float | None = None) -> bool:
        """Close acceptance and drain accepted work within a bounded wait.

        If the timeout expires, queued (not in-flight) events are discarded and
        counted.  A repository call already in progress cannot be forcefully
        cancelled; the daemon worker exits after that call returns.
        """

        if timeout is not None:
            _require_non_negative_float(timeout, "timeout")

        with self._lock:
            self._reject_worker_lifecycle_control()
            self._accepting = False
            worker = self._worker
            if worker is None or not worker.is_alive():
                self._health = replace(
                    self._health,
                    state=PersistenceState.STOPPED,
                    queue_depth=self._queue.qsize(),
                    worker_alive=False,
                )
                return True
            self._stop_requested.set()
            self._health = replace(
                self._health,
                state=PersistenceState.STOPPING,
            )

        worker.join(self._shutdown_timeout if timeout is None else float(timeout))
        if not worker.is_alive():
            return True

        self._abandon_requested.set()
        with self._lock:
            self._discard_queued_locked()
            self._health = replace(
                self._health,
                state=PersistenceState.STOPPING,
                last_error=self._diagnostic(
                    DiagnosticCode.PERSISTENCE_SHUTDOWN_TIMEOUT,
                    DiagnosticSeverity.WARNING,
                ),
                worker_alive=True,
            )
        return False

    def _reject_worker_lifecycle_control(self) -> None:
        if self._worker is not None and current_thread() is self._worker:
            raise HistoryWriterLifecycleError(
                "history writer lifecycle cannot be controlled from its worker"
            )

    def _run(self) -> None:
        session_entered = False
        try:
            try:
                session_manager = self._repository_factory()
                with session_manager as repository:
                    session_entered = True
                    self._consume(repository)
            except Exception:
                self._record_worker_failure(
                    DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR
                    if session_entered
                    else DiagnosticCode.PERSISTENCE_START_FAILED
                )
        finally:
            with self._lock:
                self._accepting = False
                self._discard_queued_locked()
                self._health = replace(
                    self._health,
                    state=PersistenceState.STOPPED,
                    queue_depth=0,
                    worker_alive=False,
                )

    def _consume(self, repository: ConnectionHistoryWriteSession) -> None:
        while not self._abandon_requested.is_set():
            if self._stop_requested.is_set() and self._queue.empty():
                return

            try:
                first = self._queue.get(timeout=min(self._batch_interval, 0.05) or 0.01)
            except Empty:
                continue

            batch = [first]
            deadline = self._monotonic() + self._batch_interval
            while len(batch) < self._batch_size:
                try:
                    if self._stop_requested.is_set():
                        item = self._queue.get_nowait()
                    else:
                        remaining = deadline - self._monotonic()
                        if remaining <= 0:
                            break
                        item = self._queue.get(timeout=remaining)
                except Empty:
                    break
                batch.append(item)

            try:
                self._persist_batch_resilient(repository, tuple(batch))
            finally:
                for _ in batch:
                    self._queue.task_done()

    def _persist_batch_resilient(
        self,
        repository: ConnectionHistoryWriteSession,
        batch: tuple[ConnectionLifecycleEvent, ...],
    ) -> None:
        if self._attempt_batch(repository, batch):
            self._record_success(len(batch))
            return

        # A malformed or permanently failing event must not poison later FIFO
        # entries.  Replaying one-by-one is safe because repositories provide
        # idempotent lifecycle operations and the original batch rolled back.
        for event in batch:
            if self._abandon_requested.is_set():
                self._record_dropped_count(1)
                continue
            if self._attempt_batch(repository, (event,)):
                self._record_success(1)
            else:
                with self._lock:
                    self._health = replace(
                        self._health,
                        counters=replace(
                            self._health.counters,
                            failed_writes=self._health.counters.failed_writes + 1,
                        ),
                    )

    def _attempt_batch(
        self,
        repository: ConnectionHistoryWriteSession,
        batch: tuple[ConnectionLifecycleEvent, ...],
    ) -> bool:
        for attempt in range(self._retry_limit + 1):
            try:
                with repository.batch():
                    for event in batch:
                        self._persist_event(repository, event)
            except HistoryRepositoryError:
                code = DiagnosticCode.PERSISTENCE_WRITE_FAILED
            except Exception:
                self._record_error(DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR)
                return False
            else:
                return True

            self._record_error(code)
            if attempt >= self._retry_limit:
                return False
            with self._lock:
                self._health = replace(
                    self._health,
                    counters=replace(
                        self._health.counters,
                        retry_attempts=self._health.counters.retry_attempts + 1,
                    ),
                )
            self._stop_requested.wait(self._retry_backoff * (attempt + 1))
        return False

    @staticmethod
    def _persist_event(
        repository: ConnectionHistoryWriteSession,
        event: ConnectionLifecycleEvent,
    ) -> None:
        if isinstance(event, ConnectionOpened):
            repository.record_opened(event)
        elif isinstance(event, ConnectionUpdated):
            repository.record_updated(event)
        elif isinstance(event, ConnectionClosed):
            repository.record_closed(event)
        else:  # pragma: no cover - submit validates this boundary
            raise TypeError("unsupported connection lifecycle event")

    def _record_success(self, count: int) -> None:
        now = self._utc_now()
        with self._lock:
            self._health = replace(
                self._health,
                queue_depth=self._queue.qsize(),
                counters=replace(
                    self._health.counters,
                    persisted_events=self._health.counters.persisted_events + count,
                    batches=self._health.counters.batches + 1,
                ),
                last_successful_write_at=now,
            )

    def _record_error(self, code: DiagnosticCode) -> None:
        with self._lock:
            self._health = replace(
                self._health,
                last_error=self._diagnostic(code, DiagnosticSeverity.ERROR),
            )

    def _record_worker_failure(self, code: DiagnosticCode) -> None:
        self._record_error(code)

    def _record_drop_locked(self, code: DiagnosticCode) -> None:
        self._health = replace(
            self._health,
            queue_depth=self._queue.qsize(),
            counters=replace(
                self._health.counters,
                dropped_events=self._health.counters.dropped_events + 1,
            ),
            last_error=self._diagnostic(code, DiagnosticSeverity.WARNING),
        )

    def _record_dropped_count(self, count: int) -> None:
        with self._lock:
            self._health = replace(
                self._health,
                counters=replace(
                    self._health.counters,
                    dropped_events=self._health.counters.dropped_events + count,
                ),
            )

    def _discard_queued_locked(self) -> int:
        discarded = 0
        while True:
            try:
                self._queue.get_nowait()
            except Empty:
                break
            self._queue.task_done()
            discarded += 1
        if discarded:
            self._health = replace(
                self._health,
                queue_depth=0,
                counters=replace(
                    self._health.counters,
                    dropped_events=(
                        self._health.counters.dropped_events + discarded
                    ),
                ),
            )
        return discarded

    def _utc_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _diagnostic(
        self,
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
    ) -> Diagnostic:
        return Diagnostic(
            code=code,
            component=DiagnosticComponent.PERSISTENCE,
            severity=severity,
            occurred_at=self._utc_now(),
        )


def _require_positive_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be greater than zero")


def _require_non_negative_float(value: float, field_name: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
    ):
        raise TypeError(f"{field_name} must be a finite number")
    if value < 0:
        raise ValueError(f"{field_name} must be zero or greater")


__all__ = (
    "ConnectionHistoryPersistence",
    "ConnectionHistoryWriter",
    "DEFAULT_BATCH_INTERVAL",
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_QUEUE_CAPACITY",
    "DEFAULT_RETRY_BACKOFF",
    "DEFAULT_RETRY_LIMIT",
    "DEFAULT_SHUTDOWN_TIMEOUT",
    "HistoryWriterLifecycleError",
)
