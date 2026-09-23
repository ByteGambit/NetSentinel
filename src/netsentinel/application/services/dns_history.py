"""NS-033 bounded DNS history writer and manual retention."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import isfinite
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
from time import monotonic
from uuid import UUID, uuid4

from netsentinel.application.ports import (
    DnsHistoryRepositoryError, DnsHistoryRetentionRepository, DnsHistoryWriteSession,
)
from netsentinel.domain.dns import DnsHistoryRecord, DnsTransaction


@dataclass(frozen=True, slots=True)
class DnsWriterHealth:
    running: bool
    queue_depth: int
    queue_capacity: int
    accepted: int
    persisted: int
    dropped: int
    failed: int
    retries: int
    batches: int
    error_code: str | None


class DnsHistoryWriter:
    """Nonblocking producer, one connection-owning worker, bounded FIFO batches."""

    def __init__(
        self,
        session_factory: Callable[[], AbstractContextManager[DnsHistoryWriteSession]],
        *, queue_capacity: int = 2048, batch_size: int = 64,
        batch_interval: float = .1, retry_limit: int = 2,
        shutdown_timeout: float = 2.0,
        record_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        for name, value in (("queue_capacity", queue_capacity), ("batch_size", batch_size)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if batch_size > min(queue_capacity, 500):
            raise ValueError("batch_size exceeds queue or storage bound")
        if type(retry_limit) is not int or retry_limit < 0:
            raise ValueError("retry_limit must be nonnegative")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not isfinite(value) or value < 0
            for value in (batch_interval, shutdown_timeout)
        ):
            raise ValueError("interval and timeout must be finite and nonnegative")
        self._factory = session_factory
        self._id_factory = record_id_factory
        self._queue: Queue[DnsHistoryRecord] = Queue(queue_capacity)
        self._batch_size = batch_size
        self._interval = batch_interval
        self._retry_limit = retry_limit
        self._timeout = shutdown_timeout
        self._lock = Lock()
        self._stop = Event()
        self._abandon = Event()
        self._thread: Thread | None = None
        self._accepting = False
        self._accepted = self._persisted = self._dropped = self._failed = self._retries = self._batches = 0
        self._error: str | None = None

    def health_snapshot(self) -> DnsWriterHealth:
        with self._lock:
            return DnsWriterHealth(
                self._thread is not None and self._thread.is_alive(),
                self._queue.qsize(), self._queue.maxsize, self._accepted,
                self._persisted, self._dropped, self._failed, self._retries,
                self._batches, self._error,
            )

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._abandon.clear()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-dns-history-writer", daemon=True)
            self._thread.start()
            return True

    def submit(self, transaction: DnsTransaction | DnsHistoryRecord) -> UUID | None:
        if isinstance(transaction, DnsTransaction):
            record = DnsHistoryRecord(self._id_factory(), transaction)
        elif isinstance(transaction, DnsHistoryRecord):
            record = transaction
        else:
            raise TypeError("DNS history requires a portable transaction or record")
        with self._lock:
            if not self._accepting:
                self._dropped += 1
                self._error = "not_running"
                return None
            try:
                self._queue.put_nowait(record)
            except Full:
                self._dropped += 1
                self._error = "overflow"
                return None
            self._accepted += 1
            return record.id

    def stop(self, timeout: float | None = None) -> bool:
        with self._lock:
            if self._thread is current_thread():
                raise RuntimeError("DNS writer cannot join itself")
            self._accepting = False
            thread = self._thread
            self._stop.set()
        if thread is None:
            return True
        thread.join(self._timeout if timeout is None else timeout)
        if thread.is_alive():
            self._abandon.set()
            with self._lock:
                self._error = "shutdown_timeout"
                self._discard()
            return False
        return True

    def _discard(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                self._dropped += 1
            except Empty:
                return

    def _run(self) -> None:
        try:
            with self._factory() as session:
                while not self._abandon.is_set():
                    if self._stop.is_set() and self._queue.empty():
                        break
                    try:
                        first = self._queue.get(timeout=.05)
                    except Empty:
                        continue
                    batch = [first]
                    deadline = monotonic() + self._interval
                    while len(batch) < self._batch_size:
                        try:
                            remaining = deadline - monotonic()
                            if remaining <= 0 and not self._stop.is_set():
                                break
                            batch.append(self._queue.get_nowait() if self._stop.is_set() else self._queue.get(timeout=max(0, remaining)))
                        except Empty:
                            break
                    self._persist(session, tuple(batch))
                    for _ in batch:
                        self._queue.task_done()
        except Exception:
            with self._lock:
                self._error = "worker_failed"
        finally:
            with self._lock:
                self._accepting = False
                self._discard()

    def _persist(self, session: DnsHistoryWriteSession, batch: tuple[DnsHistoryRecord, ...]) -> None:
        if self._attempt(session, batch):
            with self._lock:
                self._persisted += len(batch)
                self._batches += 1
            return
        for record in batch:
            if self._abandon.is_set():
                with self._lock:
                    self._dropped += 1
            elif self._attempt(session, (record,)):
                with self._lock:
                    self._persisted += 1
                    self._batches += 1
            else:
                with self._lock:
                    self._failed += 1

    def _attempt(self, session: DnsHistoryWriteSession, batch: tuple[DnsHistoryRecord, ...]) -> bool:
        for attempt in range(self._retry_limit + 1):
            try:
                session.write_batch(batch)
                return True
            except Exception:
                with self._lock:
                    self._error = "write_failed"
                if attempt == self._retry_limit:
                    return False
                with self._lock:
                    self._retries += 1
                self._stop.wait(.05 * (attempt + 1))
        return False


@dataclass(frozen=True, slots=True)
class DnsRetentionConfig:
    retention_days: int = 30
    max_rows: int = 100_000
    chunk_size: int = 500

    def __post_init__(self) -> None:
        for name in ("retention_days", "max_rows", "chunk_size"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.chunk_size > 500:
            raise ValueError("chunk_size cannot exceed 500")


@dataclass(frozen=True, slots=True)
class DnsCleanupResult:
    age_deleted: int
    row_deleted: int
    chunks: int
    interrupted: bool


class DnsHistoryRetentionService:
    """Manual age-then-row cleanup; every repository call commits one chunk."""

    def __init__(self, repository: DnsHistoryRetentionRepository, *,
                 config: DnsRetentionConfig | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self._repository = repository
        self._config = config or DnsRetentionConfig()
        self._clock = clock or (lambda: datetime.now(UTC))

    def run_cleanup(self, *, stop_requested: Callable[[], bool] | None = None) -> DnsCleanupResult:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("retention clock must be UTC-aware")
        cutoff = now - timedelta(days=self._config.retention_days)
        counts = [0, 0]
        chunks = 0
        for phase in range(2):
            while True:
                if stop_requested is not None and stop_requested():
                    return DnsCleanupResult(*counts, chunks, True)
                try:
                    deleted = (
                        self._repository.delete_before(cutoff, self._config.chunk_size)
                        if phase == 0 else
                        self._repository.delete_oldest_over_limit(self._config.max_rows, self._config.chunk_size)
                    )
                except Exception:
                    raise DnsHistoryRepositoryError("DNS history cleanup failed.") from None
                if type(deleted) is not int or not 0 <= deleted <= self._config.chunk_size:
                    raise DnsHistoryRepositoryError("DNS history cleanup returned an invalid count.")
                if deleted == 0:
                    break
                counts[phase] += deleted
                chunks += 1
                if deleted < self._config.chunk_size:
                    break
        return DnsCleanupResult(*counts, chunks, False)
