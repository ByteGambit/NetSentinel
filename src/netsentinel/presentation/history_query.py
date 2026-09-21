"""Single-worker Qt handoff for bounded connection-history reads."""

from __future__ import annotations

from collections.abc import Callable
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.ports import (
    ConnectionHistoryQuery,
    HistoryQueryCancelled,
)
from netsentinel.application.services.history_query import (
    ConnectionHistoryPage,
    ConnectionHistoryQueryService,
)


HistoryServiceFactory = Callable[[], ConnectionHistoryQueryService]
_WorkItem = tuple[int, ConnectionHistoryQuery, Event]


class HistoryQueryCoordinator(QObject):
    """Own one cancellable worker and deliver only the newest query result."""

    page_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)

    def __init__(
        self,
        service_factory: HistoryServiceFactory,
        *,
        shutdown_timeout: float = 2.0,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        if not callable(service_factory):
            raise TypeError("service_factory must be callable")
        if shutdown_timeout < 0:
            raise ValueError("shutdown_timeout must be zero or greater")
        self._service_factory = service_factory
        self._shutdown_timeout = float(shutdown_timeout)
        self._queue: Queue[_WorkItem | None] = Queue(maxsize=1)
        self._lock = RLock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._current_cancel: Event | None = None
        self._latest_generation = 0
        self._accepting = False

    @property
    def worker_alive(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop = Event()
            self._accepting = True
            thread = Thread(
                target=self._run,
                name="netsentinel-history-query",
                daemon=True,
            )
            self._thread = thread
            thread.start()
            return True

    def request(self, query: ConnectionHistoryQuery) -> int:
        if not isinstance(query, ConnectionHistoryQuery):
            raise TypeError("query must be a ConnectionHistoryQuery")
        with self._lock:
            if not self._accepting:
                raise RuntimeError("history query worker is not running")
            self._latest_generation += 1
            generation = self._latest_generation
            if self._current_cancel is not None:
                self._current_cancel.set()
            self._discard_pending_locked()
            cancellation = Event()
            try:
                self._queue.put_nowait((generation, query, cancellation))
            except Full:  # defensive: the queue was drained under this lock
                self._discard_pending_locked()
                self._queue.put_nowait((generation, query, cancellation))
            return generation

    def stop(self, timeout: float | None = None) -> bool:
        with self._lock:
            self._accepting = False
            self._latest_generation += 1
            self._stop.set()
            if self._current_cancel is not None:
                self._current_cancel.set()
            self._discard_pending_locked()
            try:
                self._queue.put_nowait(None)
            except Full:
                pass
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(self._shutdown_timeout if timeout is None else max(0.0, timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
                self._current_cancel = None
        return stopped

    def _run(self) -> None:
        service: ConnectionHistoryQueryService | None = None
        service_failed = False
        try:
            try:
                service = self._service_factory()
                if not isinstance(service, ConnectionHistoryQueryService):
                    raise TypeError("service_factory returned an invalid service")
            except Exception:
                service_failed = True

            while not self._stop.is_set():
                try:
                    item = self._queue.get(timeout=0.1)
                except Empty:
                    continue
                if item is None:
                    self._queue.task_done()
                    break
                generation, query, cancellation = item
                with self._lock:
                    self._current_cancel = cancellation
                try:
                    if service_failed or service is None:
                        self._emit_failure_if_current(generation)
                        continue
                    page = service.load_page(
                        query,
                        is_cancelled=lambda: (
                            cancellation.is_set() or self._stop.is_set()
                        ),
                    )
                    self._emit_page_if_current(generation, page)
                except HistoryQueryCancelled:
                    pass
                except Exception:
                    self._emit_failure_if_current(generation)
                finally:
                    with self._lock:
                        if self._current_cancel is cancellation:
                            self._current_cancel = None
                    self._queue.task_done()
        finally:
            with self._lock:
                self._accepting = False
                self._current_cancel = None

    def _emit_page_if_current(
        self, generation: int, page: ConnectionHistoryPage
    ) -> None:
        with self._lock:
            deliver = self._accepting and generation == self._latest_generation
        if deliver:
            try:
                self.page_ready.emit(generation, page)
            except RuntimeError:
                pass

    def _emit_failure_if_current(self, generation: int) -> None:
        with self._lock:
            deliver = self._accepting and generation == self._latest_generation
        if deliver:
            try:
                self.query_failed.emit(generation)
            except RuntimeError:
                pass

    def _discard_pending_locked(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except Empty:
                return
            if item is not None:
                item[2].set()
            self._queue.task_done()


__all__ = ("HistoryQueryCoordinator", "HistoryServiceFactory")
