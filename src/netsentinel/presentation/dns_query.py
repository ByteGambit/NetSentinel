"""One cancellable DNS history read worker with latest-generation delivery."""

from __future__ import annotations

from collections.abc import Callable
from queue import Empty, Queue
from threading import Event, RLock, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.ports import DnsHistoryQuery, DnsHistoryQueryCancelled
from netsentinel.application.services.dns_history_query import DnsHistoryQueryService

DnsServiceFactory = Callable[[], DnsHistoryQueryService]


class DnsQueryCoordinator(QObject):
    page_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)

    def __init__(self, service_factory: DnsServiceFactory, *,
                 shutdown_timeout: float = 2.0, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = service_factory
        self._timeout = shutdown_timeout
        self._queue: Queue[tuple[int, DnsHistoryQuery, Event]] = Queue(maxsize=1)
        self._lock = RLock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._current: Event | None = None
        self._generation = 0
        self._accepting = False

    @property
    def worker_alive(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        with self._lock:
            if self.worker_alive:
                return False
            self._stop = Event()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-dns-query", daemon=True)
            self._thread.start()
            return True

    def request(self, query: DnsHistoryQuery) -> int:
        if not isinstance(query, DnsHistoryQuery):
            raise TypeError("query must be a DnsHistoryQuery")
        with self._lock:
            if not self._accepting:
                raise RuntimeError("DNS query worker is not running")
            self._generation += 1
            if self._current is not None:
                self._current.set()
            self._discard()
            self._queue.put_nowait((self._generation, query, Event()))
            return self._generation

    def invalidate(self) -> None:
        """Prevent an in-flight result from replacing an invalid filter state."""
        with self._lock:
            self._generation += 1
            if self._current is not None:
                self._current.set()
            self._discard()

    def stop(self, timeout: float | None = None) -> bool:
        with self._lock:
            self._accepting = False
            self._generation += 1
            self._stop.set()
            if self._current is not None:
                self._current.set()
            self._discard()
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(self._timeout if timeout is None else max(0.0, timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._lock:
                self._thread = None
        return stopped

    def _discard(self) -> None:
        while True:
            try:
                _, _, cancel = self._queue.get_nowait()
            except Empty:
                return
            cancel.set()
            self._queue.task_done()

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        try:
            while not self._stop.is_set():
                try:
                    generation, query, cancel = self._queue.get(timeout=.1)
                except Empty:
                    continue
                with self._lock:
                    self._current = cancel
                try:
                    if service is None:
                        self._deliver(generation, None)
                    else:
                        page = service.load_page(query, is_cancelled=lambda: cancel.is_set() or self._stop.is_set())
                        self._deliver(generation, page)
                except DnsHistoryQueryCancelled:
                    pass
                except Exception:
                    self._deliver(generation, None)
                finally:
                    with self._lock:
                        if self._current is cancel:
                            self._current = None
                    self._queue.task_done()
        finally:
            with self._lock:
                self._accepting = False

    def _deliver(self, generation: int, page: object | None) -> None:
        with self._lock:
            if not self._accepting or generation != self._generation:
                return
        try:
            if page is None:
                self.query_failed.emit(generation)
            else:
                self.page_ready.emit(generation, page)
        except RuntimeError:
            pass
