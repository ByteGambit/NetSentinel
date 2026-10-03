"""NS-075 single latest-request worker for baseline detail snapshots."""

from __future__ import annotations

from collections.abc import Callable
from queue import Empty, Queue
from threading import Event, RLock, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.baseline_detail import (
    BaselineDetailRequest, BaselineDetailService,
)
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.application.services.behavior_baseline import BaselineResetSubmission


BaselineDetailServiceFactory = Callable[[], BaselineDetailService]


class BaselineQueryCoordinator(QObject):
    result_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)
    stopped = pyqtSignal()

    def __init__(self, service_factory: BaselineDetailServiceFactory, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = service_factory
        self._queue: Queue[tuple[int, BaselineDetailRequest] | None] = Queue(maxsize=1)
        self._lock = RLock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._generation = 0
        self._accepting = False
        self._service: BaselineDetailService | None = None

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop = Event()
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Empty:
                    break
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-baseline-query", daemon=True)
            self._thread.start()
            return True

    def request(self, request: BaselineDetailRequest) -> int:
        with self._lock:
            if not self._accepting:
                raise RuntimeError("baseline query worker is not running")
            self._generation += 1
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Empty:
                    break
            self._queue.put_nowait((self._generation, request))
            return self._generation

    def invalidate(self) -> None:
        with self._lock:
            self._generation += 1

    def reset(self, scope: BehaviorScopeKey) -> BaselineResetSubmission:
        # This is an in-memory command submission; only NS-071's owner writes SQLite.
        with self._lock:
            if not self._accepting or self._service is None:
                raise RuntimeError("baseline service unavailable")
            return self._service.reset(scope)

    def stop(self, timeout: float = 2.0) -> bool:
        with self._lock:
            self._accepting = False
            self._service = None
            self._generation += 1
            self._stop.set()
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Empty:
                    break
            self._queue.put_nowait(None)
            thread = self._thread
        self.stopped.emit()
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(timeout)
        return not thread.is_alive()

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        with self._lock:
            if self._accepting:
                self._service = service
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.1)
            except Empty:
                continue
            if item is None:
                self._queue.task_done()
                break
            generation, request = item
            try:
                result = service.lookup(request) if service is not None else None
                with self._lock:
                    current = self._accepting and generation == self._generation
                if current:
                    if result is None:
                        self.query_failed.emit(generation)
                    else:
                        self.result_ready.emit(generation, result)
            except Exception:
                with self._lock:
                    current = self._accepting and generation == self._generation
                if current:
                    self.query_failed.emit(generation)
            finally:
                self._queue.task_done()
