"""Bounded NS-082 I/O owner: latest query plus eight immutable commands."""

from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.mark_normal import (
    BehaviorPreferenceContext, MarkNormalCommandService, MarkNormalPreview,
)
from netsentinel.domain.preferences import PreferenceResult, PreferenceResultStatus, ScopedPreference

PreferenceServiceFactory = Callable[[], MarkNormalCommandService]


class PreferenceCommandCoordinator(QObject):
    result_ready = pyqtSignal(int, object)
    stopped = pyqtSignal()

    def __init__(self, factory: PreferenceServiceFactory, parent: QObject | None = None,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        super().__init__(parent)
        self._factory, self._clock = factory, clock
        self._commands: Queue[tuple[object, Future[PreferenceResult]]] = Queue(maxsize=8)
        self._query: tuple[int, BehaviorPreferenceContext] | None = None
        self._generation = 0
        self._lock = RLock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._accepting = False

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop = Event()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-preference-command", daemon=True)
            self._thread.start()
            return True

    def request(self, context: BehaviorPreferenceContext) -> int:
        with self._lock:
            if not self._accepting:
                raise RuntimeError("preference worker unavailable")
            self._generation += 1
            self._query = (self._generation, context)
            return self._generation

    def invalidate(self) -> None:
        with self._lock:
            self._generation += 1
            self._query = None

    def submit(self, command: MarkNormalPreview | ScopedPreference) -> Future[PreferenceResult]:
        future: Future[PreferenceResult] = Future()
        with self._lock:
            try:
                if not self._accepting:
                    raise Full
                self._commands.put_nowait((command, future))
            except Full:
                future.set_result(PreferenceResult(PreferenceResultStatus.UNAVAILABLE))
        return future

    def stop(self, timeout: float = 2.0) -> bool:
        with self._lock:
            self._accepting = False
            self.invalidate()
            self._stop.set()
            while True:
                try:
                    _, future = self._commands.get_nowait()
                    future.set_result(PreferenceResult(PreferenceResultStatus.UNAVAILABLE))
                    self._commands.task_done()
                except Empty:
                    break
            thread = self._thread
        self.stopped.emit()
        if thread is not None:
            thread.join(timeout)
        return thread is None or not thread.is_alive()

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        while not self._stop.is_set():
            try:
                command, future = self._commands.get_nowait()
            except Empty:
                command = None
            if command is not None:
                try:
                    result = PreferenceResult(PreferenceResultStatus.UNAVAILABLE)
                    if service is not None:
                        if isinstance(command, MarkNormalPreview):
                            result = service.save(command, now=self._clock())
                        elif isinstance(command, ScopedPreference):
                            result = service.revoke(command, now=self._clock())
                    future.set_result(result)
                except Exception:
                    future.set_result(PreferenceResult(PreferenceResultStatus.UNAVAILABLE))
                finally:
                    self._commands.task_done()
                continue
            with self._lock:
                query, self._query = self._query, None
            if query is None:
                self._stop.wait(0.05)
                continue
            generation, context = query
            try:
                page = service.relevant(context, now=self._clock()) if service else None
            except Exception:
                page = None
            with self._lock:
                if self._accepting and generation == self._generation:
                    self.result_ready.emit(generation, page)
