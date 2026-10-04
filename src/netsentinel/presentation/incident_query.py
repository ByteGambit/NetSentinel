"""NS-091 single latest-request slot and generation-guarded worker reads."""

from collections.abc import Callable
from threading import Condition, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.incident_timeline import (
    IncidentTimelineQueryService, TimelineRequest,
)

IncidentTimelineServiceFactory = Callable[[], IncidentTimelineQueryService]


class IncidentQueryCoordinator(QObject):
    result_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)
    stopped = pyqtSignal()

    def __init__(self, factory: IncidentTimelineServiceFactory, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._condition = Condition()
        self._thread: Thread | None = None
        self._accepting = False
        self._stopping = False
        self._generation = 0
        self._pending: tuple[int, TimelineRequest] | None = None

    def start(self) -> bool:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._accepting, self._stopping = True, False
            self._thread = Thread(target=self._run, name="netsentinel-incident-query", daemon=True)
            self._thread.start()
            return True

    def request(self, request: TimelineRequest) -> int:
        if type(request) is not TimelineRequest:
            raise TypeError("typed incident timeline request required")
        with self._condition:
            if not self._accepting:
                raise RuntimeError("incident query worker is not running")
            self._generation += 1
            self._pending = (self._generation, request)
            self._condition.notify()
            return self._generation

    def invalidate(self) -> None:
        with self._condition:
            self._generation += 1
            self._pending = None

    def stop(self, timeout: float = 2.0) -> bool:
        with self._condition:
            self._accepting, self._stopping = False, True
            self._generation += 1
            self._pending = None
            self._condition.notify_all()
            thread = self._thread
        try:
            self.stopped.emit()
        except RuntimeError:
            pass
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(max(0.0, timeout))
        return not thread.is_alive()

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._stopping or self._pending is not None)
                if self._stopping:
                    return
                item = self._pending
                self._pending = None
            assert item is not None
            generation, request = item
            try:
                if service is None:
                    raise RuntimeError("incident query unavailable")
                result = service.lookup(request)
            except Exception:
                result = None
            with self._condition:
                current = self._accepting and generation == self._generation
            if current:
                try:
                    if result is None:
                        self.query_failed.emit(generation)
                    else:
                        self.result_ready.emit(generation, result)
                except RuntimeError:
                    # Parent/widget may have been deleted during a blocking read.
                    pass
