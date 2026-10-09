"""NS-103 bounded single I/O owner; Qt signals only carry sanitized projections."""

from collections.abc import Callable
from datetime import datetime
from threading import Event, RLock, Thread
from uuid import UUID

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.response_ui import (
    ResponsePreview, ResponseSelection, ResponseUiReply, ResponseUiService, unavailable_reply,
)
from netsentinel.domain.response import ResponseProfile

ResponseServiceFactory = Callable[[], ResponseUiService]


class ResponseCommandCoordinator(QObject):
    completed = pyqtSignal(int, int, str, object)
    stopped = pyqtSignal()

    def __init__(self, factory: ResponseServiceFactory, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._lock = RLock()
        self._wake, self._stop = Event(), Event()
        self._thread: Thread | None = None
        self._generation = self._serial = 0
        self._job: tuple[int, int, str, tuple] | None = None
        self._active = False
        self._accepting = False

    def start(self) -> bool:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._stop.clear()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-response-command", daemon=True)
            self._thread.start()
            return True

    def invalidate(self) -> int:
        with self._lock:
            self._generation += 1
            dropped = self._job
            self._job = None
            if dropped is not None:
                serial, generation, kind, _ = dropped
                self.completed.emit(serial, generation, kind, ResponseUiReply(
                    "Cancelled before dispatch: no firewall write, response intent or ATTEMPT."))
            return self._generation

    def _submit(self, kind: str, args: tuple) -> int | None:
        with self._lock:
            if not self._accepting or self._active or self._job is not None:
                return None
            self._serial += 1
            self._job = self._serial, self._generation, kind, args
            self._wake.set()
            return self._serial

    def preview(self, selection: ResponseSelection | None, profile: ResponseProfile | None,
                operation: UUID | None = None) -> int | None:
        return self._submit("preview", (selection, profile, operation))

    def confirm(self, preview: ResponsePreview, at: datetime) -> int | None:
        return self._submit("confirm", (preview, at))

    def history(self, after: UUID | None = None, sequence: int = 0) -> int | None:
        return self._submit("history", (after, sequence))

    def stop(self, timeout: float = 2.0) -> bool:
        with self._lock:
            self._accepting = False
            self.invalidate()
            self._stop.set()
            self._wake.set()
            thread = self._thread
        self.stopped.emit()
        if thread:
            thread.join(timeout)
        return thread is None or not thread.is_alive()

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        while not self._stop.is_set():
            self._wake.wait(0.05)
            with self._lock:
                job, self._job = self._job, None
                self._wake.clear()
                if job is None:
                    continue
                serial, generation, kind, args = job
                if generation != self._generation or not self._accepting:
                    continue
                # This is the dispatch boundary. Later invalidation drops the
                # display result, never claims a dispatched OS action cancelled.
                self._active = True
            result: object = unavailable_reply()
            try:
                if service is not None:
                    if kind == "preview":
                        result = service.preview(args[0], args[1], generation, args[2])
                    elif kind == "confirm":
                        result = service.confirm(args[0], generation, args[1])
                    elif kind == "history":
                        result = service.history(*args)
            except Exception:
                # No raw exceptions, custody, witnesses or tokens leave worker.
                result = unavailable_reply()
            with self._lock:
                self._active = False
                if self._accepting:
                    self.completed.emit(serial, generation, kind, result)
