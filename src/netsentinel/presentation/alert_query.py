"""One bounded worker for alert reads and lifecycle commands."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from threading import Condition, Event, Thread, current_thread
from uuid import UUID

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.ports import AlertQuery, AlertQueryCancelled
from netsentinel.application.services.alert_query import AlertQueryService


AlertServiceFactory = Callable[[], AlertQueryService]


class AlertQueryCoordinator(QObject):
    page_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)
    acknowledged = pyqtSignal(object)
    action_failed = pyqtSignal(object)

    def __init__(self, factory: AlertServiceFactory, *, shutdown_timeout: float = 2.0,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        if not callable(factory) or shutdown_timeout < 0:
            raise ValueError("invalid alert worker configuration")
        self._factory = factory
        self._shutdown_timeout = shutdown_timeout
        self._condition = Condition()
        self._stop = Event()
        self._thread: Thread | None = None
        self._accepting = False
        self._generation = 0
        self._pending: tuple[int, AlertQuery, Event] | None = None
        self._current_cancel: Event | None = None
        self._actions: deque[UUID] = deque()

    @property
    def worker_alive(self) -> bool:
        with self._condition:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-alert-query", daemon=True)
            self._thread.start()
            return True

    def request(self, query: AlertQuery) -> int:
        if not isinstance(query, AlertQuery):
            raise TypeError("query must be an AlertQuery")
        with self._condition:
            if not self._accepting:
                raise RuntimeError("alert worker is not running")
            self._generation += 1
            if self._current_cancel is not None:
                self._current_cancel.set()
            if self._pending is not None:
                self._pending[2].set()
            self._pending = (self._generation, query, Event())
            self._condition.notify()
            return self._generation

    def acknowledge(self, alert_id: UUID) -> bool:
        if not isinstance(alert_id, UUID):
            raise TypeError("alert ID must be UUID")
        with self._condition:
            if not self._accepting or len(self._actions) >= 8:
                return False
            self._actions.append(alert_id)
            self._condition.notify()
            return True

    def stop(self, timeout: float | None = None) -> bool:
        with self._condition:
            self._accepting = False
            self._generation += 1
            self._stop.set()
            if self._current_cancel is not None:
                self._current_cancel.set()
            if self._pending is not None:
                self._pending[2].set()
                self._pending = None
            self._actions.clear()
            self._condition.notify_all()
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(self._shutdown_timeout if timeout is None else max(0.0, timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._condition:
                if self._thread is thread:
                    self._thread = None
        return stopped

    def _run(self) -> None:
        try:
            service = self._factory()
            if not isinstance(service, AlertQueryService):
                raise TypeError("invalid alert service")
        except Exception:
            service = None
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: self._stop.is_set() or self._actions or self._pending is not None)
                    if self._stop.is_set():
                        break
                    if self._actions:
                        action = self._actions.popleft()
                        item = None
                    else:
                        action = None
                        item = self._pending
                        self._pending = None
                        self._current_cancel = item[2] if item is not None else None
                if action is not None:
                    try:
                        result = service.acknowledge(action) if service is not None else None
                        if not self._stop.is_set():
                            try:
                                if result is None:
                                    self.action_failed.emit(action)
                                else:
                                    self.acknowledged.emit(result)
                            except RuntimeError:
                                pass
                    except Exception:
                        if not self._stop.is_set():
                            try:
                                self.action_failed.emit(action)
                            except RuntimeError:
                                pass
                    continue
                if item is None:
                    continue
                generation, query, cancellation = item
                try:
                    if service is None:
                        raise RuntimeError("alert service unavailable")
                    page = service.load_page(query, is_cancelled=lambda: cancellation.is_set() or self._stop.is_set())
                    with self._condition:
                        deliver = self._accepting and generation == self._generation
                    if deliver:
                        try:
                            self.page_ready.emit(generation, page)
                        except RuntimeError:
                            pass
                except AlertQueryCancelled:
                    pass
                except Exception:
                    with self._condition:
                        deliver = self._accepting and generation == self._generation
                    if deliver:
                        try:
                            self.query_failed.emit(generation)
                        except RuntimeError:
                            pass
                finally:
                    with self._condition:
                        if self._current_cancel is cancellation:
                            self._current_cancel = None
        finally:
            with self._condition:
                self._accepting = False


__all__ = ("AlertQueryCoordinator", "AlertServiceFactory")
