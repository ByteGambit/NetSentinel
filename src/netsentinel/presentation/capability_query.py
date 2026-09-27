"""Bounded, single-worker bridge for startup and retry capability checks."""

from __future__ import annotations

from collections.abc import Callable
from threading import Event, Lock, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.capabilities import CapabilityService


class CapabilityCoordinator(QObject):
    ready = pyqtSignal(int, object)
    failed = pyqtSignal(int)

    def __init__(self, factory: Callable[[], CapabilityService], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._wake = Event()
        self._stop = Event()
        self._lock = Lock()
        self._generation = 0
        self._thread: Thread | None = None
        self._accepting = False

    @property
    def worker_alive(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-capabilities", daemon=True)
            self._thread.start()
            return True

    def request(self) -> bool:
        with self._lock:
            if not self._accepting:
                return False
            self._generation += 1
            self._wake.set()
            return True

    def stop(self, timeout: float = 3.5) -> bool:
        with self._lock:
            self._accepting = False
            self._generation += 1
            self._stop.set()
            self._wake.set()
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(timeout)
        return not thread.is_alive()

    def _run(self) -> None:
        try:
            service = self._factory()
            while not self._stop.is_set():
                self._wake.wait()
                self._wake.clear()
                if self._stop.is_set():
                    break
                with self._lock:
                    generation = self._generation
                try:
                    result = service.check()
                except Exception:
                    with self._lock:
                        current = self._accepting and generation == self._generation
                    if current:
                        self.failed.emit(generation)
                else:
                    with self._lock:
                        current = self._accepting and generation == self._generation
                    if current:
                        self.ready.emit(generation, result)
        except Exception:
            if not self._stop.is_set():
                self.failed.emit(self.generation)
        finally:
            with self._lock:
                self._accepting = False


__all__ = ("CapabilityCoordinator",)
