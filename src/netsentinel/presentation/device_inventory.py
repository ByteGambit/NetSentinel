"""Single bounded worker handoff for device inventory and passive capture."""

from __future__ import annotations

from collections.abc import Callable
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread, current_thread

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.services.device_inventory import DeviceInventoryService


DeviceServiceFactory = Callable[[], DeviceInventoryService]


class DeviceInventoryCoordinator(QObject):
    snapshot_ready = pyqtSignal(object)
    load_failed = pyqtSignal()

    def __init__(self, factory: DeviceServiceFactory, *, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._commands: Queue[tuple[str, str | None]] = Queue(maxsize=8)
        self._stop = Event()
        self._lock = RLock()
        self._thread: Thread | None = None
        self._accepting = False

    @property
    def worker_alive(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    @property
    def accepting(self) -> bool:
        with self._lock:
            return self._accepting

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._accepting = True
            self._thread = Thread(target=self._run, name="netsentinel-device-inventory", daemon=True)
            self._thread.start()
            return True

    def request(self, command: str = "refresh", fingerprint: str | None = None) -> bool:
        if command not in {"refresh", "select", "capture_start", "capture_stop"}:
            raise ValueError("unsupported device command")
        with self._lock:
            if not self._accepting:
                return False
            try:
                self._commands.put_nowait((command, fingerprint))
            except Full:
                return False
            return True

    def stop(self, timeout: float = 3.5) -> bool:
        with self._lock:
            self._accepting = False
            self._stop.set()
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(max(0.0, timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
            while True:
                try:
                    self._commands.get_nowait()
                except Empty:
                    break
                self._commands.task_done()
        return stopped

    def _run(self) -> None:
        service: DeviceInventoryService | None = None
        try:
            service = self._factory()
            while not self._stop.is_set():
                try:
                    command, fingerprint = self._commands.get(timeout=1.0)
                    received_command = True
                except Empty:
                    command, fingerprint = "refresh", None
                    received_command = False
                if self._stop.is_set():
                    if received_command:
                        self._commands.task_done()
                    break
                try:
                    snapshot = service.refresh(
                        select=fingerprint if command == "select" else None,
                        start_capture=command == "capture_start",
                        stop_capture=command == "capture_stop",
                    )
                    if not self._stop.is_set():
                        self.snapshot_ready.emit(snapshot)
                except Exception:
                    if not self._stop.is_set():
                        self.load_failed.emit()
                finally:
                    if received_command:
                        self._commands.task_done()
        except Exception:
            if not self._stop.is_set():
                self.load_failed.emit()
        finally:
            if service is not None:
                try:
                    service.close()
                except Exception:
                    pass
            with self._lock:
                self._accepting = False


__all__ = ("DeviceInventoryCoordinator", "DeviceServiceFactory")
