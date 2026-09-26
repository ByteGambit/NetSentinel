"""Bounded, serial profile worker with latest-selection read delivery."""

from __future__ import annotations

from collections.abc import Callable
from threading import Condition, Thread, current_thread
from uuid import UUID

from PyQt6.QtCore import QObject, pyqtSignal

from netsentinel.application.ports import DeviceProfileMergeConflict
from netsentinel.application.services.device_profiles import DeviceProfileService, ProfileEdit, ProfileInputError
from netsentinel.domain.devices import DeviceProfile


ProfileServiceFactory = Callable[[], DeviceProfileService]


class DeviceProfileCoordinator(QObject):
    loaded = pyqtSignal(int, object, object)
    load_failed = pyqtSignal(int, object)
    saved = pyqtSignal(object, object)
    save_failed = pyqtSignal(object, str)

    def __init__(self, factory: ProfileServiceFactory, *, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._condition = Condition()
        self._thread: Thread | None = None
        self._accepting = False
        self._stopping = False
        self._generation = 0
        self._pending_load: tuple[int, UUID] | None = None
        self._pending_save: tuple[UUID, str, DeviceProfile | None, ProfileEdit] | None = None

    @property
    def worker_alive(self) -> bool:
        with self._condition:
            return self._thread is not None and self._thread.is_alive()

    @property
    def accepting(self) -> bool:
        with self._condition:
            return self._accepting

    def start(self) -> bool:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._accepting = True
            self._stopping = False
            self._thread = Thread(target=self._run, name="netsentinel-device-profile", daemon=True)
            self._thread.start()
            return True

    def load(self, device_id: UUID) -> int:
        with self._condition:
            if not self._accepting:
                raise RuntimeError("profile worker unavailable")
            self._generation += 1
            self._pending_load = (self._generation, device_id)
            self._condition.notify()
            return self._generation

    def invalidate(self) -> None:
        with self._condition:
            self._generation += 1
            self._pending_load = None

    def save(self, device_id: UUID, network_fingerprint: str,
             original: DeviceProfile | None, edit: ProfileEdit) -> bool:
        with self._condition:
            if not self._accepting or self._pending_save is not None:
                return False
            self._pending_save = (device_id, network_fingerprint, original, edit)
            self._condition.notify()
            return True

    def stop(self, timeout: float = 3.5) -> bool:
        with self._condition:
            self._accepting = False
            self._stopping = True
            self._generation += 1
            self._pending_load = None
            self._condition.notify_all()
            thread = self._thread
        if thread is None:
            return True
        if thread is current_thread():
            return False
        thread.join(max(0.0, timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._condition:
                if self._thread is thread:
                    self._thread = None
        return stopped

    def _run(self) -> None:
        try:
            service = self._factory()
        except Exception:
            service = None
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._stopping or self._pending_save is not None or self._pending_load is not None)
                if self._pending_save is not None:
                    save = self._pending_save
                    self._pending_save = None
                    load = None
                elif self._stopping:
                    break
                else:
                    save = None
                    load = self._pending_load
                    self._pending_load = None
            if save is not None:
                device_id, fingerprint, original, edit = save
                try:
                    if service is None:
                        raise RuntimeError("profile service unavailable")
                    profile = service.save(device_id, fingerprint, original, edit)
                    if not self._stopping:
                        self.saved.emit(device_id, profile)
                except ProfileInputError:
                    if not self._stopping:
                        self.save_failed.emit(device_id, "invalid")
                except DeviceProfileMergeConflict:
                    if not self._stopping:
                        self.save_failed.emit(device_id, "stale")
                except Exception:
                    if not self._stopping:
                        self.save_failed.emit(device_id, "unavailable")
                continue
            if load is not None:
                generation, device_id = load
                try:
                    if service is None:
                        raise RuntimeError("profile service unavailable")
                    profile = service.load(device_id)
                    with self._condition:
                        deliver = self._accepting and generation == self._generation
                    if deliver:
                        self.loaded.emit(generation, device_id, profile)
                except Exception:
                    with self._condition:
                        deliver = self._accepting and generation == self._generation
                    if deliver:
                        self.load_failed.emit(generation, device_id)
        with self._condition:
            self._accepting = False


__all__ = ("DeviceProfileCoordinator", "ProfileServiceFactory")
