"""One dormant NS-095 maintenance thread, bounded admission and deferred schedule."""

from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import Condition, Event, Thread
from time import monotonic

from netsentinel.application.services.storage_privacy import PrivacyOperationError, StoragePrivacyService
from netsentinel.domain.storage_privacy import (
    PurgePreview, RetentionRunResult, SanitizedExport, StorageRetentionPolicy,
    StorageScope, StorageSummary,
)
from netsentinel.shared.config import StorageMaintenanceConfig


class MaintenanceOperation(str, Enum):
    SUMMARY = "summary"
    RETENTION = "retention"
    PURGE_PREVIEW = "purge_preview"
    PURGE = "purge"
    EXPORT_PREVIEW = "export_preview"
    EXPORT_SAVE = "export_save"
    SETTINGS = "settings"


@dataclass(frozen=True, slots=True)
class StorageSettings:
    enabled: bool
    policy: StorageRetentionPolicy

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or not isinstance(self.policy, StorageRetentionPolicy):
            raise ValueError("typed storage settings required")


@dataclass(frozen=True, slots=True)
class MaintenanceRequest:
    operation: MaintenanceOperation
    scope: StorageScope | None = None
    confirmation: PurgePreview | None = None
    export: SanitizedExport | None = None
    destination: Path | None = None
    settings: StorageSettings | None = None


MaintenanceValue = StorageSummary | PurgePreview | RetentionRunResult | SanitizedExport | StorageSettings | bool


class StorageMaintenanceWorker:
    """One pending OR running operation; monitoring owns separate writers."""

    def __init__(self, factory: Callable[[], StoragePrivacyService], *,
                 settings: StorageSettings = StorageSettings(False, StorageRetentionPolicy()),
                 save_settings: Callable[[StorageSettings], None] | None = None,
                 budgets: StorageMaintenanceConfig = StorageMaintenanceConfig(),
                 timer: Callable[[], float] = monotonic) -> None:
        self._factory, self._settings = factory, settings
        self._save_settings, self.budgets, self._timer = save_settings, budgets, timer
        self._condition = Condition()
        self._stop = Event()
        self._cancel = Event()
        self._thread: Thread | None = None
        self._pending: tuple[MaintenanceRequest, Future[MaintenanceValue]] | None = None
        self._busy = False
        self._accepting = False
        self._due = float("inf")
        self.last_cleanup: RetentionRunResult | None = None
        self.failures = 0
        self.rejected = 0

    @property
    def settings(self) -> StorageSettings:
        with self._condition:
            return self._settings

    @property
    def busy(self) -> bool:
        with self._condition:
            return self._busy

    @property
    def next_due_seconds(self) -> float | None:
        with self._condition:
            return max(0.0, self._due - self._timer()) if self._settings.enabled else None

    def start(self) -> bool:
        with self._condition:
            if self._thread is not None or self._stop.is_set():
                return False
            self._accepting = True
            self._due = self._timer() + self.budgets.startup_delay_seconds
            self._thread = Thread(target=self._run, name="netsentinel-storage-maintenance", daemon=True)
            self._thread.start()
            return True

    def submit(self, request: MaintenanceRequest) -> Future[MaintenanceValue]:
        future: Future[MaintenanceValue] = Future()
        with self._condition:
            if self._busy or not self._accepting:
                self.rejected = min(self.rejected + 1, 2**63 - 1)
                future.set_exception(PrivacyOperationError())
                return future
            self._busy = True
            self._cancel.clear()
            self._pending = (request, future)
            self._condition.notify_all()
        return future

    def cancel(self) -> None:
        self._cancel.set()

    def stop(self, timeout: float | None = None) -> bool:
        with self._condition:
            self._accepting = False
            self._stop.set()
            self._cancel.set()
            self._condition.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(self.budgets.shutdown_seconds if timeout is None else min(max(0, timeout), self.budgets.shutdown_seconds))
        return thread is None or not thread.is_alive()

    def _run(self) -> None:
        service: StoragePrivacyService | None = None
        while True:
            with self._condition:
                if self._stop.is_set() and self._pending is None:
                    return
                command, self._pending = self._pending, None
                scheduled = command is None and self._accepting and self._settings.enabled and self._timer() >= self._due
                if command is None and not scheduled:
                    self._condition.wait(0.1)
                    continue
                if scheduled:
                    self._busy = True
                    self._cancel.clear()
                    command = (MaintenanceRequest(MaintenanceOperation.RETENTION), Future())
            assert command is not None
            request, future = command
            failed = False
            value: MaintenanceValue = False
            try:
                if not future.set_running_or_notify_cancel():
                    continue
                if self._stop.is_set() or self._cancel.is_set():
                    raise PrivacyOperationError()
                if service is None:
                    service = self._factory()
                service.policy = self._settings.policy
                value = self._execute(service, request)
                if isinstance(value, RetentionRunResult):
                    self.last_cleanup = value
            except Exception:
                self.failures = min(self.failures + 1, 2**63 - 1)
                failed = True
            finally:
                with self._condition:
                    self._busy = False
                    if request.operation in (MaintenanceOperation.RETENTION, MaintenanceOperation.SETTINGS):
                        self._due = self._timer() + (self.budgets.startup_delay_seconds if request.operation is MaintenanceOperation.SETTINGS else self.budgets.interval_seconds)
                    self._condition.notify_all()
            if failed:
                future.set_exception(PrivacyOperationError())
            else:
                future.set_result(value)

    def _execute(self, service: StoragePrivacyService, request: MaintenanceRequest) -> MaintenanceValue:
        def stop() -> bool:
            return self._stop.is_set() or self._cancel.is_set()
        operation = request.operation
        if operation is MaintenanceOperation.SUMMARY:
            return service.summary(stop)
        if operation is MaintenanceOperation.RETENTION:
            return service.run_retention(stop)
        if operation is MaintenanceOperation.PURGE_PREVIEW and request.scope is not None:
            return service.preview_purge(request.scope, stop)
        if operation is MaintenanceOperation.PURGE and request.confirmation is not None:
            return service.purge(request.confirmation, stop)
        if operation is MaintenanceOperation.EXPORT_PREVIEW:
            return service.preview_export(stop)
        if operation is MaintenanceOperation.EXPORT_SAVE and request.export is not None and request.destination is not None:
            return service.save_export(request.export, request.destination, stop)
        if operation is MaintenanceOperation.SETTINGS and request.settings is not None and self._save_settings is not None:
            if stop():
                raise PrivacyOperationError()
            self._save_settings(request.settings)
            with self._condition:
                self._settings = request.settings
            return request.settings
        raise PrivacyOperationError()
