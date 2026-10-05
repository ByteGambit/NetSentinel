"""NS-095 blocking maintenance service; no SQL, Qt, network or raw exports."""

from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import tempfile
from time import monotonic
from uuid import uuid4

from netsentinel.application.ports import StorageMaintenanceRepository
from netsentinel.domain.storage_privacy import (
    MaintenanceStatus, PurgePreview, RetentionRunResult, SanitizedExport,
    StorageRetentionPolicy, StorageScope, StorageSummary, Store, StoreCleanup, utc_now,
)
from netsentinel.shared.config import StorageMaintenanceConfig
from netsentinel.version import __version__


_SCOPES = {
    StorageScope.CONNECTIONS: (Store.CONNECTIONS,),
    StorageScope.DNS: (Store.ASSOCIATIONS, Store.DNS),
    StorageScope.CACHE: (Store.CACHE,),
    StorageScope.ALERTS: (Store.ALERTS,),
    StorageScope.INCIDENTS: (Store.INCIDENTS,),
    StorageScope.BASELINES: (Store.BASELINES,),
    StorageScope.DEVICES: (Store.BINDINGS, Store.DEVICES),
    StorageScope.ALL: tuple(Store),
}


class PrivacyOperationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Local maintenance could not be completed. No sensitive error details are displayed.")


class StoragePrivacyService:
    """All calls belong to the single maintenance worker; construction is lazy."""

    def __init__(self, repository: StorageMaintenanceRepository, *,
                 policy: StorageRetentionPolicy = StorageRetentionPolicy(),
                 budgets: StorageMaintenanceConfig = StorageMaintenanceConfig(),
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 timer: Callable[[], float] = monotonic) -> None:
        self.repository, self.policy, self.budgets = repository, policy, budgets
        self.clock, self.timer = clock, timer
        self._purge_preview: PurgePreview | None = None
        self._export: SanitizedExport | None = None

    def _bounded_stop(self, stop: Callable[[], bool]) -> Callable[[], bool]:
        deadline = self.timer() + self.budgets.runtime_seconds
        return lambda: stop() or self.timer() >= deadline

    def summary(self, stop: Callable[[], bool] = lambda: False) -> StorageSummary:
        try:
            return self.repository.summary(self.policy.rules, utc_now(self.clock()), self._bounded_stop(stop))
        except Exception:
            raise PrivacyOperationError() from None

    def preview_purge(self, scope: StorageScope, stop: Callable[[], bool] = lambda: False) -> PurgePreview:
        if not isinstance(scope, StorageScope):
            raise ValueError("typed purge scope required")
        summary = self.summary(stop)
        selected = tuple(s for s in summary.stores if s.store in _SCOPES[scope])
        preview = PurgePreview(uuid4(), scope, sum(s.eligible for s in selected),
                               sum(s.protected for s in summary.stores))
        self._purge_preview = preview
        return preview

    def run_retention(self, stop: Callable[[], bool] = lambda: False) -> RetentionRunResult:
        return self._cleanup(None, stop)

    def purge(self, confirmation: PurgePreview, stop: Callable[[], bool] = lambda: False) -> RetentionRunResult:
        # A preview alone never deletes. Only the exact last worker-issued
        # confirmation is accepted; tokens are consumed once and scope-bound.
        if not isinstance(confirmation, PurgePreview) or confirmation != self._purge_preview:
            raise PrivacyOperationError()
        self._purge_preview = None
        return self._cleanup(confirmation.scope, stop)

    def _cleanup(self, scope: StorageScope | None, stop: Callable[[], bool]) -> RetentionRunResult:
        started = self.timer()
        now = utc_now(self.clock())
        deadline = started + self.budgets.runtime_seconds
        results: list[StoreCleanup] = []
        deleted = chunks = 0
        status = MaintenanceStatus.COMPLETE
        def limited() -> bool:
            return stop() or self.timer() >= deadline
        # One chunk/store/pass avoids cache/telemetry starving explanations.
        rules = tuple(r for r in self.policy.rules if scope is None or r.store in _SCOPES[scope])
        pending = list(rules)
        while pending:
            next_pass = []
            for rule in pending:
                if limited() or deleted >= self.budgets.max_deletes or chunks >= self.budgets.max_chunks:
                    status = MaintenanceStatus.CANCELLED if stop() else MaintenanceStatus.LIMITED
                    return self._finish(status, results, chunks, started, now, limited, scope)
                limit = min(rule.chunk_rows, self.budgets.max_deletes - deleted)
                chunks += 1
                try:
                    count = self.repository.cleanup_chunk(rule, now, limit, scope is not None, limited)
                    if type(count) is not int or not 0 <= count <= limit:
                        raise ValueError("invalid adapter deletion receipt")
                    results.append(StoreCleanup(rule.store, count))
                    deleted += count
                    if count:
                        next_pass.append(rule)
                except Exception:
                    results.append(StoreCleanup(rule.store, 0, True))
                    status = MaintenanceStatus.CANCELLED if stop() else MaintenanceStatus.LIMITED if self.timer() >= deadline else MaintenanceStatus.PARTIAL
            pending = next_pass
        return self._finish(status, results, chunks, started, now, limited, scope)

    def _finish(self, status: MaintenanceStatus, results: list[StoreCleanup], chunks: int,
                started: float, now: datetime, stop: Callable[[], bool], scope: StorageScope | None) -> RetentionRunResult:
        summary = None
        try:
            if not stop():
                summary = self.repository.summary(self.policy.rules, now, stop)
        except Exception:
            pass  # Deletion receipts survive a failed/budget-limited final read.
        merged = []
        for store in dict.fromkeys(item.store for item in results):
            rows = tuple(item for item in results if item.store is store)
            protected = next((item.protected for item in summary.stores if item.store is store), None) if summary else None
            merged.append(StoreCleanup(store, sum(item.deleted for item in rows),
                                       any(item.failed for item in rows), protected))
        pressure = tuple(item for item in summary.stores if item.pressure) if summary else ()
        if scope is not None and summary and status is MaintenanceStatus.COMPLETE:
            if any(item.eligible for item in summary.stores if item.store in _SCOPES[scope]):
                status = MaintenanceStatus.LIMITED
        if pressure and status is MaintenanceStatus.COMPLETE:
            status = MaintenanceStatus.CAPACITY_PRESSURE
        return RetentionRunResult(status, tuple(merged), chunks, max(0.0, self.timer() - started),
                                  pressure, summary is None)

    def preview_export(self, stop: Callable[[], bool] = lambda: False) -> SanitizedExport:
        limited = self._bounded_stop(stop)
        try:
            summary = self.repository.summary(self.policy.rules, utc_now(self.clock()), limited)
            records = []
            samples = []
            for category in (Store.ALERTS, Store.INCIDENTS):
                category_records: list[dict[str, object]] = []
                for offset in range(0, self.budgets.export_category_records, self.budgets.export_page_records):
                    if limited():
                        raise PrivacyOperationError()
                    page = self.repository.export_page(category, offset,
                        min(self.budgets.export_page_records, self.budgets.export_category_records - offset), limited)
                    category_records.extend(asdict(record) for record in page)
                records.extend(category_records)
                samples.extend(category_records[:self.budgets.preview_category_records])
            manifest = {
                "format": "support-export-v1", "redaction_policy": "allowlist-v1",
                "generated_at": utc_now(self.clock()).isoformat(), "application_version": __version__,
                "schema_version": summary.schema_version,
                "categories": ["storage_summary", "retention_policy", "alert_summary", "incident_summary"],
                "limitations": "Redacted support metadata, not anonymous or a forensic log. Counts are estimates; records are limited. No automatic upload.",
            }
            body = {"manifest": manifest, "storage": asdict(summary),
                    "retention": asdict(self.policy), "records": records}
            content = json.dumps(body, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(content) > self.budgets.export_bytes or len(records) > 2 * self.budgets.export_category_records or limited():
                raise PrivacyOperationError()
            sample = json.dumps({"manifest": manifest, "storage": asdict(summary),
                                 "retention": asdict(self.policy), "sample_records": samples,
                                 "total_records": len(records), "bytes": len(content)}, sort_keys=True, indent=2)
            if len(sample.encode()) > self.budgets.export_bytes:
                raise PrivacyOperationError()
            export = SanitizedExport(uuid4(), content, len(records), sample)
            self._export = export
            return export
        except Exception:
            raise PrivacyOperationError() from None

    def save_export(self, export: SanitizedExport, destination: Path,
                    stop: Callable[[], bool] = lambda: False) -> bool:
        if export != self._export or len(export.content) > self.budgets.export_bytes:
            raise PrivacyOperationError()
        temporary: str | None = None
        try:
            if stop():
                return False
            with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                             prefix=".netsentinel-export-", suffix=".tmp", delete=False) as stream:
                temporary = stream.name
                stream.write(export.content)
                stream.flush()
                os.fsync(stream.fileno())
            if stop():
                return False
            os.replace(temporary, destination)
            temporary = None
            self._export = None
            return True
        except (OSError, ValueError):
            raise PrivacyOperationError() from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
