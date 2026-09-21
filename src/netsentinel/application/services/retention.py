"""Portable, synchronous connection-history retention command."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from netsentinel.application.ports import (
    HistoryRetentionRepository,
    HistoryStorageDiagnostics,
)
from netsentinel.shared.config import HistoryRetentionConfig


WallClock = Callable[[], datetime]
StopPredicate = Callable[[], bool]


class RetentionFailurePhase(str, Enum):
    """Stable stage identifier for a sanitized cleanup failure."""

    DIAGNOSTICS = "diagnostics"
    AGE_CLEANUP = "age_cleanup"
    ROW_CLEANUP = "row_cleanup"
    INTERRUPTION = "interruption"


class HistoryRetentionError(RuntimeError):
    """Cleanup failed after zero or more earlier chunks were committed."""

    def __init__(
        self,
        phase: RetentionFailurePhase,
        *,
        deleted_rows: int,
        chunks_completed: int,
    ) -> None:
        self.phase = phase
        self.deleted_rows = deleted_rows
        self.chunks_completed = chunks_completed
        super().__init__("Connection history cleanup could not be completed.")


@dataclass(frozen=True, slots=True)
class HistoryCleanupResult:
    """Immutable summary returned by the manual safe cleanup command."""

    cutoff: datetime
    age_deleted_rows: int
    row_limit_deleted_rows: int
    chunks_completed: int
    interrupted: bool
    before: HistoryStorageDiagnostics
    after: HistoryStorageDiagnostics

    @property
    def deleted_rows(self) -> int:
        return self.age_deleted_rows + self.row_limit_deleted_rows


class HistoryRetentionService:
    """Apply age policy first, then the total-row policy in bounded chunks.

    This service is the manual cleanup command/API.  It owns no worker and no
    scheduler.  The adapter commits each successful chunk independently;
    ``stop_requested`` is evaluated only between chunks.
    """

    def __init__(
        self,
        repository: HistoryRetentionRepository,
        *,
        config: HistoryRetentionConfig | None = None,
        clock: WallClock | None = None,
    ) -> None:
        if repository is None:
            raise TypeError("repository must not be None")
        if config is not None and not isinstance(config, HistoryRetentionConfig):
            raise TypeError("config must be a HistoryRetentionConfig")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._repository = repository
        self._config = config or HistoryRetentionConfig()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def config(self) -> HistoryRetentionConfig:
        return self._config

    def storage_diagnostics(self) -> HistoryStorageDiagnostics:
        """Return sanitized, path-free database size and row diagnostics."""

        try:
            return self._repository.storage_diagnostics()
        except Exception:
            raise HistoryRetentionError(
                RetentionFailurePhase.DIAGNOSTICS,
                deleted_rows=0,
                chunks_completed=0,
            ) from None

    def run_cleanup(
        self,
        *,
        stop_requested: StopPredicate | None = None,
    ) -> HistoryCleanupResult:
        """Run the same safe policy used by every manual cleanup caller."""

        if stop_requested is not None and not callable(stop_requested):
            raise TypeError("stop_requested must be callable")
        should_stop = stop_requested or (lambda: False)
        now = _require_utc(self._clock(), "clock result")
        cutoff = now - timedelta(days=self._config.retention_days)
        age_deleted = 0
        row_deleted = 0
        chunks = 0

        try:
            before = self._repository.storage_diagnostics()
        except Exception:
            raise HistoryRetentionError(
                RetentionFailurePhase.DIAGNOSTICS,
                deleted_rows=0,
                chunks_completed=0,
            ) from None

        while True:
            if _stop_safely(should_stop, age_deleted + row_deleted, chunks):
                return self._interrupted_result(
                    cutoff, age_deleted, row_deleted, chunks, before
                )
            try:
                deleted = self._repository.delete_completed_before(
                    cutoff,
                    self._config.cleanup_chunk_size,
                )
            except Exception:
                raise HistoryRetentionError(
                    RetentionFailurePhase.AGE_CLEANUP,
                    deleted_rows=age_deleted + row_deleted,
                    chunks_completed=chunks,
                ) from None
            _validate_adapter_count(
                deleted,
                self._config.cleanup_chunk_size,
                phase=RetentionFailurePhase.AGE_CLEANUP,
                deleted_rows=age_deleted + row_deleted,
                chunks=chunks,
            )
            if deleted == 0:
                break
            age_deleted += deleted
            chunks += 1
            if deleted < self._config.cleanup_chunk_size:
                break

        while True:
            if _stop_safely(should_stop, age_deleted + row_deleted, chunks):
                return self._interrupted_result(
                    cutoff, age_deleted, row_deleted, chunks, before
                )
            try:
                deleted = self._repository.delete_oldest_completed_over_total_limit(
                    self._config.max_history_rows,
                    self._config.cleanup_chunk_size,
                )
            except Exception:
                raise HistoryRetentionError(
                    RetentionFailurePhase.ROW_CLEANUP,
                    deleted_rows=age_deleted + row_deleted,
                    chunks_completed=chunks,
                ) from None
            _validate_adapter_count(
                deleted,
                self._config.cleanup_chunk_size,
                phase=RetentionFailurePhase.ROW_CLEANUP,
                deleted_rows=age_deleted + row_deleted,
                chunks=chunks,
            )
            if deleted == 0:
                break
            row_deleted += deleted
            chunks += 1
            if deleted < self._config.cleanup_chunk_size:
                break

        after = self._diagnostics_after_cleanup(age_deleted + row_deleted, chunks)
        return HistoryCleanupResult(
            cutoff=cutoff,
            age_deleted_rows=age_deleted,
            row_limit_deleted_rows=row_deleted,
            chunks_completed=chunks,
            interrupted=False,
            before=before,
            after=after,
        )

    def _interrupted_result(
        self,
        cutoff: datetime,
        age_deleted: int,
        row_deleted: int,
        chunks: int,
        before: HistoryStorageDiagnostics,
    ) -> HistoryCleanupResult:
        after = self._diagnostics_after_cleanup(age_deleted + row_deleted, chunks)
        return HistoryCleanupResult(
            cutoff=cutoff,
            age_deleted_rows=age_deleted,
            row_limit_deleted_rows=row_deleted,
            chunks_completed=chunks,
            interrupted=True,
            before=before,
            after=after,
        )

    def _diagnostics_after_cleanup(
        self,
        deleted_rows: int,
        chunks: int,
    ) -> HistoryStorageDiagnostics:
        try:
            return self._repository.storage_diagnostics()
        except Exception:
            raise HistoryRetentionError(
                RetentionFailurePhase.DIAGNOSTICS,
                deleted_rows=deleted_rows,
                chunks_completed=chunks,
            ) from None


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware and in UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use a UTC offset")
    return value.astimezone(UTC)


def _stop_safely(
    predicate: StopPredicate,
    deleted_rows: int,
    chunks: int,
) -> bool:
    try:
        result = predicate()
    except Exception:
        raise HistoryRetentionError(
            RetentionFailurePhase.INTERRUPTION,
            deleted_rows=deleted_rows,
            chunks_completed=chunks,
        ) from None
    if not isinstance(result, bool):
        raise HistoryRetentionError(
            RetentionFailurePhase.INTERRUPTION,
            deleted_rows=deleted_rows,
            chunks_completed=chunks,
        )
    return result


def _validate_adapter_count(
    deleted: int,
    chunk_size: int,
    *,
    phase: RetentionFailurePhase,
    deleted_rows: int,
    chunks: int,
) -> None:
    if isinstance(deleted, bool) or not isinstance(deleted, int):
        raise HistoryRetentionError(
            phase,
            deleted_rows=deleted_rows,
            chunks_completed=chunks,
        )
    if not 0 <= deleted <= chunk_size:
        raise HistoryRetentionError(
            phase,
            deleted_rows=deleted_rows,
            chunks_completed=chunks,
        )


__all__ = (
    "HistoryCleanupResult",
    "HistoryRetentionError",
    "HistoryRetentionService",
    "RetentionFailurePhase",
)
