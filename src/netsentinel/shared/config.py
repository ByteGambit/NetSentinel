"""Portable configuration values shared across application compositions."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_HISTORY_ROWS = 100_000
DEFAULT_CLEANUP_CHUNK_SIZE = 500


def _require_positive_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be greater than zero")


@dataclass(frozen=True, slots=True)
class HistoryRetentionConfig:
    """Portable connection-history retention policy.

    Both age and row policies are always enabled.  The row limit counts active
    and completed lifecycle records together, while cleanup may delete only
    completed records.  Each committed delete is bounded by ``cleanup_chunk_size``.
    """

    retention_days: int = DEFAULT_RETENTION_DAYS
    max_history_rows: int = DEFAULT_MAX_HISTORY_ROWS
    cleanup_chunk_size: int = DEFAULT_CLEANUP_CHUNK_SIZE

    def __post_init__(self) -> None:
        _require_positive_int(self.retention_days, "retention_days")
        _require_positive_int(self.max_history_rows, "max_history_rows")
        _require_positive_int(self.cleanup_chunk_size, "cleanup_chunk_size")


__all__ = (
    "DEFAULT_CLEANUP_CHUNK_SIZE",
    "DEFAULT_MAX_HISTORY_ROWS",
    "DEFAULT_RETENTION_DAYS",
    "HistoryRetentionConfig",
)
