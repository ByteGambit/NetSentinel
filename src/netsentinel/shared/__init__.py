"""Cross-cutting support package."""

from netsentinel.shared.config import (
    DEFAULT_CLEANUP_CHUNK_SIZE,
    DEFAULT_MAX_HISTORY_ROWS,
    DEFAULT_RETENTION_DAYS,
    HistoryRetentionConfig,
)

__all__ = (
    "DEFAULT_CLEANUP_CHUNK_SIZE",
    "DEFAULT_MAX_HISTORY_ROWS",
    "DEFAULT_RETENTION_DAYS",
    "HistoryRetentionConfig",
)
