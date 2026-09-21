"""Application services package."""

from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.history import (
    ConnectionHistoryPersistence,
    ConnectionHistoryWriter,
)
from netsentinel.application.services.history_query import (
    ConnectionHistoryPage,
    ConnectionHistoryQueryService,
)
from netsentinel.application.services.retention import (
    HistoryCleanupResult,
    HistoryRetentionError,
    HistoryRetentionService,
    RetentionFailurePhase,
)
from netsentinel.application.services.statistics import (
    StatisticsService,
    StatisticsSnapshot,
)

__all__ = (
    "ConnectionTrackingService",
    "ConnectionHistoryPersistence",
    "ConnectionHistoryWriter",
    "ConnectionHistoryPage",
    "ConnectionHistoryQueryService",
    "HistoryCleanupResult",
    "HistoryRetentionError",
    "HistoryRetentionService",
    "RetentionFailurePhase",
    "StatisticsService",
    "StatisticsSnapshot",
)
