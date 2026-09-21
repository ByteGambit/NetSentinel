"""Composition root for the GUI-independent connection monitoring engine."""

from __future__ import annotations

from os import PathLike

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.connections import (
    ConnectionTrackingService,
)
from netsentinel.application.services.history import ConnectionHistoryPersistence
from netsentinel.application.services.retention import HistoryRetentionService
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.infrastructure.psutil_connections import (
    PsutilConnectionCollector,
)
from netsentinel.infrastructure.psutil_processes import (
    PsutilProcessMetadataResolver,
)
from netsentinel.infrastructure.sqlite import (
    SQLiteDatabase,
    SQLiteHistoryRetentionRepository,
    SQLiteHistoryWriter,
)
from netsentinel.shared.config import HistoryRetentionConfig


def create_monitoring_engine(
    *,
    polling_interval: float = 1.0,
    shutdown_timeout: float = 2.0,
) -> MonitoringEngine:
    """Create the NS-006 connection pipeline without starting it or any GUI."""

    return MonitoringEngine(
        collector=PsutilConnectionCollector(),
        enricher=ProcessMetadataEnricher(PsutilProcessMetadataResolver()),
        tracker=ConnectionTrackingService(),
        dispatcher=EventDispatcher(),
        polling_interval=polling_interval,
        shutdown_timeout=shutdown_timeout,
    )


def create_desktop_engine(
    *,
    polling_interval: float = 1.0,
    shutdown_timeout: float = 2.0,
    database_path: str | PathLike[str] | None = None,
    history_queue_capacity: int = 2_048,
    history_batch_size: int = 64,
    history_batch_interval: float = 0.1,
    history_retry_limit: int = 2,
    history_retry_backoff: float = 0.05,
) -> MonitoringEngine:
    """Create the production engine with NS-016 history persistence."""

    dispatcher = EventDispatcher()
    writer = SQLiteHistoryWriter(
        SQLiteDatabase(database_path),
        queue_capacity=history_queue_capacity,
        batch_size=history_batch_size,
        batch_interval=history_batch_interval,
        retry_limit=history_retry_limit,
        retry_backoff=history_retry_backoff,
        shutdown_timeout=shutdown_timeout,
    )
    persistence = ConnectionHistoryPersistence(dispatcher, writer)
    return MonitoringEngine(
        collector=PsutilConnectionCollector(),
        enricher=ProcessMetadataEnricher(PsutilProcessMetadataResolver()),
        tracker=ConnectionTrackingService(),
        dispatcher=dispatcher,
        polling_interval=polling_interval,
        shutdown_timeout=shutdown_timeout,
        persistence=persistence,
    )


def create_history_retention_service(
    *,
    database_path: str | PathLike[str] | None = None,
    config: HistoryRetentionConfig | None = None,
) -> HistoryRetentionService:
    """Create the synchronous NS-017 manual cleanup command without running it."""

    database = SQLiteDatabase(database_path)
    repository = SQLiteHistoryRetentionRepository(database)
    return HistoryRetentionService(repository, config=config)


__all__ = (
    "create_desktop_engine",
    "create_history_retention_service",
    "create_monitoring_engine",
)
