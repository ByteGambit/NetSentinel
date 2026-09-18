"""Composition root for the GUI-independent connection monitoring engine."""

from __future__ import annotations

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.connections import (
    ConnectionTrackingService,
)
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.infrastructure.psutil_connections import (
    PsutilConnectionCollector,
)
from netsentinel.infrastructure.psutil_processes import (
    PsutilProcessMetadataResolver,
)


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


__all__ = ("create_monitoring_engine",)
