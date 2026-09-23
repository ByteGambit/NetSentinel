"""Composition root for NetSentinel application and infrastructure adapters."""

from __future__ import annotations

from os import PathLike
from collections.abc import Callable

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.ports import NetworkContextProvider, PacketCapture
from netsentinel.application.services.connections import (
    ConnectionTrackingService,
)
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.dns_config import DnsConfigMonitoringService
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.history import ConnectionHistoryPersistence
from netsentinel.application.services.history_query import ConnectionHistoryQueryService
from netsentinel.application.services.retention import HistoryRetentionService
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.infrastructure.psutil_connections import (
    PsutilConnectionCollector,
)
from netsentinel.infrastructure.psutil_processes import (
    PsutilProcessMetadataResolver,
)
from netsentinel.infrastructure.windows_network import WindowsNetworkContextProvider
from netsentinel.infrastructure.scapy_capture import ScapyCaptureWorker
from netsentinel.infrastructure.sqlite import (
    SQLiteDatabase,
    SQLiteConnectionHistoryRepository,
    SQLiteHistoryRetentionRepository,
    SQLiteHistoryWriter,
)
from netsentinel.infrastructure.sqlite.repositories import (
    SQLiteDeviceRepository, SQLiteGatewayBaselineRepository,
)
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
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
    database = SQLiteDatabase(database_path)
    dns_config = DnsConfigMonitoringService(
        create_network_context_provider(),
        AlertService(SQLiteAlertRepository(database)),
    )
    return MonitoringEngine(
        collector=PsutilConnectionCollector(),
        enricher=ProcessMetadataEnricher(PsutilProcessMetadataResolver()),
        tracker=ConnectionTrackingService(),
        dispatcher=dispatcher,
        polling_interval=polling_interval,
        shutdown_timeout=shutdown_timeout,
        persistence=persistence,
        dns_config_poller=dns_config,
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


def create_history_query_service_factory(
    *,
    database_path: str | PathLike[str] | None = None,
) -> Callable[[], ConnectionHistoryQueryService]:
    """Return a factory whose repository is constructed in the query worker."""

    database = SQLiteDatabase(database_path)

    def create_service() -> ConnectionHistoryQueryService:
        return ConnectionHistoryQueryService(
            SQLiteConnectionHistoryRepository(database)
        )

    return create_service


def create_alert_query_service_factory(
    *, database_path: str | PathLike[str] | None = None,
) -> Callable[[], AlertQueryService]:
    """Construct the alert port/service inside its owning query worker."""

    database = SQLiteDatabase(database_path)

    def create_service() -> AlertQueryService:
        return AlertQueryService(AlertService(SQLiteAlertRepository(database)))

    return create_service


def create_network_context_provider() -> NetworkContextProvider:
    """Create the synchronous NS-019 read-only Windows context adapter."""

    return WindowsNetworkContextProvider()


def create_packet_capture(
    *,
    context_provider: NetworkContextProvider | None = None,
    queue_capacity: int = 1_024,
    startup_timeout: float = 1.0,
    shutdown_timeout: float = 2.0,
) -> PacketCapture:
    """Create the dormant NS-020 passive capture boundary.

    Construction performs no network read, Scapy import, socket open, or worker
    start.  A concrete NS-019 context and filter are still required by
    ``PacketCapture.start``.
    """

    provider = (
        context_provider
        if context_provider is not None
        else create_network_context_provider()
    )
    return ScapyCaptureWorker(
        provider,
        queue_capacity=queue_capacity,
        startup_timeout=startup_timeout,
        shutdown_timeout=shutdown_timeout,
    )


def create_device_inventory_service_factory(
    *, database_path: str | PathLike[str] | None = None,
) -> Callable[[], DeviceInventoryService]:
    """Create worker-owned portable inventory dependencies without starting capture."""

    def create_service() -> DeviceInventoryService:
        contexts = create_network_context_provider()
        database = SQLiteDatabase(database_path)
        return DeviceInventoryService(
            contexts,
            SQLiteDeviceRepository(database),
            create_packet_capture(context_provider=contexts),
            GatewayBaselineService(SQLiteGatewayBaselineRepository(database), contexts),
            AlertService(SQLiteAlertRepository(database)),
        )

    return create_service


def create_gateway_baseline_service(
    *,
    database_path: str | PathLike[str] | None = None,
    context_provider: NetworkContextProvider | None = None,
) -> GatewayBaselineService:
    """Create a synchronous NS-025 baseline command/read service without I/O."""

    contexts = context_provider or create_network_context_provider()
    return GatewayBaselineService(
        SQLiteGatewayBaselineRepository(SQLiteDatabase(database_path)), contexts
    )


__all__ = (
    "create_alert_query_service_factory",
    "create_desktop_engine",
    "create_device_inventory_service_factory",
    "create_gateway_baseline_service",
    "create_history_retention_service",
    "create_history_query_service_factory",
    "create_monitoring_engine",
    "create_network_context_provider",
    "create_packet_capture",
)
