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
from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.application.services.device_inventory import DeviceInventoryService
from netsentinel.application.services.device_profiles import DeviceProfileService
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.dns_config import DnsConfigMonitoringService
from netsentinel.application.services.dns_history import (
    DnsHistoryRetentionService, DnsHistoryWriter, DnsRetentionConfig,
)
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.dns_history_query import DnsHistoryQueryService
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
from netsentinel.infrastructure.windows_privileges import is_process_elevated
from netsentinel.infrastructure.scapy_capture import ScapyCaptureWorker
from netsentinel.infrastructure.sqlite import (
    SQLiteDatabase,
    SQLiteConnectionHistoryRepository,
    SQLiteHistoryRetentionRepository,
    SQLiteHistoryWriter,
)
from netsentinel.infrastructure.sqlite.repositories import (
    SQLiteDeviceRepository, SQLiteDeviceProfileRepository, SQLiteGatewayBaselineRepository,
)
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.dns_repository import (
    SQLiteDnsHistoryRepository, SQLiteDnsHistorySessionFactory,
)
from netsentinel.shared.config import AppConfig, ConfigLoadResult, HistoryRetentionConfig, load_config_file
from netsentinel.shared.diagnostics import DatabaseDiagnostic, DatabaseStatus, DiagnosticsSnapshot
from netsentinel.shared.logging import configure_logging, log_event
from netsentinel.infrastructure.sqlite.database import default_database_path
from netsentinel.application.ports import HistoryStorageDiagnostics
import logging
from pathlib import Path


def create_monitoring_engine(
    *,
    polling_interval: float | None = None,
    shutdown_timeout: float | None = None,
    config: AppConfig | None = None,
) -> MonitoringEngine:
    """Create the NS-006 connection pipeline without starting it or any GUI."""

    settings = config or AppConfig()
    return MonitoringEngine(
        collector=PsutilConnectionCollector(),
        enricher=ProcessMetadataEnricher(PsutilProcessMetadataResolver()),
        tracker=ConnectionTrackingService(),
        dispatcher=EventDispatcher(),
        polling_interval=settings.polling_interval if polling_interval is None else polling_interval,
        shutdown_timeout=settings.shutdown_timeout if shutdown_timeout is None else shutdown_timeout,
    )


def create_desktop_engine(
    *,
    polling_interval: float | None = None,
    shutdown_timeout: float | None = None,
    database_path: str | PathLike[str] | None = None,
    history_queue_capacity: int | None = None,
    history_batch_size: int | None = None,
    history_batch_interval: float = 0.1,
    history_retry_limit: int = 2,
    history_retry_backoff: float = 0.05,
    config: AppConfig | None = None,
) -> MonitoringEngine:
    """Create the production engine with NS-016 history persistence."""

    settings = config or AppConfig()
    polling_interval = settings.polling_interval if polling_interval is None else polling_interval
    shutdown_timeout = settings.shutdown_timeout if shutdown_timeout is None else shutdown_timeout
    history_queue_capacity = settings.history_queue_capacity if history_queue_capacity is None else history_queue_capacity
    history_batch_size = settings.history_batch_size if history_batch_size is None else history_batch_size
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


def create_dns_history_writer(
    *, database_path: str | PathLike[str] | None = None, config: AppConfig | None = None,
    **writer_options: object,
) -> DnsHistoryWriter:
    """Build a dormant NS-033 writer; an NS-031 consumer submits transactions."""

    settings = config or AppConfig()
    writer_options.setdefault("queue_capacity", settings.dns_queue_capacity)
    writer_options.setdefault("batch_size", settings.dns_batch_size)
    return DnsHistoryWriter(
        SQLiteDnsHistorySessionFactory(SQLiteDatabase(database_path)),
        **writer_options,
    )


def create_dns_history_repository(
    *, database_path: str | PathLike[str] | None = None,
) -> SQLiteDnsHistoryRepository:
    return SQLiteDnsHistoryRepository(SQLiteDatabase(database_path))


def create_dns_history_retention_service(
    *, database_path: str | PathLike[str] | None = None,
    config: DnsRetentionConfig | None = None,
) -> DnsHistoryRetentionService:
    return DnsHistoryRetentionService(
        create_dns_history_repository(database_path=database_path), config=config,
    )


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


def create_dns_query_service_factory(
    *, database_path: str | PathLike[str] | None = None,
) -> Callable[[], DnsHistoryQueryService]:
    database = SQLiteDatabase(database_path)

    def create_service() -> DnsHistoryQueryService:
        return DnsHistoryQueryService(SQLiteDnsHistoryRepository(database))

    return create_service


def create_network_context_provider() -> NetworkContextProvider:
    """Create the synchronous NS-019 read-only Windows context adapter."""

    return WindowsNetworkContextProvider()


def create_packet_capture(
    *,
    context_provider: NetworkContextProvider | None = None,
    queue_capacity: int | None = None,
    startup_timeout: float = 1.0,
    shutdown_timeout: float = 2.0,
    config: AppConfig | None = None,
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
        queue_capacity=(config or AppConfig()).capture_queue_capacity if queue_capacity is None else queue_capacity,
        startup_timeout=startup_timeout,
        shutdown_timeout=shutdown_timeout,
    )


def create_device_inventory_service_factory(
    *, database_path: str | PathLike[str] | None = None, config: AppConfig | None = None,
) -> Callable[[], DeviceInventoryService]:
    """Create worker-owned portable inventory dependencies without starting capture."""

    def create_service() -> DeviceInventoryService:
        contexts = create_network_context_provider()
        database = SQLiteDatabase(database_path)
        return DeviceInventoryService(
            contexts,
            SQLiteDeviceRepository(database),
            create_packet_capture(context_provider=contexts, config=config),
            GatewayBaselineService(SQLiteGatewayBaselineRepository(database), contexts),
            AlertService(SQLiteAlertRepository(database)),
            dns_writer=create_dns_history_writer(database_path=database_path, config=config),
            profiles=SQLiteDeviceProfileRepository(database),
            vlan_summary=VlanSummaryService(SQLiteVlanSummaryRepository(database)),
        )

    return create_service


def initialize_runtime(*, config_path: str | Path | None = None, log_path: str | Path | None = None) -> ConfigLoadResult:
    """Load local settings and configure a bounded, privacy-safe log at startup."""

    directory = default_database_path().parent
    result = load_config_file(config_path or directory / "config.json")
    try:
        logger = configure_logging(log_path or directory / "netsentinel.log", result.config)
    except OSError:
        logger = logging.getLogger("netsentinel")
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.NullHandler())
    for issue in result.issues:
        # Field names and user values are deliberately never logged.
        log_event(logger, component="config", code=issue.code)
    return result


def runtime_config_path() -> Path:
    """Return the user-local central config location without creating it."""

    return default_database_path().parent / "config.json"


def collect_diagnostics(
    engine: MonitoringEngine,
    *, capture: PacketCapture | None = None,
    dns_writer: DnsHistoryWriter | None = None,
    storage_probe: Callable[[], HistoryStorageDiagnostics] | None = None,
    database_path: str | PathLike[str] | None = None,
) -> DiagnosticsSnapshot:
    """Collect current health on a caller-owned worker, without starting resources."""

    probe = storage_probe or create_history_retention_service(database_path=database_path).storage_diagnostics
    try:
        storage = probe()
        database = DatabaseDiagnostic(DatabaseStatus.AVAILABLE, storage.database_bytes, storage.wal_bytes, storage.total_rows)
    except Exception:
        database = DatabaseDiagnostic(DatabaseStatus.UNAVAILABLE)
    dns = dns_writer.health_snapshot() if dns_writer is not None else None
    return DiagnosticsSnapshot(
        engine=engine.health_snapshot(),
        persistence=engine.persistence_health_snapshot(),
        capture=capture.health_snapshot() if capture is not None else None,
        database=database,
        dns_writer_running=None if dns is None else dns.running,
        dns_queue_depth=None if dns is None else dns.queue_depth,
        dns_queue_capacity=None if dns is None else dns.queue_capacity,
    )


def create_capability_service_factory(
    engine: MonitoringEngine,
    *, database_path: str | PathLike[str] | None = None,
    config: AppConfig | None = None,
) -> Callable[[], CapabilityService]:
    """Build worker-owned readiness probes; no capture socket is opened."""

    def create_service() -> CapabilityService:
        contexts = create_network_context_provider()
        capture = create_packet_capture(context_provider=contexts, config=config)
        storage = SQLiteHistoryRetentionRepository(
            SQLiteDatabase(database_path, busy_timeout_ms=1_000)
        )
        return CapabilityService(
            contexts, capture,
            lambda: collect_diagnostics(engine, capture=capture, storage_probe=storage.storage_diagnostics),
            is_process_elevated,
        )

    return create_service


def create_device_profile_service_factory(
    *, database_path: str | PathLike[str] | None = None,
) -> Callable[[], DeviceProfileService]:
    database = SQLiteDatabase(database_path)

    def create_service() -> DeviceProfileService:
        return DeviceProfileService(SQLiteDeviceProfileRepository(database))

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
    "initialize_runtime", "runtime_config_path", "collect_diagnostics", "create_capability_service_factory",
    "create_dns_history_repository",
    "create_dns_history_retention_service",
    "create_dns_history_writer",
    "create_dns_query_service_factory",
    "create_alert_query_service_factory",
    "create_desktop_engine",
    "create_device_inventory_service_factory",
    "create_device_profile_service_factory",
    "create_gateway_baseline_service",
    "create_history_retention_service",
    "create_history_query_service_factory",
    "create_monitoring_engine",
    "create_network_context_provider",
    "create_packet_capture",
)
