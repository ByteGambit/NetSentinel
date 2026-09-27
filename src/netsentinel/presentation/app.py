"""PyQt6 application startup and MonitoringEngine lifecycle integration."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import resources
import sys
from typing import Protocol

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon, QPixmap

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.presentation.bridge import EngineEventSource, QtEngineBridge
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator, DeviceServiceFactory
from netsentinel.presentation.device_profile import DeviceProfileCoordinator, ProfileServiceFactory
from netsentinel.presentation.history_query import (
    HistoryQueryCoordinator,
    HistoryServiceFactory,
)
from netsentinel.presentation.alert_query import AlertQueryCoordinator, AlertServiceFactory
from netsentinel.presentation.dns_query import DnsQueryCoordinator, DnsServiceFactory
from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.presentation.views.main_window import MainWindow
from netsentinel.version import __version__


class EngineLifecycle(Protocol):
    """Narrow lifecycle surface required by the desktop shell."""

    def start(self) -> bool: ...

    def stop(self, timeout: float | None = None) -> bool: ...


class DesktopEngine(EngineLifecycle, EngineEventSource, Protocol):
    """Combined engine surface required by the composed desktop application."""


class ApplicationLifecycle:
    """Own bridge attachment and the engine's controlled lifecycle."""

    def __init__(
        self,
        engine: EngineLifecycle,
        bridge: QtEngineBridge,
        history_queries: HistoryQueryCoordinator | None = None,
        device_inventory: DeviceInventoryCoordinator | None = None,
        device_profiles: DeviceProfileCoordinator | None = None,
        alert_queries: AlertQueryCoordinator | None = None,
        dns_queries: DnsQueryCoordinator | None = None,
        capability_queries: CapabilityCoordinator | None = None,
    ) -> None:
        self._engine = engine
        self._bridge = bridge
        self._history_queries = history_queries
        self._device_inventory = device_inventory
        self._device_profiles = device_profiles
        self._alert_queries = alert_queries
        self._dns_queries = dns_queries
        self._capability_queries = capability_queries
        self._start_requested = False
        self._shutdown_requested = False
        self._shutdown_result: bool | None = None

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested

    def start(self) -> bool:
        """Attach the bridge before starting the engine, at most once."""

        if self._start_requested:
            return False
        self._start_requested = True
        if self._history_queries is not None:
            self._history_queries.start()
        if self._alert_queries is not None:
            self._alert_queries.start()
        if self._dns_queries is not None:
            self._dns_queries.start()
        if self._device_inventory is not None:
            self._device_inventory.start()
            self._device_inventory.request("refresh")
        if self._device_profiles is not None:
            self._device_profiles.start()
        if self._capability_queries is not None:
            self._capability_queries.start()
            self._capability_queries.request()
        self._bridge.start()
        try:
            return self._engine.start()
        except BaseException:
            self._bridge.stop()
            if self._history_queries is not None:
                self._history_queries.stop()
            if self._alert_queries is not None:
                self._alert_queries.stop()
            if self._dns_queries is not None:
                self._dns_queries.stop()
            if self._device_inventory is not None:
                self._device_inventory.stop()
            if self._device_profiles is not None:
                self._device_profiles.stop()
            if self._capability_queries is not None:
                self._capability_queries.stop()
            raise

    def shutdown(self) -> bool:
        """Detach GUI delivery, then request one bounded engine stop."""

        if self._shutdown_requested:
            return bool(self._shutdown_result)
        self._shutdown_requested = True
        history_stopped = (
            True
            if self._history_queries is None
            else self._history_queries.stop()
        )
        alerts_stopped = True if self._alert_queries is None else self._alert_queries.stop()
        dns_stopped = True if self._dns_queries is None else self._dns_queries.stop()
        devices_stopped = (
            True if self._device_inventory is None else self._device_inventory.stop()
        )
        profiles_stopped = True if self._device_profiles is None else self._device_profiles.stop()
        capabilities_stopped = True if self._capability_queries is None else self._capability_queries.stop()
        self._bridge.stop()
        self._shutdown_result = self._engine.stop() and history_stopped and alerts_stopped and dns_stopped and devices_stopped and profiles_stopped and capabilities_stopped
        return self._shutdown_result


@dataclass(frozen=True, slots=True)
class ApplicationShell:
    """Objects composing one desktop application run."""

    application: QApplication
    window: MainWindow
    bridge: QtEngineBridge
    lifecycle: ApplicationLifecycle
    history_queries: HistoryQueryCoordinator | None = None
    device_inventory: DeviceInventoryCoordinator | None = None
    device_profiles: DeviceProfileCoordinator | None = None
    alert_queries: AlertQueryCoordinator | None = None
    dns_queries: DnsQueryCoordinator | None = None
    capability_queries: CapabilityCoordinator | None = None


def create_application(
    engine: DesktopEngine,
    argv: Sequence[str] | None = None,
    *,
    history_service_factory: HistoryServiceFactory | None = None,
    device_service_factory: DeviceServiceFactory | None = None,
    profile_service_factory: ProfileServiceFactory | None = None,
    alert_service_factory: AlertServiceFactory | None = None,
    dns_service_factory: DnsServiceFactory | None = None,
    capability_service_factory: Callable[[], CapabilityService] | None = None,
) -> ApplicationShell:
    """Create, but do not show or run, the NetSentinel desktop shell."""

    existing = QApplication.instance()
    if existing is None:
        application = QApplication(list(argv) if argv is not None else [])
    elif isinstance(existing, QApplication):
        application = existing
    else:  # pragma: no cover - defensive guard for unusual embedding hosts
        raise RuntimeError("an incompatible Qt core application already exists")

    application.setApplicationName("NetSentinel")
    application.setOrganizationName("NetSentinel")
    application.setApplicationVersion(__version__)
    icon = QPixmap()
    icon.loadFromData(resources.files("netsentinel.assets").joinpath("netsentinel.ico").read_bytes(), "ICO")
    application.setWindowIcon(QIcon(icon))

    bridge = QtEngineBridge(engine)
    history_queries = (
        HistoryQueryCoordinator(history_service_factory)
        if history_service_factory is not None
        else None
    )
    device_inventory = (
        DeviceInventoryCoordinator(device_service_factory)
        if device_service_factory is not None else None
    )
    device_profiles = DeviceProfileCoordinator(profile_service_factory) if profile_service_factory is not None else None
    alert_queries = AlertQueryCoordinator(alert_service_factory) if alert_service_factory is not None else None
    dns_queries = DnsQueryCoordinator(dns_service_factory) if dns_service_factory is not None else None
    capability_queries = CapabilityCoordinator(capability_service_factory) if capability_service_factory is not None else None
    lifecycle = ApplicationLifecycle(engine, bridge, history_queries, device_inventory, device_profiles, alert_queries, dns_queries, capability_queries)
    window = MainWindow(
        on_close=lifecycle.shutdown,
        statistics=StatisticsService(),
        history_queries=history_queries,
        device_inventory=device_inventory,
        device_profiles=device_profiles,
        alert_queries=alert_queries,
        dns_queries=dns_queries,
        capability_queries=capability_queries,
    )
    bridge.setParent(window)
    if history_queries is not None:
        history_queries.setParent(window)
    if device_inventory is not None:
        device_inventory.setParent(window)
    if device_profiles is not None:
        device_profiles.setParent(window)
    if alert_queries is not None:
        alert_queries.setParent(window)
    if dns_queries is not None:
        dns_queries.setParent(window)
    if capability_queries is not None:
        capability_queries.setParent(window)
    window.bind_engine_bridge(bridge)
    application.aboutToQuit.connect(lifecycle.shutdown)
    return ApplicationShell(application, window, bridge, lifecycle, history_queries, device_inventory, device_profiles, alert_queries, dns_queries, capability_queries)


def run_application(
    argv: Sequence[str] | None = None,
    *,
    engine: DesktopEngine | None = None,
) -> int:
    """Compose dependencies, start monitoring, and enter the Qt event loop."""

    first_run = False
    config_path = None
    config_issues = False
    capability_service_factory = None
    if engine is None:
        # Importing the composition root lazily keeps widget modules free from
        # infrastructure dependencies and keeps GUI tests lightweight.
        from netsentinel.bootstrap import (
            initialize_runtime,
            create_desktop_engine,
            create_history_query_service_factory,
            create_device_inventory_service_factory,
            create_device_profile_service_factory,
            create_alert_query_service_factory,
            create_dns_query_service_factory,
            create_capability_service_factory,
            runtime_config_path,
        )

        config_path = runtime_config_path()
        loaded = initialize_runtime(config_path=config_path)
        settings = loaded.config
        config_issues = bool(loaded.issues)
        first_run = not settings.onboarding_completed
        engine = create_desktop_engine(config=settings)
        capability_service_factory = create_capability_service_factory(engine, config=settings)
        history_service_factory = create_history_query_service_factory()
        device_service_factory = create_device_inventory_service_factory(config=settings)
        profile_service_factory = create_device_profile_service_factory()
        alert_service_factory = create_alert_query_service_factory()
        dns_service_factory = create_dns_query_service_factory()
    else:
        history_service_factory = None
        device_service_factory = None
        profile_service_factory = None
        alert_service_factory = None
        dns_service_factory = None

    shell = create_application(
        engine,
        argv=sys.argv if argv is None else argv,
        history_service_factory=history_service_factory,
        device_service_factory=device_service_factory,
        profile_service_factory=profile_service_factory,
        alert_service_factory=alert_service_factory,
        dns_service_factory=dns_service_factory,
        capability_service_factory=capability_service_factory,
    )
    onboarding = None
    if first_run:
        from netsentinel.presentation.widgets.onboarding import OnboardingDialog
        from netsentinel.shared.config import complete_onboarding

        assert shell.capability_queries is not None and config_path is not None
        shell.capability_queries.start()

        def finish() -> bool:
            try:
                complete_onboarding(config_path, settings)
            except OSError:
                return False
            try:
                shell.lifecycle.start()
            except Exception:
                # Completion is a user preference. A failed core worker must
                # not turn the first-run explanation into an application gate.
                shell.capability_queries.start()
                shell.capability_queries.request()
            shell.window.show()
            return True

        onboarding = OnboardingDialog(shell.capability_queries, finish)
        if config_issues:
            onboarding.error.setText("Configuration invalid; safe defaults are being used.")
        onboarding.rejected.connect(shell.application.quit)
        onboarding.show()
    else:
        shell.lifecycle.start()
        shell.window.show()
    try:
        return shell.application.exec()
    finally:
        # closeEvent and aboutToQuit also use this path. The lifecycle guard
        # ensures the engine receives one bounded stop request only.
        shell.lifecycle.shutdown()
        if onboarding is not None:
            onboarding.close()
        if engine is not None and 'settings' in locals():
            import logging
            from netsentinel.shared.logging import close_logging

            close_logging(logging.getLogger("netsentinel"))


def main() -> int:
    """Run the standalone presentation entry point."""

    return run_application()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "ApplicationLifecycle",
    "ApplicationShell",
    "DesktopEngine",
    "EngineLifecycle",
    "create_application",
    "run_application",
)
