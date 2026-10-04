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
from netsentinel.application.services.executable_signer import ExecutableSignerService
from netsentinel.presentation.bridge import EngineEventSource, QtEngineBridge
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator, DeviceServiceFactory
from netsentinel.presentation.device_profile import DeviceProfileCoordinator, ProfileServiceFactory
from netsentinel.presentation.history_query import (
    HistoryQueryCoordinator,
    HistoryServiceFactory,
)
from netsentinel.presentation.destination_query import DestinationQueryCoordinator, DestinationServiceFactory
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator, BaselineDetailServiceFactory
from netsentinel.presentation.incident_query import IncidentQueryCoordinator, IncidentTimelineServiceFactory
from netsentinel.presentation.risk_query import RiskQueryCoordinator, RiskExplanationServiceFactory
from netsentinel.presentation.preference_commands import PreferenceCommandCoordinator, PreferenceServiceFactory
from netsentinel.presentation.alert_query import AlertQueryCoordinator, AlertServiceFactory
from netsentinel.presentation.dns_query import DnsQueryCoordinator, DnsServiceFactory
from netsentinel.presentation.capability_query import CapabilityCoordinator
from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.presentation.views.main_window import MainWindow
from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupScheduler
from netsentinel.presentation.widgets.threat_intel_lookup import ThreatIntelLookupWidget, ThreatIntelRiskSubmit
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
        destination_queries: tuple[DestinationQueryCoordinator, DestinationQueryCoordinator] | None = None,
        signer_service: ExecutableSignerService | None = None,
        baseline_queries: BaselineQueryCoordinator | None = None,
        preference_commands: PreferenceCommandCoordinator | None = None,
        risk_queries: tuple[RiskQueryCoordinator, RiskQueryCoordinator] | None = None,
        threat_intel_scheduler: ThreatIntelLookupScheduler | None = None,
        threat_intel_lookup: ThreatIntelLookupWidget | None = None,
        incident_queries: tuple[IncidentQueryCoordinator, IncidentQueryCoordinator] | None = None,
        incident_risk_queries: RiskQueryCoordinator | None = None,
    ) -> None:
        self._engine = engine
        self._bridge = bridge
        self._history_queries = history_queries
        self._destination_queries = destination_queries or ()
        self._signer_service = signer_service
        self._baseline_queries = baseline_queries
        self._preference_commands = preference_commands
        self._incident_queries = incident_queries or ()
        self._incident_risk_queries = incident_risk_queries
        self._risk_queries = risk_queries or ()
        self._threat_intel = threat_intel_scheduler
        self._threat_intel_lookup = threat_intel_lookup
        self._threat_intel_failed = False
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
        if self._threat_intel is not None:
            try:
                self._threat_intel_failed = not self._threat_intel.start()
            except Exception:
                self._threat_intel_failed = True
        for query in self._incident_queries:
            query.start()
        if self._incident_risk_queries is not None:
            self._incident_risk_queries.start()
        for query in self._risk_queries:
            query.start()
        if self._preference_commands is not None:
            self._preference_commands.start()
        if self._baseline_queries is not None:
            self._baseline_queries.start()
        if self._history_queries is not None:
            self._history_queries.start()
        for destination_query in self._destination_queries:
            destination_query.start()
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
            if self._threat_intel_lookup is not None:
                self._threat_intel_lookup.stop()
            if self._threat_intel is not None:
                self._threat_intel.stop()
            for query in self._incident_queries:
                query.stop()
            if self._incident_risk_queries is not None:
                self._incident_risk_queries.stop()
            for query in self._risk_queries:
                query.stop()
            if self._preference_commands is not None:
                self._preference_commands.stop()
            if self._baseline_queries is not None:
                self._baseline_queries.stop()
            self._bridge.stop()
            if self._history_queries is not None:
                self._history_queries.stop()
            for destination_query in self._destination_queries:
                destination_query.stop()
            if self._signer_service is not None:
                self._signer_service.stop()
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
        if self._threat_intel_lookup is not None:
            self._threat_intel_lookup.stop()
        ti_stopped = True if self._threat_intel is None else self._threat_intel.stop()
        incident_stopped = all(tuple(query.stop() for query in self._incident_queries))
        incident_risk_stopped = True if self._incident_risk_queries is None else self._incident_risk_queries.stop()
        risk_stopped = all(tuple(query.stop() for query in self._risk_queries))
        preferences_stopped = True if self._preference_commands is None else self._preference_commands.stop()
        baseline_stopped = True if self._baseline_queries is None else self._baseline_queries.stop()
        history_stopped = (
            True
            if self._history_queries is None
            else self._history_queries.stop()
        )
        destination_stopped = all(tuple(query.stop() for query in self._destination_queries))
        signer_stopped = True if self._signer_service is None else self._signer_service.stop()
        alerts_stopped = True if self._alert_queries is None else self._alert_queries.stop()
        dns_stopped = True if self._dns_queries is None else self._dns_queries.stop()
        devices_stopped = (
            True if self._device_inventory is None else self._device_inventory.stop()
        )
        profiles_stopped = True if self._device_profiles is None else self._device_profiles.stop()
        capabilities_stopped = True if self._capability_queries is None else self._capability_queries.stop()
        self._bridge.stop()
        self._shutdown_result = self._engine.stop() and incident_stopped and incident_risk_stopped and ti_stopped and risk_stopped and preferences_stopped and baseline_stopped and history_stopped and destination_stopped and signer_stopped and alerts_stopped and dns_stopped and devices_stopped and profiles_stopped and capabilities_stopped
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
    destination_queries: tuple[DestinationQueryCoordinator, DestinationQueryCoordinator] | None = None
    signer_service: ExecutableSignerService | None = None
    baseline_queries: BaselineQueryCoordinator | None = None
    preference_commands: PreferenceCommandCoordinator | None = None
    risk_queries: tuple[RiskQueryCoordinator, RiskQueryCoordinator] | None = None
    threat_intel_scheduler: ThreatIntelLookupScheduler | None = None
    incident_queries: tuple[IncidentQueryCoordinator, IncidentQueryCoordinator] | None = None
    incident_risk_queries: RiskQueryCoordinator | None = None


def create_application(
    engine: DesktopEngine,
    argv: Sequence[str] | None = None,
    *,
    history_service_factory: HistoryServiceFactory | None = None,
    destination_service_factory: DestinationServiceFactory | None = None,
    signer_service: ExecutableSignerService | None = None,
    baseline_service_factory: BaselineDetailServiceFactory | None = None,
    preference_service_factory: PreferenceServiceFactory | None = None,
    risk_service_factory: RiskExplanationServiceFactory | None = None,
    incident_service_factory: IncidentTimelineServiceFactory | None = None,
    device_service_factory: DeviceServiceFactory | None = None,
    profile_service_factory: ProfileServiceFactory | None = None,
    alert_service_factory: AlertServiceFactory | None = None,
    dns_service_factory: DnsServiceFactory | None = None,
    capability_service_factory: Callable[[], CapabilityService] | None = None,
    threat_intel_consent_service: ThreatIntelConsentService | None = None,
    threat_intel_scheduler: ThreatIntelLookupScheduler | None = None,
    threat_intel_risk_submit: ThreatIntelRiskSubmit | None = None,
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
    destination_queries = (DestinationQueryCoordinator(destination_service_factory),
                           DestinationQueryCoordinator(destination_service_factory)) if destination_service_factory else None
    device_inventory = (
        DeviceInventoryCoordinator(device_service_factory)
        if device_service_factory is not None else None
    )
    device_profiles = DeviceProfileCoordinator(profile_service_factory) if profile_service_factory is not None else None
    alert_queries = AlertQueryCoordinator(alert_service_factory) if alert_service_factory is not None else None
    dns_queries = DnsQueryCoordinator(dns_service_factory) if dns_service_factory is not None else None
    capability_queries = CapabilityCoordinator(capability_service_factory) if capability_service_factory is not None else None
    baseline_queries = BaselineQueryCoordinator(baseline_service_factory) if baseline_service_factory else None
    preference_commands = PreferenceCommandCoordinator(preference_service_factory) if preference_service_factory else None
    risk_queries = (RiskQueryCoordinator(risk_service_factory), RiskQueryCoordinator(risk_service_factory)) if risk_service_factory else None
    incident_queries = (IncidentQueryCoordinator(incident_service_factory), IncidentQueryCoordinator(incident_service_factory)) if incident_service_factory else None
    incident_risk_queries = RiskQueryCoordinator(risk_service_factory) if risk_service_factory and incident_service_factory else None
    ti_lookup = ThreatIntelLookupWidget(threat_intel_scheduler, threat_intel_consent_service, threat_intel_risk_submit)
    lifecycle = ApplicationLifecycle(engine, bridge, history_queries, device_inventory, device_profiles, alert_queries, dns_queries, capability_queries, destination_queries, signer_service, baseline_queries, preference_commands, risk_queries, threat_intel_scheduler, ti_lookup, incident_queries, incident_risk_queries)
    window = MainWindow(
        on_close=lifecycle.shutdown,
        statistics=StatisticsService(),
        history_queries=history_queries,
        destination_queries=destination_queries,
        signer_service=signer_service,
        baseline_queries=baseline_queries,
        preference_commands=preference_commands,
        risk_queries=risk_queries,
        incident_queries=incident_queries,
        incident_risk_queries=incident_risk_queries,
        device_inventory=device_inventory,
        device_profiles=device_profiles,
        alert_queries=alert_queries,
        dns_queries=dns_queries,
        capability_queries=capability_queries,
        threat_intel_consent_service=threat_intel_consent_service,
        threat_intel_lookup=ti_lookup,
    )
    for query in incident_queries or ():
        query.setParent(window)
    if incident_risk_queries is not None:
        incident_risk_queries.setParent(window)
    bridge.setParent(window)
    for query in risk_queries or ():
        query.setParent(window)
    if preference_commands is not None:
        preference_commands.setParent(window)
    if baseline_queries is not None:
        baseline_queries.setParent(window)
    if history_queries is not None:
        history_queries.setParent(window)
    if destination_queries is not None:
        for destination_query in destination_queries:
            destination_query.setParent(window)
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
    return ApplicationShell(application, window, bridge, lifecycle, history_queries, device_inventory, device_profiles, alert_queries, dns_queries, capability_queries, destination_queries, signer_service, baseline_queries, preference_commands, risk_queries, threat_intel_scheduler, incident_queries, incident_risk_queries)


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
    baseline_service_factory = None
    preference_service_factory = None
    risk_service_factory = None
    threat_intel_consent_service = None
    threat_intel_scheduler = None
    threat_intel_risk_submit: ThreatIntelRiskSubmit | None = None
    incident_service_factory = None
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
            create_destination_evidence_service_factory,
            create_executable_signer_service,
            create_capability_service_factory,
            create_baseline_detail_service_factory,
            create_risk_explanation_service_factory,
            create_incident_timeline_service_factory,
            create_preference_command_service_factory,
            runtime_config_path,
            create_threat_intel_consent_service,
            create_threat_intel_scheduler,
            ABUSEIPDB_DESCRIPTOR,
        )

        config_path = runtime_config_path()
        loaded = initialize_runtime(config_path=config_path)
        settings = loaded.config
        threat_intel_consent_service = create_threat_intel_consent_service(
            config_path=config_path, descriptors=(ABUSEIPDB_DESCRIPTOR,))
        try:
            threat_intel_scheduler = create_threat_intel_scheduler(threat_intel_consent_service)
        except Exception:
            pass  # optional TI construction cannot prevent local monitoring
        config_issues = bool(loaded.issues)
        first_run = not settings.onboarding_completed
        engine = create_desktop_engine(config=settings)
        behavior_risk = getattr(engine, "behavior_risk", None)
        threat_intel_risk_submit = behavior_risk.worker.submit_threat_intelligence if behavior_risk else None
        baseline_service_factory = create_baseline_detail_service_factory(engine)
        risk_service_factory = create_risk_explanation_service_factory(engine)
        incident_service_factory = create_incident_timeline_service_factory()
        preference_service_factory = create_preference_command_service_factory()
        capability_service_factory = create_capability_service_factory(
            engine, config=settings, threat_intel=threat_intel_scheduler)
        history_service_factory = create_history_query_service_factory()
        device_service_factory = create_device_inventory_service_factory(config=settings)
        profile_service_factory = create_device_profile_service_factory()
        alert_service_factory = create_alert_query_service_factory()
        dns_service_factory = create_dns_query_service_factory()
        destination_service_factory = create_destination_evidence_service_factory(config=settings)
        signer_service = create_executable_signer_service()
    else:
        history_service_factory = None
        device_service_factory = None
        profile_service_factory = None
        alert_service_factory = None
        dns_service_factory = None
        destination_service_factory = None
        signer_service = None

    shell = create_application(
        engine,
        argv=sys.argv if argv is None else argv,
        history_service_factory=history_service_factory,
        device_service_factory=device_service_factory,
        profile_service_factory=profile_service_factory,
        alert_service_factory=alert_service_factory,
        dns_service_factory=dns_service_factory,
        destination_service_factory=destination_service_factory,
        signer_service=signer_service,
        capability_service_factory=capability_service_factory,
        baseline_service_factory=baseline_service_factory,
        preference_service_factory=preference_service_factory,
        risk_service_factory=risk_service_factory,
        incident_service_factory=incident_service_factory,
        threat_intel_consent_service=threat_intel_consent_service,
        threat_intel_scheduler=threat_intel_scheduler,
        threat_intel_risk_submit=threat_intel_risk_submit,
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
            except (OSError, ValueError):
                return False
            try:
                shell.lifecycle.start()
            except Exception:
                # Completion is a user preference. A failed core worker must
                # not turn the first-run explanation into an application gate.
                assert shell.capability_queries is not None
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
