"""Portable, passive device inventory read model for the Devices page."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import Enum

from netsentinel.application.detectors.new_device import NewDeviceDetector
from netsentinel.application.detectors.arp_identity import GatewayMacChangeDetector, IpMacConflictDetector
from netsentinel.application.detectors.arp_anomaly import ArpAnomalyCorrelator
from netsentinel.application.detectors.traffic_rate import TrafficRateDetector
from netsentinel.application.detectors.device_identity import DeviceIdentityChangeDetector
from netsentinel.application.ports import (
    DeviceRepository,
    DeviceProfileRepository,
    NetworkContextPermissionDenied,
    NetworkContextProvider,
    PacketCapture,
    PacketCaptureRequest,
)
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.dns import DnsTrackingService
from netsentinel.application.services.dns_history import DnsHistoryWriter
from netsentinel.application.services.traffic_metrics import TrafficMetricsService, TrafficMetricsSnapshot
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.domain.alerts import ArpIdentityConflictDetected, ArpRiskAssessment, NewDeviceDetected
from netsentinel.domain.alerts import alert_id
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureHealthSnapshot, CaptureState
from netsentinel.shared.config import TrafficRateConfig


MAX_VISIBLE_BINDINGS = 20
CAPTURE_DRAIN_LIMIT = 128


class DeviceInventoryProblem(str, Enum):
    NONE = "none"
    CONTEXT_PERMISSION = "context_permission"
    CONTEXT_UNAVAILABLE = "context_unavailable"
    REPOSITORY_UNAVAILABLE = "repository_unavailable"
    OBSERVATION_UNAVAILABLE = "observation_unavailable"
    ALERT_UNAVAILABLE = "alert_unavailable"


@dataclass(frozen=True, slots=True)
class DeviceInventoryEntry:
    device: DeviceIdentity
    bindings: tuple[IdentityBinding, ...]
    interface_name: str
    subnet: str


@dataclass(frozen=True, slots=True)
class DeviceInventorySnapshot:
    contexts: tuple[NetworkContext, ...]
    selected_fingerprint: str | None
    entries: tuple[DeviceInventoryEntry, ...]
    capture: CaptureHealthSnapshot | None
    problem: DeviceInventoryProblem = DeviceInventoryProblem.NONE
    new_devices: tuple[NewDeviceDetected, ...] = ()
    identity_events: tuple[ArpIdentityConflictDetected, ...] = ()
    arp_assessments: tuple[ArpRiskAssessment, ...] = ()
    dns_persisted_count: int = 0
    dns_writer_available: bool = True
    traffic_metrics: TrafficMetricsSnapshot | None = None
    traffic_policy: TrafficRateConfig | None = None
    traffic_alert_changed: bool = False
    identity_alert_changed: bool = False


class DeviceInventoryService:
    """One worker-owned service; all I/O stays outside the Qt main thread.

    Capture is dormant until an explicit start request. The detector owns its
    warm-up rule. The service only forwards its portable info events.
    """

    def __init__(
        self,
        contexts: NetworkContextProvider,
        repository: DeviceRepository,
        capture: PacketCapture,
        gateway_baseline: GatewayBaselineService | None = None,
        alerts: AlertService | None = None,
        dns_writer: DnsHistoryWriter | None = None,
        dns_tracking: DnsTrackingService | None = None,
        traffic_metrics: TrafficMetricsService | None = None,
        traffic_detector: TrafficRateDetector | None = None,
        traffic_observed_clock: Callable[[], datetime] | None = None,
        profiles: DeviceProfileRepository | None = None,
        vlan_summary: VlanSummaryService | None = None,
    ) -> None:
        self._contexts = contexts
        self._registry = DeviceRegistryService(repository)
        self._detector = NewDeviceDetector(self._registry)
        self._ip_conflicts = IpMacConflictDetector(repository, contexts)
        self._gateway_changes = GatewayMacChangeDetector(gateway_baseline) if gateway_baseline is not None else None
        self._arp_correlation = ArpAnomalyCorrelator()
        self._capture = capture
        self._gateway_baseline = gateway_baseline
        self._alerts = alerts
        self._dns_writer = dns_writer
        self._dns_tracking = dns_tracking or DnsTrackingService()
        self._traffic_metrics = traffic_metrics or TrafficMetricsService()
        self._traffic_detector = traffic_detector or TrafficRateDetector()
        self._traffic_observed_clock = traffic_observed_clock or (lambda: datetime.now(UTC))
        self._profiles = profiles
        self._vlan_summary = vlan_summary
        self._identity_detector = DeviceIdentityChangeDetector() if profiles is not None else None
        if self._dns_writer is not None:
            self._dns_writer.start()
        self._selected: str | None = None

    def refresh(
        self,
        *,
        select: str | None = None,
        start_capture: bool = False,
        stop_capture: bool = False,
    ) -> DeviceInventorySnapshot:
        try:
            contexts = tuple(context for context in self._contexts.get_contexts() if not context.is_loopback)
        except NetworkContextPermissionDenied:
            self._capture.stop(timeout=1.0)
            return DeviceInventorySnapshot((), None, (), self._capture.health_snapshot(), DeviceInventoryProblem.CONTEXT_PERMISSION)
        except Exception:
            self._capture.stop(timeout=1.0)
            return DeviceInventorySnapshot((), None, (), self._capture.health_snapshot(), DeviceInventoryProblem.CONTEXT_UNAVAILABLE)

        by_fingerprint = {context.fingerprint: context for context in contexts}
        selected = select if select is not None else self._selected
        if selected not in by_fingerprint:
            selected = next(iter(by_fingerprint), None)
        context = by_fingerprint.get(selected)
        observation_failed = False
        health = self._capture.health_snapshot()
        if health.running and health.network_fingerprint != selected:
            self._capture.stop(timeout=1.0)
        self._selected = selected
        if stop_capture:
            self._capture.stop(timeout=1.0)
        elif start_capture and context is not None:
            capture_filter = "arp or ether broadcast or ip broadcast or vlan"
            if self._dns_writer is not None:
                capture_filter += " or port 53"
            self._capture.start(PacketCaptureRequest(context, capture_filter))
        health = self._capture.health_snapshot()
        if context is not None and health.running:
            try:
                self._traffic_metrics.record_capture_health(context, health)
            except Exception:
                observation_failed = True
        if context is not None and not health.running and health.capability.reason is CaptureCapabilityReason.NOT_PROBED:
            self._capture.probe(context)
            health = self._capture.health_snapshot()

        events: list[NewDeviceDetected] = []
        identity_events: list[ArpIdentityConflictDetected] = []
        assessments: list[ArpRiskAssessment] = []
        alert_failed = False
        identity_alert_changed = False
        profile_ready = False
        if context is not None and health.state is CaptureState.RUNNING and self._profiles is not None:
            try:
                now = self._traffic_observed_clock()
                rows = self._profiles.snapshot_for_network(context.fingerprint, now - timedelta(minutes=5))
                self._identity_detector.replace_snapshot(context.fingerprint, rows, now)
                profile_ready = True
            except Exception:
                observation_failed = True
        if context is not None and health.state is CaptureState.RUNNING:
            try:
                for observation in self._capture.drain(min(CAPTURE_DRAIN_LIMIT, health.queue_capacity)):
                    try:
                        belongs_to_context = observation.network_fingerprint == context.fingerprint
                    except (AttributeError, TypeError):
                        observation_failed = True
                        continue
                    if not belongs_to_context:
                        continue
                    try:
                        self._traffic_metrics.observe(context, observation)
                    except Exception:
                        observation_failed = True
                    if self._vlan_summary is not None and observation.vlan is not None:
                        try:
                            self._vlan_summary.observe(context, observation)
                        except Exception:
                            observation_failed = True
                    if self._dns_writer is not None and observation.dns is not None:
                        try:
                            for transaction in self._dns_tracking.observe(observation):
                                self._dns_writer.submit(transaction)
                        except Exception:
                            observation_failed = True
                        continue
                    packet_events: list[ArpIdentityConflictDetected] = []
                    try:
                        conflict = self._ip_conflicts.observe(context, observation)
                    except Exception:
                        conflict = None
                        observation_failed = True
                    try:
                        event, observed = self._detector.observe_with_state(context, observation)
                        if event is not None:
                            events.append(event)
                            if self._alerts is not None:
                                try:
                                    self._alerts.record(event)
                                except Exception:
                                    alert_failed = True
                        if conflict is not None:
                            identity_events.append(conflict)
                            packet_events.append(conflict)
                    except Exception:
                        observation_failed = True
                        observed = None
                    if profile_ready and observed is not None:
                        try:
                            for candidate in self._identity_detector.observe(
                                context, observed[0], observed[1], observation.observed_at
                            ):
                                if self._alerts is not None:
                                    try:
                                        self._alerts.record(candidate)
                                        self._identity_detector.mark_persisted(candidate)
                                        identity_alert_changed = True
                                    except Exception:
                                        alert_failed = True
                        except Exception:
                            observation_failed = True
                    if self._gateway_baseline is not None:
                        try:
                            gateway_event = self._gateway_changes.observe(context, observation)
                            self._gateway_baseline.observe(context, observation)
                            if gateway_event is not None:
                                identity_events.append(gateway_event)
                                packet_events.append(gateway_event)
                        except Exception:
                            observation_failed = True
                    try:
                        new_assessments = self._arp_correlation.observe(context, observation, packet_events)
                        assessments.extend(new_assessments)
                        if self._alerts is not None:
                            for assessment in new_assessments:
                                try:
                                    self._alerts.record(assessment)
                                except Exception:
                                    alert_failed = True
                    except Exception:
                        observation_failed = True
            except Exception:
                observation_failed = True
            try:
                health = self._capture.health_snapshot()
                self._traffic_metrics.record_capture_health(context, health)
            except Exception:
                observation_failed = True
        if self._dns_writer is not None:
            try:
                for transaction in self._dns_tracking.expire():
                    self._dns_writer.submit(transaction)
            except Exception:
                observation_failed = True

        if context is None:
            return DeviceInventorySnapshot(contexts, None, (), health)
        try:
            entries = tuple(
                DeviceInventoryEntry(
                    device=device,
                    bindings=self._registry.bindings(device, MAX_VISIBLE_BINDINGS),
                    interface_name=context.interface_name,
                    subnet=context.subnet,
                )
                for device in self._registry.devices(context)
            )
        except Exception:
            return DeviceInventorySnapshot(contexts, selected, (), health, DeviceInventoryProblem.REPOSITORY_UNAVAILABLE)
        problem = (DeviceInventoryProblem.OBSERVATION_UNAVAILABLE if observation_failed else
                   DeviceInventoryProblem.ALERT_UNAVAILABLE if alert_failed else DeviceInventoryProblem.NONE)
        dns_health = self._dns_writer.health_snapshot() if self._dns_writer is not None else None
        try:
            traffic_snapshot = self._traffic_metrics.snapshot(context)
        except Exception:
            traffic_snapshot = None
            observation_failed = True
            problem = DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
        traffic_alert_changed = False
        if traffic_snapshot is not None and health.state is CaptureState.RUNNING and self._alerts is not None:
            try:
                decisions = self._traffic_detector.assess(traffic_snapshot, self._traffic_observed_clock())
                for decision in decisions:
                    try:
                        if decision.candidate is not None:
                            self._alerts.record(decision.candidate)
                            traffic_alert_changed = True
                        elif decision.resolved_fingerprint is not None:
                            self._alerts.resolve(alert_id(decision.resolved_fingerprint))
                            traffic_alert_changed = True
                    except Exception:
                        alert_failed = True
                        self._traffic_detector.retry_after_alert_failure(decision)
            except Exception:
                observation_failed = True
        problem = (DeviceInventoryProblem.OBSERVATION_UNAVAILABLE if observation_failed else
                   DeviceInventoryProblem.ALERT_UNAVAILABLE if alert_failed else problem)
        return DeviceInventorySnapshot(
            contexts, selected, entries, health, problem,
            tuple(events), tuple(identity_events), tuple(assessments),
            dns_health.persisted if dns_health is not None else 0,
            dns_health.running if dns_health is not None else True,
            traffic_snapshot,
            self._traffic_detector.config,
            traffic_alert_changed,
            identity_alert_changed,
        )

    def close(self) -> bool:
        capture_stopped = self._capture.stop(timeout=1.0)
        writer_stopped = True if self._dns_writer is None else self._dns_writer.stop()
        return capture_stopped and writer_stopped


__all__ = (
    "DeviceInventoryEntry", "DeviceInventoryProblem", "DeviceInventoryService",
    "DeviceInventorySnapshot", "MAX_VISIBLE_BINDINGS",
)
