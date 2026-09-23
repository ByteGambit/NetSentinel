"""Portable, passive device inventory read model for the Devices page."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netsentinel.application.detectors.new_device import NewDeviceDetector
from netsentinel.application.detectors.arp_identity import GatewayMacChangeDetector, IpMacConflictDetector
from netsentinel.application.ports import (
    DeviceRepository,
    NetworkContextPermissionDenied,
    NetworkContextProvider,
    PacketCapture,
    PacketCaptureRequest,
)
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.application.services.baselines import GatewayBaselineService
from netsentinel.domain.alerts import ArpIdentityConflictDetected, NewDeviceDetected
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext
from netsentinel.shared.diagnostics import CaptureCapabilityReason, CaptureHealthSnapshot, CaptureState


MAX_VISIBLE_BINDINGS = 20
CAPTURE_DRAIN_LIMIT = 128


class DeviceInventoryProblem(str, Enum):
    NONE = "none"
    CONTEXT_PERMISSION = "context_permission"
    CONTEXT_UNAVAILABLE = "context_unavailable"
    REPOSITORY_UNAVAILABLE = "repository_unavailable"
    OBSERVATION_UNAVAILABLE = "observation_unavailable"


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
    ) -> None:
        self._contexts = contexts
        self._registry = DeviceRegistryService(repository)
        self._detector = NewDeviceDetector(self._registry)
        self._ip_conflicts = IpMacConflictDetector(repository, contexts)
        self._gateway_changes = GatewayMacChangeDetector(gateway_baseline) if gateway_baseline is not None else None
        self._capture = capture
        self._gateway_baseline = gateway_baseline
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
        health = self._capture.health_snapshot()
        if health.running and health.network_fingerprint != selected:
            self._capture.stop(timeout=1.0)
        self._selected = selected
        if stop_capture:
            self._capture.stop(timeout=1.0)
        elif start_capture and context is not None:
            self._capture.start(PacketCaptureRequest(context, "arp"))
        health = self._capture.health_snapshot()
        if context is not None and not health.running and health.capability.reason is CaptureCapabilityReason.NOT_PROBED:
            self._capture.probe(context)
            health = self._capture.health_snapshot()

        events: list[NewDeviceDetected] = []
        identity_events: list[ArpIdentityConflictDetected] = []
        observation_failed = False
        if context is not None and health.state is CaptureState.RUNNING:
            try:
                for observation in self._capture.drain(CAPTURE_DRAIN_LIMIT):
                    try:
                        belongs_to_context = observation.network_fingerprint == context.fingerprint
                    except (AttributeError, TypeError):
                        observation_failed = True
                        continue
                    if not belongs_to_context:
                        continue
                    try:
                        conflict = self._ip_conflicts.observe(context, observation)
                    except Exception:
                        conflict = None
                        observation_failed = True
                    try:
                        event = self._detector.observe(context, observation)
                        if event is not None:
                            events.append(event)
                        if conflict is not None:
                            identity_events.append(conflict)
                    except Exception:
                        observation_failed = True
                    if self._gateway_baseline is not None:
                        try:
                            gateway_event = self._gateway_changes.observe(context, observation)
                            self._gateway_baseline.observe(context, observation)
                            if gateway_event is not None:
                                identity_events.append(gateway_event)
                        except Exception:
                            observation_failed = True
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
        problem = DeviceInventoryProblem.OBSERVATION_UNAVAILABLE if observation_failed else DeviceInventoryProblem.NONE
        return DeviceInventorySnapshot(contexts, selected, entries, health, problem, tuple(events), tuple(identity_events))

    def close(self) -> bool:
        return self._capture.stop(timeout=1.0)


__all__ = (
    "DeviceInventoryEntry", "DeviceInventoryProblem", "DeviceInventoryService",
    "DeviceInventorySnapshot", "MAX_VISIBLE_BINDINGS",
)
