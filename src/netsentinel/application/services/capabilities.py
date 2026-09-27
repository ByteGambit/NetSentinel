"""NS-048 portable capability matrix derived from existing diagnostics and probes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from netsentinel.application.ports import NetworkContextPermissionDenied, NetworkContextProvider, PacketCapture
from netsentinel.shared.diagnostics import (
    CapabilityStatus, CaptureCapabilityReason, DatabaseStatus, DiagnosticsSnapshot,
)


@dataclass(frozen=True, slots=True)
class FeatureCapability:
    name: str
    status: CapabilityStatus
    reason: str


@dataclass(frozen=True, slots=True)
class CapabilityMatrix:
    features: tuple[FeatureCapability, ...]
    diagnostics: DiagnosticsSnapshot
    interface_context: str
    is_elevated: bool | None = None


class CapabilityService:
    """Runs on a caller-owned worker. Probing never starts passive capture."""

    def __init__(
        self,
        contexts: NetworkContextProvider,
        capture: PacketCapture,
        diagnostics: Callable[[], DiagnosticsSnapshot],
        privilege_probe: Callable[[], bool | None] | None = None,
    ) -> None:
        self._contexts = contexts
        self._capture = capture
        self._diagnostics = diagnostics
        self._privilege_probe = privilege_probe

    def check(self) -> CapabilityMatrix:
        context_state = "interface_unavailable"
        try:
            contexts = tuple(c for c in self._contexts.get_contexts() if not c.is_loopback)
        except NetworkContextPermissionDenied:
            contexts = ()
            context_state = "permission_denied"
        except Exception:
            contexts = ()
            context_state = "context_unavailable"
        if contexts:
            context_state = "interface_available"
            # Readiness only. The Devices page still requires an explicit user
            # action to open a capture handle on the current selected network.
            try:
                self._capture.probe(contexts[0])
            except Exception:
                context_state = "probe_unavailable"
        snapshot = self._diagnostics()
        capture = snapshot.capture.capability if snapshot.capture is not None else None
        if contexts and capture is not None and context_state != "probe_unavailable":
            capture_status = capture.status
            capture_reason = capture.reason.value
        else:
            capture_status = CapabilityStatus.UNAVAILABLE
            capture_reason = context_state
        database_ok = snapshot.database.status is DatabaseStatus.AVAILABLE
        connection = snapshot.engine.capabilities.connection_monitoring
        process = snapshot.engine.capabilities.process_metadata
        db_status = CapabilityStatus.AVAILABLE if database_ok else CapabilityStatus.UNAVAILABLE
        db_reason = "local_storage_available" if database_ok else "local_storage_unavailable"
        passive_status = (
            CapabilityStatus.AVAILABLE if capture_status is CapabilityStatus.AVAILABLE and database_ok
            else CapabilityStatus.DEGRADED if database_ok else CapabilityStatus.UNAVAILABLE
        )
        passive_reason = (
            "passive_capture_available" if passive_status is CapabilityStatus.AVAILABLE
            else "saved_data_only" if database_ok else "local_storage_unavailable"
        )
        try:
            elevated = self._privilege_probe() if self._privilege_probe is not None else None
        except Exception:
            elevated = None
        return CapabilityMatrix((
            FeatureCapability("Connections", connection, "connection_monitoring"),
            FeatureCapability("Process details", process, "process_metadata"),
            FeatureCapability("History", db_status, db_reason),
            FeatureCapability("Packet capture", capture_status, capture_reason),
            FeatureCapability("Devices", passive_status, passive_reason),
            FeatureCapability("DNS", passive_status, passive_reason),
            FeatureCapability("Alerts", passive_status, passive_reason),
        ), snapshot, context_state, elevated)


__all__ = ("CapabilityMatrix", "CapabilityService", "FeatureCapability")
