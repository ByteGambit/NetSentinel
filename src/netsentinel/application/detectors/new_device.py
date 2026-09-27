"""NS-023 passive new-device detection over the existing device registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
from time import monotonic
from uuid import UUID

from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.domain.alerts import NewDeviceDetected
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext
from netsentinel.domain.observations import PacketObservation


@dataclass(frozen=True, slots=True)
class NewDeviceConfig:
    """First-import learning interval, measured by a monotonic clock.

    Only an empty persisted context enters warm-up. Zero explicitly disables
    learning and makes the first valid sender eligible for an event.
    """

    warmup_seconds: float = 60.0

    def __post_init__(self) -> None:
        if isinstance(self.warmup_seconds, bool) or not isinstance(self.warmup_seconds, (int, float)):
            raise TypeError("warmup_seconds must be a number")
        if not isfinite(self.warmup_seconds) or self.warmup_seconds < 0:
            raise ValueError("warmup_seconds must be finite and nonnegative")


@dataclass(slots=True)
class _ContextState:
    known_ids: set[UUID]
    warmup_started_at: float | None = None
    needs_warmup: bool = False


class NewDeviceDetector:
    """Single-consumer detector; the registry remains the device source of truth.

    The first accepted ARP sender in a never-seen context starts the learning
    interval. Every accepted device is persisted through the existing registry,
    including those seen during warm-up. On restart, persisted identities are
    loaded before processing another observation so they cannot alert again.
    """

    def __init__(
        self,
        registry: DeviceRegistryService,
        *,
        config: NewDeviceConfig | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if not isinstance(registry, DeviceRegistryService):
            raise TypeError("registry must be a DeviceRegistryService")
        if config is not None and not isinstance(config, NewDeviceConfig):
            raise TypeError("config must be a NewDeviceConfig")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._registry = registry
        self._config = config if config is not None else NewDeviceConfig()
        self._clock = clock
        self._contexts: dict[str, _ContextState] = {}

    def observe(
        self, context: NetworkContext, observation: PacketObservation
    ) -> NewDeviceDetected | None:
        event, _ = self.observe_with_state(context, observation)
        return event

    def observe_with_state(
        self, context: NetworkContext, observation: PacketObservation
    ) -> tuple[NewDeviceDetected | None, tuple[DeviceIdentity, IdentityBinding] | None]:
        """Persist a sender and return both NS-023 event and observed registry state.

        Invalid, non-ARP, non-device, or stale-context observations never
        produce an event. Typed registry/repository failures propagate without
        marking a device known, allowing a later valid retry.
        """

        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        if not isinstance(observation, PacketObservation):
            raise TypeError("observation must be a PacketObservation")

        state = self._contexts.get(context.fingerprint)
        if state is None:
            persisted = self._registry.devices(context)
            state = _ContextState(
                known_ids={device.device_id for device in persisted},
                needs_warmup=not persisted,
            )
            self._contexts[context.fingerprint] = state

        result = self._registry.observe(context, observation)
        if result is None:
            return None, None

        device, binding = result
        if device.device_id in state.known_ids:
            return None, result

        # A failed write never arrives here; accepted sender is now durable.
        state.known_ids.add(device.device_id)
        if state.needs_warmup:
            now = self._clock()
            if state.warmup_started_at is None:
                state.warmup_started_at = now
            if now - state.warmup_started_at < self._config.warmup_seconds:
                return None, result
            state.needs_warmup = False

        return NewDeviceDetected(
            device=device, binding=binding, observed_at=observation.observed_at
        ), result


__all__ = ("NewDeviceConfig", "NewDeviceDetector")
