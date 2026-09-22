"""Portable, immutable detector events (alert lifecycle belongs to NS-028)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from uuid import UUID

from netsentinel.domain.devices import DeviceIdentity, IdentityBinding


@dataclass(frozen=True, slots=True)
class NewDeviceDetected:
    """An unverified device identity first observed after context warm-up.

    This is an informational observation, not a malicious-device verdict.
    ``event_fingerprint`` is stable for one network/device identity, independent
    of its mutable IP binding and observation time.
    """

    device: DeviceIdentity
    binding: IdentityBinding
    observed_at: datetime
    rule_id: str = field(default="new_device", init=False)
    severity: str = field(default="info", init=False)
    confidence: str = field(default="passive_observation", init=False)
    event_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.device, DeviceIdentity):
            raise TypeError("device must be a DeviceIdentity")
        if not isinstance(self.binding, IdentityBinding):
            raise TypeError("binding must be an IdentityBinding")
        if self.binding.device_id != self.device.device_id:
            raise ValueError("binding must belong to device")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be UTC-aware")
        if self.observed_at.utcoffset().total_seconds() != 0:
            raise ValueError("observed_at must use UTC")
        object.__setattr__(
            self,
            "event_fingerprint",
            sha256(f"{self.rule_id}:{self.device.device_id}".encode("ascii")).hexdigest(),
        )

    @property
    def entity_id(self) -> UUID:
        return self.device.device_id


__all__ = ("NewDeviceDetected",)
