"""Portable, immutable detector events (alert lifecycle belongs to NS-028)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from datetime import UTC, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address
from uuid import UUID

from netsentinel.domain.devices import DeviceIdentity, GatewayBaselineStatus, IdentityBinding
from netsentinel.domain.observations import MacAddress


class ArpIdentityRule(str, Enum):
    IP_MAC_CONFLICT = "ip_mac_conflict"
    GATEWAY_MAC_CHANGE = "gateway_mac_change"


class ArpIdentityReason(str, Enum):
    RECENT_SENDER_CONFLICT = "recent_sender_conflict"
    LEARNED_GATEWAY_CONFLICT = "learned_gateway_conflict"
    VERIFIED_GATEWAY_CONFLICT = "verified_gateway_conflict"


@dataclass(frozen=True, slots=True)
class ArpIdentityEvidence:
    network_fingerprint: str
    ip_address: str
    expected_mac: MacAddress
    observed_mac: MacAddress
    expected_last_seen_at: datetime
    observed_at: datetime
    baseline_status: GatewayBaselineStatus | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.network_fingerprint, str) or len(self.network_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.network_fingerprint):
            raise ValueError("network_fingerprint must be canonical SHA-256 hex")
        object.__setattr__(self, "ip_address", str(IPv4Address(self.ip_address)))
        if not isinstance(self.expected_mac, MacAddress) or not isinstance(self.observed_mac, MacAddress) or self.expected_mac == self.observed_mac:
            raise ValueError("evidence requires two distinct MAC addresses")
        for name in ("expected_last_seen_at", "observed_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
            object.__setattr__(self, name, value.astimezone(UTC))
        if self.observed_at <= self.expected_last_seen_at:
            raise ValueError("observed_at must follow expected_last_seen_at")
        if self.baseline_status is not None and not isinstance(self.baseline_status, GatewayBaselineStatus):
            raise TypeError("baseline_status must be a GatewayBaselineStatus or None")


@dataclass(frozen=True, slots=True)
class ArpIdentityConflictDetected:
    """A passive identity discrepancy, never attribution of an attacker."""

    rule_id: ArpIdentityRule
    reason: ArpIdentityReason
    evidence: ArpIdentityEvidence
    severity: str
    confidence: str
    event_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, ArpIdentityRule) or not isinstance(self.reason, ArpIdentityReason):
            raise TypeError("rule_id and reason must be typed enums")
        if not isinstance(self.evidence, ArpIdentityEvidence):
            raise TypeError("evidence must be ArpIdentityEvidence")
        if self.severity not in ("low", "medium") or self.confidence not in ("low", "moderate"):
            raise ValueError("unsupported severity or confidence")
        payload = ":".join((self.rule_id.value, self.evidence.network_fingerprint,
                            self.evidence.ip_address, str(self.evidence.expected_mac),
                            str(self.evidence.observed_mac)))
        object.__setattr__(self, "event_fingerprint", sha256(payload.encode("ascii")).hexdigest())

    @property
    def observed_at(self) -> datetime:
        return self.evidence.observed_at

    @property
    def entity_id(self) -> str:
        return f"{self.evidence.network_fingerprint}:{self.evidence.ip_address}"


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


__all__ = ("ArpIdentityConflictDetected", "ArpIdentityEvidence", "ArpIdentityReason", "ArpIdentityRule", "NewDeviceDetected")
