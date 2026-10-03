"""Portable detector events and bounded, persistent alert records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from datetime import UTC, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import IPv4Address
from uuid import UUID, uuid5, NAMESPACE_URL

from netsentinel.domain.devices import DeviceIdentity, GatewayBaselineStatus, IdentityBinding
from netsentinel.domain.observations import MacAddress
from netsentinel.domain.alert_risk import AlertAssessmentReference, AlertWriteIntent
from netsentinel.domain.connections import NetworkScopeStatus


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


class ArpScoreRule(str, Enum):
    IDENTITY_CONFLICT = "identity_conflict"
    REPEATED_OBSERVATION = "repeated_observation"
    VERIFIED_GATEWAY = "verified_gateway"
    COMBINED_TARGETS = "combined_targets"


@dataclass(frozen=True, slots=True)
class ArpScoreComponent:
    rule: ArpScoreRule
    points: int

    def __post_init__(self) -> None:
        if not isinstance(self.rule, ArpScoreRule) or type(self.points) is not int or self.points <= 0:
            raise ValueError("score component requires a typed rule and positive points")


@dataclass(frozen=True, slots=True)
class ArpRiskAssessment:
    """Bounded correlation of passive evidence; no attack verdict or alert state."""

    source: ArpIdentityConflictDetected
    first_observed_at: datetime
    last_observed_at: datetime
    observation_count: int
    breakdown: tuple[ArpScoreComponent, ...]
    score: int
    confidence: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, ArpIdentityConflictDetected):
            raise TypeError("source must be an identity event")
        for name in ("first_observed_at", "last_observed_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
            object.__setattr__(self, name, value.astimezone(UTC))
        if self.first_observed_at > self.last_observed_at or self.last_observed_at < self.source.observed_at:
            raise ValueError("assessment times must include the source event")
        if type(self.observation_count) is not int or self.observation_count < 1:
            raise ValueError("observation_count must be positive")
        if not self.breakdown or any(not isinstance(part, ArpScoreComponent) for part in self.breakdown):
            raise ValueError("breakdown must contain typed score components")
        if self.score != sum(part.points for part in self.breakdown) or self.confidence not in ("low", "moderate"):
            raise ValueError("score or confidence is invalid")

    @property
    def event_fingerprint(self) -> str:
        return self.source.event_fingerprint

    @property
    def severity(self) -> str:
        return self.source.severity


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
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be UTC-aware")
        offset = self.observed_at.utcoffset()
        if offset is None:
            raise ValueError("observed_at must be UTC-aware")
        if offset.total_seconds() != 0:
            raise ValueError("observed_at must use UTC")
        object.__setattr__(
            self,
            "event_fingerprint",
            sha256(f"{self.rule_id}:{self.device.device_id}".encode("ascii")).hexdigest(),
        )

    @property
    def entity_id(self) -> UUID:
        return self.device.device_id


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


MAX_ALERT_EVIDENCE = 8


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    """Small, typed metadata from a detector or correlator, never packet data."""

    observed_at: datetime
    ip_address: str | None = None
    observed_mac: MacAddress | None = None
    expected_mac: MacAddress | None = None
    expected_last_seen_at: datetime | None = None
    baseline_status: GatewayBaselineStatus | None = None
    score: int | None = None
    breakdown: tuple[ArpScoreComponent, ...] = ()
    observation_count: int = 1
    details: tuple[tuple[str, str], ...] = ()
    assessment: AlertAssessmentReference | None = None

    def __post_init__(self) -> None:
        if self.assessment is not None and not isinstance(self.assessment, AlertAssessmentReference):
            raise TypeError("assessment must be a typed reference")
        for name in ("observed_at", "expected_last_seen_at"):
            value = getattr(self, name)
            if value is None and name == "expected_last_seen_at":
                continue
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
            object.__setattr__(self, name, value.astimezone(UTC))
        if self.ip_address is not None:
            object.__setattr__(self, "ip_address", str(IPv4Address(self.ip_address)))
        if self.observed_mac is not None and not isinstance(self.observed_mac, MacAddress):
            raise TypeError("observed_mac must be a MacAddress or None")
        if self.expected_mac is not None and not isinstance(self.expected_mac, MacAddress):
            raise TypeError("expected_mac must be a MacAddress")
        if self.baseline_status is not None and not isinstance(self.baseline_status, GatewayBaselineStatus):
            raise TypeError("baseline_status must be typed")
        if type(self.observation_count) is not int or not 1 <= self.observation_count <= 1_000_000_000:
            raise ValueError("observation_count must be bounded and positive")
        if len(self.breakdown) > 8 or any(not isinstance(item, ArpScoreComponent) for item in self.breakdown):
            raise ValueError("breakdown must be bounded and typed")
        if self.score is not None and (type(self.score) is not int or self.score != sum(item.points for item in self.breakdown)):
            raise ValueError("score must equal breakdown")
        if len(self.details) > 8:
            raise ValueError("details must be bounded")
        for pair in self.details:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError("details must contain key-value pairs")
            key, value = pair
            if (not isinstance(key, str) or not 1 <= len(key) <= 32 or
                    not key.isascii() or not all(c.isalnum() or c == "_" for c in key) or
                    any(word in key.lower() for word in ("payload", "packet", "frame", "secret", "credential", "body"))):
                raise ValueError("detail key is invalid or sensitive")
            if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 for c in value):
                raise ValueError("detail value must be short printable text")


@dataclass(frozen=True, slots=True)
class AlertCandidate:
    fingerprint: str
    rule_id: str
    network_fingerprint: str | None
    entity_id: str
    severity: str
    confidence: str
    evidence: AlertEvidence
    intent: AlertWriteIntent = AlertWriteIntent.OCCURRENCE

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, AlertEvidence):
            raise TypeError("evidence must be AlertEvidence")
        for name in ("fingerprint", "network_fingerprint"):
            value = getattr(self, name)
            if name == "network_fingerprint" and value is None and self.evidence.assessment is not None:
                continue
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"{name} must be canonical SHA-256 hex")
        if not isinstance(self.rule_id, str) or not 1 <= len(self.rule_id) <= 64 or not self.rule_id.isascii():
            raise ValueError("rule_id must be bounded ASCII")
        if not isinstance(self.entity_id, str) or not 1 <= len(self.entity_id) <= 128 or not self.entity_id.isascii():
            raise ValueError("entity_id must be bounded ASCII")
        if self.severity not in {"info", "low", "medium", "high"}:
            raise ValueError("unsupported severity")
        if self.confidence not in {"passive_observation", "low", "moderate", "high"}:
            raise ValueError("unsupported confidence")
        if not isinstance(self.evidence, AlertEvidence):
            raise TypeError("evidence must be AlertEvidence")
        if not isinstance(self.intent, AlertWriteIntent):
            raise TypeError("write intent must be typed")
        reference = self.evidence.assessment
        if reference is not None:
            if (reference.network_status is NetworkScopeStatus.RESOLVED) != (self.network_fingerprint is not None):
                raise ValueError("risk scope and network fingerprint must agree")
        elif self.intent is not AlertWriteIntent.OCCURRENCE:
            raise ValueError("reassessment requires an assessment reference")


@dataclass(frozen=True, slots=True)
class Alert:
    id: UUID
    fingerprint: str
    rule_id: str
    network_fingerprint: str | None
    entity_id: str
    severity: str
    confidence: str
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    evidence: tuple[AlertEvidence, ...]
    created_at: datetime
    updated_at: datetime
    last_notified_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID) or not isinstance(self.status, AlertStatus):
            raise TypeError("alert identity and status must be typed")
        for name in ("first_seen", "last_seen", "created_at", "updated_at", "last_notified_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
            object.__setattr__(self, name, value.astimezone(UTC))
        if self.first_seen > self.last_seen or self.created_at > self.updated_at:
            raise ValueError("alert times are inconsistent")
        if type(self.occurrence_count) is not int or self.occurrence_count < 1:
            raise ValueError("occurrence_count must be positive")
        if not 1 <= len(self.evidence) <= MAX_ALERT_EVIDENCE or any(not isinstance(item, AlertEvidence) for item in self.evidence):
            raise ValueError("evidence must be bounded and typed")
        AlertCandidate(self.fingerprint, self.rule_id, self.network_fingerprint, self.entity_id,
                       self.severity, self.confidence, self.evidence[-1])
        if self.id != alert_id(self.fingerprint):
            raise ValueError("alert id does not match fingerprint")


def alert_id(fingerprint: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"netsentinel:alert:{fingerprint}")


__all__ = ("Alert", "AlertCandidate", "AlertEvidence", "AlertStatus", "MAX_ALERT_EVIDENCE", "alert_id", "ArpIdentityConflictDetected", "ArpIdentityEvidence", "ArpIdentityReason", "ArpIdentityRule", "ArpRiskAssessment", "ArpScoreComponent", "ArpScoreRule", "NewDeviceDetected")
