"""Immutable, bounded observations of application connection appearances."""

from __future__ import annotations

from dataclasses import dataclass

from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.connections import NetworkScopeStatus, TransportProtocol


@dataclass(frozen=True, slots=True)
class BehaviorScopeKey:
    application_key: str
    identity_quality: ApplicationIdentityQuality
    revision_digest: str | None
    network_status: NetworkScopeStatus
    network_token: str

    @property
    def identity_restart_stable(self) -> bool:
        return (
            self.identity_quality is ApplicationIdentityQuality.STABLE
            and self.network_status is NetworkScopeStatus.RESOLVED
        )

    @property
    def revision_verified(self) -> bool:
        return self.revision_digest is not None


@dataclass(frozen=True, slots=True)
class FeatureCount:
    value: str | int | TransportProtocol
    observed_appearances: int


@dataclass(frozen=True, slots=True)
class BehaviorFeatureSnapshot:
    scope: BehaviorScopeKey
    observed_appearances: int
    reduced_appearances: int
    monitored_seconds: float
    destinations: tuple[FeatureCount, ...]
    ports: tuple[FeatureCount, ...]
    protocols: tuple[FeatureCount, ...]
    other_destinations: int
    other_ports: int
    other_protocols: int
    unknown_destinations: int
    destination_diversity: int
    port_diversity: int
    protocol_diversity: int
    gap_seen: bool
    capacity_loss: bool


@dataclass(frozen=True, slots=True)
class BehaviorAccumulatorSnapshot:
    scopes: tuple[BehaviorFeatureSnapshot, ...]
    evicted_scopes: int
    skipped_unknown_applications: int
    bucket_seconds: int
    bucket_count: int
