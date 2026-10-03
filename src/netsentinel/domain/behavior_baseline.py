"""NS-071 versioned learning summaries; lifecycle is never a risk verdict."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from math import isfinite
import ntpath

from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.connections import NetworkScopeStatus, TransportProtocol

from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey

SUMMARY_VERSION = 1
FEATURE_POLICY_VERSION = 1
MAX_BASELINE_PAYLOAD_BYTES = 16_384
MAX_BASELINE_ROWS = 512
MAX_BASELINE_LOAD = 128
MAX_BASELINE_COUNTER = 2**63 - 1


def validate_baseline_scope(scope: BehaviorScopeKey) -> None:
    """Persistence accepts only canonical NS-069/057 restart-safe scopes."""
    key = scope.application_key
    if (scope.identity_quality is not ApplicationIdentityQuality.STABLE
            or scope.network_status is not NetworkScopeStatus.RESOLVED
            or not isinstance(key, str) or not key.startswith("winpath:v1:")
            or len(key.encode("utf-8")) > 4096 or any(ord(c) < 32 for c in key)):
        raise ValueError("invalid persistent application scope")
    path = key[len("winpath:v1:"):]
    drive, tail = ntpath.splitdrive(path)
    if not drive or not tail.startswith("\\") or ntpath.normcase(ntpath.normpath(path)) != path:
        raise ValueError("noncanonical application path")
    for digest, optional in ((scope.revision_digest, True), (scope.network_token, False)):
        if digest is None and optional:
            continue
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid revision or network fingerprint")


def validate_baseline_summary(summary: BaselineSummary) -> None:
    validate_baseline_scope(summary.features.scope)
    if type(summary.summary_version) is not int or summary.summary_version != SUMMARY_VERSION:
        raise ValueError("unsupported summary version")
    if type(summary.feature_policy_version) is not int or summary.feature_policy_version != FEATURE_POLICY_VERSION:
        raise ValueError("unsupported feature policy")
    if not isinstance(summary.policy_key, str) or not 1 <= len(summary.policy_key) <= 512:
        raise ValueError("invalid policy key")
    for stamp in (summary.last_observed_at, summary.persisted_at):
        offset = stamp.utcoffset() if isinstance(stamp, datetime) else None
        if not isinstance(stamp, datetime) or stamp.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("baseline times must be UTC")
    f = summary.features
    for name in ("observed_appearances", "reduced_appearances", "other_destinations", "other_ports", "other_protocols", "unknown_destinations", "destination_diversity", "port_diversity", "protocol_diversity"):
        value = getattr(f, name)
        if type(value) is not int or not 0 <= value <= MAX_BASELINE_COUNTER:
            raise ValueError("invalid baseline counter")
    if f.reduced_appearances > f.observed_appearances:
        raise ValueError("reduced count exceeds samples")
    if isinstance(f.monitored_seconds, bool) or not isinstance(f.monitored_seconds, (int, float)) or not isfinite(f.monitored_seconds) or not 0 <= f.monitored_seconds <= 1e12:
        raise ValueError("invalid monitored coverage")
    if type(f.gap_seen) is not bool or type(f.capacity_loss) is not bool:
        raise ValueError("invalid quality markers")
    for name, cap, diversity in (("destinations", 64, f.destination_diversity), ("ports", 32, f.port_diversity), ("protocols", 2, f.protocol_diversity)):
        counts = getattr(f, name)
        if not isinstance(counts, tuple) or len(counts) > cap or diversity != len(counts):
            raise ValueError("feature capacity or diversity mismatch")
        values = set()
        total = 0
        for item in counts:
            if type(item.observed_appearances) is not int or not 1 <= item.observed_appearances <= MAX_BASELINE_COUNTER:
                raise ValueError("invalid feature counter")
            value = item.value
            if name == "destinations":
                if not isinstance(value, str) or len(value) > 45 or str(ip_address(value)) != value:
                    raise ValueError("invalid canonical IP")
            elif name == "ports":
                if type(value) is not int or not 0 <= value <= 65535:
                    raise ValueError("invalid port")
            elif not isinstance(value, TransportProtocol):
                raise ValueError("invalid protocol")
            if value in values:
                raise ValueError("duplicate feature")
            values.add(value)
            total += item.observed_appearances
        total += getattr(f, "other_" + name)
        if name != "protocols":
            total += f.unknown_destinations
        if total != f.observed_appearances:
            raise ValueError("feature totals do not match samples")
    if (f.other_destinations or f.other_ports or f.other_protocols) and not f.capacity_loss:
        raise ValueError("overflow must retain capacity loss")


class BaselineState(str, Enum):
    LEARNING = "learning"
    INSUFFICIENT_DATA = "insufficient_data"
    INSUFFICIENT_QUALITY = "insufficient_quality"
    READY = "ready"
    STALE = "stale"
    EXPIRED = "expired"
    CLOCK_ANOMALY = "clock_anomaly"
    CORRUPT = "corrupt"
    UNSUPPORTED_VERSION = "unsupported_version"
    POLICY_MISMATCH = "policy_mismatch"
    UNAVAILABLE = "unavailable"


class BaselineOrigin(str, Enum):
    NEW = "new"
    RESTORED = "restored"
    RESET = "reset"
    PREVIOUS_UNAVAILABLE = "previous_unavailable"
    SESSION_ONLY = "session_only"


class BaselineStorageState(str, Enum):
    LOADING = "loading"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class BaselineSummary:
    features: BehaviorFeatureSnapshot
    last_observed_at: datetime
    persisted_at: datetime
    policy_key: str
    summary_version: int = SUMMARY_VERSION
    feature_policy_version: int = FEATURE_POLICY_VERSION


@dataclass(frozen=True, slots=True)
class BaselineRead:
    scope: BehaviorScopeKey | None
    state: BaselineState
    summary: BaselineSummary | None = None


@dataclass(frozen=True, slots=True)
class BaselineLoad:
    records: tuple[BaselineRead, ...]
    capacity_loss: bool = False


@dataclass(frozen=True, slots=True)
class BaselineSnapshot:
    scope: BehaviorScopeKey
    state: BaselineState
    origin: BaselineOrigin
    storage: BaselineStorageState
    summary: BaselineSummary | None


@dataclass(frozen=True, slots=True)
class BaselineDiagnostics:
    storage: BaselineStorageState
    loaded_scopes: int
    dirty_scopes: int
    pending_scopes: int
    checkpoints: int
    write_failures: int
    rejected_jobs: int
    invalid_summaries: int
    cleanup_rows: int
    resets: int
    capacity_loss: bool
