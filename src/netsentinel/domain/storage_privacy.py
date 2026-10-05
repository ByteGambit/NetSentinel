"""NS-095 immutable local maintenance and support-export contracts."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID


HISTORY_ROW_QUOTA = 100_000
DEVICE_ROW_QUOTA = 4096
BINDING_ROW_QUOTA = 16_384
PROFILE_ROW_QUOTA = 4096
GATEWAY_ROW_QUOTA = 4096
GATEWAY_HISTORY_ROW_QUOTA = 16_384
ALERT_ROW_QUOTA = 10_000


class StorageScope(str, Enum):
    CONNECTIONS = "Completed connection history"
    DNS = "DNS history"
    CACHE = "Reputation cache"
    ALERTS = "Resolved alerts"
    INCIDENTS = "Resolved incidents"
    BASELINES = "Expired baselines"
    DEVICES = "Eligible device history"
    ALL = "All eligible history"


class Store(str, Enum):
    CACHE = "threat_intel_cache"
    ASSOCIATIONS = "dns_associations"
    CONNECTIONS = "connection_history"
    DNS = "dns_history"
    BINDINGS = "device_bindings"
    DEVICES = "devices"
    GATEWAY_CHANGES = "gateway_baseline_changes"
    ALERTS = "alerts"
    INCIDENTS = "incidents"
    ASSESSMENTS = "risk_assessments"
    BASELINES = "behavior_baselines"
    PROFILES = "device_profiles"
    PROFILE_MEMBERS = "device_profile_members"
    GATEWAYS = "gateway_baselines"
    VLANS = "vlan_summaries"
    VLAN_IDS = "vlan_id_summaries"
    ASSESSMENT_REVISIONS = "risk_assessment_revisions"
    INCIDENT_REVISIONS = "incident_revisions"
    INCIDENT_REFERENCES = "incident_references"
    PREFERENCES = "scoped_preferences"
    PREFERENCE_REVISIONS = "scoped_preference_revisions"


class MaintenanceStatus(str, Enum):
    COMPLETE = "complete"
    LIMITED = "budget reached; eligible rows may remain"
    CANCELLED = "cancelled; earlier chunks remain committed"
    PARTIAL = "partial; storage busy or unavailable"
    CAPACITY_PRESSURE = "capacity pressure; protected data remains"


@dataclass(frozen=True, slots=True)
class StoreRetentionRule:
    store: Store
    age_days: int | None
    max_rows: int
    chunk_rows: int

    def __post_init__(self) -> None:
        if not isinstance(self.store, Store):
            raise TypeError("typed store required")
        if self.age_days is not None and (type(self.age_days) is not int or not 1 <= self.age_days <= 3650):
            raise ValueError("age outside retention policy")
        if type(self.max_rows) is not int or not 1 <= self.max_rows <= 1_000_000:
            raise ValueError("row quota outside policy")
        if type(self.chunk_rows) is not int or not 1 <= self.chunk_rows <= 512:
            raise ValueError("chunk outside policy")


@dataclass(frozen=True, slots=True)
class StorageRetentionPolicy:
    history_days: int = 30
    security_days: int = 90

    def __post_init__(self) -> None:
        for value in (self.history_days, self.security_days):
            if type(value) is not int or not 30 <= value <= 365:
                raise ValueError("retention must be between 30 and 365 days")

    @property
    def rules(self) -> tuple[StoreRetentionRule, ...]:
        return (
            StoreRetentionRule(Store.CACHE, None, 1024, 128),
            StoreRetentionRule(Store.ASSOCIATIONS, None, HISTORY_ROW_QUOTA, 128),
            StoreRetentionRule(Store.CONNECTIONS, self.history_days, HISTORY_ROW_QUOTA, 128),
            StoreRetentionRule(Store.DNS, self.history_days, HISTORY_ROW_QUOTA, 128),
            StoreRetentionRule(Store.BINDINGS, 90, BINDING_ROW_QUOTA, 128),
            StoreRetentionRule(Store.DEVICES, 90, DEVICE_ROW_QUOTA, 128),
            StoreRetentionRule(Store.GATEWAY_CHANGES, 90, GATEWAY_HISTORY_ROW_QUOTA, 128),
            StoreRetentionRule(Store.ALERTS, self.security_days, ALERT_ROW_QUOTA, 128),
            StoreRetentionRule(Store.INCIDENTS, self.security_days, 1024, 512),
            StoreRetentionRule(Store.ASSESSMENTS, 30, 512, 512),
            StoreRetentionRule(Store.BASELINES, 90, 512, 64),
        )


@dataclass(frozen=True, slots=True)
class StoreSummary:
    store: Store
    rows: int
    eligible: int
    protected: int
    quota: int

    @property
    def pressure(self) -> bool:
        return self.rows > self.quota or (self.rows >= self.quota and self.protected == self.rows)


@dataclass(frozen=True, slots=True)
class StorageSummary:
    stores: tuple[StoreSummary, ...]
    database_bytes: int
    wal_bytes: int
    schema_version: int


@dataclass(frozen=True, slots=True)
class PurgePreview:
    token: UUID
    scope: StorageScope
    eligible: int
    protected: int


@dataclass(frozen=True, slots=True)
class StoreCleanup:
    store: Store
    deleted: int
    failed: bool = False
    protected: int | None = None
    source_expired: int | None = None  # Lazy source states; no invented attribution/count.


@dataclass(frozen=True, slots=True)
class RetentionRunResult:
    status: MaintenanceStatus
    stores: tuple[StoreCleanup, ...]
    chunks: int
    elapsed_seconds: float
    capacity_pressure: tuple[StoreSummary, ...] = ()
    summary_unavailable: bool = False

    @property
    def deleted_rows(self) -> int:
        """Physical deletes, including owned child rows, excluding metadata updates."""
        return sum(item.deleted for item in self.stores)


@dataclass(frozen=True, slots=True)
class SanitizedExport:
    token: UUID
    content: bytes
    record_count: int
    sample: str


@dataclass(frozen=True, slots=True)
class SupportRecord:
    category: Store
    state: str
    severity: str | None = None
    revision: int | None = None

    def __post_init__(self) -> None:
        if self.category not in (Store.ALERTS, Store.INCIDENTS) or self.state not in ("open", "acknowledged", "resolved"):
            raise ValueError("unsupported support projection")
        if self.category is Store.ALERTS:
            if self.severity not in ("info", "low", "medium", "high") or self.revision is not None:
                raise ValueError("invalid alert projection")
        elif self.severity is not None or type(self.revision) is not int or not 1 <= self.revision <= 2**63 - 1:
            raise ValueError("invalid incident projection")


def utc_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ValueError("UTC-aware maintenance clock required")
    return value
