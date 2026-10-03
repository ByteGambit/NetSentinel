"""NS-080 local user policy values; no trust verdict or suppression execution."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import ip_address
import json
from uuid import UUID

from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationIdentityQuality, ApplicationRevision
from netsentinel.domain.risk_evidence import (
    EvidenceScope, EvidenceScopeKind, EvidenceSubject, EvidenceSubjectKind, _code, _digest,
)

PREFERENCE_FORMAT_VERSION = 1
MAX_PREFERENCE_REASON = 512
MAX_PREFERENCE_QUERY = 100
MAX_PREFERENCE_HISTORY = 64


def preference_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("preference timestamp must be UTC-aware")
    return value.astimezone(UTC)


def preference_id(value: UUID) -> None:
    if type(value) is not UUID or value.int == 0:
        raise ValueError("preference ID must be a nonzero UUID")


def revision_number(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ValueError("preference revision must be a positive integer")


def preference_reason(value: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > MAX_PREFERENCE_REASON or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in value):
        raise ValueError("reason must be nonempty single-line plain text of at most 512 characters")


class DestinationKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class PreferenceDestination:
    kind: DestinationKind
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.kind) is not DestinationKind or type(self.value) is not str or len(self.value) > 45 or "%" in self.value:
            raise ValueError("destination requires a typed bounded IP without a zone")
        address = ip_address(self.value)
        if (address.version == 4) != (self.kind is DestinationKind.IPV4):
            raise ValueError("destination kind and address disagree")
        object.__setattr__(self, "value", str(address))


@dataclass(frozen=True, slots=True)
class PreferenceSelector:
    application: ApplicationIdentity | None = field(default=None, repr=False)
    application_revision: ApplicationRevision | None = None
    destination: PreferenceDestination | None = field(default=None, repr=False)
    network_fingerprint: str | None = field(default=None, repr=False)
    rule_id: str | None = None

    def __post_init__(self) -> None:
        if all(v is None for v in (self.application, self.destination, self.network_fingerprint, self.rule_id)):
            raise ValueError("empty global selector is forbidden")
        if self.application is not None:
            if type(self.application) is not ApplicationIdentity or self.application.quality is not ApplicationIdentityQuality.STABLE:
                raise ValueError("persistent application requires stable path identity")
            # Reuse NS-076 canonical application validation, including the 4096-byte cap.
            EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=self.application)
        if self.application_revision is not None:
            if self.application is None or type(self.application_revision) is not ApplicationRevision or not self.application_revision.known:
                raise ValueError("exact revision requires a stable application and known digest")
        if self.destination is not None and type(self.destination) is not PreferenceDestination:
            raise TypeError("destination must be typed")
        if self.network_fingerprint is not None:
            _digest(self.network_fingerprint)
        if self.rule_id is not None:
            _code(self.rule_id)


@dataclass(frozen=True, slots=True)
class PreferenceMatchContext:
    rule_id: str
    subject: EvidenceSubject
    scope: EvidenceScope

    def __post_init__(self) -> None:
        _code(self.rule_id)
        if type(self.subject) is not EvidenceSubject or type(self.scope) is not EvidenceScope:
            raise TypeError("matching context requires typed subject and scope")


def selector_matches(selector: PreferenceSelector, context: PreferenceMatchContext) -> bool:
    """Exact AND primitive only; does not evaluate effect, lifetime or eligibility."""
    if type(selector) is not PreferenceSelector or type(context) is not PreferenceMatchContext:
        raise TypeError("selector matching requires typed values")
    if selector.rule_id is not None and selector.rule_id != context.rule_id:
        return False
    if selector.application is not None:
        app = context.subject.application
        if app is None or app.quality is not ApplicationIdentityQuality.STABLE or app.key != selector.application.key:
            return False
    if selector.application_revision is not None:
        revision = context.subject.revision
        if revision is None or revision.digest != selector.application_revision.digest:
            return False
    if selector.destination is not None:
        if selector.destination.value != context.subject.ip_address:
            return False
    if selector.network_fingerprint is not None:
        if context.scope.kind is not EvidenceScopeKind.NETWORK or selector.network_fingerprint != context.scope.network_fingerprint:
            return False
    return True


class PreferenceLifetimeKind(str, Enum):
    EXPIRES_AT = "expires_at"
    PERMANENT = "permanent"


@dataclass(frozen=True, slots=True)
class PreferenceLifetime:
    kind: PreferenceLifetimeKind
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not PreferenceLifetimeKind:
            raise TypeError("explicit lifetime kind is required")
        if self.kind is PreferenceLifetimeKind.PERMANENT:
            if self.expires_at is not None:
                raise ValueError("permanent lifetime cannot have an expiry")
        elif self.expires_at is None:
            raise ValueError("timed lifetime requires an expiry")
        else:
            object.__setattr__(self, "expires_at", preference_time(self.expires_at))


class PreferenceEffect(str, Enum):
    NOTIFICATION_SUPPRESSION = "notification_suppression"


class PreferenceOrigin(str, Enum):
    MANUAL_USER = "manual_user"


class PreferenceStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"  # Derived only; never persisted as an audit transition.


class PreferenceAuditAction(str, Enum):
    CREATE = "create"
    EDIT = "edit"
    REVOKE = "revoke"


@dataclass(frozen=True, slots=True)
class PreferenceDefinition:
    selector: PreferenceSelector = field(repr=False)
    lifetime: PreferenceLifetime
    reason: str = field(repr=False)
    effect: PreferenceEffect = PreferenceEffect.NOTIFICATION_SUPPRESSION

    def __post_init__(self) -> None:
        if type(self.selector) is not PreferenceSelector or type(self.lifetime) is not PreferenceLifetime or type(self.effect) is not PreferenceEffect:
            raise TypeError("preference definition requires typed fields")
        preference_reason(self.reason)

    @property
    def content_fingerprint(self) -> str:
        s = self.selector
        values = (s.application.key if s.application else None,
                  s.application_revision.digest if s.application_revision else None,
                  s.destination.kind.value if s.destination else None,
                  s.destination.value if s.destination else None, s.network_fingerprint, s.rule_id,
                  self.lifetime.kind.value,
                  self.lifetime.expires_at.isoformat(timespec="microseconds") if self.lifetime.expires_at else None,
                  self.reason, self.effect.value)
        return sha256(json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ScopedPreference:
    preference_id: UUID
    revision: int
    definition: PreferenceDefinition
    created_at: datetime
    created_origin: PreferenceOrigin
    recorded_at: datetime
    action_origin: PreferenceOrigin
    action: PreferenceAuditAction
    status: PreferenceStatus
    format_version: int = PREFERENCE_FORMAT_VERSION

    def __post_init__(self) -> None:
        preference_id(self.preference_id)
        revision_number(self.revision)
        if type(self.definition) is not PreferenceDefinition or type(self.created_origin) is not PreferenceOrigin or type(self.action_origin) is not PreferenceOrigin or type(self.action) is not PreferenceAuditAction or type(self.status) is not PreferenceStatus:
            raise TypeError("preference revision requires typed fields")
        if type(self.format_version) is not int or self.format_version != PREFERENCE_FORMAT_VERSION:
            raise ValueError("unsupported preference format")
        object.__setattr__(self, "created_at", preference_time(self.created_at))
        object.__setattr__(self, "recorded_at", preference_time(self.recorded_at))
        if self.recorded_at < self.created_at:
            raise ValueError("audit time cannot precede creation")
        if (self.revision == 1) != (self.action is PreferenceAuditAction.CREATE):
            raise ValueError("only first revision is creation")
        if self.revision == 1 and (self.recorded_at != self.created_at or self.created_origin is not self.action_origin):
            raise ValueError("creation audit must agree with logical identity")
        expected = PreferenceStatus.REVOKED if self.action is PreferenceAuditAction.REVOKE else PreferenceStatus.ACTIVE
        if self.status is not expected:
            raise ValueError("persisted status and action disagree")

    def status_at(self, now: datetime) -> PreferenceStatus:
        now = preference_time(now)
        if self.status is PreferenceStatus.REVOKED:
            return self.status
        expiry = self.definition.lifetime.expires_at
        return PreferenceStatus.EXPIRED if expiry is not None and now >= expiry else PreferenceStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class PreferenceStoragePolicy:
    max_active_preferences: int = 256  # Includes expired but not revoked policies.
    max_preferences: int = 1024
    max_revisions: int = 64
    max_audit_revisions: int = 16384

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_active_preferences, 256), (self.max_preferences, 1024),
                               (self.max_revisions, MAX_PREFERENCE_HISTORY), (self.max_audit_revisions, 16384)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("preference storage budget exceeds hard bound")
        if self.max_active_preferences > self.max_preferences or self.max_revisions < 2 or self.max_audit_revisions < 2:
            raise ValueError("preference budgets must allow creation and revocation")


class PreferenceResultStatus(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    NO_CHANGE = "no_change"
    REVOKED = "revoked"
    ALREADY_REVOKED = "already_revoked"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    CAPACITY_REACHED = "capacity_reached"
    FOUND = "found"
    CORRUPT = "corrupt"
    UNSUPPORTED_VERSION = "unsupported_version"


@dataclass(frozen=True, slots=True)
class PreferenceResult:
    status: PreferenceResultStatus
    preference: ScopedPreference | None = None
    preference_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PreferencePage:
    status: PreferenceResultStatus
    entries: tuple[PreferenceResult, ...] = ()
    truncated: bool = False
