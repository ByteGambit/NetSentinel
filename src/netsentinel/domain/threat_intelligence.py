"""NS-084 portable reputation contracts and pure, fail-closed consent policy.

Consent authorizes one manually selected subject; it never requests a lookup.
No history, process metadata, file content, credentials or arbitrary payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from ipaddress import ip_address
import re
from uuid import UUID

from netsentinel.domain.connections import Endpoint
from netsentinel.domain.dns import canonical_dns_name
from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashStatus


TI_POLICY_VERSION = 1
TI_RESULT_CONTRACT_VERSION = 1  # normalized result semantics, independent of consent
MAX_TI_PROVIDERS = 16
MAX_TI_CONSENTS = MAX_TI_PROVIDERS * 3


class ThreatIntelSubjectKind(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class ThreatIntelDataType(str, Enum):
    IP_REPUTATION = "ip_reputation"
    DOMAIN_REPUTATION = "domain_reputation"
    HASH_REPUTATION = "hash_reputation"

    @property
    def subject_kind(self) -> ThreatIntelSubjectKind:
        return {
            self.IP_REPUTATION: ThreatIntelSubjectKind.IP,
            self.DOMAIN_REPUTATION: ThreatIntelSubjectKind.DOMAIN,
            self.HASH_REPUTATION: ThreatIntelSubjectKind.HASH,
        }[self]


class ThreatIntelTrigger(str, Enum):
    MANUAL_SELECTED = "manual_selected"
    AUTOMATIC = "automatic"  # reserved; denied even if a grant is supplied


class HashAlgorithm(str, Enum):
    SHA256 = "sha256"


@dataclass(frozen=True, slots=True)
class ThreatIntelProviderId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.value) is None:
            raise ValueError("invalid provider ID")


@dataclass(frozen=True, slots=True)
class ThreatIntelProviderDescriptor:
    provider: ThreatIntelProviderId
    display_name: str
    supported_data_types: frozenset[ThreatIntelDataType]
    # No concrete provider/terms review exists until NS-086. No retention promise.
    retention: str = "unknown"

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ThreatIntelProviderId):
            raise TypeError("provider must be a typed ID")
        if (not isinstance(self.display_name, str) or not self.display_name.strip()
                or len(self.display_name) > 128
                or any(ord(c) < 32 or ord(c) == 127 for c in self.display_name)):
            raise ValueError("invalid provider display name")
        if (not isinstance(self.supported_data_types, frozenset)
                or not self.supported_data_types
                or any(not isinstance(t, ThreatIntelDataType) for t in self.supported_data_types)):
            raise ValueError("capabilities must be a nonempty typed frozenset")
        if self.retention != "unknown":
            raise ValueError("provider retention has not been reviewed")


@dataclass(frozen=True, slots=True)
class ThreatIntelSubject:
    kind: ThreatIntelSubjectKind
    value: str
    algorithm: HashAlgorithm | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ThreatIntelSubjectKind) or not isinstance(self.value, str):
            raise TypeError("subject requires a typed kind and text value")
        if self.kind is not ThreatIntelSubjectKind.HASH and self.algorithm is not None:
            raise ValueError("only hash subjects carry an algorithm")
        if self.kind is ThreatIntelSubjectKind.IP:
            if len(self.value) > 45 or "%" in self.value:
                raise ValueError("invalid or scoped IP subject")
            try:
                canonical = Endpoint(self.value, 0).address
            except ValueError:
                raise ValueError("invalid IP subject") from None
        elif self.kind is ThreatIntelSubjectKind.DOMAIN:
            canonical = canonical_dns_name(self.value)
            labels = canonical[:-1].split(".")
            if canonical == "." or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None for label in labels):
                raise ValueError("domain subject requires hostname labels")
            try:
                ip_address(canonical[:-1])
            except ValueError:
                pass
            else:
                raise ValueError("IP literals require an IP subject")
        else:
            if self.algorithm is not HashAlgorithm.SHA256:
                raise ValueError("hash subjects require explicit SHA-256")
            if len(self.value) != 64:
                raise ValueError("hash subject requires a 64-character digest")
            canonical = self.value.lower()
            ExecutableHash(ExecutableHashStatus.AVAILABLE, canonical)
        object.__setattr__(self, "value", canonical)


def externally_eligible(subject: ThreatIntelSubject) -> bool:
    """Conservative external policy, separate from syntactic validity.

    Python ipaddress global semantics plus explicit special-address exclusion.
    DNS convention stays ASCII (including existing punycode), with a trailing dot.
    """
    if subject.kind is ThreatIntelSubjectKind.IP:
        address = ip_address(subject.value)
        return address.is_global and not any((
            address.is_multicast, address.is_reserved, address.is_unspecified,
            address.is_loopback, address.is_link_local,
        ))
    if subject.kind is ThreatIntelSubjectKind.DOMAIN:
        name = subject.value[:-1]
        return "." in name and not (
            name.endswith(".local") or name.endswith(".localhost")
        )
    return True


@dataclass(frozen=True, slots=True)
class ThreatIntelConsent:
    consent_id: UUID
    provider: ThreatIntelProviderId
    data_type: ThreatIntelDataType
    trigger: ThreatIntelTrigger = ThreatIntelTrigger.MANUAL_SELECTED
    policy_version: int = TI_POLICY_VERSION

    def __post_init__(self) -> None:
        if (not isinstance(self.consent_id, UUID)
                or not isinstance(self.provider, ThreatIntelProviderId)
                or not isinstance(self.data_type, ThreatIntelDataType)
                or not isinstance(self.trigger, ThreatIntelTrigger)):
            raise TypeError("consent requires typed dimensions and identity")
        if type(self.policy_version) is not int or self.policy_version != TI_POLICY_VERSION:
            raise ValueError("unsupported consent policy version")


def validate_consents(consents: tuple[ThreatIntelConsent, ...]) -> None:
    if (not isinstance(consents, tuple) or len(consents) > MAX_TI_CONSENTS
            or any(not isinstance(c, ThreatIntelConsent) for c in consents)):
        raise ValueError("consents must be a bounded immutable typed tuple")
    dimensions = {(c.provider, c.data_type, c.trigger) for c in consents}
    if len(dimensions) != len(consents) or len({c.consent_id for c in consents}) != len(consents):
        raise ValueError("duplicate consent dimensions or identity")
    if any(c.trigger is not ThreatIntelTrigger.MANUAL_SELECTED for c in consents):
        raise ValueError("automatic consent is not supported")


def _utc(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must be UTC-aware")


@dataclass(frozen=True, slots=True)
class ThreatIntelQuery:
    request_id: UUID
    provider: ThreatIntelProviderId
    subject: ThreatIntelSubject
    data_type: ThreatIntelDataType
    trigger: ThreatIntelTrigger
    consent: ThreatIntelConsent | None
    queried_at: datetime
    policy_version: int = TI_POLICY_VERSION

    def __post_init__(self) -> None:
        if (not isinstance(self.request_id, UUID) or not isinstance(self.provider, ThreatIntelProviderId)
                or not isinstance(self.subject, ThreatIntelSubject)
                or not isinstance(self.data_type, ThreatIntelDataType)
                or not isinstance(self.trigger, ThreatIntelTrigger)
                or (self.consent is not None and not isinstance(self.consent, ThreatIntelConsent))):
            raise TypeError("invalid query contract")
        if self.data_type.subject_kind is not self.subject.kind:
            raise ValueError("data type does not match subject")
        if type(self.policy_version) is not int or self.policy_version != TI_POLICY_VERSION:
            raise ValueError("unsupported query policy version")
        _utc(self.queried_at)


class ThreatIntelDenial(str, Enum):
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    UNSUPPORTED_DATA_TYPE = "unsupported_data_type"
    LOCAL_SUBJECT = "local_subject"
    TRIGGER_NOT_SUPPORTED = "trigger_not_supported"
    NO_CONSENT = "no_consent"


def consent_denial(query: ThreatIntelQuery, descriptor: ThreatIntelProviderDescriptor | None,
                   consents: tuple[ThreatIntelConsent, ...]) -> ThreatIntelDenial | None:
    """Pure decision: no config read, provider call, or hidden mutable policy."""
    validate_consents(consents)
    if descriptor is None or descriptor.provider != query.provider:
        return ThreatIntelDenial.UNSUPPORTED_PROVIDER
    if query.data_type not in descriptor.supported_data_types:
        return ThreatIntelDenial.UNSUPPORTED_DATA_TYPE
    if not externally_eligible(query.subject):
        return ThreatIntelDenial.LOCAL_SUBJECT
    if query.trigger is not ThreatIntelTrigger.MANUAL_SELECTED:
        return ThreatIntelDenial.TRIGGER_NOT_SUPPORTED
    if (query.consent is None or query.consent not in consents
            or query.consent.provider != query.provider
            or query.consent.data_type is not query.data_type
            or query.consent.trigger is not query.trigger):
        return ThreatIntelDenial.NO_CONSENT
    return None


class ThreatIntelResultStatus(str, Enum):
    HIT = "hit"  # a provider record exists, not a universal security verdict
    NO_HIT = "no_hit"  # no record, never safe/clean/trusted
    ERROR = "error"  # operational failure, never security evidence


class ThreatIntelError(str, Enum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    AUTHENTICATION = "authentication"
    RATE_LIMITED = "rate_limited"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    query: ThreatIntelQuery  # exact provider/subject/request/consent/version provenance
    status: ThreatIntelResultStatus
    received_at: datetime
    error: ThreatIntelError | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.query, ThreatIntelQuery) or not isinstance(self.status, ThreatIntelResultStatus):
            raise TypeError("invalid result contract")
        _utc(self.received_at)
        if self.received_at < self.query.queried_at:
            raise ValueError("result precedes query")
        if self.status is ThreatIntelResultStatus.ERROR:
            if not isinstance(self.error, ThreatIntelError):
                raise ValueError("error result requires a typed operational error")
        elif self.error is not None:
            raise ValueError("hit/no-hit cannot carry an error")
