"""Portable, on-demand evidence about a disk file's Authenticode signature."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netsentinel.domain.connections import ProcessIdentity, ProcessInfo, ProcessInfoStatus


class SignatureKind(str, Enum):
    EMBEDDED = "embedded"
    CATALOG = "catalog"
    NONE = "none"
    UNKNOWN = "unknown"


class SignatureValidation(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    NOT_SIGNED = "not_signed"
    UNKNOWN = "unknown"


class LocalTrust(str, Enum):
    TRUSTED_LOCAL_POLICY = "trusted_local_policy"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


class RevocationStatus(str, Enum):
    NOT_CHECKED = "not_checked"


class SignerAvailability(str, Enum):
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    ACCESS_DENIED = "access_denied"
    INVALID_PATH = "invalid_path"
    REMOTE_PATH = "remote_path"
    UNSUPPORTED = "unsupported"
    FILE_CHANGED = "file_changed"
    TOO_LARGE = "too_large"
    UNAVAILABLE = "unavailable"
    SATURATED = "saturated"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class SignerIdentity:
    subject: str | None = None
    issuer: str | None = None
    certificate_sha256: str | None = None

    def __post_init__(self) -> None:
        for value in (self.subject, self.issuer):
            if value is not None and (len(value) > 511 or any(ord(c) < 32 for c in value)):
                raise ValueError("certificate display name is not bounded plain text")
        value = self.certificate_sha256
        if value is not None and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("certificate_sha256 must be canonical hex")


@dataclass(frozen=True, slots=True)
class ExecutableSigner:
    availability: SignerAvailability
    kind: SignatureKind = SignatureKind.UNKNOWN
    validation: SignatureValidation = SignatureValidation.UNKNOWN
    local_trust: LocalTrust = LocalTrust.NOT_EVALUATED
    revocation: RevocationStatus = RevocationStatus.NOT_CHECKED
    signer: SignerIdentity | None = None
    timestamp_present: bool | None = None

    def __post_init__(self) -> None:
        if self.availability is not SignerAvailability.AVAILABLE and (
            self.kind is not SignatureKind.UNKNOWN or self.signer is not None
        ):
            raise ValueError("unavailable evidence cannot identify a signer")
        if self.kind is SignatureKind.NONE and self.validation is not SignatureValidation.NOT_SIGNED:
            raise ValueError("unsigned result must have not_signed validation")
        if self.local_trust is LocalTrust.TRUSTED_LOCAL_POLICY and self.validation is not SignatureValidation.VALID:
            raise ValueError("local trust requires valid signature")


@dataclass(frozen=True, slots=True)
class ExecutableSignerRequest:
    identity: ProcessIdentity
    path: str

    def matches(self, process: ProcessInfo) -> bool:
        return (process.identity == self.identity and
                process.executable_path_status is ProcessInfoStatus.AVAILABLE and
                process.executable_path == self.path)
