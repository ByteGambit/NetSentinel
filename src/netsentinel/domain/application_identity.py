"""Portable application scope and executable artifact revision evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netsentinel.domain.connections import ProcessIdentity, ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus


class ApplicationIdentityQuality(str, Enum):
    STABLE = "stable"
    PROVISIONAL = "provisional"
    UNKNOWN = "unknown"


class ApplicationIdentityEvidence(str, Enum):
    EXECUTABLE_PATH = "executable_path"
    PROCESS_INSTANCE = "process_instance"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ApplicationIdentity:
    """A baseline scope; only a path-backed key is restart-stable.

    ``key`` is versioned and serializable. Provisional keys must never be
    persisted as cross-run application identities. The canonical path remains
    local process metadata and must not be emitted to diagnostics.
    """

    quality: ApplicationIdentityQuality
    key: str | None
    evidence: ApplicationIdentityEvidence
    path_status: ProcessInfoStatus

    def __post_init__(self) -> None:
        if not isinstance(self.quality, ApplicationIdentityQuality):
            raise TypeError("quality must be ApplicationIdentityQuality")
        if not isinstance(self.evidence, ApplicationIdentityEvidence):
            raise TypeError("evidence must be ApplicationIdentityEvidence")
        if not isinstance(self.path_status, ProcessInfoStatus):
            raise TypeError("path_status must be ProcessInfoStatus")
        if self.quality is ApplicationIdentityQuality.STABLE:
            if self.evidence is not ApplicationIdentityEvidence.EXECUTABLE_PATH or self.path_status is not ProcessInfoStatus.AVAILABLE or not self.key or not self.key.startswith("winpath:v1:"):
                raise ValueError("stable identity requires an available canonical path")
        elif self.quality is ApplicationIdentityQuality.PROVISIONAL:
            if self.evidence is not ApplicationIdentityEvidence.PROCESS_INSTANCE or not self.key or not self.key.startswith("instance:v1:"):
                raise ValueError("provisional identity requires an instance key")
        elif self.key is not None or self.evidence is not ApplicationIdentityEvidence.NONE:
            raise ValueError("unknown identity cannot carry a shared key")

    @property
    def restart_stable(self) -> bool:
        return self.quality is ApplicationIdentityQuality.STABLE


@dataclass(frozen=True, slots=True)
class ApplicationRevision:
    """Known SHA-256 of disk bytes or an explicit absence of revision evidence."""

    digest: str | None
    hash_status: ExecutableHashStatus | None = None

    def __post_init__(self) -> None:
        if self.hash_status is not None and not isinstance(self.hash_status, ExecutableHashStatus):
            raise TypeError("hash_status must be ExecutableHashStatus or None")
        if self.digest is not None:
            if not isinstance(self.digest, str) or self.hash_status is not ExecutableHashStatus.AVAILABLE or len(self.digest) != 64 or any(char not in "0123456789abcdef" for char in self.digest):
                raise ValueError("known revision requires canonical SHA-256 evidence")
        elif self.hash_status is ExecutableHashStatus.AVAILABLE:
            raise ValueError("available hash requires a revision digest")

    @property
    def known(self) -> bool:
        return self.digest is not None


@dataclass(frozen=True, slots=True)
class ApplicationScope:
    identity: ApplicationIdentity
    revision: ApplicationRevision
    process_identity: ProcessIdentity | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ApplicationIdentity):
            raise TypeError("identity must be ApplicationIdentity")
        if not isinstance(self.revision, ApplicationRevision):
            raise TypeError("revision must be ApplicationRevision")
        if self.process_identity is not None and not isinstance(self.process_identity, ProcessIdentity):
            raise TypeError("process_identity must be ProcessIdentity or None")


class ApplicationIdentityChange(str, Enum):
    SAME_SCOPE = "same_scope"
    METADATA_UPGRADE = "metadata_upgrade"
    METADATA_LOSS = "metadata_loss"
    PATH_CHANGED = "path_changed"
    DIFFERENT_SCOPE = "different_scope"
    UNKNOWN = "unknown"


class ApplicationRevisionChange(str, Enum):
    SAME = "same"
    CHANGED = "changed"
    BECAME_KNOWN = "became_known"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ApplicationIdentityComparison:
    identity_change: ApplicationIdentityChange
    revision_change: ApplicationRevisionChange
    can_carry_baseline: bool
