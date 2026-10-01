"""Portable evidence for a local executable file read."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netsentinel.domain.connections import ProcessIdentity, ProcessInfo, ProcessInfoStatus


class ExecutableHashStatus(str, Enum):
    AVAILABLE = "available"
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"
    CHANGED_DURING_READ = "changed_during_read"
    TOO_LARGE = "too_large"
    TIMED_OUT = "timed_out"
    INVALID_PATH = "invalid_path"
    REMOTE_PATH = "remote_path"
    SATURATED = "saturated"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ExecutableHash:
    """SHA-256 of bytes read from a file; no process or security verdict."""

    status: ExecutableHashStatus
    digest: str | None = None
    algorithm: str = "sha256"

    def __post_init__(self) -> None:
        if not isinstance(self.status, ExecutableHashStatus):
            raise TypeError("status must be ExecutableHashStatus")
        if self.algorithm != "sha256":
            raise ValueError("only sha256 is supported")
        if self.status is ExecutableHashStatus.AVAILABLE:
            if not isinstance(self.digest, str) or len(self.digest) != 64 or any(
                char not in "0123456789abcdef" for char in self.digest
            ):
                raise ValueError("available hash requires canonical SHA-256 hex")
        elif self.digest is not None:
            raise ValueError("unavailable hash cannot have a digest")


@dataclass(frozen=True, slots=True)
class ExecutableHashRequest:
    """Correlate an on-demand result with a process instance and path snapshot."""

    identity: ProcessIdentity
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ProcessIdentity):
            raise TypeError("identity must be ProcessIdentity")
        if self.identity.create_time is None:
            raise ValueError("hash correlation requires process create_time")
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("path must be nonempty")

    def matches(self, process: ProcessInfo) -> bool:
        return (
            process.identity == self.identity
            and process.executable_path_status is ProcessInfoStatus.AVAILABLE
            and process.executable_path == self.path
        )
