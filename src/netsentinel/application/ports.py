"""Framework-independent ports used by the application layer."""

from __future__ import annotations

from typing import Protocol

from netsentinel.domain.connections import ConnectionSnapshot


class ConnectionCollectionError(RuntimeError):
    """Base error raised when a connection snapshot cannot be collected."""


class ConnectionCollectionPermissionDenied(ConnectionCollectionError):
    """The operating system denied access to connection information."""


class ConnectionCollectionTransientError(ConnectionCollectionError):
    """Collection failed because of a transient OS or process race."""


class ConnectionCollector(Protocol):
    """Port for obtaining one normalized system connection snapshot."""

    def collect(self) -> tuple[ConnectionSnapshot, ...]:
        """Return the connections visible in one collection pass."""


__all__ = (
    "ConnectionCollectionError",
    "ConnectionCollectionPermissionDenied",
    "ConnectionCollectionTransientError",
    "ConnectionCollector",
)
