"""Immutable presentation values for connection views.

Formatting belongs here rather than in the framework-independent domain.  The
duration is a snapshot value: it is measured at the most recent lifecycle
observation delivered to the presentation model and is not wall-clock driven.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from netsentinel.domain.connections import (
    ConnectionNetworkScope,
    ConnectionKey,
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    ProcessInfo,
)


MISSING_VALUE = "—"


@dataclass(frozen=True, slots=True)
class ConnectionRowId:
    """Presentation-safe stable identity derived from ``ConnectionKey``.

    Process creation time participates when the domain knows it, so a reused
    PID produces a distinct row identity.
    """

    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    pid: int | None
    process_create_time: datetime | None


@dataclass(frozen=True, slots=True)
class ConnectionRow:
    """One immutable table row with display and raw presentation values."""

    row_id: ConnectionRowId
    process_display: str
    pid_display: str
    protocol_display: str
    local_endpoint_display: str
    remote_endpoint_display: str
    state_display: str
    duration_display: str
    process_name: str | None
    pid: int | None
    protocol: str
    state: str
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    duration_seconds: float
    first_seen: datetime
    observed_at: datetime
    process_info: ProcessInfo
    network_scope: ConnectionNetworkScope


def connection_row_id(key: ConnectionKey) -> ConnectionRowId:
    """Convert a domain connection key to an immutable presentation ID."""

    process_identity = key.process_identity
    remote = key.remote_endpoint
    return ConnectionRowId(
        protocol=key.protocol.value,
        local_address=key.local_endpoint.address,
        local_port=key.local_endpoint.port,
        remote_address=remote.address if remote is not None else None,
        remote_port=remote.port if remote is not None else None,
        pid=process_identity.pid if process_identity is not None else None,
        process_create_time=(
            process_identity.create_time if process_identity is not None else None
        ),
    )


def connection_row_from_snapshot(
    snapshot: ConnectionSnapshot,
    *,
    first_seen: datetime | None = None,
) -> ConnectionRow:
    """Map a portable domain snapshot into presentation-only row values."""

    if not isinstance(snapshot, ConnectionSnapshot):
        raise TypeError("snapshot must be a ConnectionSnapshot")

    started_at = snapshot.observed_at if first_seen is None else first_seen
    duration_seconds = max(
        0.0,
        (snapshot.observed_at - started_at).total_seconds(),
    )
    process_identity = snapshot.process.identity
    pid = process_identity.pid if process_identity is not None else None
    remote = snapshot.remote_endpoint

    return ConnectionRow(
        row_id=connection_row_id(snapshot.key),
        process_display=snapshot.process.name or MISSING_VALUE,
        pid_display=str(pid) if pid is not None else MISSING_VALUE,
        protocol_display=snapshot.protocol.value.upper(),
        local_endpoint_display=format_endpoint(snapshot.local_endpoint),
        remote_endpoint_display=(
            format_endpoint(remote) if remote is not None else MISSING_VALUE
        ),
        state_display=format_state(snapshot.state),
        duration_display=format_duration(duration_seconds),
        process_name=snapshot.process.name,
        pid=pid,
        protocol=snapshot.protocol.value,
        state=snapshot.state.value,
        local_address=snapshot.local_endpoint.address,
        local_port=snapshot.local_endpoint.port,
        remote_address=remote.address if remote is not None else None,
        remote_port=remote.port if remote is not None else None,
        duration_seconds=duration_seconds,
        first_seen=started_at,
        observed_at=snapshot.observed_at,
        process_info=snapshot.process,
        network_scope=snapshot.network_scope,
    )


def format_endpoint(endpoint: Endpoint) -> str:
    """Format IPv4 and IPv6 endpoints without ambiguous IPv6 ports."""

    if endpoint.ip_version == 6:
        return f"[{endpoint.address}]:{endpoint.port}"
    return f"{endpoint.address}:{endpoint.port}"


def format_state(state: ConnectionState) -> str:
    """Format a portable state for people while retaining a raw state role."""

    if state is ConnectionState.NONE:
        return MISSING_VALUE
    return state.value.replace("_", " ").title()


def format_duration(seconds: float) -> str:
    """Format a non-negative observation-based duration as HH:MM:SS."""

    whole_seconds = max(0, int(seconds))
    hours, remainder = divmod(whole_seconds, 3_600)
    minutes, seconds_part = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds_part:02d}"


__all__ = (
    "ConnectionRow",
    "ConnectionRowId",
    "MISSING_VALUE",
    "connection_row_from_snapshot",
    "connection_row_id",
    "format_duration",
    "format_endpoint",
    "format_state",
)
