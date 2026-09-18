"""psutil adapter for normalized TCP and UDP connection snapshots."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
import socket
from typing import Any

import psutil

from netsentinel.application.ports import (
    ConnectionCollectionPermissionDenied,
    ConnectionCollectionTransientError,
)
from netsentinel.domain.connections import (
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)


ConnectionProvider = Callable[..., Iterable[Any]]
Clock = Callable[[], datetime]


_TCP_STATE_MAP: dict[str, ConnectionState] = {
    "ESTABLISHED": ConnectionState.ESTABLISHED,
    "SYN_SENT": ConnectionState.SYN_SENT,
    "SYN_RECV": ConnectionState.SYN_RECEIVED,
    "FIN_WAIT1": ConnectionState.FIN_WAIT_1,
    "FIN_WAIT2": ConnectionState.FIN_WAIT_2,
    "CLOSE_WAIT": ConnectionState.CLOSE_WAIT,
    "CLOSING": ConnectionState.CLOSING,
    "LAST_ACK": ConnectionState.LAST_ACK,
    "TIME_WAIT": ConnectionState.TIME_WAIT,
    "CLOSE": ConnectionState.CLOSED,
    "LISTEN": ConnectionState.LISTEN,
}


class PsutilConnectionCollector:
    """Collect system-wide psutil rows and isolate their OS-specific shape."""

    def __init__(
        self,
        *,
        connections_provider: ConnectionProvider | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._connections_provider = (
            connections_provider
            if connections_provider is not None
            else psutil.net_connections
        )
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def collect(self) -> tuple[ConnectionSnapshot, ...]:
        """Return a deterministic tuple of valid rows visible in this pass.

        Failure to obtain the system-wide table is surfaced as a typed adapter
        error. Individual malformed or racy rows are skipped so one bad row
        cannot discard the rest of the snapshot.
        """

        try:
            records = tuple(self._connections_provider(kind="inet"))
        except (psutil.AccessDenied, PermissionError) as error:
            raise ConnectionCollectionPermissionDenied(
                "access to system connection information was denied"
            ) from error
        except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError) as error:
            raise ConnectionCollectionTransientError(
                "connection information changed while it was being collected"
            ) from error
        except psutil.Error as error:
            raise ConnectionCollectionTransientError(
                "psutil could not collect system connection information"
            ) from error

        observed_at = _utc_time(self._clock())
        snapshots: list[ConnectionSnapshot] = []
        for record in records:
            try:
                snapshots.append(_normalize_record(record, observed_at))
            except (AttributeError, IndexError, TypeError, ValueError, psutil.Error):
                continue

        return tuple(sorted(snapshots, key=_snapshot_sort_key))


def _normalize_record(record: Any, observed_at: datetime) -> ConnectionSnapshot:
    family = record.family
    if family == socket.AF_INET:
        ip_version = 4
    elif family == socket.AF_INET6:
        ip_version = 6
    else:
        raise ValueError("unsupported address family")

    if record.type == socket.SOCK_STREAM:
        protocol = TransportProtocol.TCP
    elif record.type == socket.SOCK_DGRAM:
        protocol = TransportProtocol.UDP
    else:
        raise ValueError("unsupported socket type")

    local_endpoint = _normalize_endpoint(record.laddr, required=True)
    if local_endpoint is None:  # pragma: no cover - required=True guarantees this
        raise ValueError("local endpoint is required")
    if local_endpoint.ip_version != ip_version:
        raise ValueError("local endpoint does not match address family")

    remote_endpoint = _normalize_endpoint(record.raddr, required=False)
    if remote_endpoint is not None and remote_endpoint.ip_version != ip_version:
        raise ValueError("remote endpoint does not match address family")

    state = (
        ConnectionState.NONE
        if protocol is TransportProtocol.UDP
        else _normalize_tcp_state(record.status)
    )

    pid = getattr(record, "pid", None)
    process = ProcessInfo.unavailable()
    if pid is not None:
        process = ProcessInfo(
            status=ProcessInfoStatus.UNAVAILABLE,
            identity=ProcessIdentity(pid=pid),
        )

    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=local_endpoint,
        remote_endpoint=remote_endpoint,
        state=state,
        process=process,
        observed_at=observed_at,
    )


def _normalize_endpoint(raw_endpoint: Any, *, required: bool) -> Endpoint | None:
    if not raw_endpoint:
        if required:
            raise ValueError("local endpoint is missing")
        return None

    address = getattr(raw_endpoint, "ip", None)
    port = getattr(raw_endpoint, "port", None)
    if address is None or port is None:
        if isinstance(raw_endpoint, (str, bytes)):
            raise TypeError("endpoint must contain an address and port")
        try:
            address, port, *_ = raw_endpoint
        except (TypeError, ValueError) as error:
            raise ValueError("endpoint must contain an address and port") from error

    return Endpoint(address=address, port=port)


def _normalize_tcp_state(raw_state: Any) -> ConnectionState:
    if not isinstance(raw_state, str):
        return ConnectionState.UNKNOWN
    return _TCP_STATE_MAP.get(raw_state.upper(), ConnectionState.UNKNOWN)


def _utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("clock must return a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _snapshot_sort_key(snapshot: ConnectionSnapshot) -> tuple[object, ...]:
    remote = snapshot.remote_endpoint
    identity = snapshot.process.identity
    return (
        snapshot.protocol.value,
        snapshot.local_endpoint.ip_version,
        snapshot.local_endpoint.address,
        snapshot.local_endpoint.port,
        remote is not None,
        remote.address if remote is not None else "",
        remote.port if remote is not None else -1,
        identity.pid if identity is not None else -1,
        snapshot.state.value,
    )


__all__ = ("PsutilConnectionCollector",)
