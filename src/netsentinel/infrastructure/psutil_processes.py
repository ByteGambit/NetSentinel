"""psutil adapter for portable process metadata resolution."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psutil

from netsentinel.domain.connections import (
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
)


ProcessFactory = Callable[[int], Any]


class PsutilProcessMetadataResolver:
    """Resolve one PID without exposing psutil objects or exceptions."""

    def __init__(self, process_factory: ProcessFactory | None = None) -> None:
        self._process_factory = process_factory or psutil.Process

    def resolve(self, pid: int) -> ProcessInfo:
        """Return the metadata still available if lookup races or is restricted."""

        identity = ProcessIdentity(pid=pid)
        try:
            process = self._process_factory(pid)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return ProcessInfo(
                status=ProcessInfoStatus.NOT_FOUND,
                identity=identity,
            )
        except psutil.AccessDenied:
            return ProcessInfo(
                status=ProcessInfoStatus.ACCESS_DENIED,
                identity=identity,
            )
        except (psutil.Error, OSError):
            return ProcessInfo(
                status=ProcessInfoStatus.UNAVAILABLE,
                identity=identity,
            )

        create_time, create_status = _read_create_time(process)
        identity = ProcessIdentity(pid=pid, create_time=create_time)
        name, name_status = _read_name(process)

        if name is not None:
            return ProcessInfo(
                status=ProcessInfoStatus.AVAILABLE,
                identity=identity,
                name=name,
            )

        return ProcessInfo(
            status=_unavailable_status(name_status, create_status),
            identity=identity,
        )


def _read_create_time(
    process: Any,
) -> tuple[datetime | None, ProcessInfoStatus | None]:
    try:
        timestamp = process.create_time()
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise TypeError("process create time must be a number")
        return datetime.fromtimestamp(timestamp, tz=UTC), None
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, ProcessInfoStatus.NOT_FOUND
    except psutil.AccessDenied:
        return None, ProcessInfoStatus.ACCESS_DENIED
    except (psutil.Error, OSError, OverflowError, TypeError, ValueError):
        return None, ProcessInfoStatus.UNAVAILABLE


def _read_name(process: Any) -> tuple[str | None, ProcessInfoStatus | None]:
    try:
        name = process.name()
        if not isinstance(name, str) or not name.strip():
            raise ValueError("process name must be a non-empty string")
        return name, None
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, ProcessInfoStatus.NOT_FOUND
    except psutil.AccessDenied:
        return None, ProcessInfoStatus.ACCESS_DENIED
    except (psutil.Error, OSError, TypeError, ValueError):
        return None, ProcessInfoStatus.UNAVAILABLE


def _unavailable_status(
    first: ProcessInfoStatus | None,
    second: ProcessInfoStatus | None,
) -> ProcessInfoStatus:
    statuses = {first, second}
    if ProcessInfoStatus.NOT_FOUND in statuses:
        return ProcessInfoStatus.NOT_FOUND
    if ProcessInfoStatus.ACCESS_DENIED in statuses:
        return ProcessInfoStatus.ACCESS_DENIED
    return ProcessInfoStatus.UNAVAILABLE


__all__ = ("PsutilProcessMetadataResolver",)
