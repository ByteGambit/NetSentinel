"""psutil adapter for portable process metadata resolution."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psutil

from netsentinel.domain.connections import (
    MAX_EXECUTABLE_PATH_LENGTH,
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
            return _unresolved(identity, ProcessInfoStatus.NOT_FOUND)
        except psutil.AccessDenied:
            return _unresolved(identity, ProcessInfoStatus.ACCESS_DENIED)
        except Exception:
            return _unresolved(identity, ProcessInfoStatus.UNAVAILABLE)

        create_time, create_status = _read_create_time(process)
        identity = ProcessIdentity(pid=pid, create_time=create_time)
        name, name_status = _read_name(process)
        executable_path, path_status = _read_executable_path(process)
        status = (
            ProcessInfoStatus.AVAILABLE
            if name is not None
            else _unavailable_status(name_status, create_status)
        )

        return ProcessInfo(
            status=status,
            identity=identity,
            name=name,
            executable_path=executable_path,
            name_status=name_status or ProcessInfoStatus.AVAILABLE,
            create_time_status=create_status or ProcessInfoStatus.AVAILABLE,
            executable_path_status=path_status or ProcessInfoStatus.AVAILABLE,
        )


def _unresolved(identity: ProcessIdentity, status: ProcessInfoStatus) -> ProcessInfo:
    return ProcessInfo(
        status=status,
        identity=identity,
        create_time_status=status,
        executable_path_status=status,
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
    except Exception:
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
    except Exception:
        return None, ProcessInfoStatus.UNAVAILABLE


def _read_executable_path(
    process: Any,
) -> tuple[str | None, ProcessInfoStatus | None]:
    try:
        path = process.exe()
        if (
            not isinstance(path, str)
            or not path.strip()
            or len(path) > MAX_EXECUTABLE_PATH_LENGTH
            or any(ord(char) < 32 for char in path)
        ):
            return None, ProcessInfoStatus.UNAVAILABLE
        return path, None
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, ProcessInfoStatus.NOT_FOUND
    except psutil.AccessDenied:
        return None, ProcessInfoStatus.ACCESS_DENIED
    except Exception:
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
