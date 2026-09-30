"""psutil adapter for portable process metadata resolution."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psutil

from netsentinel.domain.connections import (
    MAX_EXECUTABLE_PATH_LENGTH,
    MAX_PARENT_NAME_LENGTH,
    ParentProcessInfo,
    ParentProcessStatus,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
)


ProcessFactory = Callable[[int], Any]
Clock = Callable[[], datetime]


class PsutilProcessMetadataResolver:
    """Resolve one PID without exposing psutil objects or exceptions."""

    def __init__(
        self,
        process_factory: ProcessFactory | None = None,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._process_factory = process_factory or psutil.Process
        self._clock = clock or (lambda: datetime.now(UTC))

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
        parent = self._read_parent(process, create_time)
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
            parent=parent,
        )

    def _read_parent(
        self, child: Any, child_create_time: datetime | None
    ) -> ParentProcessInfo:
        """Read one parent, then verify child PID and parent instance again."""
        try:
            parent_pid = child.ppid()
            if (
                isinstance(parent_pid, bool)
                or not isinstance(parent_pid, int)
                or parent_pid < 0
            ):
                raise ValueError("invalid parent PID")
        except Exception as error:
            status = _error_status(error)
            return ParentProcessInfo(
                status=_parent_status(status),
                observed_at=self._clock(),
                pid_status=status,
            )
        if parent_pid == 0:
            return ParentProcessInfo(
                status=ParentProcessStatus.ABSENT,
                observed_at=self._clock(),
            )

        try:
            parent = self._process_factory(parent_pid)
        except Exception as error:
            return _parent_failure(parent_pid, _error_status(error), self._clock())

        parent_create_time, create_status = _read_create_time(parent)
        if parent_create_time is None:
            return _parent_failure(
                parent_pid,
                create_status or ProcessInfoStatus.UNAVAILABLE,
                self._clock(),
            )
        if child_create_time is not None and parent_create_time > child_create_time:
            return _parent_failure(
                parent_pid, ProcessInfoStatus.UNAVAILABLE, self._clock(), reused=True
            )

        name, name_status = _read_name(parent)
        if name is not None and (
            len(name) > MAX_PARENT_NAME_LENGTH or any(ord(char) < 32 for char in name)
        ):
            name, name_status = None, ProcessInfoStatus.UNAVAILABLE

        try:
            current_parent_pid = child.ppid()
        except Exception as error:
            return _parent_failure(parent_pid, _error_status(error), self._clock())
        if current_parent_pid != parent_pid:
            return _parent_failure(
                parent_pid, ProcessInfoStatus.UNAVAILABLE, self._clock(), reused=True
            )

        try:
            fresh_parent = self._process_factory(parent_pid)
        except Exception as error:
            return _parent_failure(parent_pid, _error_status(error), self._clock())
        fresh_create_time, fresh_status = _read_create_time(fresh_parent)
        if fresh_create_time is None:
            return _parent_failure(
                parent_pid,
                fresh_status or ProcessInfoStatus.UNAVAILABLE,
                self._clock(),
            )
        if fresh_create_time != parent_create_time:
            return _parent_failure(
                parent_pid, ProcessInfoStatus.UNAVAILABLE, self._clock(), reused=True
            )

        return ParentProcessInfo(
            status=ParentProcessStatus.OBSERVED,
            observed_at=self._clock(),
            parent_pid=parent_pid,
            identity=ProcessIdentity(parent_pid, parent_create_time),
            name=name,
            pid_status=ProcessInfoStatus.AVAILABLE,
            create_time_status=ProcessInfoStatus.AVAILABLE,
            name_status=name_status or ProcessInfoStatus.AVAILABLE,
        )


def _error_status(error: Exception) -> ProcessInfoStatus:
    if isinstance(error, (psutil.NoSuchProcess, psutil.ZombieProcess)):
        return ProcessInfoStatus.NOT_FOUND
    if isinstance(error, psutil.AccessDenied):
        return ProcessInfoStatus.ACCESS_DENIED
    return ProcessInfoStatus.UNAVAILABLE


def _parent_status(status: ProcessInfoStatus) -> ParentProcessStatus:
    if status is ProcessInfoStatus.NOT_FOUND:
        return ParentProcessStatus.NOT_FOUND
    if status is ProcessInfoStatus.ACCESS_DENIED:
        return ParentProcessStatus.ACCESS_DENIED
    return ParentProcessStatus.UNAVAILABLE


def _parent_failure(
    parent_pid: int,
    status: ProcessInfoStatus,
    observed_at: datetime,
    *,
    reused: bool = False,
) -> ParentProcessInfo:
    return ParentProcessInfo(
        status=ParentProcessStatus.REUSED if reused else _parent_status(status),
        observed_at=observed_at,
        parent_pid=parent_pid,
        pid_status=ProcessInfoStatus.AVAILABLE,
        create_time_status=status,
        name_status=status,
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
