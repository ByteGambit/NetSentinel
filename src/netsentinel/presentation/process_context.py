"""Human-readable, conservative display of observed process metadata."""

from __future__ import annotations

from datetime import datetime

from netsentinel.domain.connections import (
    ParentProcessStatus,
    ProcessInfo,
    ProcessInfoStatus,
)


PROCESS_CONTEXT_FIELDS: tuple[tuple[str, str], ...] = (
    ("process_create_time", "Process created"),
    ("executable", "Executable path"),
    ("parent_status", "Observed parent context"),
    ("parent_name", "Parent name"),
    ("parent_pid", "Parent PID"),
    ("parent_create_time", "Parent created"),
    ("parent_observed_at", "Parent observed at"),
)


def _timestamp(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %z")


def _missing(status: ProcessInfoStatus | None) -> str:
    return {
        ProcessInfoStatus.ACCESS_DENIED: "Restricted by Windows permissions",
        ProcessInfoStatus.NOT_FOUND: "Process no longer found",
        ProcessInfoStatus.UNAVAILABLE: "Not available",
        None: "Not available",
    }.get(status, "Not available")


def process_context_text(process: ProcessInfo) -> dict[str, str]:
    """Map each independent availability state without claiming parent lineage."""

    identity = process.identity
    created = identity.create_time if identity is not None else None
    parent = process.parent
    values = {
        "process": process.name if process.name is not None else _missing(process.name_status),
        "pid": str(identity.pid) if identity is not None else "Not available",
        "process_create_time": (
            _timestamp(created) if created is not None else _missing(process.create_time_status)
        ),
        "executable": (
            process.executable_path
            if process.executable_path is not None
            else _missing(process.executable_path_status)
        ),
        "parent_status": "Not observed",
        "parent_name": "Not observed",
        "parent_pid": "Not observed",
        "parent_create_time": "Not observed",
        "parent_observed_at": "Not observed",
    }
    if parent is None:
        return values

    values["parent_status"] = {
        ParentProcessStatus.OBSERVED: "Observed; parent instance verified",
        ParentProcessStatus.ABSENT: "No parent reported",
        ParentProcessStatus.ACCESS_DENIED: "Restricted by Windows permissions",
        ParentProcessStatus.NOT_FOUND: "Parent no longer found",
        ParentProcessStatus.REUSED: "Parent PID may have been reused; instance unverified",
        ParentProcessStatus.UNAVAILABLE: "Parent context unavailable",
    }[parent.status]
    if parent.status is ParentProcessStatus.ABSENT:
        values["parent_name"] = "No parent reported"
        values["parent_pid"] = "No parent reported"
        values["parent_create_time"] = "No parent reported"
    elif parent.status is ParentProcessStatus.REUSED:
        values["parent_name"] = "Not verified"
        values["parent_create_time"] = "Not verified"
    else:
        values["parent_name"] = (
            parent.name if parent.name is not None else _missing(parent.name_status)
        )
        parent_created = parent.identity.create_time if parent.identity is not None else None
        values["parent_create_time"] = (
            _timestamp(parent_created)
            if parent_created is not None
            else _missing(parent.create_time_status)
        )
    if parent.parent_pid is not None:
        values["parent_pid"] = str(parent.parent_pid)
    elif parent.status is not ParentProcessStatus.ABSENT:
        values["parent_pid"] = _missing(parent.pid_status)
    values["parent_observed_at"] = _timestamp(parent.observed_at)
    return values
