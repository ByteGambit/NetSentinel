"""Unit tests for the psutil process metadata resolver adapter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import psutil
import pytest

from netsentinel.application.ports import ProcessMetadataResolver
from netsentinel.domain.connections import (
    MAX_EXECUTABLE_PATH_LENGTH,
    ParentProcessStatus,
    ProcessIdentity,
    ProcessInfoStatus,
)
from netsentinel.infrastructure.psutil_processes import (
    PsutilProcessMetadataResolver,
)


STARTED_AT = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


class FakeProcess:
    def __init__(
        self,
        *,
        name: Any = "browser.exe",
        create_time: Any = None,
        executable_path: Any = "C:\\Apps\\browser.exe",
        ppid: Any = 0,
    ) -> None:
        self._name = name
        self._create_time = (
            STARTED_AT.timestamp() if create_time is None else create_time
        )
        self._executable_path = executable_path
        self._ppid = ppid
        self.exe_calls = 0

    def name(self) -> Any:
        if isinstance(self._name, BaseException):
            raise self._name
        return self._name

    def create_time(self) -> Any:
        if isinstance(self._create_time, BaseException):
            raise self._create_time
        return self._create_time

    def exe(self) -> Any:
        self.exe_calls += 1
        if isinstance(self._executable_path, BaseException):
            raise self._executable_path
        return self._executable_path

    def ppid(self) -> Any:
        if isinstance(self._ppid, BaseException):
            raise self._ppid
        return self._ppid


def resolver_for(process: FakeProcess) -> PsutilProcessMetadataResolver:
    return PsutilProcessMetadataResolver(process_factory=lambda pid: process)


def test_resolver_satisfies_port_and_returns_portable_metadata() -> None:
    resolver: ProcessMetadataResolver = resolver_for(FakeProcess())

    result = resolver.resolve(42)

    assert result.status is ProcessInfoStatus.AVAILABLE
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.name == "browser.exe"
    assert result.executable_path == "C:\\Apps\\browser.exe"
    assert result.name_status is ProcessInfoStatus.AVAILABLE
    assert result.create_time_status is ProcessInfoStatus.AVAILABLE
    assert result.executable_path_status is ProcessInfoStatus.AVAILABLE
    assert type(result).__module__ == "netsentinel.domain.connections"


def test_create_time_is_converted_to_utc() -> None:
    local_time = datetime(
        2026,
        9,
        18,
        11,
        0,
        tzinfo=timezone(timedelta(hours=3)),
    )

    result = resolver_for(FakeProcess(create_time=local_time.timestamp())).resolve(42)

    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.identity.create_time is not None
    assert result.identity.create_time.tzinfo is UTC


def test_same_pid_with_different_create_time_has_different_identity() -> None:
    starts = iter(
        [
            STARTED_AT.timestamp(),
            (STARTED_AT + timedelta(minutes=5)).timestamp(),
        ]
    )

    def factory(pid: int) -> FakeProcess:
        return FakeProcess(create_time=next(starts))

    resolver = PsutilProcessMetadataResolver(process_factory=factory)

    first = resolver.resolve(42)
    second = resolver.resolve(42)

    assert first.identity != second.identity
    assert first.identity.pid == second.identity.pid == 42


def test_access_denied_during_process_lookup_is_explicit() -> None:
    def denied(pid: int) -> FakeProcess:
        raise psutil.AccessDenied(pid=pid)

    result = PsutilProcessMetadataResolver(process_factory=denied).resolve(4)

    assert result.status is ProcessInfoStatus.ACCESS_DENIED
    assert result.identity == ProcessIdentity(4)
    assert result.name is None


@pytest.mark.parametrize(
    "error",
    [
        psutil.NoSuchProcess(pid=42),
        psutil.ZombieProcess(pid=42),
    ],
)
def test_missing_or_zombie_process_is_not_found(error: psutil.Error) -> None:
    def missing(pid: int) -> FakeProcess:
        raise error

    result = PsutilProcessMetadataResolver(process_factory=missing).resolve(42)

    assert result.status is ProcessInfoStatus.NOT_FOUND
    assert result.identity == ProcessIdentity(42)
    assert result.name is None


def test_process_exit_between_metadata_reads_preserves_known_create_time() -> None:
    process = FakeProcess(name=psutil.NoSuchProcess(pid=42))

    result = resolver_for(process).resolve(42)

    assert result.status is ProcessInfoStatus.NOT_FOUND
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.name is None


def test_partial_metadata_keeps_name_when_create_time_is_denied() -> None:
    process = FakeProcess(
        name="visible.exe",
        create_time=psutil.AccessDenied(pid=42),
    )

    result = resolver_for(process).resolve(42)

    assert result.status is ProcessInfoStatus.AVAILABLE
    assert result.identity == ProcessIdentity(42)
    assert result.name == "visible.exe"


def test_partial_metadata_keeps_create_time_when_name_is_denied() -> None:
    process = FakeProcess(name=psutil.AccessDenied(pid=42))

    result = resolver_for(process).resolve(42)

    assert result.status is ProcessInfoStatus.ACCESS_DENIED
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.name is None
    assert result.name_status is ProcessInfoStatus.ACCESS_DENIED
    assert result.create_time_status is ProcessInfoStatus.AVAILABLE
    assert result.executable_path == "C:\\Apps\\browser.exe"
    assert result.executable_path_status is ProcessInfoStatus.AVAILABLE


def test_path_denial_keeps_name_create_time_and_identity() -> None:
    result = resolver_for(
        FakeProcess(executable_path=psutil.AccessDenied(pid=42))
    ).resolve(42)

    assert result.status is ProcessInfoStatus.AVAILABLE
    assert result.name == "browser.exe"
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.name_status is ProcessInfoStatus.AVAILABLE
    assert result.create_time_status is ProcessInfoStatus.AVAILABLE
    assert result.executable_path is None
    assert result.executable_path_status is ProcessInfoStatus.ACCESS_DENIED


def test_path_exit_race_preserves_earlier_metadata() -> None:
    result = resolver_for(
        FakeProcess(executable_path=psutil.NoSuchProcess(pid=42))
    ).resolve(42)

    assert result.status is ProcessInfoStatus.AVAILABLE
    assert result.name == "browser.exe"
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.executable_path is None
    assert result.executable_path_status is ProcessInfoStatus.NOT_FOUND


@pytest.mark.parametrize(
    "path",
    ["", "   ", object(), "C:\\bad\x00path", "x" * (MAX_EXECUTABLE_PATH_LENGTH + 1)],
)
def test_empty_invalid_or_oversized_path_is_typed_unavailable(path: Any) -> None:
    result = resolver_for(FakeProcess(executable_path=path)).resolve(42)

    assert result.name == "browser.exe"
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.executable_path is None
    assert result.executable_path_status is ProcessInfoStatus.UNAVAILABLE


def test_unexpected_path_api_failure_is_sanitized() -> None:
    result = resolver_for(
        FakeProcess(executable_path=RuntimeError("sensitive local path"))
    ).resolve(42)

    assert result.name == "browser.exe"
    assert result.executable_path_status is ProcessInfoStatus.UNAVAILABLE


@pytest.mark.parametrize(
    ("name", "create_time"),
    [
        ("", STARTED_AT.timestamp()),
        (object(), STARTED_AT.timestamp()),
        ("visible.exe", "not-a-timestamp"),
        (OSError("lookup failed"), OSError("lookup failed")),
    ],
)
def test_malformed_or_unavailable_partial_fields_are_safe(
    name: Any, create_time: Any
) -> None:
    result = resolver_for(FakeProcess(name=name, create_time=create_time)).resolve(42)

    assert result.identity is not None
    assert result.identity.pid == 42
    assert result.status in {
        ProcessInfoStatus.AVAILABLE,
        ProcessInfoStatus.UNAVAILABLE,
    }


PARENT_STARTED_AT = STARTED_AT - timedelta(hours=1)


def parent_resolver(
    child: FakeProcess,
    parent_factory: Any,
) -> tuple[PsutilProcessMetadataResolver, list[int]]:
    calls: list[int] = []

    def factory(pid: int) -> FakeProcess:
        calls.append(pid)
        return child if pid == 42 else parent_factory()

    return (
        PsutilProcessMetadataResolver(
            process_factory=factory,
            clock=lambda: STARTED_AT + timedelta(minutes=1),
        ),
        calls,
    )


def test_parent_success_has_verified_instance_name_and_observation_time() -> None:
    resolver, calls = parent_resolver(
        FakeProcess(ppid=7),
        lambda: FakeProcess(
            name="WINWORD.EXE", create_time=PARENT_STARTED_AT.timestamp()
        ),
    )

    result = resolver.resolve(42)
    parent = result.parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.OBSERVED
    assert parent.parent_pid == 7
    assert parent.identity == ProcessIdentity(7, PARENT_STARTED_AT)
    assert parent.name == "WINWORD.EXE"
    assert parent.observed_at == STARTED_AT + timedelta(minutes=1)
    assert parent.pid_status is ProcessInfoStatus.AVAILABLE
    assert parent.create_time_status is ProcessInfoStatus.AVAILABLE
    assert parent.name_status is ProcessInfoStatus.AVAILABLE
    assert calls == [42, 7, 7]


def test_parent_absence_is_not_lookup_failure() -> None:
    resolver, calls = parent_resolver(FakeProcess(ppid=0), lambda: None)

    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.ABSENT
    assert parent.parent_pid is None
    assert calls == [42]


@pytest.mark.parametrize(
    ("parent_factory", "expected"),
    [
        (
            lambda: (_ for _ in ()).throw(psutil.AccessDenied(pid=7)),
            ParentProcessStatus.ACCESS_DENIED,
        ),
        (
            lambda: (_ for _ in ()).throw(psutil.NoSuchProcess(pid=7)),
            ParentProcessStatus.NOT_FOUND,
        ),
    ],
)
def test_parent_lookup_failure_preserves_current_metadata(
    parent_factory: Any, expected: ParentProcessStatus
) -> None:
    resolver, _ = parent_resolver(FakeProcess(ppid=7), parent_factory)

    result = resolver.resolve(42)

    assert result.name == "browser.exe"
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.executable_path == "C:\\Apps\\browser.exe"
    assert result.parent is not None
    assert result.parent.status is expected
    assert result.parent.parent_pid == 7
    assert result.parent.identity is None
    assert result.parent.name is None


def test_parent_exit_after_first_lookup_discards_unverified_relationship() -> None:
    calls = 0

    def parent_factory() -> FakeProcess:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise psutil.NoSuchProcess(pid=7)
        return FakeProcess(name="old.exe", create_time=PARENT_STARTED_AT.timestamp())

    resolver, _ = parent_resolver(FakeProcess(ppid=7), parent_factory)
    result = resolver.resolve(42)

    assert result.parent is not None
    assert result.parent.status is ParentProcessStatus.NOT_FOUND
    assert result.parent.identity is None
    assert result.parent.name is None
    assert result.name == "browser.exe"


def test_parent_pid_reuse_between_reads_discards_relationship() -> None:
    calls = 0

    def parent_factory() -> FakeProcess:
        nonlocal calls
        calls += 1
        started = (
            PARENT_STARTED_AT
            if calls == 1
            else PARENT_STARTED_AT + timedelta(minutes=1)
        )
        return FakeProcess(name="other.exe", create_time=started.timestamp())

    resolver, _ = parent_resolver(FakeProcess(ppid=7), parent_factory)
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.REUSED
    assert parent.identity is None
    assert parent.name is None


def test_child_ppid_change_during_lookup_discards_relationship() -> None:
    class ChangingChild(FakeProcess):
        calls = 0

        def ppid(self) -> int:
            self.calls += 1
            return 7 if self.calls == 1 else 8

    resolver, calls = parent_resolver(
        ChangingChild(),
        lambda: FakeProcess(create_time=PARENT_STARTED_AT.timestamp()),
    )
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.REUSED
    assert parent.identity is None
    assert calls == [42, 7]


@pytest.mark.parametrize("name", ["bad\x00name", "x" * 256])
def test_invalid_parent_name_preserves_verified_instance(name: str) -> None:
    resolver, _ = parent_resolver(
        FakeProcess(ppid=7),
        lambda: FakeProcess(name=name, create_time=PARENT_STARTED_AT.timestamp()),
    )
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.OBSERVED
    assert parent.identity == ProcessIdentity(7, PARENT_STARTED_AT)
    assert parent.name is None
    assert parent.name_status is ProcessInfoStatus.UNAVAILABLE


def test_parent_newer_than_child_is_reuse_risk() -> None:
    resolver, _ = parent_resolver(
        FakeProcess(ppid=7),
        lambda: FakeProcess(
            create_time=(STARTED_AT + timedelta(minutes=1)).timestamp()
        ),
    )
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.REUSED
    assert parent.identity is None


def test_parent_name_denial_retains_verified_pid_and_create_time() -> None:
    resolver, _ = parent_resolver(
        FakeProcess(ppid=7),
        lambda: FakeProcess(
            name=psutil.AccessDenied(pid=7), create_time=PARENT_STARTED_AT.timestamp()
        ),
    )
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.OBSERVED
    assert parent.identity == ProcessIdentity(7, PARENT_STARTED_AT)
    assert parent.name is None
    assert parent.name_status is ProcessInfoStatus.ACCESS_DENIED


def test_parent_create_time_denial_keeps_only_reported_pid() -> None:
    resolver, _ = parent_resolver(
        FakeProcess(ppid=7),
        lambda: FakeProcess(create_time=psutil.AccessDenied(pid=7)),
    )
    parent = resolver.resolve(42).parent

    assert parent is not None
    assert parent.status is ParentProcessStatus.ACCESS_DENIED
    assert parent.parent_pid == 7
    assert parent.identity is None
    assert parent.create_time_status is ProcessInfoStatus.ACCESS_DENIED
