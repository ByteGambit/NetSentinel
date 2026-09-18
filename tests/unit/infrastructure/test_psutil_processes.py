"""Unit tests for the psutil process metadata resolver adapter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import psutil
import pytest

from netsentinel.application.ports import ProcessMetadataResolver
from netsentinel.domain.connections import (
    ProcessIdentity,
    ProcessInfoStatus,
)
from netsentinel.infrastructure.psutil_processes import (
    PsutilProcessMetadataResolver,
)


STARTED_AT = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


class FakeProcess:
    def __init__(self, *, name: Any = "browser.exe", create_time: Any = None) -> None:
        self._name = name
        self._create_time = (
            STARTED_AT.timestamp() if create_time is None else create_time
        )

    def name(self) -> Any:
        if isinstance(self._name, BaseException):
            raise self._name
        return self._name

    def create_time(self) -> Any:
        if isinstance(self._create_time, BaseException):
            raise self._create_time
        return self._create_time


def resolver_for(process: FakeProcess) -> PsutilProcessMetadataResolver:
    return PsutilProcessMetadataResolver(process_factory=lambda pid: process)


def test_resolver_satisfies_port_and_returns_portable_metadata() -> None:
    resolver: ProcessMetadataResolver = resolver_for(FakeProcess())

    result = resolver.resolve(42)

    assert result.status is ProcessInfoStatus.AVAILABLE
    assert result.identity == ProcessIdentity(42, STARTED_AT)
    assert result.name == "browser.exe"
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

    result = resolver_for(
        FakeProcess(create_time=local_time.timestamp())
    ).resolve(42)

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
    result = resolver_for(
        FakeProcess(name=name, create_time=create_time)
    ).resolve(42)

    assert result.identity is not None
    assert result.identity.pid == 42
    assert result.status in {
        ProcessInfoStatus.AVAILABLE,
        ProcessInfoStatus.UNAVAILABLE,
    }

