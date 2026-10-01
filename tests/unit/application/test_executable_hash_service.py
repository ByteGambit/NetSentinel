"""Bounded on-demand scheduling and process/path correlation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

from netsentinel.application.services.executable_hash import ExecutableHashService
from netsentinel.domain.connections import ProcessIdentity, ProcessInfo, ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashStatus as Status
from netsentinel.infrastructure.local_executable_hasher import LocalFileExecutableHasher


START = datetime(2026, 9, 1, tzinfo=UTC)


def process(pid: int, path: str, *, started: datetime = START) -> ProcessInfo:
    return ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(pid, started), name="sample.exe",
        executable_path=path,
    )


class BlockingHasher:
    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()
        self.calls: list[str] = []

    def hash(self, path: str, *, is_cancelled: object) -> ExecutableHash:
        self.calls.append(path)
        self.entered.set()
        assert self.release.wait(2)
        return ExecutableHash(Status.AVAILABLE, "a" * 64)


def test_many_processes_share_one_pending_file_job_and_keep_tokens() -> None:
    hasher = BlockingHasher()
    service = ExecutableHashService(hasher)
    try:
        first = service.request(process(1, "C:\\same.exe"))
        assert hasher.entered.wait(2)
        others = [service.request(process(pid, "C:\\same.exe")) for pid in range(2, 202)]
        assert all(item.future is first.future for item in others)
        assert service.health_snapshot().coalesced == 200
        assert service.health_snapshot().active == 1
        assert service.health_snapshot().pending == 0
        hasher.release.set()
        assert first.future.result(timeout=2).status is Status.AVAILABLE
        assert hasher.calls == ["C:\\same.exe"]
        assert first.matches(process(1, "C:\\same.exe"))
        assert not first.matches(process(1, "C:\\new.exe"))
        assert not first.matches(process(1, "C:\\same.exe", started=START + timedelta(seconds=1)))
    finally:
        hasher.release.set()
        assert service.stop()


def test_saturation_is_immediate_and_queue_bounded() -> None:
    hasher = BlockingHasher()
    service = ExecutableHashService(hasher, queue_capacity=1)
    try:
        active = service.request(process(1, "C:\\one.exe"))
        assert hasher.entered.wait(2)
        waiting = service.request(process(2, "C:\\two.exe"))
        duplicate = service.request(process(3, "C:\\two.exe"))
        dropped = service.request(process(4, "C:\\three.exe"))
        assert duplicate.future is waiting.future
        assert dropped.future.result().status is Status.SATURATED
        assert service.health_snapshot().pending == 1
        assert service.health_snapshot().saturated == 1
        hasher.release.set()
        assert active.future.result(timeout=2).status is Status.AVAILABLE
        assert waiting.future.result(timeout=2).status is Status.AVAILABLE
    finally:
        hasher.release.set()
        assert service.stop()


def test_shutdown_cancels_active_and_pending_without_hanging() -> None:
    hasher = BlockingHasher()
    service = ExecutableHashService(hasher, queue_capacity=1)
    active = service.request(process(1, "C:\\one.exe"))
    assert hasher.entered.wait(2)
    waiting = service.request(process(2, "C:\\two.exe"))
    assert not service.stop(timeout=0)
    assert active.future.result().status is Status.CANCELLED
    assert waiting.future.result().status is Status.CANCELLED
    assert service.request(process(3, "C:\\three.exe")).future.result().status is Status.CANCELLED
    hasher.release.set()
    assert service.stop(timeout=2)
    assert hasher.calls == ["C:\\one.exe"]


def test_real_service_is_on_demand_and_process_exit_does_not_change_evidence(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"local only")
    service = ExecutableHashService(LocalFileExecutableHasher())
    try:
        assert service.health_snapshot().requested == 0
        submission = service.request(process(10, str(path)))
        assert submission.future.result(timeout=2).status is Status.AVAILABLE
        # The file is still hashable after the process instance has gone away;
        # its result says nothing about whether that process is currently alive.
        assert service.request(process(10, str(path))).future.result(timeout=2).status is Status.AVAILABLE
    finally:
        assert service.stop()


def test_missing_process_path_is_typed_unavailable() -> None:
    service = ExecutableHashService(LocalFileExecutableHasher())
    try:
        info = ProcessInfo(status=ProcessInfoStatus.NOT_FOUND, identity=ProcessIdentity(7))
        assert service.request(info).future.result().status is Status.UNAVAILABLE
        pid_only = ProcessInfo(
            status=ProcessInfoStatus.AVAILABLE, identity=ProcessIdentity(7),
            name="sample.exe", executable_path="C:\\sample.exe",
        )
        assert service.request(pid_only).future.result().status is Status.UNAVAILABLE
        assert service.health_snapshot().active == 0
    finally:
        assert service.stop()
