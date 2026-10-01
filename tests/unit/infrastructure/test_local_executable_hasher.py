"""Deterministic local executable hashing tests."""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
from typing import BinaryIO

import pytest

from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashStatus as Status
from netsentinel.infrastructure.local_executable_hasher import LocalFileExecutableHasher


def run(hasher: LocalFileExecutableHasher, path: str) -> ExecutableHash:
    return hasher.hash(path, is_cancelled=lambda: False)


@pytest.mark.parametrize("content", [b"abc", b"", b"0123456789" * 100_000], ids=["known", "empty", "large"])
def test_sha256_is_canonical_and_streamed(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(content)
    reads: list[int] = []

    class Reader:
        def __init__(self, stream: BinaryIO) -> None:
            self.stream = stream

        def __enter__(self) -> Reader:
            return self

        def __exit__(self, *_args: object) -> None:
            self.stream.close()

        def fileno(self) -> int:
            return self.stream.fileno()

        def read(self, count: int) -> bytes:
            reads.append(count)
            return self.stream.read(count)

    hasher = LocalFileExecutableHasher(chunk_size=17, opener=lambda p: Reader(open(p, "rb")))  # type: ignore[arg-type]
    result = run(hasher, str(path))
    assert result == ExecutableHash(Status.AVAILABLE, sha256(content).hexdigest())
    assert reads and set(reads) == {17}


def test_changed_content_and_metadata_invalidate_cache(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"one")
    hasher = LocalFileExecutableHasher()
    first = run(hasher, str(path))
    assert run(hasher, str(path)) == first
    assert hasher.cache_hits == 1
    path.write_bytes(b"two-longer")
    second = run(hasher, str(path))
    assert second.status is Status.AVAILABLE and second.digest != first.digest
    assert hasher.cache_hits == 1


def test_cache_is_bounded_lru(tmp_path: Path) -> None:
    paths = [tmp_path / f"{index}.exe" for index in range(3)]
    for index, path in enumerate(paths):
        path.write_bytes(bytes([index]))
    hasher = LocalFileExecutableHasher(cache_capacity=2)
    run(hasher, str(paths[0]))
    run(hasher, str(paths[1]))
    run(hasher, str(paths[0]))
    run(hasher, str(paths[2]))
    assert hasher.cache_size == 2
    hits = hasher.cache_hits
    run(hasher, str(paths[1]))
    assert hasher.cache_hits == hits  # path 1 was the LRU victim


def test_metadata_mutation_during_read_never_publishes_success(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"content")

    class MutatingReader:
        def __init__(self, stream: BinaryIO) -> None:
            self.stream = stream

        def __enter__(self) -> MutatingReader:
            return self

        def __exit__(self, *_args: object) -> None:
            self.stream.close()

        def fileno(self) -> int:
            return self.stream.fileno()

        def read(self, count: int) -> bytes:
            os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 2_000_000_000))
            return self.stream.read(count)

    hasher = LocalFileExecutableHasher(opener=lambda p: MutatingReader(open(p, "rb")))  # type: ignore[arg-type]
    assert run(hasher, str(path)).status is Status.CHANGED_DURING_READ
    assert hasher.cache_size == 0


def test_deleted_and_denied_are_typed(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    assert run(LocalFileExecutableHasher(), str(path)).status is Status.NOT_FOUND
    path.write_bytes(b"x")

    def denied(_path: str) -> BinaryIO:
        raise PermissionError

    assert run(LocalFileExecutableHasher(opener=denied), str(path)).status is Status.ACCESS_DENIED

    def deleted(_path: str) -> BinaryIO:
        path.unlink()
        raise FileNotFoundError

    assert run(LocalFileExecutableHasher(opener=deleted), str(path)).status is Status.NOT_FOUND


def test_path_replaced_between_stat_and_open_is_changed(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"original")

    def replace_before_open(value: str) -> BinaryIO:
        path.write_bytes(b"different length")
        return open(value, "rb")

    hasher = LocalFileExecutableHasher(opener=replace_before_open)
    assert run(hasher, str(path)).status is Status.CHANGED_DURING_READ
    assert hasher.cache_size == 0


def test_path_disappearing_during_read_is_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import netsentinel.infrastructure.local_executable_hasher as module

    path = tmp_path / "sample.exe"
    path.write_bytes(b"content")
    real_stat = os.stat
    opened = False

    def disappearing_stat(value: object, *args: object, **kwargs: object) -> os.stat_result:
        if str(value) == str(path) and opened:
            raise FileNotFoundError
        return real_stat(value, *args, **kwargs)  # type: ignore[arg-type]

    def open_then_disappear(value: str) -> BinaryIO:
        nonlocal opened
        stream = open(value, "rb")
        opened = True
        return stream

    monkeypatch.setattr(module.os, "stat", disappearing_stat)
    assert run(LocalFileExecutableHasher(opener=open_then_disappear), str(path)).status is Status.CHANGED_DURING_READ


def test_limits_invalid_directory_remote_and_cancel(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"12345")
    assert run(LocalFileExecutableHasher(max_bytes=4), str(path)).status is Status.TOO_LARGE
    assert run(LocalFileExecutableHasher(), str(tmp_path)).status is Status.INVALID_PATH
    assert run(LocalFileExecutableHasher(), "relative.exe").status is Status.INVALID_PATH
    assert run(LocalFileExecutableHasher(), "\\\\server\\share\\file.exe").status is Status.REMOTE_PATH
    assert LocalFileExecutableHasher().hash(str(path), is_cancelled=lambda: True).status is Status.CANCELLED
    assert run(LocalFileExecutableHasher(clock=lambda: 0, time_budget=1), str(path)).status is Status.AVAILABLE


def test_time_budget_is_cooperative_and_typed(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"x")
    ticks = iter((0.0, 1.0))
    hasher = LocalFileExecutableHasher(time_budget=1, clock=lambda: next(ticks))
    assert run(hasher, str(path)).status is Status.TIMED_OUT


def test_invalid_digest_rejected() -> None:
    with pytest.raises(ValueError):
        ExecutableHash(Status.AVAILABLE, "A" * 64)
    with pytest.raises(ValueError):
        ExecutableHash(Status.AVAILABLE, "a" * 63)
    with pytest.raises(ValueError):
        ExecutableHash(Status.NOT_FOUND, "a" * 64)
