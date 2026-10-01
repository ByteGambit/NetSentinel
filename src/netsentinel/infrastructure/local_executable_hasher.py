"""Bounded, local-only SHA-256 adapter for executable file evidence."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from hashlib import sha256
import os
from pathlib import Path
import stat
from threading import Lock
from time import monotonic
from typing import BinaryIO

from netsentinel.domain.connections import MAX_EXECUTABLE_PATH_LENGTH
from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashStatus as Status


FileKey = tuple[int, int, int, int, str]


class LocalFileExecutableHasher:
    """Read a regular local file; metadata cache is an optimization, not identity proof."""

    def __init__(
        self, *, max_bytes: int = 1_073_741_824, time_budget: float = 5.0,
        chunk_size: int = 1_048_576, cache_capacity: int = 128,
        clock: Callable[[], float] = monotonic,
        opener: Callable[[str], BinaryIO] | None = None,
    ) -> None:
        if any(type(value) is not int or value <= 0 for value in (max_bytes, chunk_size, cache_capacity)):
            raise ValueError("size and cache limits must be positive integers")
        if not isinstance(time_budget, (int, float)) or isinstance(time_budget, bool) or not 0 < time_budget <= 60:
            raise ValueError("time_budget must be between zero and 60 seconds")
        self.max_bytes = max_bytes
        self.time_budget = float(time_budget)
        self.chunk_size = chunk_size
        self.cache_capacity = cache_capacity
        self._clock = clock
        self._opener = opener or (lambda path: open(path, "rb"))
        self._cache: OrderedDict[FileKey, ExecutableHash] = OrderedDict()
        self._lock = Lock()
        self._cache_hits = 0

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def cache_hits(self) -> int:
        with self._lock:
            return self._cache_hits

    def hash(self, path: str, *, is_cancelled: Callable[[], bool]) -> ExecutableHash:
        if not isinstance(path, str) or not path or len(path) > MAX_EXECUTABLE_PATH_LENGTH or any(ord(c) < 32 for c in path):
            return ExecutableHash(Status.INVALID_PATH)
        if path.startswith(("\\\\", "//")) or path.lower().startswith(("\\\\?\\unc\\", "//?/unc/")):
            return ExecutableHash(Status.REMOTE_PATH)
        if not os.path.isabs(path):
            return ExecutableHash(Status.INVALID_PATH)
        if is_cancelled():
            return ExecutableHash(Status.CANCELLED)
        deadline = self._clock() + self.time_budget
        try:
            # Do not traverse a link that may redirect a local path to a UNC share.
            if Path(path).is_symlink():
                return ExecutableHash(Status.UNAVAILABLE)
            before = os.stat(path)
            if not stat.S_ISREG(before.st_mode):
                return ExecutableHash(Status.INVALID_PATH)
            if before.st_size > self.max_bytes:
                return ExecutableHash(Status.TOO_LARGE)
            key = _file_key(before, path)
            with self._lock:
                cached = self._cache.get(key)
                if cached is not None:
                    # A second lookup catches an obvious replacement between
                    # the first stat and cache delivery. Metadata collisions
                    # remain possible and are documented as a TOCTOU limit.
                    if _file_key(os.stat(path), path) != key:
                        return ExecutableHash(Status.CHANGED_DURING_READ)
                    self._cache.move_to_end(key)
                    self._cache_hits += 1
                    return cached

            digest = sha256()
            total = 0
            with self._opener(path) as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or _file_key(opened, path) != key:
                    return ExecutableHash(Status.CHANGED_DURING_READ)
                while True:
                    if is_cancelled():
                        return ExecutableHash(Status.CANCELLED)
                    if self._clock() >= deadline:
                        return ExecutableHash(Status.TIMED_OUT)
                    chunk = stream.read(self.chunk_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_bytes:
                        return ExecutableHash(Status.TOO_LARGE)
                    digest.update(chunk)
                end_handle = os.fstat(stream.fileno())
            try:
                end_path = os.stat(path)
            except FileNotFoundError:
                return ExecutableHash(Status.CHANGED_DURING_READ)
            if _file_key(end_handle, path) != key or _file_key(end_path, path) != key or total != before.st_size:
                return ExecutableHash(Status.CHANGED_DURING_READ)
            if is_cancelled():
                return ExecutableHash(Status.CANCELLED)
            if self._clock() >= deadline:
                return ExecutableHash(Status.TIMED_OUT)
            result = ExecutableHash(Status.AVAILABLE, digest.hexdigest())
            with self._lock:
                self._cache[key] = result
                self._cache.move_to_end(key)
                if len(self._cache) > self.cache_capacity:
                    self._cache.popitem(last=False)
            return result
        except PermissionError:
            return ExecutableHash(Status.ACCESS_DENIED)
        except FileNotFoundError:
            return ExecutableHash(Status.NOT_FOUND)
        except (IsADirectoryError, NotADirectoryError, ValueError):
            return ExecutableHash(Status.INVALID_PATH)
        except OSError:
            return ExecutableHash(Status.UNAVAILABLE)


def _file_key(info: os.stat_result, path: str) -> FileKey:
    # st_ino may be zero on some Windows filesystems; then keep paths separate.
    fallback = os.path.normcase(path) if info.st_ino == 0 else ""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, fallback)
