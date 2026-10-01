"""On-demand bounded scheduling of local executable fingerprints."""

from __future__ import annotations

from collections import deque
from concurrent.futures import Future, InvalidStateError
from dataclasses import dataclass
from threading import Condition, Event, Thread, current_thread

from netsentinel.application.ports import ExecutableHasher
from netsentinel.domain.connections import ProcessInfo, ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashRequest, ExecutableHashStatus as Status
from netsentinel.shared.diagnostics import ExecutableHashDiagnostics


@dataclass(frozen=True, slots=True)
class HashSubmission:
    """A result is usable only while its request still matches current metadata."""

    request: ExecutableHashRequest | None
    future: Future[ExecutableHash]

    def matches(self, process: ProcessInfo) -> bool:
        return self.request is not None and self.request.matches(process)


class ExecutableHashService:
    """One daemon worker; queue contains at most ``queue_capacity`` unique paths."""

    def __init__(self, hasher: ExecutableHasher, *, queue_capacity: int = 64) -> None:
        if type(queue_capacity) is not int or not 1 <= queue_capacity <= 4096:
            raise ValueError("queue_capacity must be between 1 and 4096")
        self._hasher = hasher
        self._capacity = queue_capacity
        self._condition = Condition()
        self._cancel = Event()
        self._pending: deque[str] = deque()
        self._jobs: dict[str, Future[ExecutableHash]] = {}
        self._active: str | None = None
        self._worker: Thread | None = None
        self._closed = False
        self._requested = 0
        self._completed = 0
        self._coalesced = 0
        self._saturated = 0
        self._cancelled = 0

    def request(self, process: ProcessInfo) -> HashSubmission:
        """Schedule only an observed executable path; never read on caller thread."""
        if not isinstance(process, ProcessInfo):
            raise TypeError("process must be ProcessInfo")
        path = process.executable_path
        identity = process.identity
        token = (
            ExecutableHashRequest(identity, path)
            if identity is not None and identity.create_time is not None and path is not None
            else None
        )
        with self._condition:
            self._requested += 1
            if self._closed:
                self._cancelled += 1
                return HashSubmission(token, _ready(Status.CANCELLED))
            if token is None or process.executable_path_status is not ProcessInfoStatus.AVAILABLE:
                return HashSubmission(token, _ready(Status.UNAVAILABLE))
            path = token.path
            existing = self._jobs.get(path)
            if existing is not None:
                self._coalesced += 1
                return HashSubmission(token, existing)
            if len(self._pending) >= self._capacity:
                self._saturated += 1
                return HashSubmission(token, _ready(Status.SATURATED))
            future: Future[ExecutableHash] = Future()
            self._jobs[path] = future
            self._pending.append(path)
            if self._worker is None:
                self._worker = Thread(target=self._run, name="netsentinel-executable-hash", daemon=True)
                self._worker.start()
            self._condition.notify()
            return HashSubmission(token, future)

    def health_snapshot(self) -> ExecutableHashDiagnostics:
        with self._condition:
            return ExecutableHashDiagnostics(
                requested=self._requested, completed=self._completed,
                coalesced=self._coalesced, saturated=self._saturated,
                cancelled=self._cancelled, active=int(self._active is not None),
                pending=len(self._pending), queue_capacity=self._capacity,
            )

    def stop(self, timeout: float = 2.0) -> bool:
        """Cancel every published future and wait at most timeout for active I/O."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
            raise ValueError("timeout must be between zero and 60 seconds")
        with self._condition:
            self._closed = True
            self._cancel.set()
            futures = tuple(self._jobs.values())
            self._cancelled += sum(not future.done() for future in futures)
            self._pending.clear()
            self._jobs.clear()
            worker = self._worker
            self._condition.notify_all()
        for future in futures:
            _publish(future, ExecutableHash(Status.CANCELLED))
        if worker is not None and worker is not current_thread():
            worker.join(timeout)
        return worker is None or not worker.is_alive()

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._pending and not self._closed:
                    self._condition.wait()
                if self._closed:
                    return
                path = self._pending.popleft()
                future = self._jobs[path]
                self._active = path
            try:
                result = self._hasher.hash(path, is_cancelled=self._cancel.is_set)
            except Exception:
                result = ExecutableHash(Status.UNAVAILABLE)
            with self._condition:
                self._active = None
                self._jobs.pop(path, None)
                if self._closed:
                    result = ExecutableHash(Status.CANCELLED)
                else:
                    self._completed += 1
            _publish(future, result)


def _ready(status: Status) -> Future[ExecutableHash]:
    future: Future[ExecutableHash] = Future()
    future.set_result(ExecutableHash(status))
    return future


def _publish(future: Future[ExecutableHash], result: ExecutableHash) -> None:
    try:
        future.set_result(result)
    except InvalidStateError:
        # Shutdown may have resolved the same future between worker completion
        # and this publication. The cancelled result remains authoritative.
        pass
