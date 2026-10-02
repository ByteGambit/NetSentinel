"""Bounded on-demand scheduling for disk-file signature evidence."""

from __future__ import annotations

from collections import deque
from concurrent.futures import Future, InvalidStateError
from dataclasses import dataclass
from threading import Condition, Event, Thread, current_thread

from netsentinel.application.ports import ExecutableSignerVerifier
from netsentinel.domain.connections import ProcessInfo, ProcessInfoStatus
from netsentinel.domain.executable_signer import (
    ExecutableSigner, ExecutableSignerRequest, SignerAvailability as Availability,
)


@dataclass(frozen=True, slots=True)
class SignerSubmission:
    request: ExecutableSignerRequest | None
    future: Future[ExecutableSigner]

    def matches(self, process: ProcessInfo) -> bool:
        return self.request is not None and self.request.matches(process)


class ExecutableSignerService:
    """One daemon worker, 64 pending unique paths by default, no poll hook."""

    def __init__(self, verifier: ExecutableSignerVerifier, *, queue_capacity: int = 64) -> None:
        if type(queue_capacity) is not int or not 1 <= queue_capacity <= 4096:
            raise ValueError("queue_capacity must be between 1 and 4096")
        self._verifier = verifier
        self._capacity = queue_capacity
        self._condition = Condition()
        self._cancel = Event()
        self._pending: deque[str] = deque()
        self._jobs: dict[str, Future[ExecutableSigner]] = {}
        self._worker: Thread | None = None
        self._closed = False
        self.requested = self.completed = self.coalesced = self.saturated = 0

    def request(self, process: ProcessInfo) -> SignerSubmission:
        if not isinstance(process, ProcessInfo):
            raise TypeError("process must be ProcessInfo")
        token = (ExecutableSignerRequest(process.identity, process.executable_path)
                 if process.identity is not None and process.identity.create_time is not None
                 and process.executable_path is not None else None)
        with self._condition:
            self.requested += 1
            if self._closed:
                return SignerSubmission(token, _ready(Availability.CANCELLED))
            if token is None or process.executable_path_status is not ProcessInfoStatus.AVAILABLE:
                return SignerSubmission(token, _ready(Availability.UNAVAILABLE))
            existing = self._jobs.get(token.path)
            if existing is not None:
                self.coalesced += 1
                return SignerSubmission(token, existing)
            if len(self._pending) >= self._capacity:
                self.saturated += 1
                return SignerSubmission(token, _ready(Availability.SATURATED))
            future: Future[ExecutableSigner] = Future()
            self._jobs[token.path] = future
            self._pending.append(token.path)
            if self._worker is None:
                self._worker = Thread(target=self._run, name="netsentinel-executable-signer", daemon=True)
                self._worker.start()
            self._condition.notify()
            return SignerSubmission(token, future)

    def stop(self, timeout: float = 2.0) -> bool:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
            raise ValueError("timeout must be between zero and 60 seconds")
        with self._condition:
            self._closed = True
            self._cancel.set()
            futures = tuple(self._jobs.values())
            self._pending.clear()
            self._jobs.clear()
            worker = self._worker
            self._condition.notify_all()
        for future in futures:
            _publish(future, ExecutableSigner(Availability.CANCELLED))
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
            try:
                result = self._verifier.verify(path, is_cancelled=self._cancel.is_set)
            except Exception:
                result = ExecutableSigner(Availability.UNAVAILABLE)
            with self._condition:
                self._jobs.pop(path, None)
                if self._closed:
                    result = ExecutableSigner(Availability.CANCELLED)
                else:
                    self.completed += 1
            _publish(future, result)


def _ready(status: Availability) -> Future[ExecutableSigner]:
    future: Future[ExecutableSigner] = Future()
    future.set_result(ExecutableSigner(status))
    return future


def _publish(future: Future[ExecutableSigner], result: ExecutableSigner) -> None:
    try:
        future.set_result(result)
    except InvalidStateError:
        pass
