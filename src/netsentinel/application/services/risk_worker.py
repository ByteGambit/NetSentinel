"""Bounded NS-079 handoff; normalization/scoring/SQL stay off the poll thread."""

from collections import OrderedDict, deque
from dataclasses import dataclass
from concurrent.futures import Future
from math import isfinite
from threading import Condition, Thread, current_thread

from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.risk_alerts import (
    BehaviorRiskSignal, RiskAlertResult, RiskAlertStatus, RiskToAlertService,
)
from netsentinel.domain.suppression import SuppressionEvaluation
from netsentinel.domain.threat_intel_evidence import ThreatIntelAssessmentSignal


@dataclass(frozen=True, slots=True)
class RiskWorkerDiagnostics:
    pending: int
    processed: int
    failed: int
    rejected: int
    dropped: int


class RiskAlertWorker:
    """128 pending signals + one active; FIFO, no replay store or hidden retry.

    An explicit retry retains the original signal identity. On stop, drain up to
    the deadline; drop pending work and count it if the active call stalls.
    A live old worker prevents restart and its currently active call may finish.
    """

    def __init__(self, service: RiskToAlertService, dispatcher: EventDispatcher, *,
                 capacity: int = 128, shutdown_timeout: float = 2.0) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 128:
            raise ValueError("invalid risk queue capacity")
        self._validate_timeout(shutdown_timeout)
        self._service, self._dispatcher = service, dispatcher
        self._capacity, self._timeout = capacity, shutdown_timeout
        self._condition = Condition()
        self._pending: deque[BehaviorRiskSignal | tuple[ThreatIntelAssessmentSignal, Future[RiskAlertResult]]] = deque()
        self._thread: Thread | None = None
        self._accepting = False
        self._stopping = False
        self._processed = self._failed = self._rejected = self._dropped = 0
        # Session-only explanation cache, no replay, scoring or preference usage writes.
        self._explanations: OrderedDict[tuple[str, int], SuppressionEvaluation] = OrderedDict()

    def suppression_for(self, assessment_id: str, revision: int) -> SuppressionEvaluation | None:
        with self._condition:
            return self._explanations.get((assessment_id, revision))

    @staticmethod
    def _validate_timeout(value: float) -> None:
        if isinstance(value, bool) or not isfinite(value) or not 0 <= value <= 60:
            raise ValueError("invalid risk shutdown timeout")

    def start(self) -> bool:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._accepting, self._stopping = True, False
            self._explanations.clear()
            self._thread = Thread(target=self._run, name="netsentinel-risk-worker", daemon=True)
            self._thread.start()
            return True

    def submit(self, signal: BehaviorRiskSignal) -> RiskAlertStatus:
        if not isinstance(signal, BehaviorRiskSignal):
            raise TypeError("typed behavior signal required")
        with self._condition:
            if not self._accepting:
                self._rejected += 1
                return RiskAlertStatus.UNAVAILABLE
            if len(self._pending) >= self._capacity:
                self._rejected += 1
                return RiskAlertStatus.SATURATED
            self._pending.append(signal)
            self._condition.notify()
            return RiskAlertStatus.SUCCESS

    def diagnostics(self) -> RiskWorkerDiagnostics:
        with self._condition:
            return RiskWorkerDiagnostics(len(self._pending), self._processed, self._failed,
                                         self._rejected, self._dropped)

    def submit_threat_intelligence(self, signal: ThreatIntelAssessmentSignal) -> Future[RiskAlertResult]:
        if type(signal) is not ThreatIntelAssessmentSignal:
            raise TypeError("typed TI revision signal required")
        receipt: Future[RiskAlertResult] = Future()
        with self._condition:
            status = RiskAlertStatus.UNAVAILABLE if not self._accepting else RiskAlertStatus.SATURATED if len(self._pending) >= self._capacity else RiskAlertStatus.SUCCESS
            if status is not RiskAlertStatus.SUCCESS:
                self._rejected += 1
                receipt.set_result(RiskAlertResult(status))
            else:
                self._pending.append((signal, receipt))
                self._condition.notify()
        return receipt

    def stop(self, timeout: float | None = None) -> bool:
        duration = self._timeout if timeout is None else timeout
        self._validate_timeout(duration)
        with self._condition:
            thread = self._thread
            if thread is current_thread():
                raise RuntimeError("risk worker cannot join itself")
            self._accepting, self._stopping = False, True
            self._condition.notify_all()
        if thread is None:
            return True
        thread.join(duration)
        if thread.is_alive():
            with self._condition:
                self._dropped += len(self._pending)
                for item in self._pending:
                    if isinstance(item, tuple):
                        if not item[1].done():
                            item[1].set_result(RiskAlertResult(RiskAlertStatus.UNAVAILABLE))
                self._pending.clear()
            return False
        return True

    def _run(self) -> None:
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._pending or self._stopping)
                if not self._pending:
                    return
                signal = self._pending.popleft()
            try:
                result = self._service.enrich(signal[0]) if isinstance(signal, tuple) else self._service.process(signal)
            except Exception:
                result = RiskAlertResult(RiskAlertStatus.UNAVAILABLE)
            if isinstance(signal, tuple) and not signal[1].done():
                signal[1].set_result(result)
            with self._condition:
                self._processed += 1
                self._failed += int(result.status not in (RiskAlertStatus.SUCCESS, RiskAlertStatus.NO_ALERT))
                if result.suppression is not None:
                    reference = result.suppression.assessment
                    identity = (reference.assessment_id, reference.revision)
                    self._explanations[identity] = result.suppression
                    self._explanations.move_to_end(identity)
                    while len(self._explanations) > 32:
                        self._explanations.popitem(last=False)
            self._dispatcher.publish(result)
