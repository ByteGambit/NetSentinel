"""Engine ordering, bounded asynchronous handoff and synthetic runtime wiring."""

from dataclasses import replace
from datetime import timedelta
from threading import Event, current_thread
from uuid import UUID

import pytest

from netsentinel.application.engine import MonitoringEngine
from netsentinel.application.events import EventDispatcher
from netsentinel.application.ports import ConnectionCollectionRound, ConnectionCollectionTransientError
from netsentinel.application.services.behavior_baseline import BaselineWriter, BehaviorBaselineService
from netsentinel.application.services.behavior_risk import BehaviorRiskPipeline
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.risk_alerts import BehaviorRiskSignal, RiskAlertResult, RiskAlertStatus
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.bootstrap import create_desktop_engine
from netsentinel.domain.behavior_baseline import BaselineLoad, BaselineRead, BaselineState
from netsentinel.domain.connections import (
    ConnectionNetworkScope, ConnectionSnapshot, ConnectionState, Endpoint,
    NetworkAttributionMethod, NetworkScopeStatus, ObservationQuality, ProcessInfo, ProcessInfoStatus,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyClassification
from tests.fixtures.behavior_risk import NOW, SCOPE, PROCESS, baseline, key, novelty
from tests.integration.test_risk_alert_pipeline import Harness


def signal():
    return BehaviorRiskSignal(key(), (novelty(),), NOW)


def test_queue_saturation_shutdown_drop_and_no_poll_thread_sql():
    entered, release = Event(), Event()
    threads = []
    class BlockingService:
        def process(self, value):
            threads.append(current_thread().name)
            entered.set()
            assert release.wait(2)
            return RiskAlertResult(RiskAlertStatus.NO_ALERT)
    worker = RiskAlertWorker(BlockingService(), EventDispatcher(), capacity=1)
    assert worker.submit(signal()) is RiskAlertStatus.UNAVAILABLE
    assert worker.start()
    try:
        assert worker.submit(signal()) is RiskAlertStatus.SUCCESS
        assert entered.wait(1)
        assert worker.submit(signal()) is RiskAlertStatus.SUCCESS
        assert worker.submit(signal()) is RiskAlertStatus.SATURATED
        assert worker.diagnostics().pending == 1
        assert not worker.stop(0)
        assert worker.diagnostics().dropped == 1
        assert not worker.start()
        assert worker.submit(signal()) is RiskAlertStatus.UNAVAILABLE
    finally:
        release.set()
        assert worker.stop(1)
    assert threads == ["netsentinel-risk-worker"]
    assert worker.start() and worker.stop(1)


def test_worker_exception_and_result_subscriber_failure_are_isolated():
    completion = Event()
    class FailingService:
        def process(self, value):
            raise RuntimeError("private storage detail")
    dispatcher = EventDispatcher()
    dispatcher.subscribe(RiskAlertResult, lambda _: completion.set())
    dispatcher.subscribe(RiskAlertResult, lambda _: (_ for _ in ()).throw(RuntimeError("private")))
    worker = RiskAlertWorker(FailingService(), dispatcher)
    assert worker.start()
    try:
        assert worker.submit(signal()) is RiskAlertStatus.SUCCESS
        assert completion.wait(1)
    finally:
        assert worker.stop(1)
    assert worker.diagnostics().failed == 1


@pytest.mark.parametrize("capacity", [0, 129, True])
def test_queue_hard_cap_validation(capacity):
    with pytest.raises(ValueError):
        RiskAlertWorker(None, EventDispatcher(), capacity=capacity)


def runtime(tmp_path, *, spy=False):
    clock = [NOW, 0.0]
    baselines = BehaviorBaselineService(BaselineWriter(lambda: None),
        clock=lambda: clock[0], monotonic_clock=lambda: clock[1])
    summary = replace(baseline().summary, policy_key=baselines.policy_key)
    baselines.restore(BaselineLoad((BaselineRead(SCOPE, BaselineState.READY, summary),)))
    harness = Harness(tmp_path / "runtime.sqlite3")
    signals = []
    original = harness.service.process
    def record(value):
        signals.append(value)
        return original(value)
    if spy:
        harness.service.process = record
    worker = RiskAlertWorker(harness.service, harness.dispatcher)
    pipeline = BehaviorRiskPipeline(baselines, worker, polling_interval=1)
    class Collector:
        value = ()
        def collect(self):
            if isinstance(self.value, Exception):
                raise self.value
            return self.value
    class Enricher:
        def enrich(self, snapshots):
            return snapshots
    collector = Collector()
    tracker = ConnectionTrackingService(clock=lambda: clock[0])
    engine = MonitoringEngine(collector=collector, enricher=Enricher(), tracker=tracker,
        dispatcher=harness.dispatcher, behavior_baselines=baselines, behavior_risk=pipeline,
        clock=lambda: clock[0], monotonic_clock=lambda: clock[1])
    return engine, collector, clock, harness, worker, signals


def connection(stamp=NOW, *, port=50000, address="203.0.113.2"):
    from netsentinel.domain.connections import TransportProtocol
    return ConnectionSnapshot(TransportProtocol.TCP, Endpoint("192.0.2.10", port), Endpoint(address, 443),
        ConnectionState.ESTABLISHED,
        ProcessInfo(ProcessInfoStatus.AVAILABLE, PROCESS, "example", r"C:\Apps\example.exe"), stamp,
        ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "eth", 1,
                               NetworkAttributionMethod.LOCAL_ADDRESS_MATCH))


def test_real_engine_pre_post_order_full_db_pipeline_and_no_repeat_poll(tmp_path):
    engine, collector, clock, harness, worker, signals = runtime(tmp_path, spy=True)
    done = Event()
    harness.dispatcher.subscribe(RiskAlertResult, lambda _: done.set())
    assert worker.start()
    try:
        collector.value = (connection(address="192.0.2.1"),)
        engine._poll_once()  # INITIAL can initialize baseline, no risk signal.
        assert worker.diagnostics().pending == worker.diagnostics().processed == 0
        clock[:] = [NOW + timedelta(seconds=1), 1.0]
        collector.value = (connection(clock[0], address="192.0.2.1"), connection(clock[0], port=50001))
        engine._poll_once()
        assert done.wait(2)
        assert worker.stop(2)
        assert len(signals) == 1
        original = signals[0]
        assert original.evidence[0].classification is DestinationNoveltyClassification.FIRST_SEEN
        assert original.evidence[0].destination_appearances == 0
        assert original.evidence[1].current_appearances == 1  # POST mutation, INITIAL excluded.
        assert len(original.evidence) == 4
        assert original.key.observation_reference.value != UUID(int=0)
        assert harness.assessments.latest(original.key.assessment_id).revision.snapshot.score == 20
        assert len(harness.intents) == 1
        assert worker.start()
        clock[:] = [NOW + timedelta(seconds=2), 2.0]
        collector.value = tuple(replace(c, observed_at=clock[0]) for c in collector.value)
        engine._poll_once()  # long-lived poll produces no new appearance.
        assert worker.diagnostics().pending == 0
    finally:
        assert worker.stop(2)


def test_failed_and_reduced_rounds_preserve_quality(tmp_path):
    engine, collector, clock, harness, worker, signals = runtime(tmp_path, spy=True)
    assert worker.start()
    try:
        engine._poll_once()  # complete empty round initializes tracker.
        collector.value = ConnectionCollectionTransientError("private")
        clock[:] = [NOW + timedelta(seconds=1), 1.0]
        engine._poll_once()
        assert not signals
        clock[:] = [NOW + timedelta(seconds=2), 2.0]
        collector.value = ConnectionCollectionRound((connection(clock[0]),), ObservationQuality.REDUCED)
        engine._poll_once()
    finally:
        assert worker.stop(2)
    assert len(signals) == 1
    assert all(getattr(e, "quality", ObservationQuality.REDUCED) is ObservationQuality.REDUCED
               for e in signals[0].evidence)
    assert len(signals[0].evidence) == 3  # NS-074 never consumes reduced appearances.


def test_desktop_composition_dormant_worker_and_bounded_lifecycle(tmp_path):
    engine = create_desktop_engine(database_path=tmp_path / "new.sqlite3")
    assert engine.behavior_risk is not None
    assert engine.behavior_risk.worker.diagnostics().processed == 0
    assert not (tmp_path / "new.sqlite3").exists()
    assert engine.stop(1)


def test_round_preparation_has_hard_bound(tmp_path):
    from netsentinel.domain.connections import ConnectionOpened, ConnectionRoundObservation
    engine, *_ = runtime(tmp_path)
    events = tuple(ConnectionOpened(connection(port=50000 + i), session_id=UUID(int=1),
                                   lifecycle_id=UUID(int=i + 1)) for i in range(130))
    prepared = engine.behavior_risk.prepare(ConnectionRoundObservation(UUID(int=1), NOW,
        ObservationQuality.COMPLETE), events)
    assert len(prepared) == 128 and engine.behavior_risk.dropped == 2


def test_engine_risk_failure_is_sanitized_without_losing_round(tmp_path, monkeypatch):
    from netsentinel.shared.diagnostics import DiagnosticCode
    engine, collector, *_ = runtime(tmp_path)
    def fail(*args):
        raise RuntimeError("private detector detail")
    monkeypatch.setattr(engine.behavior_risk, "prepare", fail)
    engine._poll_once()
    assert engine.health.counters.successful_rounds == 1
    assert engine.health.last_error.code is DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR
