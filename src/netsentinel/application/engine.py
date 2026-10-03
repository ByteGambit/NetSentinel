"""GUI-independent lifecycle for the connection monitoring pipeline."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime
from math import isfinite
from threading import Event, RLock, Thread, current_thread
from time import monotonic
from typing import Protocol
from uuid import UUID, uuid4

from netsentinel.application.events import EventDispatcher, PublishReport
from netsentinel.application.ports import (
    ConnectionCollectionPermissionDenied,
    ConnectionCollectionTransientError,
    ConnectionCollector,
    ConnectionCollectionRound,
    NetworkContextProvider,
)
from netsentinel.application.services.connection_network_scope import ConnectionNetworkScopeResolver
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.application.services.behavior_baseline import BehaviorBaselineService
from netsentinel.application.services.behavior_risk import BehaviorRiskPipeline, PreparedBehaviorSignal
from netsentinel.domain.connections import (
    ConnectionLifecycleEvent,
    ConnectionSnapshot,
    ConnectionRoundObservation,
    ObservationQuality,
    ProcessInfoStatus,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot
from netsentinel.shared.diagnostics import (
    CapabilitySnapshot,
    CapabilityStatus,
    Diagnostic,
    DiagnosticCode,
    DiagnosticComponent,
    DiagnosticSeverity,
    EngineCounters,
    EngineHealthSnapshot,
    EngineState,
    PersistenceHealthSnapshot,
)


WallClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


class SnapshotEnricher(Protocol):
    def enrich(
        self, snapshots: Iterable[ConnectionSnapshot]
    ) -> tuple[ConnectionSnapshot, ...]: ...


class LifecycleTracker(Protocol):
    def track(
        self, snapshots: Iterable[ConnectionSnapshot], *,
        quality: ObservationQuality = ObservationQuality.COMPLETE, discarded_rows: int = 0,
    ) -> tuple[ConnectionLifecycleEvent, ...]: ...


class PersistencePipeline(Protocol):
    """Optional application-level lifecycle sink managed with the poller."""

    def start(self) -> bool: ...

    def stop(self, timeout: float | None = None) -> bool: ...

    def health_snapshot(self) -> PersistenceHealthSnapshot: ...


class DnsConfigPoller(Protocol):
    def poll(self) -> object: ...


class EngineLifecycleError(RuntimeError):
    """Raised when lifecycle control is attempted from the engine worker."""


class MonitoringEngine:
    """Run one non-overlapping connection polling pipeline on one worker.

    Scheduling uses fixed delay: the interval begins after a polling round has
    completed. Consequently a slow round can be reported as an overrun but can
    never overlap a later round. A normally stopped engine is restartable; its
    tracker state and cumulative health counters are retained across restarts.
    """

    def __init__(
        self,
        *,
        collector: ConnectionCollector,
        enricher: SnapshotEnricher,
        tracker: LifecycleTracker,
        dispatcher: EventDispatcher | None = None,
        polling_interval: float = 1.0,
        shutdown_timeout: float = 2.0,
        clock: WallClock | None = None,
        monotonic_clock: MonotonicClock | None = None,
        thread_name: str = "netsentinel-connection-poller",
        persistence: PersistencePipeline | None = None,
        dns_config_poller: DnsConfigPoller | None = None,
        network_context_provider: NetworkContextProvider | None = None,
        behavior_accumulator: BehaviorFeatureAccumulator | None = None,
        behavior_baselines: BehaviorBaselineService | None = None,
        behavior_risk: BehaviorRiskPipeline | None = None,
    ) -> None:
        if (
            isinstance(polling_interval, bool)
            or not isinstance(polling_interval, (int, float))
            or not isfinite(polling_interval)
            or polling_interval <= 0
        ):
            raise ValueError("polling_interval must be greater than zero")
        if (
            isinstance(shutdown_timeout, bool)
            or not isinstance(shutdown_timeout, (int, float))
            or not isfinite(shutdown_timeout)
            or shutdown_timeout < 0
        ):
            raise ValueError("shutdown_timeout must be zero or greater")
        if not thread_name:
            raise ValueError("thread_name must not be empty")

        self._collector = collector
        self._enricher = enricher
        self._tracker = tracker
        self._session_id = getattr(tracker, "session_id", uuid4())
        self._started_once = False
        self._dispatcher = dispatcher if dispatcher is not None else EventDispatcher()
        self._polling_interval = float(polling_interval)
        self._shutdown_timeout = float(shutdown_timeout)
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock if monotonic_clock is not None else monotonic
        self.behavior_features = behavior_accumulator or BehaviorFeatureAccumulator(
            polling_interval=float(polling_interval), monotonic_clock=self._monotonic,
        )
        self.behavior_baselines = behavior_baselines
        self.behavior_risk = behavior_risk
        self._thread_name = thread_name
        self._persistence = persistence
        self._dns_config_poller = dns_config_poller
        self._network_scope_resolver = (
            ConnectionNetworkScopeResolver(network_context_provider)
            if network_context_provider is not None else None
        )

        self._lock = RLock()
        self._cancel = Event()
        self._worker: Thread | None = None
        self._health = EngineHealthSnapshot(
            state=EngineState.STOPPED,
            capabilities=CapabilitySnapshot(),
            counters=EngineCounters(),
        )

    @property
    def dispatcher(self) -> EventDispatcher:
        return self._dispatcher

    @property
    def session_id(self) -> UUID:
        return self._session_id

    @property
    def health(self) -> EngineHealthSnapshot:
        """Return an immutable and internally consistent health snapshot."""

        with self._lock:
            worker_alive = self._worker is not None and self._worker.is_alive()
            return replace(self._health, worker_alive=worker_alive)

    def health_snapshot(self) -> EngineHealthSnapshot:
        """Return the current portable health snapshot."""

        return self.health

    def persistence_health_snapshot(self) -> PersistenceHealthSnapshot | None:
        """Return portable persistence health when the pipeline is configured."""

        persistence = self._persistence
        return None if persistence is None else persistence.health_snapshot()

    def start(self) -> bool:
        """Start polling once; return ``False`` when already running/stopping."""

        with self._lock:
            self._reject_worker_lifecycle_control()
            if self._worker is not None and self._worker.is_alive():
                return False

            persistence = self._persistence
            if persistence is not None and not persistence.start():
                return False

            if self.behavior_risk is not None and not self.behavior_risk.start():
                if persistence is not None:
                    persistence.stop()
                self._record_error(DiagnosticCode.PERSISTENCE_START_FAILED, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
                return False

            if self.behavior_baselines is not None:
                try:
                    self.behavior_baselines.start()
                except Exception:
                    self._record_error(DiagnosticCode.PERSISTENCE_START_FAILED, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)

            if self._started_once:
                reset = getattr(self._tracker, "reset_session", None)
                if callable(reset):
                    reset()
                    self._session_id = getattr(self._tracker, "session_id", uuid4())
                else:
                    self._session_id = uuid4()
            self._started_once = True

            self._cancel = Event()
            worker = Thread(
                target=self._run,
                name=self._thread_name,
                daemon=True,
            )
            self._worker = worker
            self._health = replace(
                self._health,
                state=EngineState.RUNNING,
                polling=False,
                worker_alive=True,
            )
            try:
                worker.start()
            except BaseException:
                self._worker = None
                self._health = replace(
                    self._health,
                    state=EngineState.STOPPED,
                    worker_alive=False,
                )
                if persistence is not None:
                    persistence.stop()
                if self.behavior_baselines is not None:
                    self._stop_baselines()
                if self.behavior_risk is not None:
                    self._stop_risk()
                raise
            return True

    def stop(self, timeout: float | None = None) -> bool:
        """Request cancellation and wait for at most the configured timeout.

        Python cannot forcibly cancel a blocking adapter call. If it exceeds the
        timeout, the engine remains ``STOPPING`` and cannot be restarted until
        that worker returns. The daemon worker observes cancellation before any
        subsequent round or pipeline stage.
        """

        if timeout is not None:
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not isfinite(timeout)
                or timeout < 0
            ):
                raise ValueError("timeout must be zero or greater")

        with self._lock:
            self._reject_worker_lifecycle_control()
            worker = self._worker
            if worker is None or not worker.is_alive():
                persistence = self._persistence
                persistence_stopped = (
                    True if persistence is None else persistence.stop(timeout)
                )
                if self.behavior_baselines is not None:
                    persistence_stopped = self._stop_baselines(timeout) and persistence_stopped
                if self.behavior_risk is not None:
                    persistence_stopped = self._stop_risk(timeout) and persistence_stopped
                self._health = replace(
                    self._health,
                    state=EngineState.STOPPED,
                    polling=False,
                    worker_alive=False,
                )
                return persistence_stopped
            self._cancel.set()
            self._health = replace(self._health, state=EngineState.STOPPING)

        worker.join(self._shutdown_timeout if timeout is None else timeout)
        if not worker.is_alive():
            return True

        self._record_error(
            DiagnosticCode.SHUTDOWN_TIMEOUT,
            DiagnosticComponent.ENGINE,
            severity=DiagnosticSeverity.WARNING,
        )
        with self._lock:
            self._health = replace(
                self._health,
                state=EngineState.STOPPING,
                worker_alive=True,
            )
        return False

    def _reject_worker_lifecycle_control(self) -> None:
        if self._worker is not None and current_thread() is self._worker:
            raise EngineLifecycleError(
                "engine lifecycle cannot be controlled from its worker"
            )

    def _run(self) -> None:
        try:
            while not self._cancel.is_set():
                started = self._monotonic()
                self._mark_poll_started()
                try:
                    if self._dns_config_poller is not None and not self._cancel.is_set():
                        try:
                            self._dns_config_poller.poll()
                        except Exception:
                            self._record_error(
                                DiagnosticCode.DNS_CONFIG_UNAVAILABLE,
                                DiagnosticComponent.DNS_CONFIG,
                                severity=DiagnosticSeverity.WARNING,
                            )
                    self._poll_once()
                except Exception:
                    # A defect in engine bookkeeping must remain observable and
                    # must not silently terminate the long-lived worker.
                    self._mark_round_failed(
                        DiagnosticCode.WORKER_ERROR,
                        DiagnosticComponent.ENGINE,
                    )
                finally:
                    duration = max(0.0, self._monotonic() - started)
                    self._mark_poll_completed(duration)

                if self._cancel.wait(self._polling_interval):
                    break
        finally:
            if self.behavior_risk is not None:
                self._stop_risk()
            if self.behavior_baselines is not None:
                self._stop_baselines()
            persistence = self._persistence
            if persistence is not None:
                try:
                    persistence_stopped = persistence.stop()
                except Exception:
                    persistence_stopped = False
                if not persistence_stopped:
                    self._record_error(
                        DiagnosticCode.PERSISTENCE_SHUTDOWN_TIMEOUT,
                        DiagnosticComponent.PERSISTENCE,
                        severity=DiagnosticSeverity.WARNING,
                    )
            with self._lock:
                self._health = replace(
                    self._health,
                    state=EngineState.STOPPED,
                    polling=False,
                    worker_alive=False,
                )

    def _poll_once(self) -> None:
        try:
            collect_round = getattr(self._collector, "collect_round", None)
            collected = collect_round() if callable(collect_round) else self._collector.collect()
            round_result = collected if isinstance(collected, ConnectionCollectionRound) else ConnectionCollectionRound(tuple(collected))
            snapshots = round_result.snapshots
        except ConnectionCollectionPermissionDenied:
            self._set_connection_capability(CapabilityStatus.UNAVAILABLE)
            self._publish_failed_observation()
            self._mark_round_failed(
                DiagnosticCode.COLLECTOR_PERMISSION_DENIED,
                DiagnosticComponent.COLLECTOR,
                severity=DiagnosticSeverity.WARNING,
            )
            return
        except ConnectionCollectionTransientError:
            self._set_connection_capability(CapabilityStatus.DEGRADED)
            self._publish_failed_observation()
            self._mark_round_failed(
                DiagnosticCode.COLLECTOR_TRANSIENT_ERROR,
                DiagnosticComponent.COLLECTOR,
                severity=DiagnosticSeverity.WARNING,
            )
            return
        except Exception:
            self._set_connection_capability(CapabilityStatus.DEGRADED)
            self._publish_failed_observation()
            self._mark_round_failed(
                DiagnosticCode.COLLECTOR_UNEXPECTED_ERROR,
                DiagnosticComponent.COLLECTOR,
            )
            return

        if self._cancel.is_set():
            return

        try:
            enriched = self._enricher.enrich(snapshots)
        except Exception:
            self._set_process_capability(CapabilityStatus.DEGRADED)
            self._publish_failed_observation()
            self._mark_round_failed(
                DiagnosticCode.PROCESS_ENRICHMENT_ERROR,
                DiagnosticComponent.PROCESS_ENRICHER,
            )
            return

        unavailable = sum(
            1
            for snapshot in enriched
            if snapshot.process.identity is not None
            and snapshot.process.status is not ProcessInfoStatus.AVAILABLE
        )
        self._record_process_metadata_result(unavailable)

        if self._network_scope_resolver is not None:
            enriched = self._network_scope_resolver.attribute(enriched)

        if self._cancel.is_set():
            return

        try:
            if round_result.quality is ObservationQuality.COMPLETE:
                events = self._tracker.track(enriched)
            else:
                events = self._tracker.track(enriched, quality=round_result.quality, discarded_rows=round_result.discarded_rows)
        except Exception:
            self._publish_failed_observation()
            self._mark_round_failed(
                DiagnosticCode.TRACKER_ERROR,
                DiagnosticComponent.TRACKER,
            )
            return

        observation = getattr(self._tracker, "last_round", None)
        if isinstance(observation, ConnectionRoundObservation):
            prepared: tuple[PreparedBehaviorSignal, ...] = ()
            if self.behavior_risk is not None:
                try:
                    prepared = self.behavior_risk.prepare(observation, events)
                except Exception:
                    self._record_error(DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
            contributions = self.behavior_features.observe_round(observation, events, enriched)
            if self.behavior_baselines is not None:
                self._observe_baselines(contributions, observation)
            if self.behavior_risk is not None:
                try:
                    self.behavior_risk.finish(observation, events, prepared, self.behavior_features,
                        now_monotonic=self._monotonic(), assessed_at=self._utc_now())
                except Exception:
                    self._record_error(DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
        subscriber_failures = (
            self._dispatcher.publish(observation).failed
            if isinstance(observation, ConnectionRoundObservation)
            else 0
        )
        for event in events:
            try:
                report: PublishReport = self._dispatcher.publish(event)
            except Exception:
                self._mark_round_failed(
                    DiagnosticCode.DISPATCHER_ERROR,
                    DiagnosticComponent.DISPATCHER,
                )
                return
            subscriber_failures += report.failed

        persistence = self._persistence
        observe_round = getattr(persistence, "observe_round", None)
        active = getattr(self._tracker, "active_connections", None)
        if callable(observe_round) and isinstance(active, tuple):
            observe_round(active, {snapshot.key for snapshot in enriched})

        self._mark_round_success(len(events), subscriber_failures)
        if isinstance(observation, ConnectionRoundObservation) and observation.quality is ObservationQuality.REDUCED:
            self._record_reduced_round(observation)

    def _publish_failed_observation(self) -> None:
        record_failure = getattr(self._tracker, "record_failure", None)
        observation = record_failure(observed_at=self._utc_now()) if callable(record_failure) else ConnectionRoundObservation(self._session_id, self._utc_now(), ObservationQuality.FAILED)
        self.behavior_features.observe_round(observation)
        if self.behavior_baselines is not None:
            self._observe_baselines((), observation)
        if self.behavior_risk is not None:
            try:
                self.behavior_risk.finish(observation, (), (), self.behavior_features,
                    now_monotonic=self._monotonic(), assessed_at=self._utc_now())
            except Exception:
                self._record_error(DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
        self._dispatcher.publish(observation)
        with self._lock:
            self._health = replace(self._health, counters=replace(
                self._health.counters,
                collection_gaps=self._health.counters.collection_gaps + 1,
            ))

    def _observe_baselines(self, contributions: tuple[BehaviorFeatureSnapshot, ...], observation: ConnectionRoundObservation) -> None:
        try:
            assert self.behavior_baselines is not None
            self.behavior_baselines.observe(contributions, observation.observed_at, observation.quality)
        except Exception:
            self._record_error(DiagnosticCode.PERSISTENCE_UNEXPECTED_ERROR, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)

    def _stop_baselines(self, timeout: float | None = None) -> bool:
        try:
            assert self.behavior_baselines is not None
            stopped = self.behavior_baselines.stop(timeout)
        except Exception:
            stopped = False
        if not stopped:
            self._record_error(DiagnosticCode.PERSISTENCE_SHUTDOWN_TIMEOUT, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
        return stopped

    def _stop_risk(self, timeout: float | None = None) -> bool:
        try:
            assert self.behavior_risk is not None
            stopped = self.behavior_risk.stop(timeout)
        except Exception:
            stopped = False
        if not stopped:
            self._record_error(DiagnosticCode.PERSISTENCE_SHUTDOWN_TIMEOUT, DiagnosticComponent.PERSISTENCE,
                                       severity=DiagnosticSeverity.WARNING)
        return stopped

    def _record_reduced_round(self, observation: ConnectionRoundObservation) -> None:
        now = self._utc_now()
        with self._lock:
            counters = replace(self._health.counters,
                reduced_rounds=self._health.counters.reduced_rounds + 1,
                collection_gaps=self._health.counters.collection_gaps + 1,
                discarded_observations=self._health.counters.discarded_observations + observation.discarded_observations,
            )
            code = DiagnosticCode.CONNECTION_CAPACITY_LOSS if observation.capacity_drops else DiagnosticCode.CONNECTION_REDUCED_ROUND
            self._health = replace(self._health,
                counters=counters,
                last_error=self._diagnostic(code, DiagnosticComponent.TRACKER, DiagnosticSeverity.WARNING, now),
                capabilities=replace(self._health.capabilities, connection_monitoring=CapabilityStatus.DEGRADED),
            )

    def _mark_poll_started(self) -> None:
        now = self._utc_now()
        with self._lock:
            counters = replace(
                self._health.counters,
                polling_rounds=self._health.counters.polling_rounds + 1,
            )
            self._health = replace(
                self._health,
                counters=counters,
                last_poll_started_at=now,
                polling=True,
            )

    def _mark_poll_completed(self, duration: float) -> None:
        now = self._utc_now()
        with self._lock:
            counters = self._health.counters
            last_error = self._health.last_error
            if duration > self._polling_interval:
                counters = replace(
                    counters,
                    polling_overruns=counters.polling_overruns + 1,
                )
                poll_started = self._health.last_poll_started_at
                if (
                    last_error is None
                    or poll_started is None
                    or last_error.occurred_at < poll_started
                ):
                    last_error = self._diagnostic(
                        DiagnosticCode.POLLING_OVERRUN,
                        DiagnosticComponent.ENGINE,
                        DiagnosticSeverity.WARNING,
                        now,
                    )
            self._health = replace(
                self._health,
                counters=counters,
                last_poll_completed_at=now,
                last_error=last_error,
                polling=False,
            )

    def _mark_round_success(
        self, event_count: int, subscriber_failures: int
    ) -> None:
        now = self._utc_now()
        with self._lock:
            counters = replace(
                self._health.counters,
                successful_rounds=self._health.counters.successful_rounds + 1,
                lifecycle_events=self._health.counters.lifecycle_events + event_count,
                subscriber_failures=(
                    self._health.counters.subscriber_failures + subscriber_failures
                ),
            )
            capabilities = replace(
                self._health.capabilities,
                connection_monitoring=CapabilityStatus.AVAILABLE,
            )
            last_error = self._health.last_error
            if subscriber_failures:
                last_error = self._diagnostic(
                    DiagnosticCode.SUBSCRIBER_ERROR,
                    DiagnosticComponent.SUBSCRIBER,
                    DiagnosticSeverity.WARNING,
                    now,
                )
            self._health = replace(
                self._health,
                capabilities=capabilities,
                counters=counters,
                last_successful_poll_at=now,
                last_error=last_error,
            )

    def _mark_round_failed(
        self,
        code: DiagnosticCode,
        component: DiagnosticComponent,
        *,
        severity: DiagnosticSeverity = DiagnosticSeverity.ERROR,
    ) -> None:
        now = self._utc_now()
        with self._lock:
            counters = replace(
                self._health.counters,
                failed_rounds=self._health.counters.failed_rounds + 1,
            )
            self._health = replace(
                self._health,
                counters=counters,
                last_error=self._diagnostic(code, component, severity, now),
            )

    def _record_process_metadata_result(self, unavailable: int) -> None:
        with self._lock:
            status = (
                CapabilityStatus.DEGRADED
                if unavailable
                else CapabilityStatus.AVAILABLE
            )
            capabilities = replace(
                self._health.capabilities,
                process_metadata=status,
            )
            counters = replace(
                self._health.counters,
                process_metadata_unavailable=(
                    self._health.counters.process_metadata_unavailable + unavailable
                ),
            )
            self._health = replace(
                self._health,
                capabilities=capabilities,
                counters=counters,
            )

    def _set_connection_capability(self, status: CapabilityStatus) -> None:
        with self._lock:
            self._health = replace(
                self._health,
                capabilities=replace(
                    self._health.capabilities,
                    connection_monitoring=status,
                ),
            )

    def _set_process_capability(self, status: CapabilityStatus) -> None:
        with self._lock:
            self._health = replace(
                self._health,
                capabilities=replace(
                    self._health.capabilities,
                    process_metadata=status,
                ),
            )

    def _record_error(
        self,
        code: DiagnosticCode,
        component: DiagnosticComponent,
        *,
        severity: DiagnosticSeverity,
    ) -> None:
        now = self._utc_now()
        with self._lock:
            self._health = replace(
                self._health,
                last_error=self._diagnostic(code, component, severity, now),
            )

    def _utc_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    @staticmethod
    def _diagnostic(
        code: DiagnosticCode,
        component: DiagnosticComponent,
        severity: DiagnosticSeverity,
        occurred_at: datetime,
    ) -> Diagnostic:
        return Diagnostic(
            code=code,
            component=component,
            severity=severity,
            occurred_at=occurred_at,
        )


__all__ = (
    "EngineLifecycleError",
    "LifecycleTracker",
    "MonitoringEngine",
    "PersistencePipeline",
    "SnapshotEnricher",
)
