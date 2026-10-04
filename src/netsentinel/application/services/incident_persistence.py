"""NS-090 explicit durable commands; SQL/network/alert services stay outside."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timedelta
from threading import RLock
from uuid import UUID

from netsentinel.application.ports import IncidentRepository
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.incidents import (
    CorrelatedIncident, IncidentCorrelationStatus, IncidentInput, incident_time,
)
from netsentinel.domain.incident_persistence import (
    IncidentAction as Action, IncidentCommandError, IncidentOrigin as Origin,
    IncidentRecord, IncidentResult, IncidentState as State, IncidentStatus as Status,
    stable_incident_id, validate_incident,
)


class IncidentPersistenceService:
    """Blocking explicit API. A private temporary correlator never outlives commit.

    The small live-ID LRU carries known process-local continuity only. It is not
    a database cache or an occurrence source. Across restart keys are conservative.
    """

    def __init__(self, repository: IncidentRepository) -> None:
        self.repository = repository
        self._live: OrderedDict[UUID, None] = OrderedDict()
        self._lock = RLock()

    def create_or_get(self, snapshot: CorrelatedIncident, *, now: datetime) -> IncidentResult:
        now = incident_time(now)
        policy = self.repository.policy.correlation
        validate_incident(snapshot, policy)
        if now < snapshot.last_observed_at:
            raise ValueError("create time precedes observation")
        stable = replace(snapshot, incident_id=stable_incident_id(snapshot, policy))

        def create(current: IncidentRecord | None) -> IncidentRecord:
            if current is not None:
                if current.correlation_policy != policy:
                    raise IncidentCommandError(Status.IDENTITY_CONFLICT)
                # Exact retry of an earlier snapshot remains a no-op after append.
                for name in ("processes", "connections", "destinations", "evidence", "assessments", "alerts", "scopes", "relations", "limitations"):
                    if not set(getattr(stable, name)).issubset(set(getattr(current.snapshot, name))):
                        raise IncidentCommandError(Status.IDENTITY_CONFLICT)
                return current
            return IncidentRecord(stable, 1, State.OPEN, now, now, Action.CREATED,
                                  Origin.SYSTEM_CORRELATION, correlation_policy=policy)

        with self._lock:
            result = self.repository.update(stable.incident_id, create)
            if result.status is Status.CHANGED:
                self._live[stable.incident_id] = None
                while len(self._live) > self.repository.policy.max_hydration:
                    self._live.popitem(last=False)
            return result

    @staticmethod
    def _current(value: IncidentRecord | None) -> IncidentRecord:
        if value is None:
            raise IncidentCommandError(Status.NOT_FOUND)
        return value

    @staticmethod
    def _clock(record: IncidentRecord, now: datetime) -> None:
        if now < record.updated_at:
            raise IncidentCommandError(Status.INVALID_TRANSITION)

    def _append_snapshot(self, record: IncidentRecord, item: IncidentInput) -> CorrelatedIncident:
        snapshot = record.snapshot
        if record.correlation_policy != self.repository.policy.correlation:
            # Historical policy is not silently reinterpreted.
            raise IncidentCommandError(Status.NOT_CORRELATED)
        if any(r.observation == item.observation for r in snapshot.relations):
            # Observation refs are immutable. A retry may not smuggle new fields.
            for value, values in ((item.process, snapshot.processes), (item.connection, snapshot.connections),
                                  (item.destination, snapshot.destinations), (item.assessment, snapshot.assessments),
                                  (item.alert_id, snapshot.alerts), (item.scope, snapshot.scopes)):
                if value is not None and value not in values:
                    raise IncidentCommandError(Status.IDENTITY_CONFLICT)
            if not set(item.evidence).issubset(set(snapshot.evidence)):
                raise IncidentCommandError(Status.IDENTITY_CONFLICT)
            return snapshot
        correlator = IncidentCorrelator(record.correlation_policy)
        correlator.hydrate((snapshot,), continuity_gap=record.incident_id not in self._live)
        result = correlator.correlate(item)
        if result.status is IncidentCorrelationStatus.CAPACITY_LIMITED:
            raise IncidentCommandError(Status.CAPACITY_REACHED)
        if result.status is not IncidentCorrelationStatus.ATTACHED or result.incident is None or result.incident.incident_id != record.incident_id:
            raise IncidentCommandError(Status.NOT_CORRELATED)
        return result.incident

    def append(self, incident_id: UUID, item: IncidentInput, *, now: datetime,
               expected_revision: int | None = None) -> IncidentResult:
        if type(item) is not IncidentInput:
            raise TypeError("canonical incident input required")
        now = incident_time(now)
        if now < item.observed_at:
            raise ValueError("append time precedes observation")

        def append_to(current: IncidentRecord | None) -> IncidentRecord:
            record = self._current(current)
            proposed = self._append_snapshot(record, item)
            if proposed == record.snapshot:
                return record
            self._clock(record, now)
            return replace(record, snapshot=proposed, revision=record.revision + 1,
                           updated_at=now, action=Action.APPENDED, origin=Origin.SYSTEM_CORRELATION)

        with self._lock:
            return self.repository.update(incident_id, append_to, expected_revision=expected_revision)

    def acknowledge(self, incident_id: UUID, *, expected_revision: int, now: datetime,
                    origin: Origin = Origin.MANUAL_USER) -> IncidentResult:
        return self._lifecycle(incident_id, Action.ACKNOWLEDGED, expected_revision, now, origin)

    def resolve(self, incident_id: UUID, *, expected_revision: int, now: datetime,
                origin: Origin = Origin.MANUAL_USER) -> IncidentResult:
        return self._lifecycle(incident_id, Action.RESOLVED, expected_revision, now, origin)

    def _lifecycle(self, incident_id: UUID, action: Action, expected_revision: int,
                   now: datetime, origin: Origin) -> IncidentResult:
        now = incident_time(now)
        if type(origin) is not Origin:
            raise TypeError("typed incident origin required")

        def change(current: IncidentRecord | None) -> IncidentRecord:
            record = self._current(current)
            target = State.ACKNOWLEDGED if action is Action.ACKNOWLEDGED else State.RESOLVED
            if record.state is target:
                return record
            if action is Action.ACKNOWLEDGED and record.state is State.RESOLVED:
                raise IncidentCommandError(Status.INVALID_TRANSITION)
            self._clock(record, now)
            if now < record.snapshot.last_observed_at:
                raise IncidentCommandError(Status.INVALID_TRANSITION)
            return replace(record, revision=record.revision + 1, state=target, updated_at=now,
                           action=action, origin=origin,
                           acknowledged_at=now if action is Action.ACKNOWLEDGED else record.acknowledged_at,
                           resolved_at=now if action is Action.RESOLVED else record.resolved_at)

        return self.repository.update(incident_id, change, expected_revision=expected_revision)

    def reopen(self, incident_id: UUID, item: IncidentInput, *, expected_revision: int,
               now: datetime, origin: Origin = Origin.SYSTEM_CORRELATION) -> IncidentResult:
        now = incident_time(now)
        if type(item) is not IncidentInput or type(origin) is not Origin:
            raise TypeError("typed reopen input and origin required")
        if now < item.observed_at:
            raise ValueError("reopen time precedes observation")

        def change(current: IncidentRecord | None) -> IncidentRecord:
            record = self._current(current)
            if record.state is not State.RESOLVED or record.resolved_at is None:
                raise IncidentCommandError(Status.INVALID_TRANSITION)
            delta = item.observed_at - record.resolved_at
            if not timedelta(0) <= delta <= self.repository.policy.reopen_horizon:
                raise IncidentCommandError(Status.HORIZON_EXCEEDED)
            proposed = self._append_snapshot(record, item)
            if proposed == record.snapshot:
                return record
            self._clock(record, now)
            return replace(record, snapshot=proposed, revision=record.revision + 1, state=State.OPEN,
                           updated_at=now, reopened_at=now, acknowledged_at=None,
                           action=Action.REOPENED, origin=origin)

        with self._lock:
            return self.repository.update(incident_id, change, expected_revision=expected_revision)

    def observe(self, item: IncidentInput, *, now: datetime) -> IncidentResult:
        """Restart continuation: exact cohort only, finite candidates, no preload.

        This convenience operation is serialized within the service; independent
        seed creation by multiple services is not a global graph union guarantee.
        Existing incident appends/lifecycle remain serialized by the repository.
        """
        if type(item) is not IncidentInput:
            raise TypeError("canonical incident input required")
        with self._lock:
            p = self.repository.policy
            cohort = p.correlation.cohort(item.observed_at)
            page = self.repository.list_current(limit=p.max_hydration, cohort=cohort)
            if page.has_more:
                return IncidentResult(Status.CAPACITY_REACHED)
            records = []
            for entry in page.entries:
                if entry.status is not Status.FOUND or entry.record is None:
                    return IncidentResult(entry.status)
                if entry.record.correlation_policy != p.correlation:
                    return IncidentResult(Status.NOT_CORRELATED)
                records.append(entry.record)
            correlator = IncidentCorrelator(p.correlation)
            try:
                correlator.hydrate(tuple(r.snapshot for r in records),
                    continuity_gap=any(r.incident_id not in self._live for r in records))
            except ValueError:
                return IncidentResult(Status.CAPACITY_REACHED)
            result = correlator.correlate(item)
            if result.incident is None or result.status in (IncidentCorrelationStatus.CAPACITY_LIMITED, IncidentCorrelationStatus.LATE):
                return IncidentResult(Status.CAPACITY_REACHED if result.status is IncidentCorrelationStatus.CAPACITY_LIMITED else Status.NOT_CORRELATED)
            current = next((r for r in records if r.incident_id == result.incident.incident_id), None)
            if current is not None:
                return self.append(current.incident_id, item, now=now)
            # New groups always use a canonical isolated seed, not random UUID.
            return self.create_or_get(result.incident, now=now)

    def get(self, incident_id: UUID) -> IncidentResult:
        return self.repository.get(incident_id)

    def diagnostics(self) -> dict[str, int]:
        """Only bounded aggregate continuity state; no source identifiers."""
        with self._lock:
            return {"live_continuity_incidents": len(self._live)}
