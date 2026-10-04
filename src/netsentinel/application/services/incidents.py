"""NS-089 synchronous, bounded in-memory incident correlation boundary."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime
from enum import Enum
import json
from threading import RLock
from typing import TypeVar
from uuid import UUID, uuid4

from netsentinel.domain.connections import ConnectionRoundObservation, ObservationQuality
from netsentinel.domain.incidents import (
    CorrelatedIncident, IncidentCorrelationKey, IncidentCorrelationResult,
    IncidentCorrelationStatus as Status, IncidentDiagnostics, IncidentInput,
    IncidentLimitation as Limitation, IncidentObservationRef, IncidentPolicy,
    IncidentProcessDestination, IncidentRelation, IncidentRelationReason as Reason,
    RELATION_PRIORITY,
)
from netsentinel.domain.risk_evidence import EvidenceLimitation, EvidenceScopeKind


T = TypeVar("T")
MAX_COUNTER = 2**63 - 1


def _sort_key(value: object) -> str:
    """Canonical ordering of validated pointers, never a metadata dump/log."""
    def primitive(item: object) -> object:
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, (UUID, datetime)):
            return str(item)
        if is_dataclass(item) and not isinstance(item, type):
            return [type(item).__name__, [primitive(getattr(item, f.name)) for f in fields(item)]]
        return item
    return json.dumps(primitive(value), ensure_ascii=True, separators=(",", ":"))


def _add(items: tuple[T, ...], additions: tuple[T, ...]) -> tuple[T, ...]:
    return tuple(sorted(set(items) | set(additions), key=_sort_key))


@dataclass(slots=True)
class _State:
    snapshot: CorrelatedIncident
    keys: set[IncidentCorrelationKey]


class IncidentCorrelator:
    """No I/O or callbacks; one lock owns admission, eviction and read snapshots."""

    def __init__(self, policy: IncidentPolicy = IncidentPolicy()) -> None:
        if type(policy) is not IncidentPolicy:
            raise TypeError("correlator policy must be typed")
        self._policy = policy
        self._lock = RLock()
        self._states: dict[UUID, _State] = {}
        self._indexes: dict[tuple[datetime, IncidentCorrelationKey], set[UUID]] = {}
        self._observations: dict[IncidentObservationRef, UUID] = {}
        self._gaps: set[tuple[UUID, datetime]] = set()
        self._gap_overflow_at: datetime | None = None
        self._watermark: datetime | None = None
        self._index_entries = 0
        self._counters = dict.fromkeys(("new_incidents", "attachments", "duplicates",
            "out_of_order", "late", "gap_separated", "capacity_limited", "evictions", "expired"), 0)

    @property
    def policy(self) -> IncidentPolicy:
        return self._policy

    def _count(self, name: str) -> None:
        self._counters[name] = min(MAX_COUNTER, self._counters[name] + 1)

    def _remove(self, incident_id: UUID) -> None:
        state = self._states.pop(incident_id)
        for key in state.keys:
            index_key = (state.snapshot.cohort, key)
            ids = self._indexes[index_key]
            ids.remove(incident_id)
            if not ids:
                del self._indexes[index_key]
        for relation in state.snapshot.relations:
            del self._observations[relation.observation]
        self._index_entries -= len(state.keys) + len(state.snapshot.relations)

    def _advance(self, stamp: datetime) -> None:
        if self._watermark is None or stamp > self._watermark:
            self._watermark = stamp
        watermark = self._watermark
        horizon = self.policy.retention_horizon
        for incident_id, state in tuple(self._states.items()):
            if watermark - state.snapshot.last_observed_at > horizon:
                self._remove(incident_id)
                self._count("expired")
        self._gaps = {(session, at) for session, at in self._gaps if watermark - at <= horizon}
        if self._gap_overflow_at is not None and watermark - self._gap_overflow_at > horizon:
            self._gap_overflow_at = None

    def observe_round(self, observation: ConnectionRoundObservation) -> bool:
        """Supply existing quality markers before observations that depend on them.

        False means late or marker capacity loss, not a security finding.
        """
        if type(observation) is not ConnectionRoundObservation:
            raise TypeError("round must be a canonical ConnectionRoundObservation")
        with self._lock:
            if self._watermark is not None and self._watermark - observation.observed_at > self.policy.max_lateness:
                self._count("late")
                return False
            self._advance(observation.observed_at)
            if observation.quality is ObservationQuality.COMPLETE and not observation.discarded_observations:
                return True
            marker = (observation.session_id, observation.observed_at)
            if marker in self._gaps:
                return True
            if len(self._gaps) >= self.policy.max_gaps:
                self._gap_overflow_at = max(self._gap_overflow_at or observation.observed_at, observation.observed_at)
                self._count("capacity_limited")
                return False
            self._gaps.add(marker)
            # Late markers explain uncertainty; they do not rewrite memberships.
            for state in self._states.values():
                incident = state.snapshot
                sessions = {r.session_id for r in incident.connections} | {p.session_id for p in incident.processes}
                if observation.session_id in sessions and incident.first_observed_at <= observation.observed_at <= incident.last_observed_at:
                    state.snapshot = replace(incident, limitations=_add(incident.limitations, (Limitation.MONITORING_GAP,)))
            return True

    @staticmethod
    def _quality_limited(item: IncidentInput) -> bool:
        return item.quality.measurement is not ObservationQuality.COMPLETE or bool(item.quality.limitations)

    def _keys(self, item: IncidentInput) -> set[IncidentCorrelationKey]:
        keys: set[IncidentCorrelationKey] = set()
        if item.connection is not None:
            keys.add(IncidentCorrelationKey(Reason.SAME_CONNECTION_LIFECYCLE, item.connection))
        keys.update(IncidentCorrelationKey(Reason.SAME_CANONICAL_EVIDENCE, ref) for ref in item.evidence)
        if item.assessment is not None:
            keys.add(IncidentCorrelationKey(Reason.SAME_ASSESSMENT_LINEAGE, item.assessment.assessment_id))
        if item.alert_id is not None:
            keys.add(IncidentCorrelationKey(Reason.SAME_ALERT_OBSERVATION, item.alert_id))
        if (item.process is not None and item.process.identity.create_time is not None
                and item.destination is not None and item.destination.port is not None
                and item.destination.protocol is not None and item.scope.kind is EvidenceScopeKind.NETWORK
                and not self._quality_limited(item)):
            keys.add(IncidentCorrelationKey(Reason.SAME_PROCESS_AND_DESTINATION,
                IncidentProcessDestination(item.process, item.destination, item.scope)))
        return keys

    def _has_gap(self, incident: CorrelatedIncident, item: IncidentInput) -> bool:
        sessions = {r.session_id for r in incident.connections} | {p.session_id for p in incident.processes}
        if item.connection is not None:
            sessions.add(item.connection.session_id)
        if item.process is not None:
            sessions.add(item.process.session_id)
        first = min(incident.first_observed_at, item.observed_at)
        last = max(incident.last_observed_at, item.observed_at)
        return (EvidenceLimitation.MONITORING_GAP in item.quality.limitations
            or Limitation.MONITORING_GAP in incident.limitations
            or any(session in sessions and first <= at <= last for session, at in self._gaps))

    def _proposed(self, incident: CorrelatedIncident, item: IncidentInput,
                  reason: Reason, matched_key: IncidentCorrelationKey | None,
                  limitations: tuple[Limitation, ...]) -> CorrelatedIncident:
        return replace(incident,
            first_observed_at=min(incident.first_observed_at, item.observed_at),
            last_observed_at=max(incident.last_observed_at, item.observed_at),
            processes=_add(incident.processes, (item.process,) if item.process else ()),
            connections=_add(incident.connections, (item.connection,) if item.connection else ()),
            destinations=_add(incident.destinations, (item.destination,) if item.destination else ()),
            evidence=_add(incident.evidence, item.evidence),
            assessments=_add(incident.assessments, (item.assessment,) if item.assessment else ()),
            alerts=_add(incident.alerts, (item.alert_id,) if item.alert_id else ()),
            scopes=_add(incident.scopes, (item.scope,)),
            relations=tuple(sorted((*incident.relations, IncidentRelation(item.observation, reason, matched_key)),
                key=lambda r: (r.observation.observed_at, _sort_key(r.observation)))),
            limitations=_add(incident.limitations, limitations))

    def _within_capacity(self, incident: CorrelatedIncident, keys: set[IncidentCorrelationKey],
                         added_entries: int, released_entries: int = 0) -> bool:
        p = self.policy
        return (len(incident.processes) <= p.max_processes and len(incident.connections) <= p.max_connections
            and len(incident.destinations) <= p.max_destinations and len(incident.evidence) <= p.max_evidence
            and len(incident.alerts) <= p.max_alerts and len(incident.assessments) <= p.max_assessments
            and len(incident.scopes) <= p.max_scopes and len(incident.relations) <= p.max_relations
            and len(keys) <= p.max_keys_per_incident
            and self._index_entries + added_entries - released_entries <= p.max_index_entries)

    def correlate(self, item: IncidentInput) -> IncidentCorrelationResult:
        if type(item) is not IncidentInput:
            raise TypeError("correlation requires a canonical IncidentInput")
        with self._lock:
            if self._watermark is not None and self._watermark - item.observed_at > self.policy.max_lateness:
                self._count("late")
                return IncidentCorrelationResult(Status.LATE, limitations=(Limitation.LATE,))
            out_of_order = self._watermark is not None and item.observed_at < self._watermark
            self._advance(item.observed_at)
            existing = self._observations.get(item.observation)
            if existing is not None:
                self._count("duplicates")
                return IncidentCorrelationResult(Status.DUPLICATE, self._states[existing].snapshot)
            cohort = self.policy.cohort(item.observed_at)
            keys = self._keys(item)
            matches: list[tuple[int, UUID, IncidentCorrelationKey]] = []
            gap_separated = False
            for key in keys:
                for incident_id in self._indexes.get((cohort, key), ()):
                    incident = self._states[incident_id].snapshot
                    if max(incident.last_observed_at, item.observed_at) - min(incident.first_observed_at, item.observed_at) > self.policy.window:
                        continue
                    if key.reason is Reason.SAME_PROCESS_AND_DESTINATION and (
                            self._gap_overflow_at is not None or self._has_gap(incident, item)
                            or Limitation.QUALITY_LIMITED in incident.limitations):
                        gap_separated = True
                        continue
                    matches.append((RELATION_PRIORITY.index(key.reason), incident_id, key))
            if gap_separated:
                self._count("gap_separated")
            matches.sort(key=lambda m: (m[0],
                _sort_key(self._states[m[1]].snapshot.relations[0].observation), _sort_key(m[2])))
            matched_key = matches[0][2] if matches else None
            reason = matched_key.reason if matched_key else Reason.FIRST_OBSERVATION
            incident_id = matches[0][1] if matches else uuid4()
            state = self._states.get(incident_id)
            incident = state.snapshot if state else CorrelatedIncident(incident_id, cohort, item.observed_at, item.observed_at)
            limitations: tuple[Limitation, ...] = ()
            if self._quality_limited(item):
                limitations += (Limitation.QUALITY_LIMITED,)
            if self._gap_overflow_at is not None:
                limitations += (Limitation.GAP_CAPACITY,)
            if self._has_gap(incident, item):
                limitations += (Limitation.MONITORING_GAP,)
                if matched_key is not None:
                    limitations += (Limitation.CANONICAL_GAP_BRIDGE,)
            if len({m[1] for m in matches}) > 1:
                limitations += (Limitation.AMBIGUOUS_MATCH,)
            proposed = self._proposed(incident, item, reason, matched_key, limitations)
            old_keys = state.keys if state else set()
            new_keys = old_keys | keys
            added = len(keys - old_keys) + 1
            victim: _State | None = None
            if state is None and len(self._states) >= self.policy.max_incidents:
                victim = min(self._states.values(), key=lambda s: (
                    s.snapshot.last_observed_at, s.snapshot.first_observed_at,
                    _sort_key(s.snapshot.relations[0].observation)))
            released = len(victim.keys) + len(victim.snapshot.relations) if victim else 0
            if not self._within_capacity(proposed, new_keys, added, released):
                self._count("capacity_limited")
                if state:
                    state.snapshot = replace(incident, limitations=_add(incident.limitations, (Limitation.CAPACITY_LIMITED,)))
                return IncidentCorrelationResult(Status.CAPACITY_LIMITED, state.snapshot if state else None,
                    limitations=(Limitation.CAPACITY_LIMITED,))
            if victim:
                self._remove(victim.snapshot.incident_id)
                self._count("evictions")
            self._states[incident_id] = _State(proposed, new_keys)
            for key in keys - old_keys:
                self._indexes.setdefault((cohort, key), set()).add(incident_id)
            self._observations[item.observation] = incident_id
            self._index_entries += added
            self._count("attachments" if state else "new_incidents")
            if out_of_order:
                self._count("out_of_order")
            return IncidentCorrelationResult(Status.ATTACHED if state else Status.NEW_INCIDENT,
                proposed, reason, proposed.limitations)

    def snapshot(self) -> tuple[CorrelatedIncident, ...]:
        with self._lock:
            return tuple(sorted((s.snapshot for s in self._states.values()), key=lambda s: (
                s.first_observed_at, s.incident_id.int)))

    def diagnostics(self) -> IncidentDiagnostics:
        """Only aggregate counts; never pointers, addresses or exception text."""
        with self._lock:
            return IncidentDiagnostics(len(self._states), self._index_entries, len(self._gaps), **self._counters)
