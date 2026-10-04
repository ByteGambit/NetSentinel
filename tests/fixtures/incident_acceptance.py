"""NS-092 composition at existing observation/application ports, entirely offline.

DNS is destination context, not process attribution: its canonical seed remains
separate. No new automatic engine subscription or invented DNS-risk link.
All repository connections are scoped; both owning workers drain before return.
"""

from dataclasses import replace
from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import UUID

import pytest

from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.behavior_baseline import BaselineWriter, BehaviorBaselineService
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.application.services.behavior_risk import BehaviorRiskPipeline
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.dns_association import DnsAssociationService
from netsentinel.application.services.incident_inputs import (
    incident_input_from_assessment, incident_input_from_connection, incident_input_from_evidence,
)
from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incident_timeline import IncidentTimelineQueryService, TimelineRequest, TimelineStatus
from netsentinel.application.services.risk_alerts import RiskAlertResult, RiskToAlertService
from netsentinel.application.services.risk_assessments import RiskAssessmentService
from netsentinel.application.services.risk_evidence import evidence_from_behavior
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.domain.connections import (
    ConnectionNetworkScope, ConnectionOpened, ConnectionSnapshot, ConnectionState, Endpoint,
    NetworkAttributionMethod, NetworkScopeStatus, ObservationQuality, ProcessIdentity,
    ProcessInfo, ProcessInfoStatus, TransportProtocol,
)
from netsentinel.domain.dns import DnsAnswer, DnsEvidenceId, DnsHistoryRecord, DnsQuestion, DnsRecordType, DnsTransaction, DnsTransactionStatus, DnsTransport
from netsentinel.domain.incident_persistence import IncidentStatus
from netsentinel.domain.incidents import IncidentConnectionRef, IncidentInput, IncidentObservationKind, IncidentObservationRef
from netsentinel.domain.risk_evidence import EvidenceQuality, EvidenceReference, EvidenceReferenceKind
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.behavior_baselines import baseline_repository_session
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.dns_repository import SQLiteDnsHistoryRepository
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
from netsentinel.infrastructure.sqlite.repositories import SQLiteConnectionHistoryRepository
from netsentinel.shared.config import BehaviorBaselineConfig
from tests.fixtures.incidents import NOW, SESSION, PROCESS, DESTINATION, SCOPE


class Clock:
    def __init__(self):
        self.utc = NOW - timedelta(seconds=601)
        self.tick = 0.0


def timeline_input(n, connection=None):
    ref = connection or IncidentConnectionRef(SESSION, UUID(int=5000))
    return IncidentInput(IncidentObservationRef(IncidentObservationKind.CONNECTION_UPDATED, ref,
        NOW + timedelta(microseconds=n)), SCOPE, PROCESS, ref, DESTINATION)


def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("NS-092 attempted network access")
    for name in ("socket.socket.connect", "socket.socket.connect_ex", "socket.getaddrinfo",
                 "socket.socket.sendto", "socket.create_connection"):
        monkeypatch.setattr(name, forbidden)


def connection(stamp=NOW, *, port=50000, address="8.8.8.8", process=None, network="a" * 64):
    return ConnectionSnapshot(TransportProtocol.TCP, Endpoint("192.0.2.20", port),
        Endpoint(address, 443), ConnectionState.ESTABLISHED,
        process or ProcessInfo(ProcessInfoStatus.AVAILABLE, ProcessIdentity(12, NOW - timedelta(hours=1)),
                              "example.exe", executable_path=r"C:\Apps\example.exe"), stamp,
        ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, network, "adapter", 1,
                               NetworkAttributionMethod.LOCAL_ADDRESS_MATCH))


class Story:
    def __init__(self, path):
        self.path = path
        self.db = SQLiteDatabase(path)
        self.assessments = SQLiteAssessmentRepository(self.db)
        self.alerts = SQLiteAlertRepository(self.db)
        self.alert_service = AlertService(self.alerts, clock=lambda: NOW + timedelta(seconds=2))
        self.dispatcher = EventDispatcher()
        self.risk = RiskToAlertService(RiskAssessmentService(self.assessments), self.alert_service, self.dispatcher)
        self.incidents = IncidentPersistenceService(SQLiteIncidentRepository(self.db))
        self.query = IncidentTimelineQueryService(SQLiteIncidentTimelineRepository(self.db))
        self.history = SQLiteConnectionHistoryRepository(self.db)
        self.dns_history = SQLiteDnsHistoryRepository(self.db)

    def build(self):
        clock = Clock()
        config = BehaviorBaselineConfig()
        writer = BaselineWriter(lambda: baseline_repository_session(self.db, config))
        baseline = BehaviorBaselineService(writer, clock=lambda: clock.utc, monotonic_clock=lambda: clock.tick)
        loaded = Event()
        restore = writer.on_load
        def on_load(value):
            restore(value)
            loaded.set()
        writer.on_load = on_load
        worker = RiskAlertWorker(self.risk, self.dispatcher)
        pipeline = BehaviorRiskPipeline(baseline, worker, polling_interval=1)
        accumulator = BehaviorFeatureAccumulator(monotonic_clock=lambda: clock.tick)
        results, done = [], Event()
        def receive(result):
            results.append(result)
            done.set()
        self.dispatcher.subscribe(RiskAlertResult, receive)
        serial = iter(UUID(int=n) for n in range(1000, 5000))
        with patch("netsentinel.application.services.connections.uuid4", side_effect=lambda: next(serial)):
            tracker = ConnectionTrackingService(clock=lambda: clock.utc)
            assert baseline.start() and loaded.wait(5)
            try:
                # 601 seconds of actual clean observed coverage, twenty appearances.
                # The persistent visible scope makes the one-second denominator real.
                for n in range(601):
                    clock.tick = float(n)
                    clock.utc = NOW - timedelta(seconds=601 - n)
                    snapshots = [connection(clock.utc, address="192.0.2.1")]
                    if n and n % 30 == 0:
                        snapshots.append(connection(clock.utc, port=50001, address="192.0.2.1"))
                    events = tracker.track(snapshots, observed_at=clock.utc)
                    contributions = accumulator.observe_round(tracker.last_round, events, snapshots)
                    baseline.observe(contributions, clock.utc, tracker.last_round.quality)
                clock.tick, clock.utc = 601.0, NOW
                snapshots = [connection()]
                events = tracker.track(snapshots, observed_at=NOW)
                self.event = next(e for e in events if isinstance(e, ConnectionOpened))
                prepared = pipeline.prepare(tracker.last_round, events)
                assert len(prepared) == 1
                self.prepared = prepared[0]
                contributions = accumulator.observe_round(tracker.last_round, events, snapshots)
                baseline.observe(contributions, NOW, ObservationQuality.COMPLETE)
                assert pipeline.start()
                pipeline.finish(tracker.last_round, events, prepared, accumulator,
                                now_monotonic=clock.tick, assessed_at=NOW + timedelta(seconds=2))
                assert done.wait(5)
                self.result = results[0]
                self.tracker, self.pipeline, self.accumulator, self.baseline, self.clock = tracker, pipeline, accumulator, baseline, clock
            finally:
                assert pipeline.stop(5)
                assert baseline.stop(5)
        self.history.record_opened(self.event)
        revision = self.result.assessment.revision
        self.inputs = [incident_input_from_connection(self.event, EvidenceQuality(ObservationQuality.COMPLETE))]
        # The persisted minimum snapshot is not the original RiskEvidence object.
        # Normalize the actual pre-mutation novelty through its public adapter.
        self.evidence = evidence_from_behavior(self.prepared.novelty, subject=revision.key.subject,
            scope=revision.key.scope, references=(revision.key.observation_reference,
                EvidenceReference(EvidenceReferenceKind.MONITORING_SESSION, self.event.session_id)))
        assert self.evidence.evidence_id in {e.evidence_id for e in revision.snapshot.evidence}
        self.inputs.append(incident_input_from_evidence(self.evidence))
        self.inputs.append(incident_input_from_assessment(revision))
        alert = self.result.alert
        assert alert is not None
        self.inputs.append(replace(self.inputs[0], observation=IncidentObservationRef(
            IncidentObservationKind.ALERT_OBSERVED, alert.id, NOW), alert_id=alert.id))
        for value in self.inputs:
            saved = self.incidents.observe(value, now=NOW + timedelta(seconds=2))
            assert saved.status is IncidentStatus.CHANGED
        self.record = saved.record
        # A CNAME and direct answer share one exact canonical DNS evidence ID.
        dns = DnsAssociationService(clock=lambda: 0.0)
        tx = DnsTransaction(DnsTransactionStatus.COMPLETED, "a" * 64, DnsTransport.UDP,
            "192.0.2.20", 53000, "198.51.100.53", 53, 42, (DnsQuestion("example.test", 1),),
            NOW - timedelta(milliseconds=1), NOW, .001, 0, False,
            (DnsAnswer("example.test", DnsRecordType.CNAME, "edge.test", 20),
             DnsAnswer("edge.test", DnsRecordType.A, "8.8.8.8", 60)), 0,
            evidence_id=DnsEvidenceId(UUID(int=9000)))
        self.dns_associations = dns.observe(tx)
        self.dns_lookup = dns.lookup_by_ip("8.8.8.8", network_scope=self.event.snapshot.network_scope,
                                         client_ip="192.0.2.20")
        self.dns_history.record(DnsHistoryRecord(UUID(int=9001), tx, self.dns_associations))
        self.dns_ref = EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, tx.evidence_id.value)
        value = IncidentInput(IncidentObservationRef(IncidentObservationKind.EVIDENCE_OBSERVED, self.dns_ref, NOW),
                              self.inputs[0].scope, evidence=(self.dns_ref,))
        self.dns_record = self.incidents.observe(value, now=NOW + timedelta(seconds=2)).record
        return self

    def restart(self):
        # All facade methods close their connections and build() drained workers.
        return Story(self.path)


def all_pages(query, incident_id, limit=25):
    entries, cursor, pages = [], None, 0
    while True:
        page = query.lookup(TimelineRequest(incident_id, cursor=cursor, limit=limit))
        assert page.status is TimelineStatus.FOUND
        assert len(page.entries) <= limit
        entries.extend(page.entries)
        pages += 1
        if page.next_cursor is None:
            return tuple(entries), pages
        assert page.next_cursor != cursor
        cursor = page.next_cursor


def table_state(db):
    with db.connection() as conn:
        return tuple(tuple(tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1,2"))
                     for table in ("incidents", "incident_references", "incident_revisions", "alerts",
                                   "risk_assessments", "risk_assessment_revisions"))
