"""NS-092 offline story, restart, retention, time/identity and loss acceptance."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from netsentinel.application.services.incident_inputs import incident_input_from_assessment, incident_input_from_connection
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.application.services.incident_timeline import TimelineRequest
from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.behavior_baseline import BaselineState
from netsentinel.domain.connections import ConnectionRoundObservation, ObservationQuality, ProcessIdentity
from netsentinel.domain.destination_novelty import DestinationNoveltyClassification
from netsentinel.domain.dns import DnsAssociationStatus, DnsAssociationProvenance
from netsentinel.domain.incidents import IncidentCorrelationStatus as C, IncidentLimitation as L, IncidentProcessRef
from netsentinel.domain.incident_persistence import IncidentSourceStatus as Source, IncidentState as State, IncidentStatus as S
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness
from netsentinel.domain.threat_intel_evidence import ThreatIntelAssessmentSignal
from netsentinel.domain.threat_intelligence import ThreatIntelError, ThreatIntelResultStatus
from netsentinel.infrastructure.sqlite.writer import SQLiteHistoryWriteSessionFactory
from tests.fixtures.incident_acceptance import Story, all_pages, connection, deny_network, table_state
from tests.fixtures.incidents import NOW, SESSION, PROCESS, SCOPE, item
from tests.fixtures.threat_intel_evidence import mapping


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    deny_network(monkeypatch)


def test_incident_end_to_end_story(tmp_path):
    story = Story(tmp_path / "story.db").build()
    prepared, revision = story.prepared, story.result.assessment.revision
    assert prepared.baseline.state is BaselineState.READY
    assert prepared.baseline.summary.features.observed_appearances == 20
    assert prepared.baseline.summary.features.monitored_seconds == 600
    assert prepared.novelty.classification is DestinationNoveltyClassification.FIRST_SEEN
    assert revision.key.observation_reference.value == story.event.lifecycle_id
    assert revision.key.subject.process == story.event.snapshot.process.identity
    assert revision.key.subject.session_id == story.event.session_id
    assert revision.key.original_observed_at == NOW
    assert revision.assessed_at == NOW + timedelta(seconds=2)
    assert revision.snapshot.score == 20
    assert story.result.alert.occurrence_count == 1
    record = story.record
    assert record.incident_id.version == 5
    assert record.snapshot.connections == (story.inputs[0].connection,)
    assert story.inputs[-2].assessment in record.snapshot.assessments
    assert story.result.alert.id in record.snapshot.alerts
    assert {e.evidence_id for e in revision.snapshot.evidence} <= {e.value for e in record.snapshot.evidence}
    assert story.dns_lookup.status is DnsAssociationStatus.AMBIGUOUS
    assert {a.provenance for a in story.dns_associations} == {DnsAssociationProvenance.DIRECT_ANSWER, DnsAssociationProvenance.CNAME_DERIVED}
    assert {a.ttl for a in story.dns_associations} == {20, 60}
    assert {a.evidence_id.value for a in story.dns_associations} == {story.dns_ref.value}
    assert {a.observed_at for a in story.dns_associations} == {NOW}
    assert story.dns_record.incident_id != record.incident_id  # no DNS→process causality
    ack = story.incidents.acknowledge(record.incident_id, expected_revision=record.revision,
                                    now=NOW + timedelta(seconds=3)).record
    assert ack.state is State.ACKNOWLEDGED
    resolved = story.incidents.resolve(record.incident_id, expected_revision=ack.revision,
                                      now=NOW + timedelta(seconds=4)).record
    assert resolved.state is State.RESOLVED
    assert story.alerts.get(story.result.alert.id).status is AlertStatus.OPEN
    story.alert_service.acknowledge(story.result.alert.id)
    assert story.incidents.get(record.incident_id).record == resolved
    rows, _ = all_pages(story.query, record.incident_id, 3)
    from netsentinel.application.services.incident_timeline import TimelineKind
    assert {r.kind for r in rows} == set(TimelineKind)
    assert rows == tuple(sorted(rows, key=lambda r: r.sort_key))
    for r in rows:
        if r.kind is TimelineKind.ASSESSMENT:
            assert r.assessment_time == revision.assessed_at and r.observation_time == NOW
        if r.kind is TimelineKind.USER_ACTION:
            assert r.action_time in (ack.updated_at, resolved.updated_at)
    before = table_state(story.db)
    restarted = story.restart()
    assert restarted.incidents.get(record.incident_id).record == resolved
    assert all_pages(restarted.query, record.incident_id, 3)[0] == rows
    for value in story.inputs:
        assert restarted.incidents.append(record.incident_id, value, now=NOW + timedelta(hours=1)).status is S.NO_CHANGE
    assert table_state(restarted.db) == before
    # Supported history restart path declares a gap without filling downtime.
    with SQLiteHistoryWriteSessionFactory(restarted.db)() as session:
        with session.batch():
            assert session.reconcile_open() == 1
    assert restarted.incidents.get(record.incident_id).record == resolved
    assert all_pages(restarted.query, record.incident_id)[0] == rows
    with restarted.db.connection() as conn:
        conn.execute("DELETE FROM connection_history")
        conn.execute("DELETE FROM dns_history")
    read = restarted.incidents.get(record.incident_id)
    assert read.record == resolved  # source loss ≠ incident loss
    statuses = {r.status for r in read.references}
    assert {Source.AVAILABLE, Source.SOURCE_EXPIRED_OR_UNAVAILABLE, Source.UNRESOLVED} <= statuses
    expired = restarted.incidents.get(story.dns_record.incident_id)
    assert Source.SOURCE_EXPIRED_OR_UNAVAILABLE in {r.status for r in expired.references}
    retained, _ = all_pages(restarted.query, record.incident_id, 3)
    assert [r.entry_id for r in retained] == [r.entry_id for r in rows]
    assert any(r.source_status is Source.SOURCE_EXPIRED_OR_UNAVAILABLE for r in retained)
    assert all_pages(restarted.restart().query, record.incident_id, 3)[0] == retained


@pytest.mark.parametrize("status,freshness,error", [
    (ThreatIntelResultStatus.HIT, ThreatIntelCacheFreshness.FRESH, None),
    (ThreatIntelResultStatus.NO_HIT, ThreatIntelCacheFreshness.FRESH, None),
    (ThreatIntelResultStatus.HIT, ThreatIntelCacheFreshness.STALE, None),
    (ThreatIntelResultStatus.HIT, ThreatIntelCacheFreshness.FRESH, ThreatIntelError.UNAVAILABLE),
])
def test_fake_ti_supports_same_story_without_occurrence_or_verdict(tmp_path, status, freshness, error):
    story = Story(tmp_path / "ti.db").build()
    original = story.result.assessment.revision
    before = story.alerts.get(story.result.alert.id)
    mapped = mapping(status=status, freshness=freshness, error=error, stamp=NOW + timedelta(minutes=1))
    if mapped.context is None:
        assert error is not None
        assert story.assessments.latest(original.key.assessment_id).revision == original
    else:
        enriched = story.risk.enrich(ThreatIntelAssessmentSignal(story.event.lifecycle_id, mapped.context, NOW + timedelta(minutes=1)))
        revision = enriched.assessment.revision
        assert revision.revision == 2 and revision.key == original.key
        assert revision.snapshot.score == original.snapshot.score
        context = revision.snapshot.threat_intelligence[0]
        assert context.freshness is freshness and context.result.status is status
        value = incident_input_from_assessment(revision)
        result = story.incidents.append(story.record.incident_id, value, now=NOW + timedelta(minutes=1))
        assert result.status is S.CHANGED and result.record.incident_id == story.record.incident_id
        assert result.record.snapshot.first_observed_at == result.record.snapshot.last_observed_at == NOW
        assert story.incidents.append(story.record.incident_id, value, now=NOW + timedelta(minutes=1)).status is S.NO_CHANGE
        model = RiskExplanationQueryService(story.assessments).lookup(RiskExplanationRequest.for_alert(enriched.alert), now=NOW + timedelta(minutes=1))
        text = "\n".join(line for section in model.sections for line in section.lines)
        assert "abuseipdb" in text
        assert "not a malware verdict" in text and "zero risk points" in text
        if status is ThreatIntelResultStatus.NO_HIT:
            assert "does not establish that the destination is safe" in text
        if freshness is ThreatIntelCacheFreshness.STALE:
            assert "STALE" in text
        assert all_pages(story.restart().query, story.record.incident_id)[0]
    after = story.alerts.get(before.id)
    for field in ("occurrence_count", "first_seen", "last_seen", "status", "fingerprint"):
        assert getattr(after, field) == getattr(before, field)


@pytest.mark.parametrize("mode", ["corrupt", "expired", "unsupported"])
def test_bad_assessment_source_retains_rest_of_real_story(tmp_path, mode):
    story = Story(tmp_path / "source.db").build()
    with story.db.connection() as conn:
        if mode == "expired":
            conn.execute("DELETE FROM risk_assessment_revisions")
        elif mode == "corrupt":
            conn.execute("UPDATE risk_assessment_revisions SET snapshot = 'invalid'")
        else:
            conn.execute("UPDATE risk_assessment_revisions SET format_version = 99")
    rows, _ = all_pages(story.restart().query, story.record.incident_id)
    from netsentinel.application.services.incident_timeline import TimelineKind
    row = next(r for r in rows if r.kind is TimelineKind.ASSESSMENT)
    assert row.source_status is {"corrupt": Source.CORRUPT, "expired": Source.SOURCE_EXPIRED_OR_UNAVAILABLE,
                                 "unsupported": Source.UNSUPPORTED_VERSION}[mode]
    assert row.assessment_time is None and "unknown" in row.time_semantics
    assert any(r.kind is TimelineKind.OBSERVATION for r in rows)


def test_real_story_failed_round_does_not_add_coverage_or_risk(tmp_path):
    story = Story(tmp_path / "actual-loss.db").build()
    before = table_state(story.db)
    features = story.accumulator.snapshot()
    story.clock.tick += 30
    story.clock.utc += timedelta(seconds=30)
    gap = story.tracker.record_failure(observed_at=story.clock.utc)
    assert gap.quality is ObservationQuality.FAILED
    assert story.pipeline.prepare(gap, ()) == ()
    contributions = story.accumulator.observe_round(gap, (), ())
    story.baseline.observe(contributions, story.clock.utc, gap.quality)
    after = story.accumulator.snapshot()
    assert sum(s.monitored_seconds for s in after.scopes) == sum(s.monitored_seconds for s in features.scopes)
    assert table_state(story.db) == before
    assert story.tracker.active_connections
    correlator = IncidentCorrelator()
    first = correlator.correlate(story.inputs[0]).incident
    correlator.observe_round(gap)
    ref = replace(story.inputs[0].connection, lifecycle_id=UUID(int=9999))
    weak = replace(story.inputs[0], connection=ref,
                   observation=replace(story.inputs[0].observation, reference=ref, observed_at=story.clock.utc))
    assert correlator.correlate(weak).status is C.NEW_INCIDENT
    strong = replace(story.inputs[0], observation=replace(story.inputs[0].observation, observed_at=story.clock.utc))
    related = correlator.correlate(strong)
    assert related.incident.incident_id == first.incident_id
    assert L.MONITORING_GAP in related.incident.limitations


def test_default_composition_has_no_provider_requests_or_history_creation(tmp_path):
    from netsentinel.bootstrap import create_desktop_engine
    path = tmp_path / "dormant.db"
    engine = create_desktop_engine(database_path=path)
    assert engine.behavior_risk.worker.diagnostics().processed == 0
    assert not path.exists()
    assert engine.stop(1)


@pytest.mark.parametrize("delta,expected", [
    (timedelta(minutes=5) - timedelta(microseconds=1), S.CHANGED),
    (timedelta(minutes=5), S.CHANGED),
    (timedelta(minutes=5, microseconds=1), S.HORIZON_EXCEEDED),
])
@pytest.mark.parametrize("restart", [False, True])
def test_reopen_exact_horizon_and_restart(tmp_path, delta, expected, restart):
    story = Story(tmp_path / "reopen.db")
    seed = item()
    saved = story.incidents.observe(seed, now=NOW).record
    resolved = story.incidents.resolve(saved.incident_id, expected_revision=saved.revision, now=NOW).record
    service = story.restart().incidents if restart else story.incidents
    value = item(2, stamp=NOW + delta, connection=seed.connection)
    result = service.reopen(saved.incident_id, value, expected_revision=resolved.revision, now=NOW + delta)
    assert result.status is expected
    if expected is S.CHANGED:
        assert result.record.state is State.OPEN and result.record.incident_id == saved.incident_id
        if restart:
            assert L.MONITORING_GAP in result.record.snapshot.limitations
            assert L.CANONICAL_GAP_BRIDGE in result.record.snapshot.limitations


@pytest.mark.parametrize("changes", [
    {"process": None},
    {"process": IncidentProcessRef(SESSION, ProcessIdentity(PROCESS.identity.pid, NOW))},
    {"process": IncidentProcessRef(SESSION, ProcessIdentity(PROCESS.identity.pid))},
    {"scope": replace(SCOPE, network_fingerprint="b" * 64)},
])
def test_wrong_identity_or_scope_does_not_reopen_on_same_ip(tmp_path, changes):
    story = Story(tmp_path / "weak.db")
    seed = story.incidents.observe(item(), now=NOW).record
    resolved = story.incidents.resolve(seed.incident_id, expected_revision=1, now=NOW).record
    value = item(2, stamp=NOW + timedelta(seconds=1), **changes)
    assert story.incidents.reopen(seed.incident_id, value, expected_revision=resolved.revision,
                                  now=value.observed_at).status is S.NOT_CORRELATED


@pytest.mark.parametrize("quality,discarded", [(ObservationQuality.FAILED, 0), (ObservationQuality.REDUCED, 2), (ObservationQuality.COMPLETE, 2)])
def test_typed_loss_does_not_widen_correlation_or_invent_risk(tmp_path, quality, discarded):
    correlator = IncidentCorrelator()
    first = correlator.correlate(item()).incident
    round_observation = ConnectionRoundObservation(SESSION, NOW + timedelta(seconds=1), quality,
                                                   discarded_observations=discarded)
    assert correlator.observe_round(round_observation)
    weak = correlator.correlate(item(2, stamp=NOW + timedelta(seconds=2)))
    assert weak.status is C.NEW_INCIDENT
    strong = correlator.correlate(item(3, stamp=NOW + timedelta(seconds=3), connection=item().connection))
    assert strong.status is C.ATTACHED and strong.incident.incident_id == first.incident_id
    assert {L.MONITORING_GAP, L.CANONICAL_GAP_BRIDGE} <= set(strong.incident.limitations)
    story = Story(tmp_path / "gap.db")
    result = story.incidents.create_or_get(strong.incident, now=NOW + timedelta(seconds=4))
    assert result.status is S.CHANGED
    page = story.restart().query.lookup(TimelineRequest(result.record.incident_id))
    assert any("gap" in text.lower() for text in page.limitations)
    with story.db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_polling_tuple_reuse_and_pid_reuse_have_distinct_canonical_identity(tmp_path):
    from netsentinel.application.services.connections import ConnectionTrackingService
    tracker = ConnectionTrackingService(clock=lambda: NOW)
    first = tracker.track((connection(),), observed_at=NOW)[0]
    tracker.track((), observed_at=NOW + timedelta(seconds=1))
    second = tracker.track((connection(NOW + timedelta(seconds=2)),), observed_at=NOW + timedelta(seconds=2))[0]
    assert first.snapshot.key == second.snapshot.key and first.lifecycle_id != second.lifecycle_id
    # A new process instance at the same PID/tuple cannot use a derived merge.
    process = replace(first.snapshot.process, identity=ProcessIdentity(first.snapshot.process.identity.pid, NOW))
    third = tracker.track((connection(NOW + timedelta(seconds=3), process=process),), observed_at=NOW + timedelta(seconds=3))[0]
    service = IncidentCorrelator()
    a = service.correlate(incident_input_from_connection(first)).incident
    b = service.correlate(incident_input_from_connection(third)).incident
    assert a.incident_id != b.incident_id


@pytest.mark.parametrize("offsets,groups", [
    ((0, 599_999_999), 1), ((599_999_999, 600_000_000), 2),
    ((0, 540_000_000, 1_080_000_000), 2),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_fixed_bucket_boundary_out_of_order_and_no_chain_bridge(tmp_path, offsets, groups, reverse):
    service = IncidentCorrelator()
    values = [item(n + 1, stamp=NOW + timedelta(microseconds=t), connection=item().connection) for n, t in enumerate(offsets)]
    if reverse:
        values.reverse()
    for value in values:
        service.correlate(value)
    assert len(service.snapshot()) == groups
    story = Story(tmp_path / "bucket.db")
    for snapshot in service.snapshot():
        assert snapshot.last_observed_at - snapshot.first_observed_at < timedelta(minutes=10)
        assert story.incidents.create_or_get(snapshot, now=NOW + timedelta(minutes=20)).status is S.CHANGED
    assert len(story.restart().incidents.repository.list_current().entries) == groups
