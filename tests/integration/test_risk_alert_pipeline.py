"""NS-079 offline signal/assessment/alert/intent ordering and failure matrix."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from hashlib import sha256
from uuid import UUID

import pytest

from netsentinel.application.events import AlertNotificationIntent, EventDispatcher
from netsentinel.application.ports import AlertQuery, AlertRepositoryError
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.risk_alerts import (
    BehaviorRiskSignal, RiskToAlertService, RiskAlertStatus, alert_eligible, risk_alert_fingerprint,
)
from netsentinel.application.services.risk_assessments import RiskAssessmentService
from netsentinel.application.services.risk_evidence import evidence_from_behavior
from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.behavior_baseline import BaselineState
from netsentinel.domain.connections import NetworkScopeStatus, ObservationQuality
from netsentinel.domain.connections import ProcessIdentity, ProcessInfoStatus
from netsentinel.domain.destination_novelty import DestinationNoveltyClassification as Novelty
from netsentinel.domain.frequency_diversity import BehaviorClassification as Behavior
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.periodicity import PeriodicityClassification
from netsentinel.domain.risk_assessment import AssessmentPersistenceError, AssessmentReadStatus
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.domain.risk_evidence import EvidenceLimitation, EvidenceRole, EvidenceScope, EvidenceScopeKind
from netsentinel.domain.risk_scoring import (
    RiskEvidenceBatch, RiskScoringInput, EvidenceFreshness, Freshness, RiskScoringPolicy, score_risk,
)
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, SQLiteConnectionFactory
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
from tests.fixtures.behavior_risk import (
    APP, NOW, SCOPE, SESSION, key, novelty, deviations, periodic,
)


class Harness:
    def __init__(self, path):
        self.database = SQLiteDatabase(path)
        self.assessments = SQLiteAssessmentRepository(self.database)
        self.alerts = SQLiteAlertRepository(self.database)
        self.alert_service = AlertService(self.alerts, clock=lambda: NOW + timedelta(hours=1))
        self.dispatcher = EventDispatcher()
        self.intents = []
        self.dispatcher.subscribe(AlertNotificationIntent, self.intents.append)
        self.service = RiskToAlertService(RiskAssessmentService(self.assessments), self.alert_service, self.dispatcher)

    def process(self, *outputs, occurrence=None, intent=AlertWriteIntent.OCCURRENCE, freshness=Freshness.CURRENT):
        return self.service.process(BehaviorRiskSignal(occurrence or key(), outputs or (novelty(),),
            NOW + timedelta(hours=1), intent, freshness))


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path / "risk.sqlite3")


def normalize(output, occurrence=None):
    original = occurrence or key()
    return evidence_from_behavior(output, subject=original.subject, scope=original.scope,
                                  references=(original.observation_reference,))


def test_full_pipeline_and_intent_only_after_both_commits(harness):
    def verify(intent):
        assert harness.alerts.get(intent.alert_id) is not None
        stored = harness.assessments.latest(intent.assessment.assessment_id)
        assert stored.status is AssessmentReadStatus.FOUND
        assert stored.revision.revision == intent.assessment.revision
    harness.dispatcher.subscribe(AlertNotificationIntent, verify)
    result = harness.process()
    assert result.status is RiskAlertStatus.SUCCESS
    assert result.assessment.created and result.assessment.revision.revision == 1
    assert result.alert.occurrence_count == 1
    assert result.dispatch.delivered == 2 and result.dispatch.failed == 0
    assert len(harness.intents) == 1
    e = normalize(novelty())
    score = score_risk(RiskScoringInput(RiskEvidenceBatch((e,)), (EvidenceFreshness(e.evidence_id, Freshness.CURRENT),)), RiskScoringPolicy())
    assert result.assessment.revision.snapshot.score == score.score == 20
    assert result.alert.severity == score.severity.value


def test_occurrence_retry_reassessment_and_new_event_matrix(harness):
    first = harness.process()
    retry = harness.process()
    assert not retry.assessment.created and retry.alert == first.alert and len(harness.intents) == 1
    revised = harness.process(replace(novelty(), classification=Novelty.RARE), intent=AlertWriteIntent.REASSESSMENT)
    assert revised.assessment.revision.revision == 2
    assert revised.alert.occurrence_count == 1 and revised.alert.last_seen == NOW
    assert revised.alert.fingerprint == first.alert.fingerprint
    stamp = NOW + timedelta(seconds=1)
    later = harness.process(novelty(stamp=stamp), occurrence=key(index=2, stamp=stamp))
    assert later.alert.occurrence_count == 2 and later.alert.last_seen == stamp
    assert later.alert.fingerprint == first.alert.fingerprint
    assert harness.process().alert == later.alert


@pytest.mark.parametrize("status", [AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED])
def test_reassessment_preserves_ack_resolved_and_new_occurrence_reopens(harness, status):
    first = harness.process()
    harness.alerts.set_status(first.alert.id, status, NOW)
    changed = harness.process(replace(deviations()[0], classification=Behavior.ELEVATED_CONFIRMED),
                              intent=AlertWriteIntent.REASSESSMENT)
    assert changed.alert.status is status
    assert changed.alert.occurrence_count == 1 and changed.alert.first_seen == changed.alert.last_seen == NOW
    assert changed.alert.severity == "medium" and changed.alert.confidence == "moderate"
    assert len(harness.intents) == (1 if status is AlertStatus.RESOLVED else 2)
    stamp = NOW + timedelta(seconds=10)
    later = harness.process(novelty(stamp=stamp), occurrence=key(index=2, stamp=stamp))
    assert later.alert.status is (AlertStatus.OPEN if status is AlertStatus.RESOLVED else status)
    assert later.alert.occurrence_count == 2


def test_same_score_content_revision_and_old_revision_do_not_rewind(harness):
    first = harness.process()
    changed = harness.process(replace(novelty(), gap_seen=True), intent=AlertWriteIntent.REASSESSMENT)
    assert changed.assessment.revision.revision == 2 and changed.alert.occurrence_count == 1
    assert changed.assessment.revision.snapshot.score == first.assessment.revision.snapshot.score
    assert len(harness.intents) == 1
    old = harness.process(intent=AlertWriteIntent.REASSESSMENT)
    assert old.assessment.revision.revision == 1 and old.alert == changed.alert
    assert not harness.process(replace(novelty(), gap_seen=True)).assessment.created


def test_numeric_detector_change_revises_even_with_same_result_and_score(harness):
    output = deviations()[0]
    first = harness.process(output)
    changed = replace(output, current_per_monitored_minute=output.current_per_monitored_minute + 1)
    revised = harness.process(changed, intent=AlertWriteIntent.REASSESSMENT)
    assert revised.assessment.revision.revision == 2
    assert revised.assessment.revision.snapshot.score == first.assessment.revision.snapshot.score
    assert revised.alert.occurrence_count == 1
    assert normalize(output) == normalize(output)
    assert normalize(output).evidence_id != normalize(changed).evidence_id


def test_reassessment_to_unknown_updates_existing_without_normal_alert(harness):
    first = harness.process()
    changed = harness.process(novelty(state=BaselineState.UNAVAILABLE), intent=AlertWriteIntent.REASSESSMENT)
    assert changed.status is RiskAlertStatus.NO_ALERT
    assert changed.alert.id == first.alert.id and changed.alert.severity == "info"
    assert changed.alert.occurrence_count == 1
    assert harness.process(novelty(state=BaselineState.UNAVAILABLE), occurrence=key(index=2)).alert == changed.alert


@pytest.mark.parametrize("state", [s for s in BaselineState if s is not BaselineState.READY])
def test_unavailable_baseline_persists_explanation_without_alert(harness, state):
    result = harness.process(novelty(state=state))
    assert result.status is RiskAlertStatus.NO_ALERT and result.assessment is not None
    assert result.alert is None and not harness.intents


@pytest.mark.parametrize("classification,expected", [(Novelty.KNOWN, False), (Novelty.RARE, True), (Novelty.FIRST_SEEN, True)])
def test_novelty_eligibility(harness, classification, expected):
    result = harness.process(replace(novelty(), classification=classification))
    assert (result.alert is not None) is expected


@pytest.mark.parametrize("classification", [Behavior.ELEVATED_UNCONFIRMED, Behavior.ELEVATED_CONFIRMED])
def test_frequency_retains_confirmation_semantics(harness, classification):
    output = replace(deviations()[0], classification=classification)
    e = normalize(output)
    assert e.result_code == classification.value and e.rule_id == "observed_appearance_frequency"
    result = harness.process(output)
    assert result.alert.severity == ("medium" if classification is Behavior.ELEVATED_CONFIRMED else "low")


def test_diversity_overflow_and_polling_limitations():
    output = replace(deviations()[1], current_other_destinations=1, capacity_loss=True, gap_seen=True)
    e = normalize(output)
    assert EvidenceLimitation.CAPACITY_LOSS in e.quality.limitations
    assert EvidenceLimitation.MONITORING_GAP in e.quality.limitations
    assert e.reason_code == output.reason.value
    assert e.role is EvidenceRole.LIMITATION


@pytest.mark.parametrize("intervals,poll,classification", [
    ((60.0,) * 6, 1.0, PeriodicityClassification.PERIODIC_CANDIDATE),
    ((10.0,) * 6, 5.0, PeriodicityClassification.RESOLUTION_LIMITED),
    ((60.0,), 1.0, PeriodicityClassification.INSUFFICIENT_DATA),
])
def test_periodicity_classification_and_qualifiers(harness, intervals, poll, classification):
    output = periodic(intervals=intervals, poll=poll)
    assert output.classification is classification
    e = normalize(output)
    assert e.result_code == classification.value
    for limitation in output.limitations:
        assert EvidenceLimitation(limitation.value) in e.quality.limitations
    result = harness.process(output)
    assert (result.alert is not None) is (classification is PeriodicityClassification.PERIODIC_CANDIDATE)


def test_four_detectors_one_batch_uses_scorer_correlation(harness):
    outputs = (novelty(), *deviations(), periodic())
    result = harness.process(*outputs)
    snapshot = result.assessment.revision.snapshot
    assert len(snapshot.evidence) == 4 and len(snapshot.contributors) == 5
    # Novelty (20) supersedes unconfirmed frequency (15), periodicity (15) minus schedule (3).
    assert snapshot.score == 32 and result.alert.occurrence_count == 1


def test_assessment_failure_stops_alert_and_intent(harness, monkeypatch):
    monkeypatch.setattr(harness.assessments, "save", lambda *args: (_ for _ in ()).throw(AssessmentPersistenceError("sanitized")))
    result = harness.process()
    assert result.status is RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED
    assert not harness.intents and harness.alerts.query(AlertQuery(10)) == ()


def test_alert_failure_then_restart_retry_is_idempotent(harness, monkeypatch):
    monkeypatch.setattr(harness.alerts, "record", lambda *args: (_ for _ in ()).throw(AlertRepositoryError("sanitized")))
    result = harness.process()
    assert result.status is RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED
    assert result.assessment.revision.revision == 1 and not harness.intents
    restarted = Harness(harness.database.path)
    assert restarted.alerts.query(AlertQuery(10)) == ()
    retried = restarted.process()
    assert not retried.assessment.created and retried.alert.occurrence_count == 1
    assert restarted.process().alert == retried.alert


def test_dispatch_subscriber_failure_cannot_undo_commits(harness):
    def fail(_):
        raise RuntimeError("sensitive subscriber detail")
    harness.dispatcher.subscribe(AlertNotificationIntent, fail)
    result = harness.process()
    assert result.dispatch.failed == 1
    assert harness.alerts.get(result.alert.id) == result.alert
    assert harness.process().dispatch is None


def test_normalization_failure_is_typed_and_empty(harness):
    result = harness.process(object())
    assert result.status is RiskAlertStatus.NORMALIZATION_FAILED
    assert result.assessment is result.alert is None and not harness.intents


@pytest.mark.parametrize("freshness", [Freshness.UNKNOWN, Freshness.STALE, Freshness.EXPIRED])
def test_noncurrent_findings_do_not_create_alert(harness, freshness):
    assert harness.process(freshness=freshness).status is RiskAlertStatus.NO_ALERT


@pytest.mark.parametrize("quality", [ObservationQuality.REDUCED, ObservationQuality.FAILED])
def test_quality_does_not_invent_high_confidence(harness, quality):
    result = harness.process(novelty(quality=quality))
    assert result.alert is None or (result.alert.severity == "low" and result.alert.confidence == "low")


@pytest.mark.parametrize("address", ["203.0.113.2", "2001:db8::2"])
def test_ipv4_ipv6_do_not_enter_arp_ip_field(harness, address):
    result = harness.process(novelty(address=address), occurrence=key(address=address))
    assert result.alert.evidence[-1].ip_address is None
    assert result.assessment.revision.snapshot.evidence[0].subject.ip_address == address


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_unknown_ambiguous_typed_storage_without_fake_network(harness, status):
    occurrence = key(scope=EvidenceScope(EvidenceScopeKind.UNKNOWN, status))
    output = replace(novelty(), scope=replace(SCOPE, network_status=status, network_token=f"session:{SESSION}"))
    # Synthetic recognized finding tests the additive generic storage surface.
    result = harness.process(output, occurrence=occurrence)
    assert result.alert.network_fingerprint is None
    assert result.alert.evidence[-1].assessment.network_status is status
    assert harness.alerts.get(result.alert.id) == result.alert
    assert harness.process(output, occurrence=occurrence).alert.occurrence_count == 1
    assert risk_alert_fingerprint(replace(occurrence, subject=replace(occurrence.subject, session_id=UUID(int=2)))) != result.alert.fingerprint


def test_fingerprint_excludes_revision_policy_score_and_occurrence(harness):
    first = harness.process()
    changed = harness.process(replace(deviations()[0], classification=Behavior.ELEVATED_CONFIRMED))
    assert first.alert.fingerprint == changed.alert.fingerprint
    assert risk_alert_fingerprint(key(index=2, stamp=NOW + timedelta(days=1))) == first.alert.fingerprint
    result = score_risk(RiskScoringInput(RiskEvidenceBatch((normalize(novelty()),)),
        (EvidenceFreshness(normalize(novelty()).evidence_id, Freshness.CURRENT),)), RiskScoringPolicy())
    assert alert_eligible(result)
    # NS-077 supports only v1. A stored historical future policy is a new NS-078 revision,
    # and the alert identity function accepts no scoring-policy input.
    assert risk_alert_fingerprint(key()) == first.alert.fingerprint


@pytest.mark.parametrize("change", ["application", "network", "destination", "revision"])
def test_semantic_scope_changes_fingerprint(change):
    original = key()
    if change == "application":
        altered = key(application=replace(APP, key=r"winpath:v1:c:\apps\other.exe"))
    elif change == "network":
        altered = key(scope=replace(original.scope, network_fingerprint="b" * 64))
    elif change == "destination":
        altered = key(address="2001:db8::1")
    else:
        altered = key(revision=ApplicationRevision("b" * 64, ExecutableHashStatus.AVAILABLE))
    assert risk_alert_fingerprint(original) != risk_alert_fingerprint(altered)


def test_concurrent_same_signal_allocates_one_revision_occurrence(harness):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: harness.process(), range(8)))
    assert sum(result.assessment.created for result in results) == 1
    assert {result.alert.occurrence_count for result in results} == {1}
    assert len(harness.intents) == 1


def test_migrations_001_015_unchanged_and_legacy_row_survives_016(tmp_path):
    # LF-normalized original main hashes also work in shallow CI checkouts.
    originals = {'001_initial.sql': '8a36cda5baf00b7bbb60251eb274f19673c8545d73449e69c060fb322292b0bc', '002_history_retention_indexes.sql': '12828999a74be19d4a03fe2461e1355fde8bcba177de924d584db13914163c44', '003_devices.sql': '8fd10cd4e34a9265be7ff19058f8c205e6007a9cbbc051b5740f6e79dba5a178', '004_gateway_baselines.sql': '76ca23d0d9fde2e137b2515432c1ce5397cc1633316f50b6d1e244c482f4750c', '005_alerts.sql': 'eb15ba956b1ebff1277377550d9ec3b9782c6c6ddf0fbc2ea80fc7f51a385ea8', '006_dns_history.sql': '43adeed083488a1c3313931d53da818b8f02acd62bd204424b36e99e60f72b85', '007_device_profiles.sql': '1818720330d7454f41656c3e7018b44beb53f5885eb53172229b1358d3286f19', '008_vlan_summaries.sql': '02d7c2a8a07d758e2d0a528d2450bb311eadef4c01681b3ced1aeb3043226b26', '009_vlan_verification.sql': '70f37de7f8c8920878b6dc5a7a1f1540d17b7d45ea6d1672f5b6a8f87ece3764', '010_process_metadata.sql': '87dfd0a282ea427f46830f3ec353a0b63756bd1ce934b9fad33a2a9e1c93a26d', '011_history_observation_gaps.sql': '0bc6895ed29c26ae3128e624bcb17f8d1d3a09c0a7322930ae3705f8217ce107', '012_dns_association_evidence.sql': '0fd3ba15230f794eea8b6ddefa03df73a392c8efeb5ed29922687caf2a708926', '013_connection_network_scope.sql': '7d34dd3d71a25f0dffada72185a62926786790e884248d62bec31de067c2bb9a', '014_behavior_baselines.sql': '36109f45a87ecd28d68366d74c2dfef665528ed46fd1855d5e0cb21b9a0b498b', '015_risk_assessments.sql': '30cdec4b3aae4fc5e6c54f55316a217e2b7bbdd3b91523639879a4d661165d52'}
    schema = Path("src/netsentinel/infrastructure/sqlite/schema")
    for name, digest in originals.items():
        assert sha256((schema / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() == digest
    path = tmp_path / "legacy.sqlite3"
    from tests.integration.sqlite.test_alert_repository import assessment
    old_database = SQLiteDatabase(path, migration_runner=MigrationRunner(builtin_migrations()[:15]))
    service = AlertService(SQLiteAlertRepository(old_database), clock=lambda: NOW)
    old_alert, _ = service.record(assessment())
    old_alert = service.resolve(old_alert.id)
    connection = SQLiteConnectionFactory(path).connect()
    try:
        assert MigrationRunner(builtin_migrations()[:15]).migrate(connection) == 15
        before = tuple(connection.execute("SELECT * FROM alerts").fetchone())
        assert MigrationRunner(builtin_migrations()).migrate(connection) == 20
        assert tuple(connection.execute("SELECT * FROM alerts").fetchone()) == before
    finally:
        connection.close()
    upgraded = AlertService(SQLiteAlertRepository(SQLiteDatabase(path)), clock=lambda: NOW)
    assert upgraded.record(assessment()) == (old_alert, False)


def test_scoring_failure_does_not_persist(harness, monkeypatch):
    monkeypatch.setattr("netsentinel.application.services.risk_alerts.score_risk",
        lambda *args: (_ for _ in ()).throw(ValueError("unsupported policy")))
    result = harness.process()
    assert result.status is RiskAlertStatus.SCORING_FAILED and result.assessment is result.alert is None
    assert harness.assessments.latest(key().assessment_id).status is AssessmentReadStatus.NOT_FOUND


def test_duplicate_or_mismatched_normalization_is_typed(harness):
    assert harness.process(novelty(), novelty()).status is RiskAlertStatus.NORMALIZATION_FAILED
    assert harness.process(novelty(), occurrence=key(address="2001:db8::1")).status is RiskAlertStatus.NORMALIZATION_FAILED
    assert harness.process(novelty(), occurrence=key(application=replace(APP,
        key=r"winpath:v1:c:\apps\other.exe"))).status is RiskAlertStatus.NORMALIZATION_FAILED


@pytest.mark.parametrize("delta", [0, -1])
def test_equal_or_older_observation_retains_legacy_watermark(harness, delta):
    first = harness.process()
    stamp = NOW + timedelta(seconds=delta)
    result = harness.process(novelty(stamp=stamp), occurrence=key(index=2, stamp=stamp))
    assert result.alert == first.alert and result.alert.occurrence_count == 1
    assert len(harness.intents) == 1


def test_reassessment_failure_retry_keeps_status_occurrence(harness, monkeypatch):
    first = harness.process()
    harness.alert_service.resolve(first.alert.id)
    original = harness.alerts.record
    monkeypatch.setattr(harness.alerts, "record", lambda *args: (_ for _ in ()).throw(AlertRepositoryError("sanitized")))
    changed = replace(deviations()[0], classification=Behavior.ELEVATED_CONFIRMED)
    failed = harness.process(changed, intent=AlertWriteIntent.REASSESSMENT)
    assert failed.status is RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED
    assert failed.assessment.revision.revision == 2
    monkeypatch.setattr(harness.alerts, "record", original)
    retried = harness.process(changed, intent=AlertWriteIntent.REASSESSMENT)
    assert not retried.assessment.created and retried.alert.status is AlertStatus.RESOLVED
    assert retried.alert.occurrence_count == 1 and retried.alert.last_seen == NOW
    assert len(harness.intents) == 1


def test_policy_revision_pointer_does_not_change_alert_fingerprint(harness):
    first = harness.process()
    snapshot = first.assessment.revision.snapshot
    historical_policy = replace(snapshot, policy_version=2,
        contributors=tuple(replace(c, policy_version=2) for c in snapshot.contributors))
    saved = harness.assessments.save(key(), historical_policy, NOW)
    assert saved.revision.revision == 2
    reference = AlertAssessmentReference(key().assessment_id, 2, NetworkScopeStatus.RESOLVED)
    candidate = AlertCandidate(risk_alert_fingerprint(key()), "connection_behavior", "a" * 64,
        first.alert.entity_id, "low", "low", AlertEvidence(NOW, assessment=reference))
    revised, notify = harness.alert_service.update_assessment(candidate)
    assert revised.fingerprint == first.alert.fingerprint and revised.occurrence_count == 1
    assert not notify and revised.evidence[-1].assessment.revision == 2


def test_unknown_application_pid_reuse_is_conservative():
    from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationIdentityQuality, ApplicationIdentityEvidence
    unknown = ApplicationIdentity(ApplicationIdentityQuality.UNKNOWN, None,
                                  ApplicationIdentityEvidence.NONE, ProcessInfoStatus.UNAVAILABLE)
    one = key(application=unknown, process=ProcessIdentity(12, NOW))
    two = key(application=unknown, process=ProcessIdentity(12, NOW + timedelta(seconds=1)))
    assert risk_alert_fingerprint(one) != risk_alert_fingerprint(two)
    pid_only = key(application=unknown, process=ProcessIdentity(12, None))
    assert risk_alert_fingerprint(pid_only) != risk_alert_fingerprint(replace(pid_only,
        observation_reference=replace(pid_only.observation_reference, value=UUID(int=2))))


@pytest.mark.parametrize("revision", [0, True, 2**63])
def test_invalid_assessment_reference_rejected(revision):
    with pytest.raises(ValueError):
        AlertAssessmentReference("a" * 64, revision, NetworkScopeStatus.UNKNOWN)


def test_corrupt_persisted_risk_reference_is_typed(harness):
    from netsentinel.application.ports import AlertDataCorrupt
    first = harness.process()
    with harness.database.connection() as connection:
        connection.execute("UPDATE alerts SET evidence_json = replace(evidence_json, '\"revision\":1', '\"revision\":0')")
    with pytest.raises(AlertDataCorrupt):
        harness.alerts.get(first.alert.id)


def test_real_alert_transaction_failure_rolls_back_and_retry_completes(harness):
    with harness.database.connection() as connection:
        connection.execute("CREATE TRIGGER reject_risk_alert BEFORE INSERT ON alerts BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    failed = harness.process()
    assert failed.status is RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED
    assert failed.assessment.revision.revision == 1
    assert harness.alerts.query(AlertQuery(10)) == () and not harness.intents
    with harness.database.connection() as connection:
        connection.execute("DROP TRIGGER reject_risk_alert")
    retried = harness.process()
    assert not retried.assessment.created and retried.alert.occurrence_count == 1


@pytest.mark.parametrize("stage", ["assessment", "alert"])
def test_unexpected_adapter_failures_are_sanitized(harness, monkeypatch, stage):
    def fail(*args):
        raise RuntimeError("private adapter detail")
    monkeypatch.setattr(harness.assessments if stage == "assessment" else harness.alerts,
                        "save" if stage == "assessment" else "record", fail)
    result = harness.process()
    assert result.status is (RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED if stage == "assessment"
                            else RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED)
    assert "private" not in repr(result) and not harness.intents
