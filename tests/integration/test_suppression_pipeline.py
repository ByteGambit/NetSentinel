"""NS-081 real SQLite policy reads, alert lifecycle, cooldown and owning worker."""

from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from threading import Event, current_thread
from uuid import UUID, uuid4

import pytest

from netsentinel.application.events import AlertNotificationIntent
from netsentinel.application.services.risk_alerts import BehaviorRiskSignal, RiskAlertStatus, RiskToAlertService, risk_alert_fingerprint
from netsentinel.application.services.risk_assessments import RiskAssessmentService
from netsentinel.application.services.suppression import SuppressionEvaluationService, match_context
from netsentinel.bootstrap import create_desktop_engine
from netsentinel.domain.alert_risk import AlertWriteIntent
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.preferences import (
    PreferenceDefinition, PreferenceLifetime, PreferenceLifetimeKind, PreferenceOrigin,
    PreferenceResultStatus as ReadStatus, PreferenceSelector,
)
from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceScopeKind
from netsentinel.domain.risk_scoring import Freshness
from netsentinel.domain.suppression import SuppressionDisposition as Disposition, SuppressionLimitation as Limitation
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, SQLiteConnectionFactory
from netsentinel.infrastructure.sqlite.migrations import builtin_migrations
from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
from tests.fixtures.behavior_risk import APP, NOW, SCOPE, key, novelty, periodic
from tests.fixtures.preferences import destination
from tests.integration.test_risk_alert_pipeline import Harness, normalize


class PolicyHarness(Harness):
    def __init__(self, path):
        super().__init__(path)
        self.clock = [NOW]
        self.alert_service._clock = lambda: self.clock[0]
        self.preferences = SQLiteScopedPreferenceRepository(self.database)
        self.evaluator = SuppressionEvaluationService(self.preferences)
        self.service = RiskToAlertService(RiskAssessmentService(self.assessments), self.alert_service,
                                         self.dispatcher, suppression=self.evaluator)

    def process(self, *outputs, occurrence=None, intent=AlertWriteIntent.OCCURRENCE, freshness=Freshness.CURRENT):
        return self.service.process(BehaviorRiskSignal(occurrence or key(), outputs or (novelty(),),
                                    self.clock[0], intent, freshness))

    def create(self, selector=None, *, expires_at=None, identity=None):
        d = PreferenceDefinition(selector or PreferenceSelector(rule_id="destination_ip_novelty_rarity"),
            PreferenceLifetime(PreferenceLifetimeKind.PERMANENT) if expires_at is None else
            PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expires_at), "User local preference")
        r = self.preferences.create(identity or uuid4(), d, PreferenceOrigin.MANUAL_USER, self.clock[0])
        assert r.status is ReadStatus.CREATED
        return r.preference

    def revoke(self, p):
        return self.preferences.revoke(p.preference_id, p.revision, "Explicit undo", PreferenceOrigin.MANUAL_USER, self.clock[0])

    def occurrence(self, seconds, index):
        self.clock[0] = NOW + timedelta(seconds=seconds)
        return self.process(novelty(stamp=self.clock[0]), occurrence=key(index=index, stamp=self.clock[0]))


@pytest.fixture
def harness(tmp_path):
    return PolicyHarness(tmp_path / "policy.db")


def policy_rows(db):
    with db.connection() as c:
        return {name: [tuple(r) for r in c.execute(f"SELECT * FROM {name} ORDER BY preference_id" )]
                for name in ("scoped_preferences", "scoped_preference_revisions")}


def test_no_preferences_is_unchanged_ns079_path_and_intent_after_commits(harness):
    def committed(intent):
        assert harness.alerts.get(intent.alert_id) is not None
        assert harness.assessments.latest(intent.assessment.assessment_id).revision is not None
    harness.dispatcher.subscribe(AlertNotificationIntent, committed)
    result = harness.process()
    assert result.status is RiskAlertStatus.SUCCESS and len(harness.intents) == 1
    assert result.suppression.disposition is Disposition.NOT_SUPPRESSED
    assert result.suppression.alert_eligible and result.dispatch.failed == 0


@pytest.mark.parametrize("selector", [
    PreferenceSelector(rule_id="destination_ip_novelty_rarity"), PreferenceSelector(application=APP),
    PreferenceSelector(destination=destination("203.0.113.2")), PreferenceSelector(network_fingerprint="a" * 64),
    PreferenceSelector(application=APP, destination=destination("203.0.113.2")),
    PreferenceSelector(application=APP, network_fingerprint="a" * 64),
    PreferenceSelector(application=APP, destination=destination("203.0.113.2"), network_fingerprint="a" * 64, rule_id="destination_ip_novelty_rarity"),
])
def test_full_suppression_persists_exact_assessment_without_alert_calls(harness, selector, monkeypatch):
    harness.create(selector)
    before = policy_rows(harness.database)
    def forbidden(*args):
        raise AssertionError("fully suppressed signal must not call AlertService")
    monkeypatch.setattr(harness.alert_service, "record", forbidden)
    monkeypatch.setattr(harness.alert_service, "get", forbidden)
    monkeypatch.setattr(harness.alert_service, "update_assessment", forbidden)
    result = harness.process()
    assert result.status is RiskAlertStatus.NO_ALERT
    assert result.suppression.disposition is Disposition.SUPPRESSED
    assert result.alert is result.dispatch is None and not harness.intents
    snapshot = result.assessment.revision.snapshot
    assert snapshot.score == 20 and snapshot.severity.value == "low"
    control = Harness(harness.database.path.with_name("control.db")).process().assessment.revision.snapshot
    assert snapshot == control  # Includes original evidence IDs and session/lifecycle references.
    assert result.suppression.assessment.revision == result.assessment.revision.revision
    assert harness.assessments.latest(key().assessment_id).revision.snapshot == snapshot
    assert policy_rows(harness.database) == before  # Evaluation never writes USED/usage revisions.


def test_partial_suppression_keeps_independent_positive_evidence(harness):
    harness.create()
    result = harness.process(novelty(), periodic())
    assert result.status is RiskAlertStatus.SUCCESS and len(harness.intents) == 1
    assert result.suppression.disposition is Disposition.PARTIALLY_SUPPRESSED
    assert result.assessment.revision.snapshot.score == 32  # Existing periodicity schedule mitigation stays.
    assert len(result.suppression.suppressed_evidence_ids) == len(result.suppression.unsuppressed_evidence_ids) == 1
    assert result.alert.severity == result.assessment.revision.snapshot.severity.value
    harness.create(PreferenceSelector(rule_id="observed_appearance_periodicity"))
    old = result.alert
    suppressed = harness.process(novelty(), periodic())
    assert suppressed.suppression.disposition is Disposition.SUPPRESSED
    assert harness.alerts.get(old.id) == old and len(harness.intents) == 1
    assert suppressed.assessment.revision == result.assessment.revision


@pytest.mark.parametrize("status", [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED])
def test_suppressed_new_signal_cannot_mutate_existing_lifecycle(harness, status):
    original = harness.process().alert
    if status is not AlertStatus.OPEN:
        harness.alerts.set_status(original.id, status, NOW)
    original = harness.alerts.get(original.id)
    p = harness.create()
    suppressed = harness.occurrence(240, 2)
    assert suppressed.suppression.disposition is Disposition.SUPPRESSED
    assert suppressed.assessment.revision.key.assessment_id != key().assessment_id
    assert harness.alerts.get(original.id) == original  # Includes count, last_seen, notification clock, ACK/resolve.
    assert harness.revoke(p).status is ReadStatus.REVOKED
    assert harness.alerts.get(original.id) == original and len(harness.intents) == 1
    resumed = harness.occurrence(241, 3)
    assert resumed.alert.occurrence_count == 2 and resumed.alert.last_seen == NOW + timedelta(seconds=241)
    assert resumed.alert.status is (AlertStatus.OPEN if status is AlertStatus.RESOLVED else status)
    assert resumed.alert.fingerprint == original.fingerprint
    assert len(harness.intents) == 2


def test_expiry_exact_boundary_and_no_retroactive_replay(harness):
    p = harness.create(expires_at=NOW + timedelta(seconds=60))
    first = harness.process()
    assert first.suppression.disposition is Disposition.SUPPRESSED and not harness.intents
    before = policy_rows(harness.database)
    harness.clock[0] = NOW + timedelta(seconds=60)
    assert policy_rows(harness.database) == before  # Clock advance starts no worker/timer/replay.
    assert harness.alerts.get(UUID(int=123)) is None and not harness.intents
    resumed = harness.occurrence(60, 2)
    assert resumed.suppression.disposition is Disposition.NOT_SUPPRESSED
    assert resumed.suppression.evidence[0].expired_match_count == 1
    assert resumed.alert.occurrence_count == 1 and len(harness.intents) == 1
    assert harness.preferences.get_current(p.preference_id).preference.revision == 1


def test_suppression_does_not_consume_real_notification_cooldown(harness):
    first = harness.process().alert
    genuine = harness.occurrence(30, 2)
    assert genuine.alert.occurrence_count == 2 and len(harness.intents) == 1
    assert genuine.alert.last_notified_at == first.last_notified_at == NOW
    p = harness.create()
    assert harness.occurrence(119, 3).suppression.disposition is Disposition.SUPPRESSED
    assert harness.alerts.get(first.id).last_notified_at == NOW
    assert harness.revoke(p).status is ReadStatus.REVOKED
    resumed = harness.occurrence(120, 4)
    assert resumed.alert.occurrence_count == 3 and len(harness.intents) == 2
    assert resumed.alert.last_notified_at == NOW + timedelta(seconds=120)


@pytest.mark.parametrize("status", [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED])
def test_preference_changes_and_explicit_reassessment_do_not_count_or_reopen(harness, status):
    first = harness.process().alert
    harness.alerts.set_status(first.id, status, NOW)
    p = harness.create()
    original = harness.alerts.get(first.id)
    harness.clock[0] = NOW + timedelta(seconds=1)
    assert harness.process(intent=AlertWriteIntent.REASSESSMENT).suppression.disposition is Disposition.SUPPRESSED
    assert harness.alerts.get(first.id) == original
    updated = harness.preferences.edit(p.preference_id, p.revision,
        replace(p.definition, reason="Explicit changed note"), PreferenceOrigin.MANUAL_USER, harness.clock[0])
    assert updated.status is ReadStatus.UPDATED and harness.alerts.get(first.id) == original
    assert harness.revoke(updated.preference).status is ReadStatus.REVOKED
    reassessed = harness.process(intent=AlertWriteIntent.REASSESSMENT)
    assert reassessed.alert == original and len(harness.intents) == 1
    assert risk_alert_fingerprint(key()) == first.fingerprint


def test_lookup_failure_fail_open_with_persisted_assessment(harness, monkeypatch):
    def failing(*args, **kwargs):
        raise RuntimeError("private SQLite path and user note")
    monkeypatch.setattr(harness.preferences, "find_candidates", failing)
    result = harness.process()
    assert result.status is RiskAlertStatus.SUCCESS and len(harness.intents) == 1
    assert result.suppression.disposition is Disposition.UNAVAILABLE
    assert Limitation.EVALUATION_UNAVAILABLE in result.suppression.limitations
    assert "private SQLite" not in repr(result)


def test_unconfigured_evaluator_is_explicit_unavailable_and_fail_open(tmp_path):
    result = Harness(tmp_path / "unconfigured.db").process()
    assert result.alert is not None and result.suppression.disposition is Disposition.UNAVAILABLE
    assert Limitation.EVALUATOR_NOT_CONFIGURED in result.suppression.limitations


def test_candidate_database_unavailable_is_explicit_fail_open(harness, tmp_path):
    harness.evaluator._repository = SQLiteScopedPreferenceRepository(SQLiteDatabase(tmp_path))
    result = harness.process()
    assert result.alert is not None and result.suppression.disposition is Disposition.UNAVAILABLE
    assert Limitation.LOOKUP_UNAVAILABLE in result.suppression.limitations


def test_restart_reuses_current_policy_without_replaying_old_assessments(harness):
    p = harness.create()
    first = harness.process()
    restarted = PolicyHarness(harness.database.path)
    assert not restarted.intents and restarted.preferences.get_current(p.preference_id).preference == p
    retry = restarted.process()
    assert not retry.assessment.created and retry.assessment.revision == first.assessment.revision
    assert retry.suppression.disposition is Disposition.SUPPRESSED and not restarted.intents


def test_current_evaluation_time_does_not_reuse_historical_assessment_clock(harness):
    p = harness.create(expires_at=NOW + timedelta(seconds=60))
    first = harness.process()
    harness.clock[0] = NOW + timedelta(seconds=60)
    current = harness.process(intent=AlertWriteIntent.REASSESSMENT)
    assert not current.assessment.created and current.assessment.revision == first.assessment.revision
    assert current.suppression.evaluated_at == harness.clock[0]
    assert current.suppression.disposition is Disposition.NOT_SUPPRESSED
    assert current.suppression.evidence[0].expired_match_count == 1
    assert harness.preferences.get_current(p.preference_id).preference == p


def test_incomplete_candidates_without_match_fail_open_in_pipeline(harness, monkeypatch):
    from netsentinel.domain.preferences import PreferencePage
    monkeypatch.setattr(harness.preferences, "find_candidates", lambda *args, **kwargs: PreferencePage(ReadStatus.FOUND, truncated=True))
    result = harness.process()
    assert result.alert is not None and result.suppression.disposition is Disposition.INDETERMINATE
    assert Limitation.CANDIDATES_TRUNCATED in result.suppression.limitations


def test_baseline_and_detector_state_continue_while_alerting_is_suppressed(tmp_path):
    from tests.unit.application.test_behavior_risk_runtime import connection, runtime
    from netsentinel.application.services.risk_alerts import RiskAlertResult

    engine, collector, clock, harness, worker, signals = runtime(tmp_path, spy=True)
    repo = SQLiteScopedPreferenceRepository(harness.database)
    d = PreferenceDefinition(PreferenceSelector(application=APP), PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), "Application notification preference")
    assert repo.create(uuid4(), d, PreferenceOrigin.MANUAL_USER, NOW).status is ReadStatus.CREATED
    harness.service._suppression = SuppressionEvaluationService(repo)
    done, results = Event(), []
    def received(value):
        results.append(value)
        done.set()
    harness.dispatcher.subscribe(RiskAlertResult, received)
    assert worker.start()
    try:
        collector.value = (connection(address="192.0.2.1"),)
        engine._poll_once()
        clock[:] = [NOW + timedelta(seconds=1), 1.0]
        collector.value = (connection(clock[0], address="192.0.2.1"), connection(clock[0], port=50001))
        engine._poll_once()
        assert done.wait(3)
        assert worker.stop(3)
        assert results[0].suppression.disposition is Disposition.SUPPRESSED and not harness.intents
        assert signals[0].evidence[0].destination_appearances == 0  # Pre-mutation novelty.
        assert signals[0].evidence[1].current_appearances == 1  # Post-mutation features still learn.
        assert len(signals[0].evidence) == 4  # NS-074 still observes COMPLETE timing input.
    finally:
        assert worker.stop(3)


@pytest.mark.parametrize("has_valid_match", [False, True])
def test_corrupt_current_policy_is_indeterminate_or_valid_suppression(harness, has_valid_match):
    bad = harness.create()
    if has_valid_match:
        harness.create()
    with harness.database.connection() as c:
        c.execute("UPDATE scoped_preference_revisions SET reason = 'modified outside API' WHERE preference_id = ?", (str(bad.preference_id),))
    result = harness.process()
    assert Limitation.CORRUPT_PREFERENCE in result.suppression.limitations
    assert result.suppression.disposition is (Disposition.SUPPRESSED if has_valid_match else Disposition.INDETERMINATE)
    assert bool(result.alert) is not has_valid_match


@pytest.mark.parametrize("failure", ["assessment", "alert"])
def test_failure_ordering_preserves_commit_before_intent(harness, monkeypatch, failure):
    called = []
    original = harness.evaluator.evaluate
    def evaluate(*args, **kwargs):
        called.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(harness.evaluator, "evaluate", evaluate)
    target = harness.assessments if failure == "assessment" else harness.alerts
    method = "save" if failure == "assessment" else "record"
    monkeypatch.setattr(target, method, lambda *args: (_ for _ in ()).throw(RuntimeError("private failure")))
    result = harness.process()
    assert not harness.intents
    if failure == "assessment":
        assert not called and result.assessment is result.suppression is None
        assert result.status is RiskAlertStatus.ASSESSMENT_PERSISTENCE_FAILED
    else:
        assert called and result.assessment is not None and result.suppression is not None
        assert result.status is RiskAlertStatus.ASSESSMENT_PERSISTED_ALERT_FAILED


def test_intent_subscriber_failure_is_still_isolated(harness):
    harness.dispatcher.subscribe(AlertNotificationIntent, lambda _: (_ for _ in ()).throw(RuntimeError("private")))
    result = harness.process()
    assert result.status is RiskAlertStatus.SUCCESS and result.dispatch.failed == 1 and len(harness.intents) == 1


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_unresolved_scope_and_hostwide_policy_in_real_pipeline(harness, status):
    scope = replace(SCOPE, network_status=status, network_token=f"session:{key().subject.session_id}")
    occurrence = key(scope=EvidenceScope(EvidenceScopeKind.UNKNOWN, status))
    output = replace(novelty(), scope=scope)
    harness.create(PreferenceSelector(network_fingerprint="a" * 64))
    result = harness.process(output, occurrence=occurrence)
    assert result.alert is not None and result.alert.network_fingerprint is None
    assert result.suppression.disposition is Disposition.NOT_SUPPRESSED
    harness.create(PreferenceSelector(application=APP))
    assert harness.process(output, occurrence=occurrence).suppression.disposition is Disposition.SUPPRESSED


def test_ipv6_and_exact_application_revision_in_pipeline(harness):
    revision = ApplicationRevision("b" * 64, ExecutableHashStatus.AVAILABLE)
    scope = replace(SCOPE, revision_digest=revision.digest)
    occurrence = key(address="2001:db8::1", revision=revision)
    selector = PreferenceSelector(APP, revision, destination("2001:0DB8::1"), "a" * 64)
    harness.create(selector)
    result = harness.process(novelty(address="2001:db8::1", scope=scope), occurrence=occurrence)
    assert result.suppression.disposition is Disposition.SUPPRESSED
    assert result.assessment.revision.snapshot.evidence[0].subject.ip_address == "2001:db8::1"


def test_candidate_query_filters_unrelated_rows_and_current_revisions(harness):
    p = harness.create(PreferenceSelector(rule_id="other_rule"))
    changed = harness.preferences.edit(p.preference_id, 1,
        replace(p.definition, selector=PreferenceSelector(rule_id="destination_ip_novelty_rarity")), PreferenceOrigin.MANUAL_USER, NOW)
    assert changed.status is ReadStatus.UPDATED
    for i in range(25):
        harness.create(PreferenceSelector(rule_id=f"unrelated_{i}"))
    contexts = (match_context(normalize(novelty())),)
    before = policy_rows(harness.database)
    result = harness.preferences.find_candidates(contexts, evaluated_at=NOW)
    assert len(result.entries) == 1 and result.entries[0].preference.revision == 2
    assert not result.truncated and policy_rows(harness.database) == before


def test_candidate_capacity_prioritizes_effective_policy_and_reports_truncation(harness):
    for i in range(101):
        p = harness.create(identity=UUID(int=i + 1))
        assert harness.revoke(p).status is ReadStatus.REVOKED
    active = harness.create(identity=UUID(int=999))
    result = harness.process()
    assert result.suppression.disposition is Disposition.SUPPRESSED
    assert result.suppression.evidence[0].primary.preference_id == active.preference_id
    assert Limitation.CANDIDATES_TRUNCATED in result.suppression.limitations
    assert result.suppression.evidence[0].revoked_match_count == 99


@pytest.mark.parametrize("column,value", [
    ("rule_id", "bad*"), ("application_key", "instance:v1:1:1"),
    ("destination_value", "bad"), ("network_fingerprint", "bad"),
    ("application_key", "x" * 10000), ("format_version", 2),
])
def test_malformed_selector_and_future_rows_cannot_be_silently_filtered(harness, column, value):
    p = harness.create(PreferenceSelector(application=APP, destination=destination("203.0.113.2"), network_fingerprint="a" * 64, rule_id="destination_ip_novelty_rarity"))
    with harness.database.connection() as c:
        c.execute("PRAGMA ignore_check_constraints = ON")
        c.execute(f"UPDATE scoped_preference_revisions SET {column} = ? WHERE preference_id = ?", (value, str(p.preference_id)))
    result = harness.process()
    assert result.suppression.disposition is Disposition.INDETERMINATE and result.alert is not None
    expected = Limitation.UNSUPPORTED_PREFERENCE_FORMAT if column == "format_version" else Limitation.CORRUPT_PREFERENCE
    assert expected in result.suppression.limitations


def test_missing_current_pointer_is_corrupt_candidate(harness):
    p = harness.create()
    c = SQLiteConnectionFactory(harness.database.path).connect()
    try:
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("UPDATE scoped_preferences SET last_revision = 99 WHERE preference_id = ?", (str(p.preference_id),))
    finally:
        c.close()
    assert harness.process().suppression.disposition is Disposition.INDETERMINATE


@pytest.mark.parametrize("limit", [0, 101, True])
def test_candidate_query_bounds(harness, limit):
    with pytest.raises(ValueError):
        harness.preferences.find_candidates((match_context(normalize(novelty())),), evaluated_at=NOW, limit=limit)


def test_candidate_context_and_clock_bounds(harness):
    context = match_context(normalize(novelty()))
    for contexts in ((), (context,) * 33, (None,)):
        with pytest.raises(ValueError):
            harness.preferences.find_candidates(contexts, evaluated_at=NOW)
    with pytest.raises(ValueError):
        harness.preferences.find_candidates((context,), evaluated_at=NOW.replace(tzinfo=None))


def test_production_wiring_is_dormant_and_evaluation_runs_on_existing_worker(tmp_path):
    path = tmp_path / "production.db"
    engine = create_desktop_engine(database_path=path)
    assert not path.exists()
    worker = engine.behavior_risk.worker
    service = worker._service
    assert isinstance(service._suppression, SuppressionEvaluationService)
    repo = service._suppression._repository
    d = PreferenceDefinition(PreferenceSelector(application=APP), PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), "Explicit production policy")
    assert repo.create(uuid4(), d, PreferenceOrigin.MANUAL_USER, NOW).status is ReadStatus.CREATED
    complete, received, threads = Event(), [], []
    original = repo.find_candidates
    def find(*args, **kwargs):
        threads.append(current_thread().name)
        return original(*args, **kwargs)
    repo.find_candidates = find
    from netsentinel.application.services.risk_alerts import RiskAlertResult
    def result(value):
        received.append(value)
        complete.set()
    worker._dispatcher.subscribe(RiskAlertResult, result)
    assert worker.start()
    try:
        worker.submit(BehaviorRiskSignal(key(), (novelty(),), NOW))
        assert complete.wait(3)
    finally:
        assert worker.stop(3) and engine.stop(3)
    assert received[0].suppression.disposition is Disposition.SUPPRESSED
    assert threads == ["netsentinel-risk-worker"]


def test_schema_017_immutable_after_additive_migrations(tmp_path):
    assert builtin_migrations()[-1].version == 20
    with SQLiteDatabase(tmp_path / "schema.db").connection() as c:
        assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
    data = Path("src/netsentinel/infrastructure/sqlite/schema/017_scoped_preferences.sql").read_bytes().replace(b"\r\n", b"\n")
    assert sha256(data).hexdigest() == "b830405d9c799085673bac0f5cddc2603e0a261511cb54ae4bec20a58c165281"
