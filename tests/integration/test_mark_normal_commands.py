"""NS-082 real storage, restart, idempotency, failures and NS-081 eligibility."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier

import pytest

from netsentinel.application.services.mark_normal import MarkNormalCommandService, BehaviorPreferenceContext
from netsentinel.application.services.preferences import ScopedPreferenceService
from netsentinel.domain.preferences import (
    PreferenceLifetime, PreferenceLifetimeKind, PreferenceResultStatus as Status,
    PreferenceStatus, PreferenceStoragePolicy, PreferenceMatchContext,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
from tests.fixtures.mark_normal import preview
from tests.fixtures.preferences import NOW, ORIGIN
from tests.integration.test_suppression_pipeline import PolicyHarness
from tests.fixtures.behavior_risk import NOW as SIGNAL_NOW, key
from netsentinel.application.services.mark_normal import preview_mark_normal, scope_choices
from netsentinel.domain.suppression import SuppressionDisposition


def service(path, policy=None):
    return MarkNormalCommandService(ScopedPreferenceService(SQLiteScopedPreferenceRepository(SQLiteDatabase(path), policy)))


def counts(path):
    with SQLiteDatabase(path).connection() as c:
        return tuple(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("scoped_preferences", "scoped_preference_revisions"))


@pytest.mark.parametrize("timed", [False, True])
def test_preview_no_write_save_restart_expiry_revoke_history(tmp_path, timed):
    path = tmp_path / "policy.db"
    commands = service(path)
    expiry = NOW + timedelta(hours=24)
    p = preview(lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expiry) if timed else None)
    assert counts(path) == (0, 0)
    result = commands.save(p, now=NOW)
    assert result.status is Status.CREATED and result.preference.revision == 1
    assert commands.save(p, now=NOW).status is Status.NO_CHANGE
    restarted = service(path)
    pref = restarted.relevant(p.context, now=NOW).entries[0].preference
    assert pref == result.preference
    assert pref.status_at(NOW) is PreferenceStatus.ACTIVE
    assert pref.definition.lifetime.expires_at == (expiry if timed else None)
    if timed:
        assert pref.status_at(expiry) is PreferenceStatus.EXPIRED
    assert restarted.revoke(pref, now=NOW + timedelta(minutes=1)).status is Status.REVOKED
    assert restarted.revoke(pref, now=NOW + timedelta(minutes=1)).status is Status.ALREADY_REVOKED
    again = service(path).relevant(p.context, now=NOW + timedelta(days=2)).entries[0].preference
    assert again.status_at(NOW + timedelta(days=2)) is PreferenceStatus.REVOKED
    assert counts(path) == (1, 2)


def test_distinct_preview_ids_same_active_definition_atomic_no_change(tmp_path):
    path = tmp_path / "policy.db"
    commands = service(path)
    p, q = preview(), preview()
    barrier = Barrier(2)

    def save(value):
        barrier.wait(timeout=5)
        return commands.save(value, now=NOW)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, (p, q)))
    assert {r.status for r in results} == {Status.CREATED, Status.NO_CHANGE}
    assert results[0].preference_id == results[1].preference_id
    assert counts(path) == (1, 1)


def test_stale_revoke_conflict_capacity_expired_preview(tmp_path):
    path = tmp_path / "policy.db"
    commands = service(path, PreferenceStoragePolicy(max_active_preferences=1))
    p = preview()
    pref = commands.save(p, now=NOW).preference
    assert commands.save(preview(reason="Different explicit decision"), now=NOW).status is Status.CAPACITY_REACHED
    repo = SQLiteScopedPreferenceRepository(SQLiteDatabase(path))
    repo.edit(pref.preference_id, pref.revision, replace(pref.definition, reason="Edited"), ORIGIN, NOW)
    assert commands.revoke(pref, now=NOW).status is Status.CONFLICT
    assert counts(path) == (1, 2)
    expired = preview(lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, NOW + timedelta(seconds=1)))
    assert commands.save(expired, now=NOW + timedelta(seconds=2)).status is Status.INVALID


def test_permission_and_unexpected_errors_sanitized(tmp_path):
    class Denied:
        def create(self, *args, **kwargs):
            raise PermissionError("secret path/reason/IP must never surface")

        def find_candidates(self, *args, **kwargs):
            raise RuntimeError("secret")

        def revoke(self, *args, **kwargs):
            raise RuntimeError("secret")

    commands = MarkNormalCommandService(ScopedPreferenceService(Denied()))
    p = preview()
    assert commands.save(p, now=NOW).status is Status.UNAVAILABLE
    assert commands.relevant(p.context, now=NOW).status is Status.UNAVAILABLE
    pref = service(tmp_path / "p.db").save(p, now=NOW).preference
    assert commands.revoke(pref, now=NOW).status is Status.UNAVAILABLE
    bad = service(tmp_path / "directory")
    (tmp_path / "directory").mkdir()
    assert bad.save(p, now=NOW).status is Status.UNAVAILABLE


def test_preference_commands_leave_all_other_stores_unchanged(tmp_path):
    from netsentinel.infrastructure.sqlite.behavior_baselines import SQLiteBaselineRepository
    from tests.integration.sqlite.test_behavior_baselines import make_service, summary

    path = tmp_path / "history.db"
    h = PolicyHarness(path)
    h.process()
    baselines, _, _, _ = make_service()
    learned = summary(baselines)
    with h.database.connection() as connection:
        SQLiteBaselineRepository(connection).write(learned, learned.features.scope)

    def other_stores():
        with h.database.connection() as connection:
            names = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            return {name: tuple(tuple(row) for row in connection.execute('SELECT * FROM "' + name + '"'))
                    for name in names if not name.startswith("scoped_preference")}

    before = other_stores()
    commands = service(path)
    p = preview()
    commands.relevant(p.context, now=NOW)
    assert other_stores() == before and counts(path) == (0, 0)
    pref = commands.save(p, now=NOW).preference
    assert other_stores() == before
    commands.revoke(pref, now=NOW)
    assert other_stores() == before


@pytest.mark.parametrize("end", ["expiry", "revoke"])
def test_saved_command_affects_future_signal_only_preserving_history(tmp_path, end):
    h = PolicyHarness(tmp_path / "pipeline.db")
    first = h.process()
    occurrence = key()
    c = BehaviorPreferenceContext(PreferenceMatchContext("destination_ip_novelty_rarity", occurrence.subject,
                                  occurrence.scope), "example", "resolved")
    lifetime = PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, SIGNAL_NOW + timedelta(seconds=600))
    p = preview_mark_normal(c, scope_choices(c)[0], lifetime, "Expected pattern", now=SIGNAL_NOW)
    commands = service(tmp_path / "pipeline.db")
    saved = commands.save(p, now=SIGNAL_NOW)
    assert saved.status is Status.CREATED
    assert h.alerts.get(first.alert.id) == first.alert
    assert h.assessments.latest(first.assessment.revision.key.assessment_id).revision == first.assessment.revision
    suppressed = h.occurrence(240, 2)
    assert suppressed.suppression.disposition is SuppressionDisposition.SUPPRESSED
    assert suppressed.assessment.revision.snapshot.score == first.assessment.revision.snapshot.score
    assert h.alerts.get(first.alert.id) == first.alert and len(h.intents) == 1
    if end == "revoke":
        assert commands.revoke(saved.preference, now=SIGNAL_NOW + timedelta(seconds=300)).status is Status.REVOKED
        resumed = h.occurrence(400, 3)
    else:
        resumed = h.occurrence(600, 3)
    assert resumed.suppression.disposition is SuppressionDisposition.NOT_SUPPRESSED
    assert resumed.alert.occurrence_count == 2  # Suppressed past occurrence was not replayed.
    assert len(h.intents) == 2


@pytest.mark.parametrize("dimension", ["rule", "app", "revision", "destination", "network"])
def test_nonmatching_scope_does_not_suppress(dimension, tmp_path):
    from netsentinel.application.services.suppression import SuppressionEvaluationService
    from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceScopeKind
    from tests.fixtures.preferences import application, revision
    from tests.fixtures.suppression import risk, REFERENCE
    from tests.fixtures.risk_assessments import evidence
    from netsentinel.domain.connections import NetworkScopeStatus

    path = tmp_path / "nonmatch.db"
    p = preview()
    service(path).save(p, now=NOW)
    subject = p.context.match.subject
    scope = p.context.match.scope
    rule = p.context.match.rule_id
    if dimension == "rule":
        rule = "observed_appearance_frequency"
    elif dimension == "app":
        subject = replace(subject, application=application(r"c:\other\browser.exe"))
    elif dimension == "revision":
        subject = replace(subject, revision=revision("c" * 64))
    elif dimension == "destination":
        subject = replace(subject, ip_address="203.0.113.11")
    else:
        scope = EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "d" * 64)
    from netsentinel.domain.risk_evidence import EvidenceSource
    e = evidence(rule_id=rule, subject=subject, scope=scope,
                 **({"source": EvidenceSource.FREQUENCY_DIVERSITY, "result_code": "elevated_confirmed"}
                    if dimension == "rule" else {}))
    evaluator = SuppressionEvaluationService(SQLiteScopedPreferenceRepository(SQLiteDatabase(path)))
    result = evaluator.evaluate(risk(e), REFERENCE, evaluated_at=NOW)
    assert result.disposition is SuppressionDisposition.NOT_SUPPRESSED
