"""Exact retained revisions, lifecycle isolation and no detail-open writes."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.risk_assessment import AssessmentReadStatus, AssessmentStoragePolicy
from netsentinel.domain.preferences import PreferenceDefinition, PreferenceSelector, PreferenceLifetime, PreferenceLifetimeKind, PreferenceOrigin
from netsentinel.domain.risk_scoring import Freshness
from netsentinel.infrastructure.sqlite.assessment_repository import SQLiteAssessmentRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.preference_repository import SQLiteScopedPreferenceRepository
from tests.fixtures.risk_assessments import NOW, evidence, key, snapshot
from tests.fixtures.risk_explanations import all_text


@pytest.fixture
def store(tmp_path):
    database = SQLiteDatabase(tmp_path / "risk.sqlite3")
    repo = SQLiteAssessmentRepository(database)
    repo.save(key(), snapshot(), NOW)
    return database, repo


def test_alert_exact_vs_connection_latest_after_restart(store):
    database, repo = store
    changed = snapshot(evidence(reason_code="changed_result"), freshness=Freshness.STALE)
    repo.save(key(), changed, NOW + timedelta(hours=1))
    repo = SQLiteAssessmentRepository(SQLiteDatabase(database.path))
    query = RiskExplanationQueryService(repo)
    alert = query.lookup(RiskExplanationRequest(reference=AlertAssessmentReference(key().assessment_id, 1, None)), now=NOW)
    live = query.lookup(RiskExplanationRequest(lifecycle_id=UUID(int=1)), now=NOW)
    assert alert.revision == 1 and dict(alert.summary)["Concern score"] == "20 / 100"
    assert live.revision == 2 and "insufficient evidence" in dict(live.summary)["Concern score"]
    assert dict(alert.summary)["Observed at"] == dict(live.summary)["Observed at"]
    assert "Alert-linked revision" in all_text(alert)


@pytest.mark.parametrize("column,value,status", [
    ("format_version", 99, AssessmentReadStatus.UNSUPPORTED_VERSION),
    ("snapshot", "broken JSON", AssessmentReadStatus.CORRUPT),
    ("content_fingerprint", "0" * 64, AssessmentReadStatus.CORRUPT),
])
def test_corrupt_latest_never_falls_back_and_old_link_survives(store, column, value, status):
    database, repo = store
    repo.save(key(), snapshot(evidence(reason_code="revision_two")), NOW)
    with database.connection() as connection:
        connection.execute(f"UPDATE risk_assessment_revisions SET {column}=? WHERE revision=2", (value,))
        connection.commit()
    assert repo.for_connection(UUID(int=1)).status is status
    assert repo.revision(key().assessment_id, 2).status is status
    assert repo.revision(key().assessment_id, 1).status is AssessmentReadStatus.FOUND


def test_pruned_exact_revision_does_not_substitute_latest(store):
    database, _ = store
    repo = SQLiteAssessmentRepository(database, AssessmentStoragePolicy(max_revisions=1))
    repo.save(key(), snapshot(evidence(reason_code="second")), NOW)
    assert repo.revision(key().assessment_id, 1).status is AssessmentReadStatus.NOT_FOUND
    assert repo.for_connection(UUID(int=1)).revision.revision == 2


def test_canonical_lifecycle_prevents_same_destination_other_occurrence_merge(store):
    _, repo = store
    other = key(2, subject=key().subject)
    repo.save(other, snapshot(evidence(reason_code="other_occurrence")), NOW)
    assert repo.for_connection(UUID(int=1)).revision.key == key()
    assert repo.for_connection(UUID(int=2)).revision.key == other
    assert repo.for_connection(UUID(int=999)).status is AssessmentReadStatus.NOT_FOUND
    # Two assessments for one lifecycle cannot be silently conflated.
    repo.save(replace(key(), original_observed_at=NOW + timedelta(seconds=1)), snapshot(), NOW)
    assert repo.for_connection(UUID(int=1)).status is AssessmentReadStatus.CORRUPT
    with repo._database.connection() as connection:
        connection.execute("UPDATE risk_assessments SET identity_payload=?", ("[" * 1500 + "0" + "]" * 1500,))
        connection.commit()
    assert repo.for_connection(UUID(int=1)).status is AssessmentReadStatus.CORRUPT


def test_open_and_refresh_are_read_only_for_every_store_and_schema(store):
    database, repo = store
    preferences = SQLiteScopedPreferenceRepository(database)
    preferences.create(UUID(int=1), PreferenceDefinition(PreferenceSelector(rule_id=evidence().rule_id),
        PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), "<b>local</b>"), PreferenceOrigin.MANUAL_USER, NOW)
    def dump():
        with database.connection() as connection:
            return tuple(connection.iterdump())
    before = dump()
    query = RiskExplanationQueryService(repo, preferences=preferences)
    for _ in range(3):
        result = query.lookup(RiskExplanationRequest(lifecycle_id=UUID(int=1)), now=NOW)
        assert "Current preference" in all_text(result)
        assert "source" in all_text(result).lower()
    assert dump() == before  # Includes alert/lifecycle, revision, policy/audit, baseline tables.
    with database.connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20


def test_missing_database_failure_is_typed(tmp_path, monkeypatch):
    database = SQLiteDatabase(tmp_path / "failure.sqlite3")
    from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError
    monkeypatch.setattr(database, "connection", lambda: (_ for _ in ()).throw(SQLiteAdapterError("private")))
    repo = SQLiteAssessmentRepository(database)
    assert repo.for_connection(UUID(int=1)).status is AssessmentReadStatus.UNAVAILABLE
    assert repo.revision(key().assessment_id, 1).status is AssessmentReadStatus.UNAVAILABLE
