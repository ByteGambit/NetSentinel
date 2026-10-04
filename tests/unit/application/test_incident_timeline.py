"""NS-091 deterministic typed mapping, paging, absence and read-only semantics."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from netsentinel.application.services.incident_timeline import (
    TimelineRequest, TimelineStatus, TimelineKind, IncidentTimelineQueryService, map_snapshot, SOURCE_TEXT,
)
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.incident_persistence import (
    IncidentAction, IncidentHistory, IncidentOrigin, IncidentReferenceState, IncidentRevision,
    IncidentSourceStatus as Source, IncidentStatus as Status,
)
from netsentinel.domain.incidents import IncidentRelationReason as Reason
from netsentinel.domain.risk_assessment import AssessmentRead, AssessmentReadStatus, RiskAssessmentRevision
from tests.fixtures.incident_timeline import story
from tests.fixtures.incidents import NOW, item
from tests.fixtures.risk_assessments import key, snapshot
from tests.integration.sqlite.test_incident_persistence import linked


def all_pages(query, incident_id, limit):
    cursor, entries = None, []
    while True:
        page = query.lookup(TimelineRequest(incident_id, cursor=cursor, limit=limit))
        assert page.status is TimelineStatus.FOUND
        entries.extend(page.entries)
        cursor = page.next_cursor
        if cursor is None:
            return entries


@pytest.mark.parametrize("limit", [1, 2, 3, 7, 25, 100])
def test_long_timeline_pages_are_complete_unique_and_sorted(tmp_path, limit):
    db, writer, record, repository, query = story(tmp_path, 128 if limit == 100 else 32)
    entries = all_pages(query, record.incident_id, limit)
    assert len(entries) == (256 if limit == 100 else 64)
    assert len({e.entry_id for e in entries}) == len(entries)
    assert entries == sorted(entries, key=lambda e: e.sort_key)
    assert all(e.primary_time.tzinfo is not None for e in entries)
    assert entries == all_pages(IncidentTimelineQueryService(repository), record.incident_id, limit)


def bundle_with_assessment(tmp_path):
    db, writer, record, repository, query = story(tmp_path)
    ref = AlertAssessmentReference(key(original_observed_at=NOW).assessment_id, 1, None)
    # Keep the persisted incident contract consistent while using a fake read boundary for exact mapping tests.
    record = writer.append(record.incident_id, linked(stamp=NOW, assessment=ref, scope=key().scope, connection=record.snapshot.connections[0]), now=NOW + timedelta(seconds=2)).record
    bundle = repository.read_snapshot(record.incident_id)
    assessed = RiskAssessmentRevision(key(original_observed_at=NOW), 1, NOW + timedelta(hours=1), snapshot())
    return bundle, ref, assessed


def test_assessment_observation_action_and_persistence_clocks_are_distinct(tmp_path):
    bundle, ref, assessed = bundle_with_assessment(tmp_path)
    event = IncidentRevision(bundle.incident.record.incident_id, 7, bundle.incident.record.state,
        IncidentAction.ACKNOWLEDGED, IncidentOrigin.MANUAL_USER, NOW + timedelta(hours=2), NOW, NOW)
    bundle = replace(bundle, assessments=((ref, AssessmentRead(AssessmentReadStatus.FOUND, assessed)),),
        history=IncidentHistory(Status.FOUND, (event,)))
    entries, _, _ = map_snapshot(bundle)
    e = next(e for e in entries if e.kind is TimelineKind.ASSESSMENT)
    assert e.observation_time == NOW
    assert e.assessment_time == NOW + timedelta(hours=1) == e.primary_time
    action = next(e for e in entries if e.kind is TimelineKind.USER_ACTION)
    assert action.action_time == NOW + timedelta(hours=2)
    assert action.observation_time is None
    assert action.assessment_time is None
    assert not any(e.primary_time == bundle.incident.record.updated_at for e in entries)


@pytest.mark.parametrize("source", list(Source))
def test_availability_distinct_and_retained_explanation_survives(tmp_path, source):
    bundle, ref, _ = bundle_with_assessment(tmp_path)
    bundle = replace(bundle, incident=replace(bundle.incident, references=tuple(
        IncidentReferenceState(r.link, source) for r in bundle.incident.references)))
    entries, _, context = map_snapshot(bundle)
    assert entries
    assert any(e.source_status is source for e in entries)
    assert "instance create-time (identity only)" in "\n".join(context)
    assert "Process observed" in "\n".join(context)
    assert "Process created" not in "\n".join(context)
    assert len(set(SOURCE_TEXT.values())) == len(Source)


@pytest.mark.parametrize("status", [AssessmentReadStatus.NOT_FOUND, AssessmentReadStatus.CORRUPT, AssessmentReadStatus.UNSUPPORTED_VERSION, AssessmentReadStatus.UNAVAILABLE])
def test_missing_assessment_never_assigns_assessment_time(tmp_path, status):
    bundle, ref, assessed = bundle_with_assessment(tmp_path)
    bundle = replace(bundle, assessments=((ref, AssessmentRead(status)),))
    entry = next(e for e in map_snapshot(bundle)[0] if e.kind is TimelineKind.ASSESSMENT)
    assert entry.assessment_time is None
    assert "unknown" in entry.time_semantics
    assert "unavailable" in entry.explanation


@pytest.mark.parametrize("action", list(IncidentAction))
@pytest.mark.parametrize("origin", list(IncidentOrigin))
def test_only_semantic_actions_appear_with_exact_origin_and_revision(tmp_path, action, origin):
    _, _, record, repository, _ = story(tmp_path)
    bundle = repository.read_snapshot(record.incident_id)
    event = IncidentRevision(record.incident_id, 5, record.state, action, origin, NOW, NOW, NOW)
    entries, _, _ = map_snapshot(replace(bundle, history=IncidentHistory(Status.FOUND, (event,))))
    actions = [e for e in entries if e.kind is TimelineKind.USER_ACTION]
    assert len(actions) == (action in (IncidentAction.ACKNOWLEDGED, IncidentAction.RESOLVED, IncidentAction.REOPENED))
    if actions:
        assert actions[0].action_time == NOW
        assert actions[0].revision == 5
        assert origin.value in actions[0].explanation


def test_equal_timestamp_priority_and_canonical_tie_break_across_pages(tmp_path):
    db, writer, record, repository, query = story(tmp_path, 1)
    for n in (6, 2, 4, 3, 5):
        record = writer.append(record.incident_id, item(n, stamp=NOW, connection=record.snapshot.connections[0]), now=NOW + timedelta(seconds=1)).record
    record = writer.acknowledge(record.incident_id, expected_revision=record.revision, now=NOW + timedelta(seconds=1)).record
    entries = all_pages(query, record.incident_id, 3)
    equal = [e for e in entries if e.primary_time == NOW]
    assert [e.kind for e in equal] == [TimelineKind.OBSERVATION] * 6 + [TimelineKind.INFERENCE] * 6
    assert [(e.source_kind, e.source_id) for e in equal[:6]] == sorted((e.source_kind, e.source_id) for e in equal[:6])
    assert entries == all_pages(query, record.incident_id, 1)


@pytest.mark.parametrize("change", ["revision", "source"])
def test_mid_page_changes_require_refresh(tmp_path, change):
    db, writer, record, repository, query = story(tmp_path)
    page = query.lookup(TimelineRequest(record.incident_id, limit=1))
    if change == "revision":
        writer.acknowledge(record.incident_id, expected_revision=1, now=NOW + timedelta(seconds=2))
    else:
        class Changed:
            def read_snapshot(self, incident_id):
                bundle = repository.read_snapshot(incident_id)
                return replace(bundle, incident=replace(bundle.incident, references=tuple(
                    replace(r, status=Source.AVAILABLE) for r in bundle.incident.references)))
        query = IncidentTimelineQueryService(Changed())
    result = query.lookup(TimelineRequest(record.incident_id, cursor=page.next_cursor))
    assert result.status is TimelineStatus.UPDATED
    assert not result.entries


@pytest.mark.parametrize("invalid", ["wrong_id", "negative_revision", "bad_token", "bad_key", "absent_key", "wrong_type"])
def test_invalid_cursor_is_typed(tmp_path, invalid):
    _, _, record, _, query = story(tmp_path)
    cursor = query.lookup(TimelineRequest(record.incident_id, limit=1)).next_cursor
    changes = {"wrong_id": {"incident_id": UUID(int=999)}, "negative_revision": {"incident_revision": -1},
        "bad_token": {"token": "bad"}, "bad_key": {"after": (None,)},
        "absent_key": {"after": (NOW, 0, "absent", "absent", 0, "absent")}}
    cursor = "untrusted" if invalid == "wrong_type" else replace(cursor, **changes[invalid])
    result = query.lookup(TimelineRequest(record.incident_id, cursor=cursor))
    assert result.status is TimelineStatus.INVALID_CURSOR


@pytest.mark.parametrize("limit", [0, -1, 101, 10000, True, 1.5])
def test_page_size_hard_bound(limit):
    with pytest.raises(ValueError):
        TimelineRequest(limit=limit)


def test_history_pruning_and_failure_are_context_not_fake_events(tmp_path):
    _, _, record, repository, _ = story(tmp_path)
    bundle = repository.read_snapshot(record.incident_id)
    entries, limitations, _ = map_snapshot(replace(bundle, history=IncidentHistory(Status.CORRUPT, truncated=True)))
    assert len(entries) == 6
    assert "incomplete" in " ".join(limitations)
    assert "corrupt" in " ".join(limitations)


def test_no_same_ip_reason_or_creation_language_and_all_reasons_mapped():
    from netsentinel.application.services.incident_timeline import REASONS
    assert set(REASONS) == set(Reason)
    assert "Same IP" not in " ".join(REASONS.values())
    assert "Process created" not in " ".join(REASONS.values())


def test_safe_failure_and_unknown_incident(tmp_path):
    _, _, _, _, query = story(tmp_path)
    assert query.lookup(TimelineRequest(UUID(int=999))).status is TimelineStatus.UNAVAILABLE
    class Broken:
        def read_snapshot(self, _):
            raise RuntimeError("SELECT secret/path/token")
        def list_summaries(self, **kwargs):
            raise RuntimeError("SELECT secret/path/token")
    query = IncidentTimelineQueryService(Broken())
    assert "secret" not in query.lookup(TimelineRequest(UUID(int=1))).message
    assert query.lookup(TimelineRequest()).entries[0].status is Status.UNAVAILABLE


def test_all_four_kinds_at_same_timestamp_have_frozen_total_order(tmp_path):
    bundle, ref, assessed = bundle_with_assessment(tmp_path)
    event = IncidentRevision(bundle.incident.record.incident_id, 7, bundle.incident.record.state,
        IncidentAction.ACKNOWLEDGED, IncidentOrigin.MANUAL_USER, NOW, NOW, NOW)
    bundle = replace(bundle, assessments=((ref, AssessmentRead(AssessmentReadStatus.FOUND, replace(assessed, assessed_at=NOW))),),
        history=IncidentHistory(Status.FOUND, (event,)))
    entries = [e for e in map_snapshot(bundle)[0] if e.primary_time == NOW]
    assert [e.kind for e in entries] == [TimelineKind.OBSERVATION] * 2 + [TimelineKind.INFERENCE] * 2 + [TimelineKind.ASSESSMENT, TimelineKind.USER_ACTION]
    assert entries == sorted(entries, key=lambda e: e.sort_key)


@pytest.mark.parametrize("kind,value", [("ipv4", "8.8.8.8"), ("ipv6", "2001:db8::1"), ("domain", "example.test")])
def test_destination_types_stay_distinct_without_current_lookup(tmp_path, kind, value):
    from netsentinel.domain.incidents import IncidentDestination, IncidentDestinationKind
    from netsentinel.application.services.incidents import IncidentCorrelator
    _, writer, _, repository, _ = story(tmp_path)
    candidate = item(destination=IncidentDestination(IncidentDestinationKind(kind), value))
    record = writer.create_or_get(IncidentCorrelator().correlate(candidate).incident, now=NOW).record
    context = map_snapshot(repository.read_snapshot(record.incident_id))[2]
    assert f"Destination context ({kind}): {value}" in "\n".join(context)


@pytest.mark.parametrize("observation_kind", ["connection_observed", "connection_updated", "connection_not_observed"])
def test_polling_initial_update_and_disappearance_wording_is_honest(tmp_path, observation_kind):
    from netsentinel.domain.incidents import IncidentObservationRef, IncidentObservationKind, IncidentConnectionRef
    from netsentinel.application.services.incidents import IncidentCorrelator
    _, writer, base, repository, _ = story(tmp_path)
    connection = IncidentConnectionRef(base.snapshot.connections[0].session_id, UUID(int=99))
    candidate = replace(item(connection=connection), observation=IncidentObservationRef(
        IncidentObservationKind(observation_kind), connection, NOW))
    record = writer.create_or_get(IncidentCorrelator().correlate(candidate).incident, now=NOW).record
    entries = map_snapshot(repository.read_snapshot(record.incident_id))[0]
    text = " ".join(e.title + " " + e.explanation for e in entries)
    assert "observed" in text or "observation" in text
    assert "created" not in text and "definitely opened" not in text
