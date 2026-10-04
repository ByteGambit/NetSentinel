"""NS-090 closed formats, canonical identity and central bounds."""

from dataclasses import replace
from datetime import timedelta, timezone
import json
from uuid import UUID

import pytest

from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.incidents import IncidentPolicy, IncidentRelationReason
from netsentinel.domain.incident_persistence import (
    IncidentAction, IncidentOrigin, IncidentRecord, IncidentState, IncidentStoragePolicy,
    canonical_incident_json, stable_incident_id, validate_incident,
)
from netsentinel.infrastructure.sqlite.incident_codec import decode_incident, source_links
from tests.fixtures.incidents import NOW, item


def record():
    snapshot = IncidentCorrelator().correlate(item()).incident
    return IncidentRecord(replace(snapshot, incident_id=stable_incident_id(snapshot)), 1,
        IncidentState.OPEN, NOW, NOW, IncidentAction.CREATED, IncidentOrigin.SYSTEM_CORRELATION)


@pytest.mark.parametrize("field,maximum", [("max_incidents", 1024), ("max_revisions", 32),
    ("max_links", 320), ("max_query", 100), ("max_hydration", 256), ("cleanup_chunk", 16)])
@pytest.mark.parametrize("bad", [0, -1, True, "1", None, "over"])
def test_storage_hard_bounds(field, maximum, bad):
    with pytest.raises((ValueError, TypeError)):
        IncidentStoragePolicy(**{field: maximum + 1 if bad == "over" else bad})


@pytest.mark.parametrize("value", [timedelta(0), timedelta(minutes=11), 300, None])
def test_reopen_horizon_bounds(value):
    with pytest.raises((ValueError, TypeError)):
        IncidentStoragePolicy(reopen_horizon=value)


def test_closed_codec_roundtrip_and_link_sizes():
    value = record()
    assert decode_incident(canonical_incident_json(value)) == value
    links = source_links(value.snapshot)
    assert len(links) == 6 and all(len(r.payload.encode('utf-8')) <= 2048 for r in links)
    assert len({(r.kind, r.identity) for r in links}) == len(links)


@pytest.mark.parametrize("damage", ["unknown", "missing", "bool_number", "naive", "local", "bad_uuid",
    "enum", "duplicate", "nan", "oversize", "collection", "unknown_ref", "bad_range", "policy", "missing_source"])
def test_codec_rejects_malformed_closed_payloads(damage):
    data = json.loads(canonical_incident_json(record()))
    if damage == "unknown":
        data['details'] = {'secret': 'x'}
    elif damage == "missing":
        del data['state']
    elif damage == "bool_number":
        data['revision'] = True
    elif damage in ("naive", "local"):
        data['updated_at'] = '2026-10-04T10:00:00' + ('+03:00' if damage == 'local' else '')
    elif damage == "bad_uuid":
        data['snapshot']['incident_id'] = 'x' * 36
    elif damage == "enum":
        data['state'] = 'arbitrary'
    elif damage == "collection":
        data['snapshot']['evidence'] *= 129
    elif damage == "unknown_ref":
        data['snapshot']['evidence'][0]['kind'] = 'payload'
    elif damage == "bad_range":
        data['snapshot']['last_observed_at'] = '2026-10-04T10:10:00.000000+00:00'
    elif damage == "policy":
        data['correlation_policy']['window'] = 600_000_001
    elif damage == "missing_source":
        data['snapshot']['evidence'] = []
    payload = json.dumps(data)
    if damage == 'duplicate':
        payload = payload[:-1] + ',"state":"open"}'
    elif damage == 'nan':
        payload = payload.replace('"revision": 1', '"revision": NaN')
    elif damage == 'oversize':
        payload = ' ' * 131073
    with pytest.raises((ValueError, TypeError, KeyError)):
        decode_incident(payload)


def test_stable_identity_preserves_seed_across_out_of_order_append():
    correlator = IncidentCorrelator()
    seed = correlator.correlate(item(stamp=NOW + timedelta(minutes=2))).incident
    appended = correlator.correlate(item(2, stamp=NOW + timedelta(minutes=1))).incident
    assert appended.incident_id == seed.incident_id
    assert appended.relations[0].reason is not IncidentRelationReason.FIRST_OBSERVATION
    assert stable_incident_id(seed) == stable_incident_id(appended)
    different = IncidentCorrelator().correlate(item(3)).incident
    assert stable_incident_id(different) != stable_incident_id(seed)


@pytest.mark.parametrize("field,value", [("revision", 0), ("revision", True), ("revision", 2**63),
    ("format_version", 2), ("correlation_version", 2), ("state", 'open'),
    ("action", 'created'), ("origin", 'user'), ("updated_at", NOW - timedelta(seconds=1)),
    ("updated_at", NOW.replace(tzinfo=None)), ("updated_at", NOW.replace(tzinfo=timezone(timedelta(hours=3))))])
def test_record_validation(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(record(), **{field: value})


def test_hydration_is_bounded_atomic_and_has_no_event_effect():
    snapshot = record().snapshot
    correlator = IncidentCorrelator()
    correlator.hydrate((snapshot,))
    assert correlator.diagnostics().new_incidents == correlator.diagnostics().attachments == 0
    assert correlator.snapshot()[0].relations == snapshot.relations
    with pytest.raises(ValueError):
        correlator.hydrate((snapshot,))
    fresh = IncidentCorrelator(IncidentPolicy(max_incidents=1))
    with pytest.raises(ValueError):
        fresh.hydrate((snapshot, replace(snapshot, incident_id=UUID(int=2))))
    assert fresh.snapshot() == ()


def test_snapshot_validation_rejects_empty_or_duplicate_relations():
    snapshot = record().snapshot
    with pytest.raises(ValueError):
        validate_incident(replace(snapshot, relations=()), IncidentPolicy())
    with pytest.raises(ValueError):
        validate_incident(replace(snapshot, relations=snapshot.relations * 2), IncidentPolicy())
