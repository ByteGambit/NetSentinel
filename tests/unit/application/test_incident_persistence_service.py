"""NS-090 application commands through a pure fake port; no database required."""

from dataclasses import replace
from datetime import timedelta

import pytest

from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.incident_persistence import (
    IncidentCommandError, IncidentPage, IncidentResult, IncidentState,
    IncidentStatus as Status, IncidentStoragePolicy,
)
from tests.fixtures.incidents import NOW, item


class FakeRepository:
    policy = IncidentStoragePolicy()

    def __init__(self):
        self.records = {}
        self.calls = 0

    def update(self, incident_id, transform, *, expected_revision=None):
        self.calls += 1
        old = self.records.get(incident_id)
        if expected_revision is not None and (old is None or old.revision != expected_revision):
            return IncidentResult(Status.CONFLICT)
        try:
            new = transform(old)
        except IncidentCommandError as error:
            return IncidentResult(error.status)
        if old == new:
            return IncidentResult(Status.NO_CHANGE, old)
        self.records[incident_id] = new
        return IncidentResult(Status.CHANGED, new)

    def get(self, incident_id):
        value = self.records.get(incident_id)
        return IncidentResult(Status.FOUND if value else Status.NOT_FOUND, value)

    def list_current(self, **kwargs):
        return IncidentPage(tuple(IncidentResult(Status.FOUND, r) for r in self.records.values()
                                  if r.snapshot.cohort == kwargs.get('cohort')))


def test_explicit_commands_work_through_port_without_sql_or_alert_service():
    fake = FakeRepository()
    service = IncidentPersistenceService(fake)
    snapshot = IncidentCorrelator().correlate(item()).incident
    created = service.create_or_get(snapshot, now=NOW).record
    assert service.acknowledge(created.incident_id, expected_revision=1, now=NOW).record.state is IncidentState.ACKNOWLEDGED
    assert service.resolve(created.incident_id, expected_revision=2, now=NOW).record.state is IncidentState.RESOLVED
    next_item = item(2, stamp=NOW + timedelta(seconds=1), evidence=item().evidence)
    reopened = service.reopen(created.incident_id, next_item, expected_revision=3, now=next_item.observed_at)
    assert reopened.record.state is IncidentState.OPEN and reopened.record.revision == 4
    assert fake.calls == 4 and len(fake.records) == 1


@pytest.mark.parametrize('method', ['create', 'append', 'ack', 'resolve', 'reopen'])
def test_non_utc_input_is_rejected_before_repository_io(method):
    fake = FakeRepository()
    service = IncidentPersistenceService(fake)
    snapshot = IncidentCorrelator().correlate(item()).incident
    bad = NOW.replace(tzinfo=None)
    with pytest.raises(ValueError):
        if method == 'create':
            service.create_or_get(snapshot, now=bad)
        elif method in ('append', 'reopen'):
            getattr(service, method)(snapshot.incident_id, item(), expected_revision=1, now=bad)
        else:
            getattr(service, 'acknowledge' if method == 'ack' else 'resolve')(snapshot.incident_id, expected_revision=1, now=bad)
    assert fake.calls == 0


def test_observe_new_seed_and_live_derived_membership():
    fake = FakeRepository()
    service = IncidentPersistenceService(fake)
    first = service.observe(item(), now=NOW)
    second = service.observe(item(2), now=NOW)
    assert second.record.incident_id == first.record.incident_id
    assert len(second.record.snapshot.relations) == 2


def test_changed_create_relation_does_not_overwrite_stable_identity():
    fake = FakeRepository()
    service = IncidentPersistenceService(fake)
    snapshot = IncidentCorrelator().correlate(item()).incident
    saved = service.create_or_get(snapshot, now=NOW)
    changed = replace(snapshot, destinations=(replace(snapshot.destinations[0], port=80),))
    assert service.create_or_get(changed, now=NOW).status is Status.IDENTITY_CONFLICT
    assert service.get(saved.record.incident_id).record == saved.record
