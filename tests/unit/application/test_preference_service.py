"""Explicit commands delegate through the typed storage port without evaluation."""

from uuid import UUID, uuid4

from netsentinel.application.services.preferences import ScopedPreferenceService
from netsentinel.domain.preferences import PreferencePage, PreferenceResult, PreferenceResultStatus as Status
from tests.fixtures.preferences import NOW, ORIGIN, definition


class RecordingRepository:
    def __init__(self):
        self.calls = []
        self.result = PreferenceResult(Status.UNAVAILABLE)
        self.page = PreferencePage(Status.UNAVAILABLE)

    def create(self, *args):
        self.calls.append(("create", args))
        return self.result

    def edit(self, *args):
        self.calls.append(("edit", args))
        return self.result

    def revoke(self, *args):
        self.calls.append(("revoke", args))
        return self.result

    def get_current(self, identity):
        self.calls.append(("get_current", identity))
        return self.result

    def get_history(self, identity, **kwargs):
        self.calls.append(("get_history", identity, kwargs))
        return self.page

    def list_current(self, **kwargs):
        self.calls.append(("list_current", kwargs))
        return self.page


def test_explicit_create_ids_clock_inputs_and_failure_passthrough():
    repo = RecordingRepository()
    service = ScopedPreferenceService(repo)
    assert repo.calls == []  # Construction creates no policy.
    identity, d = uuid4(), definition()
    assert service.create(d, origin=ORIGIN, now=NOW, preference_id=identity) is repo.result
    assert repo.calls[-1] == ("create", (identity, d, ORIGIN, NOW))
    service.create(d, origin=ORIGIN, now=NOW)
    assert isinstance(repo.calls[-1][1][0], UUID)
    assert service.edit(identity, d, expected_revision=1, origin=ORIGIN, now=NOW) is repo.result
    assert repo.calls[-1] == ("edit", (identity, 1, d, ORIGIN, NOW))
    assert service.revoke(identity, expected_revision=1, reason="Undo", origin=ORIGIN, now=NOW) is repo.result
    assert repo.calls[-1] == ("revoke", (identity, 1, "Undo", ORIGIN, NOW))


def test_bounded_read_arguments_pass_through():
    repo, identity = RecordingRepository(), uuid4()
    service = ScopedPreferenceService(repo)
    assert service.get_current(identity) is repo.result
    assert service.get_history(identity, limit=7, before_revision=9) is repo.page
    assert repo.calls[-1] == ("get_history", identity, {"limit": 7, "before_revision": 9})
    assert service.list_current(limit=3, after_id=identity) is repo.page
    assert repo.calls[-1] == ("list_current", {"limit": 3, "after_id": identity})
