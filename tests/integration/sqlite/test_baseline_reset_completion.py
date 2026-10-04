"""NS-075 exact-scope durable completion over NS-071's sole writer."""

from dataclasses import replace

import pytest

from netsentinel.application.services.behavior_baseline import (
    BaselineCommand, BaselineWriter, BehaviorBaselineService, BaselineResetResult,
)
from netsentinel.domain.behavior_baseline import BaselineState
from netsentinel.domain.connections import ObservationQuality
from netsentinel.infrastructure.sqlite.behavior_baselines import SQLiteBaselineRepository, baseline_repository_session
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.shared.config import BehaviorBaselineConfig
from tests.integration.sqlite.test_behavior_baselines import (
    make_service, start_loaded, key, summary, features, NOW, MemoryRepository,
)


def test_sqlite_reset_completion_is_exact_application_network_revision_and_idempotent(tmp_path):
    database = SQLiteDatabase(tmp_path / "baseline.db")
    config = BehaviorBaselineConfig()
    writer = BaselineWriter(lambda: baseline_repository_session(database, config))
    service = BehaviorBaselineService(writer, clock=lambda: NOW)
    scopes = (key(), key(app="other"), key(network="b" * 64), key(revision="c" * 64), key(revision="d" * 64))
    with database.connection() as connection:
        repo = SQLiteBaselineRepository(connection, config)
        for scope in scopes:
            repo.write(summary(service, scope), scope)
    start_loaded(service, writer)
    try:
        for scope in (scopes[0], scopes[3]):
            submission = service.reset_with_result(scope)
            assert submission.accepted
            assert submission.completion.result(timeout=5) is BaselineResetResult.COMPLETED
            assert service.snapshot(scope).state is BaselineState.LEARNING
            again = service.reset_with_result(scope)
            assert again.completion.result(timeout=5) is BaselineResetResult.COMPLETED
        with database.connection() as connection:
            remaining = {item.scope for item in SQLiteBaselineRepository(connection).load(128).records}
            assert remaining == {scopes[1], scopes[2], scopes[4]}
            assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 18
    finally:
        assert service.stop()


@pytest.mark.parametrize("fail", [False, True])
def test_reset_receipt_waits_for_writer_and_failure_is_typed(fail):
    repo = MemoryRepository()
    repo.block = True
    repo.fail = fail
    service, writer, _, _ = make_service(repo)
    start_loaded(service, writer)
    try:
        submitted = service.reset_with_result(key())
        assert submitted.accepted
        assert repo.entered.wait(2)
        assert not submitted.completion.done()
        assert service.reset_with_result(key()).completion is submitted.completion
        repo.release.set()
        assert submitted.completion.result(timeout=5) is (BaselineResetResult.FAILED if fail else BaselineResetResult.COMPLETED)
    finally:
        repo.release.set()
        assert service.stop()


def test_rejected_reset_changes_no_learning_or_dirty_state():
    service, _, _, _ = make_service()
    from netsentinel.domain.behavior_baseline import BaselineLoad
    service.restore(BaselineLoad(()))
    service.observe((features(),), NOW, ObservationQuality.COMPLETE)
    before = service.snapshot(key())
    dirty = service.diagnostics().dirty_scopes
    result = service.reset_with_result(key())
    assert not result.accepted and result.completion.result() is BaselineResetResult.UNAVAILABLE
    assert service.snapshot(key()) == before
    assert service.diagnostics().dirty_scopes == dirty
    assert service.diagnostics().resets == 0


def test_completion_tracks_coalesced_reset_even_with_newer_learning():
    service, writer, _, _ = make_service()
    from netsentinel.domain.behavior_baseline import BaselineLoad
    service.restore(BaselineLoad(()))
    commands = []
    writer.submit = lambda command: commands.append(command) or True
    submitted = service.reset_with_result(key())
    service.observe((features(samples=1, seconds=1),), NOW, ObservationQuality.COMPLETE)
    service.checkpoint(force=True)
    coalesced = replace(commands[-1], reset=True)
    assert coalesced.sequence > commands[0].sequence
    service._acknowledge(coalesced, True)
    assert submitted.completion.result() is BaselineResetResult.COMPLETED


def test_older_reset_ack_cannot_complete_newer_reset_receipt():
    service, writer, _, _ = make_service()
    writer.submit = lambda _: True
    first = service.reset_with_result(key())
    old = BaselineCommand(key(), None, service._sequence, True)
    service._acknowledge(old, False)
    assert first.completion.result() is BaselineResetResult.FAILED
    second = service.reset_with_result(key())
    service._acknowledge(old, True)
    assert not second.completion.done()
    service._acknowledge(BaselineCommand(key(), None, service._sequence, True), True)
    assert second.completion.result() is BaselineResetResult.COMPLETED


def test_shutdown_with_pending_reset_is_bounded_and_does_not_claim_completion():
    repo = MemoryRepository()
    repo.block = True
    service, writer, _, _ = make_service(repo)
    start_loaded(service, writer)
    submitted = service.reset_with_result(key())
    assert repo.entered.wait(2)
    try:
        assert not service.stop(timeout=0)
        assert submitted.completion.result() is BaselineResetResult.UNAVAILABLE
    finally:
        repo.release.set()
        assert service.stop()
