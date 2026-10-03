"""NS-075 portable application read model and exact command boundary."""

from dataclasses import replace

import pytest

from netsentinel.application.services.baseline_detail import BaselineDetailService, baseline_detail_request
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.behavior_baseline import BaselineLoad, BaselineStorageState
from netsentinel.domain.behavior_features import BehaviorAccumulatorSnapshot
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkScopeStatus, NetworkAttributionMethod,
    ProcessInfo, ProcessInfoStatus, ProcessIdentity, ObservationQuality,
)
from netsentinel.domain.executable_hash import ExecutableHashStatus
from tests.integration.sqlite.test_behavior_baselines import make_service, key, features, NOW


def selected(*, name="browser", path=r"C:\Apps\browser.exe", network="a" * 64):
    process = ProcessInfo(identity=ProcessIdentity(1, NOW), name=name, status=ProcessInfoStatus.AVAILABLE, executable_path=path)
    scope = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, network, "eth", 1, NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
    return baseline_detail_request(process, scope, "203.0.113.1")


@pytest.mark.parametrize("revision", [None, "b" * 64, "c" * 64])
def test_read_model_keeps_known_and_unknown_revision_exact(revision):
    baselines, _, _, _ = make_service()
    baselines.restore(BaselineLoad(()))
    for digest in (None, "b" * 64, "c" * 64):
        baselines.observe((features(key(revision=digest), samples=1 if digest is None else 5),), NOW, ObservationQuality.COMPLETE)
    value = selected()
    value = replace(value, application=replace(value.application, revision=ApplicationRevision(revision, ExecutableHashStatus.AVAILABLE if revision else None)))
    result = BaselineDetailService(baselines, BehaviorFeatureAccumulator()).lookup(value)
    assert result.scope == key(revision=revision)
    assert f"Observed connection appearances: {1 if revision is None else 5}" in result.text


@pytest.mark.parametrize("path,network", [(r"C:\Apps\other.exe", "a" * 64), (r"C:\Apps\browser.exe", "b" * 64)])
def test_no_foreign_application_or_network_reference(path, network):
    baselines, _, _, _ = make_service()
    baselines.restore(BaselineLoad(()))
    baselines.observe((features(),), NOW, ObservationQuality.COMPLETE)
    result = BaselineDetailService(baselines, BehaviorFeatureAccumulator()).lookup(selected(path=path, network=network))
    assert "LEARNING:" in result.text
    assert "Observed connection appearances: 0" in result.text


def test_query_keeps_live_window_and_learned_reference_separate():
    baselines, _, _, _ = make_service()
    baselines.restore(BaselineLoad(()))
    baselines.observe((features(samples=100),), NOW, ObservationQuality.COMPLETE)
    class Current:
        def snapshot(self):
            return BehaviorAccumulatorSnapshot((features(samples=3, seconds=30),), 0, 0, 60, 12)
    result = BaselineDetailService(baselines, Current()).lookup(selected())
    assert "Observed connection appearances: 100" in result.text
    assert "Observed connection appearances: 3" in result.text
    assert "Monitored coverage: 30 seconds" in result.text
    assert "no current timing evidence" in result.text


def test_storage_unavailable_is_explicit_and_does_not_invent_observations():
    baselines, _, _, _ = make_service()
    baselines.restore(None)
    result = BaselineDetailService(baselines, BehaviorFeatureAccumulator()).lookup(selected())
    assert "UNAVAILABLE:" in result.text and "storage: unavailable" in result.text
    assert baselines.diagnostics().storage is BaselineStorageState.UNAVAILABLE


def test_display_context_is_bounded_without_changing_identity():
    baselines, _, _, _ = make_service()
    service = BaselineDetailService(baselines, BehaviorFeatureAccumulator())
    value = selected(name="X" * 10_000)
    assert len(value.display_name) == 256
    result = service.lookup(value)
    assert result.scope == key()
    assert len(result.context) < 5000


def test_command_uses_exact_scope_without_querying_repository():
    baselines, writer, _, _ = make_service()
    commands = []
    writer.submit = lambda value: commands.append(value) or True
    scope = key(revision="b" * 64, network="c" * 64)
    result = BaselineDetailService(baselines, BehaviorFeatureAccumulator()).reset(scope)
    assert result.accepted and not result.completion.done()
    assert commands[0].scope == scope and commands[0].reset
    assert commands[0].summary is None
