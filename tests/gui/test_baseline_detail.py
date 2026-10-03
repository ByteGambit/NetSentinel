"""NS-075 offscreen scope, lifecycle, evidence and confirmed reset regression."""

from concurrent.futures import Future
from dataclasses import replace
from threading import Event, get_ident

import pytest
from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

from netsentinel.application.services.baseline_detail import (
    BaselineDetailEvidence, BaselineDetailService, feature_text,
    evidence_text, baseline_detail_request,
)
from netsentinel.application.services.behavior_baseline import BaselineResetSubmission, BaselineResetResult
from netsentinel.application.services.behavior_features import BehaviorFeatureAccumulator
from netsentinel.domain.application_identity import ApplicationRevision
from netsentinel.domain.behavior_baseline import BaselineState, BaselineLoad, BaselineRead
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkScopeStatus, NetworkAttributionMethod,
    ProcessInfo, ProcessIdentity, ProcessInfoStatus, TransportProtocol,
    ConnectionOpened, ConnectionUpdated,
    ObservationQuality,
)
from netsentinel.domain.destination_novelty import DestinationNoveltyClassification
from netsentinel.domain.frequency_diversity import BehaviorClassification
from netsentinel.domain.periodicity import PeriodicityClassification
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.presentation.baseline_query import BaselineQueryCoordinator
from netsentinel.presentation.widgets.baseline_detail import BaselineDetailWidget
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.app import create_application
from netsentinel.shared.config import BehaviorBaselineConfig
from tests.integration.sqlite.test_behavior_baselines import make_service, features, summary, key, NOW
from tests.gui.test_connections_view import _snapshot, _select, FakeEngine
from tests.unit.application.detectors.test_destination_novelty import evaluate as novelty_evaluate, snapshot as novelty_snapshot
from tests.unit.application.detectors.test_frequency_diversity import evaluate as deviation_evaluate
from tests.unit.application.detectors.test_periodicity import evidence as timing_evidence


NETWORK = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "eth", 1,
                                 NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
PROCESS = ProcessInfo(identity=ProcessIdentity(12, NOW), name="browser", status=ProcessInfoStatus.AVAILABLE,
                      executable_path=r"C:\Apps\browser.exe")


def request(process=PROCESS, network=NETWORK):
    return baseline_detail_request(process, network, "203.0.113.1", 443, TransportProtocol.TCP)


class Queries(QObject):
    result_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)
    stopped = pyqtSignal()

    def __init__(self, service):
        super().__init__()
        self.service = service
        self.generation = 0
        self.requests = []
        self.resets = []
        self.future = Future()
        self.accepted = True

    def request(self, value):
        self.generation += 1
        self.requests.append((self.generation, value))
        return self.generation

    def invalidate(self):
        self.generation += 1

    def deliver(self, index=-1):
        generation, value = self.requests[index]
        self.result_ready.emit(generation, self.service.lookup(value))

    def reset(self, scope):
        self.resets.append(scope)
        return BaselineResetSubmission(self.accepted, self.future)


def panel(qtbot, service=None):
    baselines, _, _, _ = make_service()
    baselines.restore(BaselineLoad(()))
    service = service or BaselineDetailService(baselines, BehaviorFeatureAccumulator())
    queries = Queries(service)
    widget = BaselineDetailWidget(queries)
    qtbot.addWidget(widget)
    widget.show()
    widget.select(request())
    queries.deliver()
    return widget, queries, baselines


@pytest.mark.parametrize("state", list(BaselineState))
def test_all_lifecycle_states_visible_with_text_and_safe_explanation(qtbot, state):
    baselines, _, _, _ = make_service()
    value = None if state in (BaselineState.LEARNING, BaselineState.CORRUPT,
                             BaselineState.UNSUPPORTED_VERSION, BaselineState.POLICY_MISMATCH,
                             BaselineState.UNAVAILABLE) else summary(baselines)

    class States:
        config = BehaviorBaselineConfig()

        def snapshot(self, scope):
            from netsentinel.domain.behavior_baseline import BaselineSnapshot, BaselineOrigin, BaselineStorageState
            return BaselineSnapshot(scope, state, BaselineOrigin.NEW, BaselineStorageState.AVAILABLE, value)

    widget, _, _ = panel(qtbot, BaselineDetailService(States(), BehaviorFeatureAccumulator()))
    assert state.name + ":" in widget.text.text()
    if state is BaselineState.READY:
        assert "not a safety verdict" in widget.text.text()
    if state is BaselineState.CLOCK_ANOMALY:
        assert "clock changes" in widget.text.text()
    assert widget.text.textFormat() is Qt.TextFormat.PlainText


@pytest.mark.parametrize("samples,seconds,loss,state", [
    (0, 0, False, BaselineState.LEARNING), (5, 100, False, BaselineState.INSUFFICIENT_DATA),
    (20, 600, False, BaselineState.READY), (20, 600, True, BaselineState.INSUFFICIENT_QUALITY),
])
def test_real_learning_progress_uses_policy_and_monitored_coverage(qtbot, samples, seconds, loss, state):
    baselines, _, _, _ = make_service()
    baselines.restore(BaselineLoad((BaselineRead(key(), state, summary(baselines, samples=samples, seconds=seconds, loss=loss)),)))
    widget, _, _ = panel(qtbot, BaselineDetailService(baselines, BehaviorFeatureAccumulator()))
    text = widget.text.text()
    assert state.name in text
    assert f"Warm-up appearances: {samples} / 20" in text
    assert f"monitored coverage: {seconds:g} / 600" in text
    assert "Observed connection appearances" in text
    if loss:
        assert "Capacity loss / overflow" in text


def test_custom_policy_thresholds_and_runtime_reference_separation(qtbot):
    baselines, _, _, _ = make_service(config=BehaviorBaselineConfig(minimum_samples=7, minimum_monitored_seconds=77))
    baselines.restore(BaselineLoad(()))
    widget, _, _ = panel(qtbot, BaselineDetailService(baselines, BehaviorFeatureAccumulator()))
    text = widget.text.text()
    assert "0 / 7" in text and "0 / 77 seconds" in text
    assert "Current observation window (memory only; separate" in text
    assert "No current window observations" in text
    assert "no current timing evidence; insufficient observations" in text
    assert "separate from user trust/preferences" in text


@pytest.mark.parametrize("network", [ConnectionNetworkScope.unknown(), ConnectionNetworkScope.ambiguous()])
def test_unknown_network_never_borrows_resolved_baseline(qtbot, network):
    widget, queries, baselines = panel(qtbot)
    before = baselines.diagnostics()
    widget.select(request(network=network))
    queries.deliver()
    assert "no persistent baseline" in widget.text.text()
    assert not widget.reset_button.isEnabled()
    assert baselines.diagnostics() == before


@pytest.mark.parametrize("identity", [ProcessIdentity(12, NOW), ProcessIdentity(12)])
def test_provisional_unknown_identity_is_not_a_persistent_baseline(qtbot, identity):
    widget, queries, _ = panel(qtbot)
    widget.select(request(ProcessInfo(identity=identity, name="browser", status=ProcessInfoStatus.AVAILABLE)))
    queries.deliver()
    assert "no persistent baseline" in widget.text.text()
    assert not widget.reset_button.isEnabled()


@pytest.mark.parametrize("digest", [None, "b" * 64])
def test_revision_and_untrusted_application_context_are_plain_text(qtbot, digest):
    widget, queries, _ = panel(qtbot)
    value = request(replace(PROCESS, name="<b>browser</b>"))
    value = replace(value, application=replace(value.application,
                    revision=ApplicationRevision(digest, ExecutableHashStatus.AVAILABLE if digest else None)))
    widget.select(value)
    queries.deliver()
    assert "<b>browser</b>" in widget.text.text()
    assert ("SHA-256 " + digest if digest else "Unknown artifact revision") in widget.text.text()
    assert "a" * 64 in widget.text.text()
    assert widget.text.textFormat() is Qt.TextFormat.PlainText


def test_retained_feature_preview_has_hard_bound_and_deterministic_order():
    from netsentinel.domain.behavior_features import FeatureCount
    values = tuple(FeatureCount(f"203.0.113.{i}", 1) for i in range(1, 65))
    f = replace(features(), destinations=values, destination_diversity=64,
                ports=(FeatureCount(443, 1), FeatureCount(80, 1)), port_diversity=2,
                other_destinations=2, capacity_loss=True)
    forward = feature_text(f)
    assert feature_text(replace(f, destinations=tuple(reversed(values)), ports=tuple(reversed(f.ports)))) == forward
    preview = next(line for line in forward.splitlines() if line.startswith("Retained destinations"))
    assert preview.count("(1)") == 8
    assert "ports: 2; preview: 80, 443" in forward
    assert "Retained protocols: 1; TCP" in forward
    assert "not an exact total" in forward


@pytest.mark.parametrize("classification", list(DestinationNoveltyClassification))
def test_novelty_classifications_keep_retained_observation_semantics(classification):
    value = replace(novelty_evaluate(novelty_snapshot()), classification=classification, destination_ip="203.0.113.1")
    text = evidence_text(BaselineDetailEvidence(novelty=value), request())
    assert classification.name in text
    assert "retained scoped baseline" in text
    assert "Retained destination appearances" in text


@pytest.mark.parametrize("classification", list(BehaviorClassification))
def test_frequency_diversity_classifications_are_measurements(classification):
    values = tuple(replace(e, classification=classification) for e in deviation_evaluate())
    text = evidence_text(BaselineDetailEvidence(deviations=values), request())
    assert ("Within observed reference range" if classification is BehaviorClassification.NORMAL else classification.name) in text
    assert "Observed appearance rate" in text
    assert "Retained destination diversity" in text
    assert "Current/reference appearances per monitored minute" in text


@pytest.mark.parametrize("classification", list(PeriodicityClassification))
def test_periodicity_is_polling_context_including_regular_updaters(classification):
    value = replace(timing_evidence((60,) * 6), classification=classification)
    process = replace(PROCESS, executable_path=r"C:\Apps\updater.exe")
    value_request = replace(request(process), remote_ip="203.0.113.7")
    text = evidence_text(BaselineDetailEvidence(periodicity=value), value_request)
    assert classification.name in text
    assert "does not prove an exact application timer" in text
    assert "Scheduled updaters" in text
    assert "beacon" not in text.lower() and "c2" not in text.lower()


def test_foreign_evidence_and_other_periodicity_port_are_not_borrowed():
    value = timing_evidence((60,) * 6)
    assert "no current timing evidence" in evidence_text(BaselineDetailEvidence(periodicity=value), request())
    value_request = replace(request(replace(PROCESS, executable_path=r"C:\Apps\updater.exe")), remote_ip="203.0.113.7", remote_port=80)
    assert "no current timing evidence" in evidence_text(BaselineDetailEvidence(periodicity=value), value_request)


def test_cancel_confirmation_sends_no_command_and_mutates_no_baseline(qtbot, monkeypatch):
    widget, queries, baselines = panel(qtbot)
    before = baselines.diagnostics()
    dialogs = []
    def cancel(dialog):
        dialogs.append(dialog)
        assert dialog.textFormat() is Qt.TextFormat.PlainText
        assert "winpath:v1:c:\\apps\\browser.exe" in dialog.text()
        assert "a" * 64 in dialog.text()
        assert "Unknown artifact revision" in dialog.text()
        assert "does not block" in dialog.text() and "connection history" in dialog.text()
        return QMessageBox.StandardButton.Cancel
    monkeypatch.setattr(QMessageBox, "exec", cancel)
    qtbot.mouseClick(widget.reset_button, Qt.MouseButton.LeftButton)
    assert dialogs and not queries.resets
    assert baselines.diagnostics() == before
    assert not widget.status.text()


@pytest.mark.parametrize("result", list(BaselineResetResult))
def test_reset_acceptance_is_not_durable_completion_and_result_refreshes(qtbot, monkeypatch, result):
    widget, queries, _ = panel(qtbot)
    monkeypatch.setattr(QMessageBox, "exec", lambda _: QMessageBox.StandardButton.Yes)
    qtbot.mouseClick(widget.reset_button, Qt.MouseButton.LeftButton)
    assert queries.resets == [request().scope]
    assert "waiting for durable" in widget.status.text()
    assert "completed" not in widget.status.text()
    assert not widget.reset_button.isEnabled()
    queries.future.set_result(result)
    widget._poll_reset()
    assert len(queries.requests) == 2
    queries.deliver()
    if result is BaselineResetResult.COMPLETED:
        assert "completed in local storage" in widget.status.text()
    else:
        assert "not confirmed" in widget.status.text()


def test_real_keyboard_cancel_and_confirmation_are_accessible(qtbot):
    widget, queries, _ = panel(qtbot)
    def dismiss():
        dialog = widget.findChild(QMessageBox)
        assert dialog is not None
        assert dialog.accessibleName()
        qtbot.keyClick(dialog, Qt.Key.Key_Escape)
    from PyQt6.QtCore import QTimer
    QTimer.singleShot(0, dismiss)
    widget.reset_button.setFocus()
    qtbot.keyClick(widget.reset_button, Qt.Key.Key_Space)
    assert not queries.resets
    assert widget.reset_button.accessibleName() and widget.reset_button.accessibleDescription()
    assert widget.refresh_button.accessibleName() and widget.text.accessibleName()


def test_rapid_selection_a_b_a_discards_late_results_and_clear(qtbot):
    widget, queries, _ = panel(qtbot)
    first = request()
    other = request(replace(PROCESS, executable_path=r"C:\Apps\other.exe"))
    widget.select(other)
    widget.select(first)
    for index in (0, 1):
        queries.deliver(index)
        assert widget.text.text() == "Loading observed behavior baseline…"
    queries.deliver()
    assert "browser" in widget.text.text()
    widget.clear()
    queries.deliver()
    assert widget.text.text() == "No connection selected."


def test_model_refresh_keeps_selection_and_deduplicates_queries(qtbot):
    baselines, _, _, _ = make_service()
    queries = Queries(BaselineDetailService(baselines, BehaviorFeatureAccumulator()))
    view = ConnectionsView(baseline_queries=queries)
    qtbot.addWidget(view)
    value = replace(_snapshot(process=PROCESS), network_scope=NETWORK)
    view.source_model.handle_connection_opened(ConnectionOpened(value))
    _select(view, 0)
    selected = view.selected_row_id
    queries.deliver()
    for _ in range(100):
        view.source_model.handle_connection_updated(ConnectionUpdated(value, replace(value, process=replace(PROCESS, name="browser"))))
        view._restore_selected_row()
    assert view.selected_row_id == selected
    assert len(queries.requests) == 1
    assert view.details.tabs.tabText(1) == "Behavior baseline"


def test_worker_coalesces_queries_keeps_io_off_gui_and_shutdown_bounded(qtbot):
    entered, release = Event(), Event()
    main_thread = get_ident()
    threads, calls = [], []
    baselines, _, _, _ = make_service()
    service = BaselineDetailService(baselines, BehaviorFeatureAccumulator())
    def lookup(value):
        threads.append(get_ident())
        calls.append(value)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
        return service.lookup(value)
    class Blocking:
        pass
    source = Blocking()
    source.lookup = lookup
    coordinator = BaselineQueryCoordinator(lambda: source)
    delivered = []
    coordinator.result_ready.connect(lambda gen, value: delivered.append((gen, value, get_ident())))
    assert coordinator.start()
    try:
        coordinator.request(request())
        assert entered.wait(2)
        other = request(replace(PROCESS, executable_path=r"C:\Apps\other.exe"))
        for _ in range(100):
            newest = coordinator.request(other)
        assert coordinator._queue.qsize() == 1
        release.set()
        qtbot.waitUntil(lambda: len(delivered) == 1)
        assert delivered[0][0] == newest
        assert delivered[0][1].request == other
        assert delivered[0][2] == main_thread
        assert all(t != main_thread for t in threads) and len(calls) == 2
    finally:
        release.set()
        assert coordinator.stop()
    with pytest.raises(RuntimeError):
        coordinator.request(request())


def test_shutdown_with_active_query_suppresses_late_delivery(qtbot):
    entered, release = Event(), Event()
    class Blocking:
        def lookup(self, value):
            entered.set()
            assert release.wait(5)
            return value
    coordinator = BaselineQueryCoordinator(Blocking)
    delivered = []
    coordinator.result_ready.connect(lambda *args: delivered.append(args))
    coordinator.start()
    coordinator.request(request())
    assert entered.wait(2)
    try:
        assert not coordinator.stop(timeout=0)
    finally:
        release.set()
        assert coordinator.stop()
    assert not delivered


def test_query_failure_is_sanitized_and_lifecycle_owns_worker(qtbot):
    def unavailable():
        raise OSError("private SQLite/path details")
    shell = create_application(FakeEngine(), argv=[], baseline_service_factory=unavailable)
    qtbot.addWidget(shell.window)
    assert shell.lifecycle.start()
    try:
        widget = shell.window._pages[next(page for page in shell.window._pages if page.value == "connections")].details.baseline
        widget.select(request())
        qtbot.waitUntil(lambda: widget.text.text().startswith("UNAVAILABLE:"))
        assert "private" not in widget.text.text()
    finally:
        assert shell.lifecycle.shutdown()
    assert not shell.baseline_queries._thread.is_alive()


def test_evidence_absence_does_not_offer_risk_trust_alert_or_cloud_actions(qtbot):
    widget, _, _ = panel(qtbot)
    text = widget.text.text().lower()
    assert "no evidence available yet" in text
    for forbidden in ("risk score", "mark normal", "malware", "beacon", "c2", "connection creation rate"):
        assert forbidden not in text


def test_real_writer_reset_success_removes_ready_reference_and_refreshes(qtbot, monkeypatch):
    from tests.integration.sqlite.test_behavior_baselines import start_loaded, MemoryRepository
    repo = MemoryRepository()
    repo.block = True
    baselines, writer, _, _ = make_service(repo)
    start_loaded(baselines, writer)
    baselines.observe((features(),), NOW, ObservationQuality.COMPLETE)
    coordinator = BaselineQueryCoordinator(lambda: BaselineDetailService(baselines, BehaviorFeatureAccumulator()))
    widget = BaselineDetailWidget(coordinator)
    qtbot.addWidget(widget)
    widget.show()
    coordinator.start()
    widget.select(request())
    try:
        qtbot.waitUntil(lambda: "READY:" in widget.text.text())
        monkeypatch.setattr(QMessageBox, "exec", lambda _: QMessageBox.StandardButton.Yes)
        qtbot.mouseClick(widget.reset_button, Qt.MouseButton.LeftButton)
        assert repo.entered.wait(2)
        assert "waiting for durable" in widget.status.text()
        repo.release.set()
        qtbot.waitUntil(lambda: "completed in local storage" in widget.status.text())
        qtbot.waitUntil(lambda: "LEARNING:" in widget.text.text())
        assert "READY:" not in widget.text.text()
        assert "Warm-up appearances: 0 / 20" in widget.text.text()
    finally:
        repo.release.set()
        assert coordinator.stop()
        assert baselines.stop()
    assert widget.text.text() == "No connection selected."
    assert not widget._refresh_timer.isActive() and not widget._completion_timer.isActive()
