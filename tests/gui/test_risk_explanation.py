"""NS-083 offscreen rendering, legacy coexistence, generations and shutdown."""

from dataclasses import replace
from datetime import timedelta
from threading import Event, current_thread
from time import monotonic
from uuid import UUID

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.alert_query import AlertPage
from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.application.services.suppression import evaluate_suppression
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import ConnectionOpened, ConnectionUpdated, ObservationQuality
from netsentinel.domain.risk_assessment import AssessmentRead, AssessmentReadStatus, RiskAssessmentRevision, snapshot_from_score
from netsentinel.domain.risk_evidence import EvidenceConfidence, EvidenceQuality, EvidenceRole
from netsentinel.domain.risk_scoring import Freshness
from netsentinel.presentation.app import create_application
from netsentinel.presentation.risk_query import RiskQueryCoordinator
from netsentinel.presentation.views.alerts import AlertDetailsWidget, AlertsView
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget
from tests.fixtures.risk_assessments import NOW, evidence, key, scoring, snapshot
from tests.fixtures.risk_explanations import ExplanationRepository, model
from tests.fixtures.suppression import page, periodic, preference
from tests.gui.test_alerts_view import candidate, Repository
from tests.gui.test_connections_view import FakeEngine, _snapshot
from tests.unit.domain.test_risk_scoring import legacy


def widget_text(widget):
    return "\n".join([widget.status.text(), *(v.text() for v in widget.values.values()),
                      *(v.toPlainText() for v in widget.section_texts.values())])


@pytest.mark.parametrize("confidence", [None, EvidenceConfidence.LOW, EvidenceConfidence.HIGH])
@pytest.mark.parametrize("quality", [None, ObservationQuality.COMPLETE, ObservationQuality.REDUCED, ObservationQuality.FAILED])
def test_summary_never_displays_score_alone_and_context_is_accessible(qtbot, confidence, quality):
    role = EvidenceRole.LIMITATION if quality is ObservationQuality.FAILED else EvidenceRole.FINDING
    widget = RiskExplanationWidget()
    qtbot.addWidget(widget)
    widget.set_model(model(snapshot(evidence(confidence=confidence, quality=EvidenceQuality(quality), role=role))))
    widget.show()
    for name in ("Concern score", "Score meaning", "Confidence", "Measurement quality", "Assessment revision", "Scoring policy", "Contributor context"):
        assert widget.values[name].accessibleName()
        assert widget.values[name].text()
        assert widget.values[name].textFormat() is Qt.TextFormat.PlainText
    assert "not a malware probability" in widget_text(widget)
    assert "%" not in widget.values["Concern score"].text()
    assert widget.values["Assessment revision"].text() == "3"
    assert widget.tabs.count() == 8
    assert all(text.isReadOnly() and text.accessibleName() for text in widget.section_texts.values())


@pytest.mark.parametrize("freshness", [Freshness.UNKNOWN, Freshness.STALE, Freshness.EXPIRED])
def test_offscreen_unknown_zero_and_stale_are_explicit(qtbot, freshness):
    widget = RiskExplanationWidget()
    qtbot.addWidget(widget)
    widget.set_model(model(snapshot(freshness=freshness)))
    assert widget.values["Concern score"].text() == "Unavailable / insufficient evidence"
    assert freshness.value.capitalize() in widget_text(widget)
    assert "0 / 100" not in widget_text(widget)


@pytest.mark.parametrize("mode", ["full", "partial", "none", "fail_open"])
def test_suppression_and_plain_text_read_only_context(qtbot, mode):
    from netsentinel.domain.preferences import PreferenceSelector, PreferencePage, PreferenceResultStatus
    candidates = {"full": page(preference(reason="<b>reason</b>"), preference(PreferenceSelector(rule_id=periodic().rule_id), index=2)),
        "partial": page(preference(reason="<b>reason</b>")), "none": page(),
        "fail_open": PreferencePage(PreferenceResultStatus.UNAVAILABLE)}[mode]
    value, score = scoring(evidence(), periodic())
    evaluation = evaluate_suppression(score, AlertAssessmentReference(key().assessment_id, 3, None), NOW, candidates)
    widget = RiskExplanationWidget()
    qtbot.addWidget(widget)
    widget.set_model(model(snapshot_from_score(value, score), suppression=evaluation))
    assert widget.values["Concern score"].text() == f"{score.score} / 100"
    text = widget.section_texts["Suppression and preferences"].toPlainText()
    if mode in ("full", "partial"):
        assert "<b>reason</b>" in text
        assert "Permanent" in text and "Rule:" in text
    if mode == "fail_open":
        assert "fail-open" in text
    assert "eligibility does not prove delivery" in text


def test_mixed_behavior_arp_keeps_legacy_expected_observed_confidence_breakdown(qtbot):
    stored = snapshot(evidence(), legacy(corroborated=True))
    coordinator = RiskQueryCoordinator(lambda: RiskExplanationQueryService(ExplanationRepository(
        AssessmentRead(AssessmentReadStatus.FOUND, RiskAssessmentRevision(key(), 3, NOW, stored)))))
    details = AlertDetailsWidget(risk_queries=coordinator)
    qtbot.addWidget(details)
    repo = Repository()
    original = candidate(1)
    linked = replace(original, network_fingerprint=None, evidence=replace(original.evidence, assessment=AlertAssessmentReference(key().assessment_id, 3, None)))
    alert = AlertService(repo).record(linked)[0]
    coordinator.start()
    try:
        details.set_alert(alert)
        qtbot.waitUntil(lambda: bool(details.risk.values))
        assert details.values["expected"].text() == "00:11:22:33:44:55"
        assert details.values["observed"].text() == "00:11:22:33:44:66"
        assert details.values["confidence"].text() == "low"
        assert "Correlation score: 2" in details.evidence.toPlainText()
        assert "ARP IP–MAC identity conflict" in widget_text(details.risk)
        assert "Expected MAC:" in widget_text(details.risk)
        assert "Destination novelty" in widget_text(details.risk)
    finally:
        assert coordinator.stop()


@pytest.mark.parametrize("rule", ["ip_mac_conflict", "dns_server_change", "unexpected_vlan", "broadcast_rate"])
def test_legacy_without_generic_reference_keeps_primary_details(qtbot, rule):
    repo = Repository()
    alert = AlertService(repo).record(candidate(1, rule=rule))[0]
    details = AlertDetailsWidget()
    qtbot.addWidget(details)
    details.set_alert(alert)
    assert details.values["rule"].text() == rule
    assert details.evidence.toPlainText()
    assert not details.tabs.isTabVisible(1)
    assert not details.risk.values


class MultiRepository:
    def __init__(self):
        self.started = Event()
        self.release = Event()
        self.calls = []
        self.block = True

    def for_connection(self, lifecycle):
        self.calls.append((lifecycle, current_thread().name))
        self.started.set()
        if self.block:
            self.release.wait(3)
            self.block = False
        index = lifecycle.int
        return AssessmentRead(AssessmentReadStatus.FOUND, RiskAssessmentRevision(key(index), 3, NOW, snapshot(evidence(index))))

    def revision(self, assessment_id, revision):
        index = next(i for i in (1, 2) if key(i).assessment_id == assessment_id)
        return self.for_connection(UUID(int=index))


@pytest.mark.parametrize("sequence", [(1, 2), (1, 2, 1)])
def test_generation_a_b_and_a_b_a_do_not_accept_late_initial_result(qtbot, sequence):
    repo = MultiRepository()
    coordinator = RiskQueryCoordinator(lambda: RiskExplanationQueryService(repo))
    widget = RiskExplanationWidget(coordinator)
    qtbot.addWidget(widget)
    coordinator.start()
    try:
        widget.select(RiskExplanationRequest(lifecycle_id=UUID(int=1)))
        qtbot.waitUntil(repo.started.is_set)
        for index in sequence[1:]:
            widget.select(RiskExplanationRequest(lifecycle_id=UUID(int=index)))
        repo.release.set()
        qtbot.waitUntil(lambda: bool(widget.values))
        assert f"192.0.2.{sequence[-1]}" in widget_text(widget)
        assert len(repo.calls) == 2  # The bounded latest pending slot replaces B in A→B→A.
        assert all(name == "netsentinel-risk-query" for _, name in repo.calls)
    finally:
        repo.release.set()
        assert coordinator.stop()


def test_connection_selection_lifecycle_updates_dedup_and_clear(qtbot):
    repo = MultiRepository()
    repo.block = False
    coordinator = RiskQueryCoordinator(lambda: RiskExplanationQueryService(repo))
    view = ConnectionsView(risk_queries=coordinator)
    qtbot.addWidget(view)
    first = _snapshot(remote_address="192.0.2.1")
    second = _snapshot(remote_address="192.0.2.2", local_port=5003)
    view.source_model.handle_connection_opened(ConnectionOpened(first, lifecycle_id=UUID(int=1)))
    view.source_model.handle_connection_opened(ConnectionOpened(second, lifecycle_id=UUID(int=2)))
    coordinator.start()
    try:
        view.table.selectRow(0)
        qtbot.waitUntil(lambda: bool(view.details.risk.values))
        view.source_model.handle_connection_updated(ConnectionUpdated(first, replace(first, observed_at=first.observed_at + timedelta(seconds=1)), lifecycle_id=UUID(int=1)))
        assert len(repo.calls) == 1
        view.table.selectRow(1)
        qtbot.waitUntil(lambda: "192.0.2.2" in widget_text(view.details.risk))
        assert len(repo.calls) == 2
        view.search_edit.setText("no match")
        assert not view.details.risk.values
    finally:
        assert coordinator.stop()


def test_alert_list_refresh_keeps_same_reference_without_query_storm(qtbot):
    repo = MultiRepository()
    repo.block = False
    coordinator = RiskQueryCoordinator(lambda: RiskExplanationQueryService(repo))
    view = AlertsView(risk_queries=coordinator)
    qtbot.addWidget(view)
    alerts = Repository()
    c = candidate(1)
    linked = replace(c, network_fingerprint=None, evidence=replace(c.evidence, assessment=AlertAssessmentReference(key().assessment_id, 3, None)))
    alert = AlertService(alerts).record(linked)[0]
    coordinator.start()
    try:
        view._generation = 1
        view._page_ready(1, AlertPage((alert,), 0, 50, False, False))
        view.table.selectRow(0)
        qtbot.waitUntil(lambda: bool(view.details.risk.values))
        for _ in range(10):
            view._page_ready(1, AlertPage((alert,), 0, 50, False, False))
        assert len(repo.calls) == 1
        view.details.risk.refresh()
        view.details.risk.refresh()
        qtbot.waitUntil(lambda: len(repo.calls) == 2)
    finally:
        assert coordinator.stop()


def test_shutdown_during_query_invalidates_delivery_and_deleted_widget_is_safe(qtbot):
    repo = MultiRepository()
    coordinator = RiskQueryCoordinator(lambda: RiskExplanationQueryService(repo))
    widget = RiskExplanationWidget(coordinator)
    qtbot.addWidget(widget)
    coordinator.start()
    widget.select(RiskExplanationRequest(lifecycle_id=UUID(int=1)))
    qtbot.waitUntil(repo.started.is_set)
    start = monotonic()
    assert not coordinator.stop(timeout=0.01)
    assert monotonic() - start < 0.5
    QApplication.processEvents()
    assert not widget.values
    widget.deleteLater()
    QApplication.processEvents()
    coordinator.deleteLater()
    QApplication.processEvents()
    repo.release.set()
    # A QObject deletion cannot leave an uncaught worker emission exception.
    qtbot.waitUntil(lambda: not coordinator._thread.is_alive())


def test_application_owns_both_risk_workers_and_stops_them_once(qtbot):
    engine = FakeEngine()
    shell = create_application(engine, [], risk_service_factory=lambda: RiskExplanationQueryService(ExplanationRepository()))
    qtbot.addWidget(shell.window)
    assert shell.risk_queries is not None and len(shell.risk_queries) == 2
    assert shell.lifecycle.start()
    assert all(q._thread.is_alive() for q in shell.risk_queries)
    assert shell.lifecycle.shutdown()
    assert shell.lifecycle.shutdown()
    assert all(not q._thread.is_alive() for q in shell.risk_queries)
    assert engine.stop_calls == 1


@pytest.mark.parametrize("status", [AssessmentReadStatus.NOT_FOUND, AssessmentReadStatus.CORRUPT, AssessmentReadStatus.UNSUPPORTED_VERSION])
def test_offscreen_typed_missing_states_never_keep_previous_score(qtbot, status):
    widget = RiskExplanationWidget()
    qtbot.addWidget(widget)
    widget.set_model(model())
    service = RiskExplanationQueryService(ExplanationRepository(AssessmentRead(status)))
    widget.set_model(service.lookup(RiskExplanationRequest(lifecycle_id=UUID(int=1)), now=NOW))
    assert not widget.values and widget.tabs.count() == 0
    assert widget.status.text()
