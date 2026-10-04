"""NS-088 offscreen explicit lookup, stored explanations and late selections."""

from concurrent.futures import Future
from dataclasses import replace
from datetime import UTC, datetime
from threading import Event
from uuid import UUID

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.risk_alerts import RiskAlertResult, RiskAlertStatus
from netsentinel.application.services.risk_worker import RiskAlertWorker
from netsentinel.application.services.risk_explanation import RiskExplanationQueryService, RiskExplanationRequest
from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.application.services.threat_intel_scheduler import (
    ThreatIntelLookupScheduler, ThreatIntelSchedulerPolicy, ThreatIntelSubmission,
    SubmissionState, LookupState,
)
from netsentinel.domain.connections import ConnectionOpened, Endpoint
from netsentinel.domain.threat_intelligence import (
    ThreatIntelResult, ThreatIntelError as E, ThreatIntelResultStatus as S,
    ThreatIntelDenial,
)
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness as F
from netsentinel.presentation.app import create_application
from netsentinel.presentation.widgets.threat_intel_lookup import ThreatIntelLookupWidget
from netsentinel.presentation.widgets.risk_explanation import RiskExplanationWidget
from netsentinel.presentation.views.main_window import PageId
from tests.fixtures.threat_intelligence import DESCRIPTORS, grant
from tests.fixtures.threat_intel_evidence import outcome, NOW
from tests.gui._ns013_support import FakeEngine, snapshot
from tests.unit.application.test_threat_intel_scheduler import Cache
from tests.integration.test_risk_alert_pipeline import Harness
from tests.integration.test_threat_intel_evidence import initial, enrich


class Scheduler:
    def __init__(self, value=None):
        self.value = value or outcome(provider="fake_provider_a")
        self.requests = []
        self.denial = None

    def submit(self, query):
        self.requests.append(query)
        return ThreatIntelSubmission(SubmissionState.REJECTED_POLICY, denial=self.denial) if self.denial else ThreatIntelSubmission(SubmissionState.ACCEPTED, self.value.ticket)

    def poll(self, ticket):
        return self.value


def consent_service():
    consent = grant()
    service = ThreatIntelConsentService(DESCRIPTORS, lambda: (consent,), lambda _: None)
    service.current()
    return service


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
@pytest.mark.parametrize("freshness", [F.FRESH, F.STALE])
def test_lookup_and_shared_historical_panel_are_plain_accessible(qtbot, tmp_path, status, freshness):
    scheduler = Scheduler(outcome(status=status, freshness=freshness))
    # One production descriptor for the provider metric rendering fixture.
    from netsentinel.infrastructure.abuseipdb import ABUSEIPDB_DESCRIPTOR
    service = ThreatIntelConsentService((ABUSEIPDB_DESCRIPTOR,), lambda: (), lambda _: None)
    widget = ThreatIntelLookupWidget(scheduler, service)
    qtbot.addWidget(widget)
    widget.select(UUID(int=1), "8.8.8.8")
    assert not scheduler.requests
    qtbot.mouseClick(widget.lookup_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: not widget._jobs)
    text = widget.result.toPlainText()
    assert status.name in text and freshness.name in text
    assert "AbuseIPDB abuse confidence score" in text and "not malware probability" in text
    assert widget.status.textFormat() is Qt.TextFormat.PlainText
    assert widget.status.accessibleName() and widget.lookup_button.accessibleName()
    assert widget.result.isReadOnly() and widget.result.accessibleName()
    if status is S.NO_HIT:
        assert "does not establish that the destination is safe" in text
    h = Harness(tmp_path / "risk.sqlite")
    original = initial(h)
    result = enrich(h, status=status, freshness=freshness)
    model = RiskExplanationQueryService(h.assessments).lookup(RiskExplanationRequest.for_alert(result.alert), now=NOW)
    panel = RiskExplanationWidget()
    qtbot.addWidget(panel)
    panel.set_model(model)
    assert "External reputation context" in panel.section_texts
    historical = panel.section_texts["External reputation context"].toPlainText()
    assert "freshness at assessment time" in historical and "current cache freshness is not inferred" in historical
    assert panel.values["Assessment revision"].text() == "2"
    assert original.assessment.revision.key.original_observed_at == result.assessment.revision.key.original_observed_at


@pytest.mark.parametrize("error", [E.TIMEOUT, E.RATE_LIMITED, E.CREDENTIAL_UNAVAILABLE, E.UNAVAILABLE, E.AUTHENTICATION])
def test_operational_status_never_shows_clean_or_safe(qtbot, error):
    scheduler = Scheduler(outcome(provider="fake_provider_a", error=error))
    widget = ThreatIntelLookupWidget(scheduler, consent_service())
    qtbot.addWidget(widget)
    widget.select(UUID(int=1), "8.8.8.8")
    widget.lookup()
    qtbot.waitUntil(lambda: not widget._jobs)
    assert error.value.replace("_", " ") in widget.result.toPlainText()
    assert "Local detection continues" in widget.result.toPlainText()
    assert "NO_HIT" not in widget.result.toPlainText()


def test_stale_refresh_failure_and_offline_are_both_visible(qtbot):
    scheduler = Scheduler(outcome(provider="fake_provider_a", freshness=F.STALE, error=E.TIMEOUT))
    widget = ThreatIntelLookupWidget(scheduler, consent_service())
    qtbot.addWidget(widget)
    widget.select(UUID(int=1), "8.8.8.8")
    widget.lookup()
    widget._poll()
    assert "STALE" in widget.result.toPlainText() and "refresh failed: timeout" in widget.result.toPlainText()
    scheduler.value = replace(outcome(provider="fake_provider_a", freshness=F.STALE), state=LookupState.OFFLINE_DEFERRED, terminal=False)
    widget.lookup()
    widget._poll()
    assert "while offline" in widget.status.text() and "STALE" in widget.result.toPlainText()
    widget.stop()
    assert not widget.timer.isActive() and not widget._jobs


@pytest.mark.parametrize("address", ["192.168.1.1", "127.0.0.1", "::1", "fe80::1", "203.0.113.1", "example.com"])
def test_ineligible_subject_has_no_scheduler_submission(qtbot, address):
    scheduler = Scheduler()
    widget = ThreatIntelLookupWidget(scheduler, consent_service())
    qtbot.addWidget(widget)
    widget.select(UUID(int=1), address)
    assert not widget.lookup_button.isEnabled()
    qtbot.mouseClick(widget.lookup_button, Qt.MouseButton.LeftButton)
    assert not scheduler.requests


def test_consent_denial_is_explicit_and_does_not_mutate_consent(qtbot):
    scheduler = Scheduler()
    scheduler.denial = ThreatIntelDenial.NO_CONSENT
    service = consent_service()
    before = service.snapshot()
    widget = ThreatIntelLookupWidget(scheduler, service)
    qtbot.addWidget(widget)
    widget.select(None, "8.8.8.8")
    widget.lookup()
    assert "enable this provider/IP type" in widget.status.text()
    assert service.snapshot() == before and not widget._jobs


@pytest.mark.parametrize("return_to_a", [False, True])
def test_late_result_targets_captured_a_without_overwriting_new_selection(qtbot, return_to_a):
    scheduler = Scheduler(replace(outcome(provider="fake_provider_a"), terminal=False))
    submitted = []
    receipts = []

    def submit(signal):
        submitted.append(signal)
        receipt = Future()
        receipts.append(receipt)
        return receipt

    widget = ThreatIntelLookupWidget(scheduler, consent_service(), submit)
    qtbot.addWidget(widget)
    widget.select(UUID(int=1), "8.8.8.8")
    widget.lookup()
    widget.select(UUID(int=2), "1.1.1.1")
    if return_to_a:
        widget.select(UUID(int=1), "8.8.8.8")
    scheduler.value = replace(scheduler.value, terminal=True)
    widget._poll()
    assert len(submitted) == 1 and submitted[0].lifecycle_id == UUID(int=1)
    assert submitted[0].context.key.subject.value == "8.8.8.8"
    receipts[0].set_result(RiskAlertResult(RiskAlertStatus.NO_ALERT))
    widget._poll()
    assert widget.result.toPlainText() == ""  # A → B → A also rejects the old epoch


def test_lookup_pending_bound_and_stop(qtbot):
    scheduler = Scheduler(replace(outcome(provider="fake_provider_a"), terminal=False))
    widget = ThreatIntelLookupWidget(scheduler, consent_service())
    qtbot.addWidget(widget)
    for index in range(9):
        widget.select(UUID(int=index + 1), "8.8.8.8")
        widget.lookup()
    assert len(widget._jobs) == 8 and len(scheduler.requests) == 8
    assert "capacity reached" in widget.status.text()
    widget.stop()
    assert not widget.timer.isActive()


def test_full_fake_scheduler_worker_revision_gui_and_nonblocking(qtbot, tmp_path):
    class Provider:
        descriptor = DESCRIPTORS[0]
        calls = 0

        def __init__(self):
            self.entered, self.release = Event(), Event()

        def query(self, query):
            self.calls += 1
            self.entered.set()
            assert self.release.wait(3)
            return ThreatIntelResult(query, S.HIT, max(datetime.now(UTC), query.queried_at))

    h = Harness(tmp_path / "full.sqlite")
    initial(h)
    provider = Provider()
    service = consent_service()
    scheduler = ThreatIntelLookupScheduler((provider,), service.snapshot, lambda: Cache(), policy=ThreatIntelSchedulerPolicy(max_attempts=1))
    worker = RiskAlertWorker(h.service, h.dispatcher)
    worker.start()
    engine = FakeEngine()
    shell = create_application(engine, argv=[], threat_intel_scheduler=scheduler, threat_intel_consent_service=service,
        threat_intel_risk_submit=worker.submit_threat_intelligence,
        risk_service_factory=lambda: RiskExplanationQueryService(h.assessments))
    qtbot.addWidget(shell.window)
    try:
        shell.window.show()
        shell.lifecycle.start()
        connection = replace(snapshot(), remote_endpoint=Endpoint("8.8.8.8", 443))
        engine.dispatcher.publish(ConnectionOpened(connection, lifecycle_id=UUID(int=1)))
        QApplication.processEvents()
        page = shell.window.page_widget(PageId.CONNECTIONS)
        page.table.selectRow(0)
        QApplication.processEvents()
        assert provider.calls == 0
        widget = page.details.threat_intel
        widget.lookup()
        qtbot.waitUntil(provider.entered.is_set)
        tick = Event()
        QTimer.singleShot(0, tick.set)
        qtbot.waitUntil(tick.is_set)
        assert not provider.release.is_set()
        provider.release.set()
        qtbot.waitUntil(lambda: "durably stored" in widget.result.toPlainText(), timeout=4000)
        assert "occurrence unchanged" in widget.result.toPlainText()
        qtbot.waitUntil(lambda: "Assessment revision" in page.details.risk.values and page.details.risk.values["Assessment revision"].text() == "2")
        assert "External reputation context" in page.details.risk.section_texts
        assert provider.calls == 1
    finally:
        provider.release.set()
        shell.lifecycle.shutdown()
        worker.stop()
    assert not widget.timer.isActive()
