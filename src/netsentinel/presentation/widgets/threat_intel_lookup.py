"""Explicit selected-IP action with bounded memory polling and selection epochs."""

from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget

from netsentinel.application.services.risk_alerts import RiskAlertResult, RiskAlertStatus
from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.application.services.threat_intel_scheduler import (
    ThreatIntelLookupScheduler, ThreatIntelLookupTicket, LookupState,
)
from netsentinel.application.services.threat_intel_evidence import ThreatIntelEvidenceAdapter, context_lines, TI_DISCLAIMER
from netsentinel.domain.threat_intel_evidence import ThreatIntelAssessmentSignal
from netsentinel.domain.threat_intelligence import (
    ThreatIntelDataType, ThreatIntelQuery, ThreatIntelSubject, ThreatIntelSubjectKind,
    ThreatIntelTrigger, ThreatIntelResultStatus, externally_eligible,
)

ThreatIntelRiskSubmit = Callable[[ThreatIntelAssessmentSignal], Future[RiskAlertResult]]


@dataclass(slots=True)
class _PendingLookup:
    epoch: int
    lifecycle: UUID | None
    subject: ThreatIntelSubject
    ticket: ThreatIntelLookupTicket
    receipt: Future[RiskAlertResult] | None = None
    text: str = ""


class ThreatIntelLookupWidget(QWidget):
    assessment_updated = pyqtSignal()

    def __init__(self, scheduler: ThreatIntelLookupScheduler | None = None,
                 consents: ThreatIntelConsentService | None = None,
                 submit_risk: ThreatIntelRiskSubmit | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scheduler, self._consents, self._submit_risk = scheduler, consents, submit_risk
        self._epoch = 0
        self._selection: tuple[UUID | None, ThreatIntelSubject] | None = None
        self._jobs: list[_PendingLookup] = []  # 8 user actions, across selection changes
        self._stopped = False
        self.setAccessibleName("External reputation lookup")
        self.provider = QComboBox(self)
        self.provider.setAccessibleName("Reputation provider")
        for descriptor in consents.descriptors if consents else ():
            if ThreatIntelDataType.IP_REPUTATION in descriptor.supported_data_types:
                self.provider.addItem(descriptor.display_name, descriptor.provider)
        self.lookup_button = QPushButton("Check reputation", self)
        self.lookup_button.setAccessibleName("Check selected public IP reputation explicitly")
        self.status = QLabel(self)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setAccessibleName("Reputation lookup status")
        self.disclaimer = QLabel(TI_DISCLAIMER, self)
        self.disclaimer.setTextFormat(Qt.TextFormat.PlainText)
        self.disclaimer.setWordWrap(True)
        self.result = QTextEdit(self)
        self.result.setReadOnly(True)
        self.result.setAccessibleName("External reputation context and provenance")
        layout = QVBoxLayout(self)
        for widget in (self.provider, self.lookup_button, self.status, self.disclaimer, self.result):
            layout.addWidget(widget)
        self.timer = QTimer(self)
        self.timer.setInterval(200)
        self.timer.timeout.connect(self._poll)
        self.lookup_button.clicked.connect(self.lookup)
        self.clear()

    def clear(self) -> None:
        self._epoch += 1
        self._selection = None
        self.result.clear()
        self.status.setText("Select an eligible public IP. No lookup has been requested.")
        self.lookup_button.setEnabled(False)

    def select(self, lifecycle: UUID | None, address: str) -> None:
        try:
            subject = ThreatIntelSubject(ThreatIntelSubjectKind.IP, address)
        except (ValueError, TypeError):
            self.clear()
            return
        selection = (lifecycle, subject)
        if selection == self._selection:
            return
        self.clear()
        self._selection = selection
        eligible = externally_eligible(subject)
        self.lookup_button.setEnabled(eligible and self._scheduler is not None and self.provider.count() > 0 and not self._stopped)
        self.status.setText("Private/local/special IP is ineligible for external lookup." if not eligible else
            "Provider lookup unavailable; local detection continues." if self._scheduler is None or not self.provider.count() else
            "Explicit lookup sends only this selected public IP to the chosen provider. Consent is required in Threat Intelligence settings.")

    def lookup(self) -> None:
        if self._stopped or self._selection is None or self._scheduler is None or self._consents is None:
            return
        if len(self._jobs) >= 8:
            self.status.setText("Lookup capacity reached; wait for a pending request.")
            return
        lifecycle, subject = self._selection
        if not externally_eligible(subject):
            return
        provider = self.provider.currentData()
        grant = next((c for c in self._consents.snapshot() if c.provider == provider and c.data_type is ThreatIntelDataType.IP_REPUTATION), None)
        query = ThreatIntelQuery(uuid4(), provider, subject, ThreatIntelDataType.IP_REPUTATION,
            ThreatIntelTrigger.MANUAL_SELECTED, grant, datetime.now(UTC))
        try:
            submission = self._scheduler.submit(query)
        except Exception:
            self.status.setText("Provider lookup unavailable; local detection continues.")
            return
        if submission.ticket is None:
            self.status.setText("Reputation lookup disabled: enable this provider/IP type in Threat Intelligence settings." if submission.denial else
                f"Lookup unavailable: {submission.state.value.replace('_', ' ')}. Local detection continues.")
            return
        # A coalesced ticket can serve different captured lifecycles. Same target
        # and epoch shares the one completion; no unbounded waiter list.
        if not any(j.ticket == submission.ticket and j.epoch == self._epoch and j.lifecycle == lifecycle for j in self._jobs):
            self._jobs.append(_PendingLookup(self._epoch, lifecycle, subject, submission.ticket))
        self.status.setText("Lookup queued; local detection continues.")
        self.timer.start()

    def _current(self, job: _PendingLookup) -> bool:
        return job.epoch == self._epoch and self._selection == (job.lifecycle, job.subject)

    def _poll(self) -> None:
        if self._scheduler is None or self._stopped:
            return
        for job in tuple(self._jobs):
            if job.receipt is not None:
                if not job.receipt.done():
                    continue
                try:
                    integrated = job.receipt.result()
                    note = (f"Assessment revision {integrated.assessment.revision.revision} durably stored; occurrence unchanged."
                        if integrated.assessment else "No assessment integrated; lookup context remains available.")
                    if integrated.status not in (RiskAlertStatus.SUCCESS, RiskAlertStatus.NO_ALERT):
                        note += f" Integration limitation: {integrated.status.value.replace('_', ' ')}."
                except Exception:
                    integrated = None
                    note = "Assessment integration unavailable; lookup context remains available."
                if self._current(job):
                    self.result.setPlainText(job.text + "\n" + note)
                    self.status.setText(note)
                    if integrated and integrated.assessment:
                        self.assessment_updated.emit()
                self._jobs.remove(job)
                continue
            outcome = self._scheduler.poll(job.ticket)
            if outcome is None:
                if self._current(job):
                    self.status.setText("Lookup ticket expired/unavailable; local detection continues.")
                self._jobs.remove(job)
                continue
            mapping = ThreatIntelEvidenceAdapter().map(outcome, job.subject)
            state = outcome.state.value.replace('_', ' ')
            if outcome.state is LookupState.OFFLINE_DEFERRED:
                state = "Provider lookup unavailable while offline; request deferred"
            if outcome.result and outcome.result.status is ThreatIntelResultStatus.ERROR:
                state += "; " + outcome.result.error.value.replace('_', ' ') if outcome.result.error else ""
            job.text = "\n".join(context_lines(mapping.context)) if mapping.context else TI_DISCLAIMER
            job.text += f"\nOperational status: {state}. Local detection continues."
            if self._current(job):
                self.result.setPlainText(job.text)
                self.status.setText(state)
            if outcome.terminal:
                if mapping.context and job.lifecycle and self._submit_risk:
                    try:
                        job.receipt = self._submit_risk(ThreatIntelAssessmentSignal(job.lifecycle, mapping.context, datetime.now(UTC)))
                    except Exception:
                        if self._current(job):
                            self.status.setText("Assessment integration unavailable; lookup context remains visible.")
                        self._jobs.remove(job)
                else:
                    if self._current(job):
                        self.result.setPlainText(job.text + "\nCache/UI context only; no behavioral occurrence fabricated.")
                    self._jobs.remove(job)
        if not self._jobs:
            self.timer.stop()

    def stop(self) -> None:
        self._stopped = True
        self._epoch += 1
        self.timer.stop()
        self._jobs.clear()
        self.lookup_button.setEnabled(False)
