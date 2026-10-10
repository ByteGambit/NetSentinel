"""Explicit selected-IP action with bounded memory polling and selection epochs."""

from netsentinel.presentation.i18n.text import display_enum

from netsentinel.presentation.i18n.text import format_text, render_join, render_text

from netsentinel.presentation.i18n.text import translate

from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QLabel, QPushButton, QVBoxLayout, QWidget

from netsentinel.presentation.widgets.page_flow import FlowTextEdit
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
        self.setAccessibleName(translate('ThreatIntelLookup', 'External reputation lookup'))
        self.provider = QComboBox(self)
        self.provider.setAccessibleName(translate('ThreatIntelLookup', 'Reputation provider'))
        for descriptor in consents.descriptors if consents else ():
            if ThreatIntelDataType.IP_REPUTATION in descriptor.supported_data_types:
                self.provider.addItem(descriptor.display_name, descriptor.provider)
        self.lookup_button = QPushButton(translate('ThreatIntelLookup', 'Check reputation'), self)
        self.lookup_button.setAccessibleName(translate('ThreatIntelLookup', 'Check selected public IP reputation explicitly'))
        self.status = QLabel(self)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setAccessibleName(translate('ThreatIntelLookup', 'Reputation lookup status'))
        self.disclaimer = QLabel(TI_DISCLAIMER, self)
        self.disclaimer.setTextFormat(Qt.TextFormat.PlainText)
        self.disclaimer.setWordWrap(True)
        self.result = FlowTextEdit(self)
        self.result.setReadOnly(True)
        self.result.setAccessibleName(translate('ThreatIntelLookup', 'External reputation context and provenance'))
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
        self.status.setText(translate('ThreatIntelLookup', 'Select an eligible public IP. No lookup has been requested.'))
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
        self.status.setText(render_text(translate('ThreatIntelLookup', 'Private/local/special IP is ineligible for external lookup.') if not eligible else translate('ThreatIntelLookup', 'Provider lookup unavailable; local detection continues.') if self._scheduler is None or not self.provider.count() else translate('ThreatIntelLookup', 'Explicit lookup sends only this selected public IP to the chosen provider. Consent is required in Threat Intelligence settings.')))

    def lookup(self) -> None:
        if self._stopped or self._selection is None or self._scheduler is None or self._consents is None:
            return
        if len(self._jobs) >= 8:
            self.status.setText(translate('ThreatIntelLookup', 'Lookup capacity reached; wait for a pending request.'))
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
            self.status.setText(translate('ThreatIntelLookup', 'Provider lookup unavailable; local detection continues.'))
            return
        if submission.ticket is None:
            self.status.setText(render_text(translate('ThreatIntelLookup', 'Reputation lookup disabled: enable this provider/IP type in Threat Intelligence settings.') if submission.denial else format_text(translate('ThreatIntelLookup', 'Lookup unavailable: {value1}. Local detection continues.'), value1=display_enum(submission.state, 'words'))))
            return
        # A coalesced ticket can serve different captured lifecycles. Same target
        # and epoch shares the one completion; no unbounded waiter list.
        if not any(j.ticket == submission.ticket and j.epoch == self._epoch and j.lifecycle == lifecycle for j in self._jobs):
            self._jobs.append(_PendingLookup(self._epoch, lifecycle, subject, submission.ticket))
        self.status.setText(translate('ThreatIntelLookup', 'Lookup queued; local detection continues.'))
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
                    note = (format_text(translate('ThreatIntelLookup', 'Assessment revision {value1} durably stored; occurrence unchanged.'), value1=integrated.assessment.revision.revision)
                        if integrated.assessment else translate('ThreatIntelLookup', 'No assessment integrated; lookup context remains available.'))
                    if integrated.status not in (RiskAlertStatus.SUCCESS, RiskAlertStatus.NO_ALERT):
                        note += format_text(translate('ThreatIntelLookup', ' Integration limitation: {value1}.'), value1=display_enum(integrated.status, 'words'))
                except Exception:
                    integrated = None
                    note = translate('ThreatIntelLookup', 'Assessment integration unavailable; lookup context remains available.')
                if self._current(job):
                    self.result.setPlainText(render_text(job.text + '\n' + note))
                    self.status.setText(render_text(note))
                    if integrated and integrated.assessment:
                        self.assessment_updated.emit()
                self._jobs.remove(job)
                continue
            outcome = self._scheduler.poll(job.ticket)
            if outcome is None:
                if self._current(job):
                    self.status.setText(translate('ThreatIntelLookup', 'Lookup ticket expired/unavailable; local detection continues.'))
                self._jobs.remove(job)
                continue
            mapping = ThreatIntelEvidenceAdapter().map(outcome, job.subject)
            state = display_enum(outcome.state, 'words')
            if outcome.state is LookupState.OFFLINE_DEFERRED:
                state = translate('ThreatIntelLookup', 'Provider lookup unavailable while offline; request deferred')
            if outcome.result and outcome.result.status is ThreatIntelResultStatus.ERROR:
                state += "; " + display_enum(outcome.result.error, 'words') if outcome.result.error else ""
            job.text = render_join('\n', context_lines(mapping.context)) if mapping.context else TI_DISCLAIMER
            job.text += format_text(translate('ThreatIntelLookup', '\nOperational status: {value1}. Local detection continues.'), value1=state)
            if self._current(job):
                self.result.setPlainText(render_text(job.text))
                self.status.setText(render_text(state))
            if outcome.terminal:
                if mapping.context and job.lifecycle and self._submit_risk:
                    try:
                        job.receipt = self._submit_risk(ThreatIntelAssessmentSignal(job.lifecycle, mapping.context, datetime.now(UTC)))
                    except Exception:
                        if self._current(job):
                            self.status.setText(translate('ThreatIntelLookup', 'Assessment integration unavailable; lookup context remains visible.'))
                        self._jobs.remove(job)
                else:
                    if self._current(job):
                        self.result.setPlainText(render_text(job.text + translate('ThreatIntelLookup', '\nCache/UI context only; no behavioral occurrence fabricated.')))
                    self._jobs.remove(job)
        if not self._jobs:
            self.timer.stop()

    def stop(self) -> None:
        self._stopped = True
        self._epoch += 1
        self.timer.stop()
        self._jobs.clear()
        self.lookup_button.setEnabled(False)
