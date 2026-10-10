"""Shared, plain-text NS-083 panel consuming only an application read model."""

from netsentinel.presentation.i18n.text import render_join, render_text

from netsentinel.presentation.i18n.text import translate
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFormLayout, QLabel, QPushButton, QScrollArea, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from netsentinel.application.services.risk_explanation import (
    RiskExplanationRequest, RiskExplanationViewModel, bounded,
)
from netsentinel.domain.risk_assessment import AssessmentReadStatus
from netsentinel.presentation.widgets.page_flow import FlowTabWidget, FlowTextEdit
from netsentinel.presentation.risk_query import RiskQueryCoordinator


class RiskExplanationWidget(QWidget):
    evidence_changed = pyqtSignal()
    def __init__(self, coordinator: RiskQueryCoordinator | None = None,
                 parent: QWidget | None = None, *, page_flow: bool = False) -> None:
        super().__init__(parent)
        self._page_flow = page_flow
        self.coordinator = coordinator
        self._request: RiskExplanationRequest | None = None
        self._generation: int | None = None
        self._pending = False
        self.setAccessibleName(translate('RiskExplanation', 'Risk explanation'))
        self.setAccessibleDescription(translate('RiskExplanation', 'Stored concern score with contributors, confidence, measurement quality, freshness, revision and preference effects'))
        self.status = QLabel(self)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setAccessibleName(translate('RiskExplanation', 'Risk explanation status'))
        self.refresh_button = QPushButton(translate('RiskExplanation', 'Refresh risk details'), self)
        self.refresh_button.setAccessibleName(translate('RiskExplanation', 'Refresh selected risk explanation'))
        self.tabs = FlowTabWidget(self) if page_flow else QTabWidget(self)
        self.tabs.setAccessibleName(translate('RiskExplanation', 'Risk explanation sections'))
        self.values: dict[str, QLabel] = {}
        self.section_texts: dict[str, QTextEdit] = {}
        layout = QVBoxLayout(self)
        layout.addWidget(self.status)
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.tabs, 1)
        self.refresh_button.clicked.connect(self.refresh)
        if coordinator is not None:
            coordinator.result_ready.connect(self._ready)
            coordinator.query_failed.connect(self._failed)
            coordinator.stopped.connect(self._stopped)
        self.clear()

    def _clear_content(self) -> None:
        self.values.clear()
        self.section_texts.clear()
        while self.tabs.count():
            widget = self.tabs.widget(0)
            self.tabs.removeTab(0)
            if widget is not None:
                widget.deleteLater()

    def clear(self, message: str = QT_TRANSLATE_NOOP('RiskExplanation', 'No selection.')) -> None:
        if self.coordinator is not None and self._request is not None:
            self.coordinator.invalidate()
        self._request = None
        self._generation = None
        self._pending = False
        self._clear_content()
        self.status.setText(render_text(message))
        self.refresh_button.setEnabled(False)

    def select(self, request: RiskExplanationRequest | None, *, empty: str = QT_TRANSLATE_NOOP('RiskExplanation', 'No risk assessment available for this connection.')) -> None:
        if request is None:
            self.clear(empty)
            return
        if request == self._request:
            return  # Live row updates never flood the query worker.
        self._request = request
        self._pending = False
        self._clear_content()
        self.refresh()

    def refresh(self) -> None:
        if self._request is None or self._pending:
            return
        self.status.setText(translate('RiskExplanation', 'Loading stored risk explanation…'))
        if self.coordinator is None:
            self.status.setText(translate('RiskExplanation', 'Risk details unavailable.'))
            return
        try:
            self._generation = self.coordinator.request(self._request)
            self._pending = True
            self.refresh_button.setEnabled(False)
        except RuntimeError:
            self.status.setText(translate('RiskExplanation', 'Risk details unavailable. Try Refresh.'))
            self.refresh_button.setEnabled(True)

    def refresh_after_commit(self) -> None:
        """Invalidate a pre-commit in-flight read; coordinator still coalesces."""
        self._pending = False
        self.refresh()

    def _ready(self, generation: int, model: object) -> None:
        if generation != self._generation or self._request is None or not isinstance(model, RiskExplanationViewModel):
            return
        self._pending = False
        self.refresh_button.setEnabled(True)
        self.set_model(model)

    def _failed(self, generation: int) -> None:
        if generation == self._generation and self._request is not None:
            self.evidence_changed.emit()
            self._pending = False
            self._clear_content()
            self.status.setText(translate('RiskExplanation', 'Risk details unavailable. Try Refresh.'))
            self.refresh_button.setEnabled(True)

    def _stopped(self) -> None:
        self.clear(translate('RiskExplanation', 'Risk query service stopped.'))

    def set_model(self, model: RiskExplanationViewModel) -> None:
        self.evidence_changed.emit()
        self._clear_content()
        self.status.setText(render_text(model.message))
        if model.status is not AssessmentReadStatus.FOUND:
            return
        summary = QWidget(self)
        form = QFormLayout(summary)
        for title, text in model.summary[:13]:
            value = QLabel(bounded(render_text(text)), summary)
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
            value.setWordWrap(True)
            value.setAccessibleName(render_text(translate('RiskExplanation', 'Risk ') + title))
            self.values[title] = value
            form.addRow(render_text(title) + ":", value)
        if self._page_flow:
            self.tabs.addTab(summary, translate('RiskExplanation', 'Summary'))
        else:
            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setWidget(summary)
            self.tabs.addTab(scroll, translate('RiskExplanation', 'Summary'))
        for section in model.sections[:8]:
            section_text = FlowTextEdit(self) if self._page_flow else QTextEdit(self)
            section_text.setReadOnly(True)
            section_text.setAccessibleName(render_text(translate('RiskExplanation', 'Risk ') + section.title))
            lines = [bounded(render_text(line)) for line in section.lines[:1536]]
            if len(section.lines) > 1536:
                lines.append(translate('RiskExplanation', 'Section display truncated.'))
            section_text.setPlainText(render_join('\n\n', lines))
            self.section_texts[section.title] = section_text
            self.tabs.addTab(section_text, render_text(section.title))
