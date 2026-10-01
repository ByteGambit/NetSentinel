"""Shared, plain-text destination evidence presentation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QGroupBox, QLabel, QVBoxLayout, QWidget

from netsentinel.application.services.destination_evidence import DestinationEvidenceResult
from netsentinel.domain.connections import NetworkScopeStatus
from netsentinel.domain.destination_context import DestinationContextStatus, DestinationDatasetSource
from netsentinel.domain.dns import (
    DnsAssociationProvenance, DnsAssociationStatus, DnsEvidenceId, DnsEvidenceSourceStatus,
    DomainAssociation,
)


MAX_VISIBLE_CANDIDATES = 32


@dataclass(frozen=True, slots=True)
class DnsCandidatePresentation:
    text: str
    evidence_id: DnsEvidenceId


@dataclass(frozen=True, slots=True)
class DestinationPresentation:
    dns_status: str
    candidates: tuple[DnsCandidatePresentation, ...]
    context_status: str
    context_details: str
    dataset_source: DestinationDatasetSource | None = None


def present_destination(result: DestinationEvidenceResult) -> DestinationPresentation:
    if result.context is None:
        return DestinationPresentation("No remote destination.", (), "No remote destination.", "")
    if result.source_unavailable:
        dns_status = "DNS association source unavailable."
    elif result.legacy_unknown:
        dns_status = "Legacy DNS observation for this IP; canonical evidence reference unavailable."
    elif result.scope_status is NetworkScopeStatus.AMBIGUOUS:
        dns_status = "DNS association unavailable: network scope is ambiguous."
    elif result.scope_status is NetworkScopeStatus.UNKNOWN:
        dns_status = "DNS association unavailable: network scope is unknown."
    elif result.dns.status is DnsAssociationStatus.AMBIGUOUS:
        dns_status = "Ambiguous DNS associations; multiple domains observed for this IP."
    elif result.dns.status is DnsAssociationStatus.CORRELATED:
        dns_status = "Correlated DNS evidence for this IP; this does not establish a connection hostname."
    else:
        dns_status = "No DNS association observed for this IP in the relevant time and scope."
    candidates = tuple(
        DnsCandidatePresentation(
            _candidate_text(item, result.as_of) + _source_suffix(result.source_statuses, index),
            item.evidence_id,
        )
        for index, item in enumerate(result.dns.candidates[:MAX_VISIBLE_CANDIDATES])
    )
    context = result.context
    if context.status is DestinationContextStatus.MATCHED:
        context_status = "Matched in current local IP dataset." if result.historical else "Matched in local IP dataset."
    elif context.status is DestinationContextStatus.UNKNOWN:
        context_status = "No match in the current local IP dataset."
    elif context.status is DestinationContextStatus.NOT_APPLICABLE:
        context_status = "Local ASN/country context does not apply to this private or special address."
    elif context.status is DestinationContextStatus.NOT_CONFIGURED:
        context_status = "Local ASN/country dataset not configured."
    else:
        context_status = "Local ASN/country dataset unavailable."
    details: list[str] = []
    if context.asn is not None:
        details.append(f"ASN: AS{context.asn}")
    if context.as_name is not None:
        details.append(f"Organization: {context.as_name}")
    if context.country_code is not None:
        details.append(f"Country (IP dataset context): {context.country_code}")
    if context.source is not None:
        details.append(f"Source: {context.source.name} v{context.source.version}")
    return DestinationPresentation(dns_status, candidates, context_status, "\n".join(details), context.source)


def _candidate_text(item: DomainAssociation, as_of: datetime | None) -> str:
    provenance = ("Direct DNS answer" if item.provenance is DnsAssociationProvenance.DIRECT_ANSWER
                  else "CNAME-derived DNS answer")
    effective = item.observed_at + timedelta(seconds=item.retention_seconds)
    freshness = "fresh" if as_of is None or as_of < effective else "expired by selected time"
    age = max(0, int(((as_of or datetime.now(item.observed_at.tzinfo)) - item.observed_at).total_seconds()))
    chain = ""
    if item.provenance is DnsAssociationProvenance.CNAME_DERIVED:
        chain = f"; queried {item.queried_domain}; chain {' → '.join(item.cname_chain)}"
    return (f"{item.domain} — {provenance}; observed {age}s before selected time; "
            f"TTL {item.ttl}s; {freshness}{chain}")


def _source_suffix(statuses: tuple[DnsEvidenceSourceStatus, ...], index: int) -> str:
    if index >= len(statuses) or statuses[index] is DnsEvidenceSourceStatus.AVAILABLE:
        return ""
    if statuses[index] is DnsEvidenceSourceStatus.UNKNOWN_LEGACY:
        return "; legacy DNS record: canonical evidence reference unavailable"
    return "; source DNS evidence expired or unavailable"


class DestinationEvidenceWidget(QWidget):
    """Two explicitly separate accessible text sections."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.dns_group = QGroupBox("Observed DNS associations", self)
        self.dns_group.setAccessibleName("Observed DNS associations")
        dns_layout = QVBoxLayout(self.dns_group)
        self.dns_status = self._label("DNS evidence status", self.dns_group)
        self.dns_candidates = self._label("DNS evidence candidates", self.dns_group)
        dns_layout.addWidget(self.dns_status)
        dns_layout.addWidget(self.dns_candidates)
        self.context_group = QGroupBox("Local destination context", self)
        self.context_group.setAccessibleName("Local ASN and country destination context")
        context_layout = QVBoxLayout(self.context_group)
        self.context_status = self._label("Local destination context status", self.context_group)
        self.context_details = self._label("ASN country and dataset provenance", self.context_group)
        context_layout.addWidget(self.context_status)
        context_layout.addWidget(self.context_details)
        layout.addWidget(self.dns_group)
        layout.addWidget(self.context_group)
        self.evidence_references: tuple[DnsEvidenceId, ...] = ()
        self.dataset_source: DestinationDatasetSource | None = None
        self.clear()

    @staticmethod
    def _label(name: str, parent: QWidget) -> QLabel:
        label = QLabel(parent)
        label.setAccessibleName(name)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse |
                                      Qt.TextInteractionFlag.TextSelectableByKeyboard)
        label.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        label.setWordWrap(True)
        return label

    def clear(self, status: str = "No remote destination selected.") -> None:
        self.dns_status.setText(status)
        self.dns_candidates.clear()
        self.context_status.setText(status)
        self.context_details.clear()
        self.evidence_references = ()
        self.dataset_source = None

    def set_result(self, result: DestinationEvidenceResult) -> None:
        view = present_destination(result)
        self.dns_status.setText(view.dns_status)
        self.dns_candidates.setText("\n".join(candidate.text for candidate in view.candidates))
        self.context_status.setText(view.context_status)
        self.context_details.setText(view.context_details)
        self.evidence_references = tuple(candidate.evidence_id for candidate in view.candidates)
        self.dataset_source = view.dataset_source
