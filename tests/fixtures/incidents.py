"""Canonical offline incident inputs; no live traffic or metadata payloads."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from netsentinel.domain.connections import NetworkScopeStatus, ObservationQuality, ProcessIdentity, TransportProtocol
from netsentinel.domain.incidents import (
    IncidentConnectionRef, IncidentDestination, IncidentDestinationKind,
    IncidentInput, IncidentObservationKind, IncidentObservationRef, IncidentProcessRef,
)
from netsentinel.domain.risk_evidence import EvidenceQuality, EvidenceReference, EvidenceReferenceKind, EvidenceScope, EvidenceScopeKind

NOW = datetime(2026, 10, 4, 10, tzinfo=UTC)
SESSION = UUID(int=1000)
PROCESS = IncidentProcessRef(SESSION, ProcessIdentity(123, NOW - timedelta(hours=1)))
DESTINATION = IncidentDestination(IncidentDestinationKind.IPV4, "8.8.8.8", 443, TransportProtocol.TCP)
SCOPE = EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64)
QUALITY = EvidenceQuality(ObservationQuality.COMPLETE)


def evidence_ref(number):
    return EvidenceReference(EvidenceReferenceKind.EVIDENCE, f"{number:064x}")


def item(number=1, *, stamp=NOW, process=PROCESS, destination=DESTINATION,
         scope=SCOPE, connection="default", evidence=(), assessment=None, alert_id=None, quality=QUALITY):
    reference = evidence_ref(number)
    if connection == "default":
        connection = IncidentConnectionRef(SESSION, UUID(int=number))
    return IncidentInput(
        IncidentObservationRef(IncidentObservationKind.EVIDENCE_OBSERVED, reference, stamp),
        scope, process, connection, destination,
        tuple(sorted({reference, *evidence}, key=lambda r: (r.kind.value, str(r.value)))),
        assessment, alert_id, quality,
    )
