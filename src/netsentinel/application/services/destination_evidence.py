"""Scoped, bounded destination reads for connection details."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from netsentinel.application.services.destination_context import DestinationContextResolver
from netsentinel.domain.connections import ConnectionNetworkScope, NetworkScopeStatus
from netsentinel.domain.destination_context import DestinationContext
from netsentinel.domain.dns import (
    DnsAssociationLookup, DnsAssociationStatus, DnsEvidenceId,
    DnsEvidenceSourceStatus, DomainAssociation,
)


class AssociationReader(Protocol):
    def overlapping_by_ip(
        self, ip: str, *, network_scope: ConnectionNetworkScope, client_ip: str | None,
        first_seen: datetime, last_seen: datetime, limit: int = 32,
    ) -> tuple[DomainAssociation, ...]: ...


class EvidenceSourceReader(Protocol):
    def source_status(self, evidence_id: DnsEvidenceId | None) -> DnsEvidenceSourceStatus: ...

    def legacy_ip_observed(
        self, ip: str, *, network_fingerprint: str, client_ip: str,
        first_seen: datetime, last_seen: datetime,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class DestinationEvidenceRequest:
    remote_ip: str | None
    client_ip: str | None
    network_scope: ConnectionNetworkScope
    first_seen: datetime
    last_seen: datetime
    historical: bool = False


@dataclass(frozen=True, slots=True)
class DestinationEvidenceResult:
    dns: DnsAssociationLookup
    context: DestinationContext | None
    scope_status: NetworkScopeStatus
    source_unavailable: bool = False
    historical: bool = False
    as_of: datetime | None = None
    source_statuses: tuple[DnsEvidenceSourceStatus, ...] = ()
    legacy_unknown: bool = False


class DestinationEvidenceService:
    """Read local evidence without inferring a hostname, process or verdict."""

    def __init__(self, associations: AssociationReader, context: DestinationContextResolver,
                 sources: EvidenceSourceReader | None = None) -> None:
        self._associations = associations
        self._context = context
        self._sources = sources

    def lookup(self, request: DestinationEvidenceRequest) -> DestinationEvidenceResult:
        if request.remote_ip is None:
            return DestinationEvidenceResult(
                DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), None,
                request.network_scope.status, historical=request.historical,
            )
        context = self._context.resolve(request.remote_ip)
        if request.network_scope.status is not NetworkScopeStatus.RESOLVED or request.client_ip is None:
            return DestinationEvidenceResult(
                DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context,
                request.network_scope.status, historical=request.historical,
                as_of=request.last_seen,
            )
        try:
            candidates = self._associations.overlapping_by_ip(
                request.remote_ip, network_scope=request.network_scope,
                client_ip=request.client_ip, first_seen=request.first_seen,
                last_seen=request.last_seen, limit=32,
            )
        except Exception:
            return DestinationEvidenceResult(
                DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context,
                request.network_scope.status, source_unavailable=True,
                historical=request.historical, as_of=request.last_seen,
            )
        # The repository orders newest evidence first. Domain ambiguity is
        # independent of multiple observations of one domain.
        status = (DnsAssociationStatus.AMBIGUOUS if len({item.domain for item in candidates}) > 1
                  else DnsAssociationStatus.CORRELATED if candidates else DnsAssociationStatus.UNKNOWN)
        statuses: tuple[DnsEvidenceSourceStatus, ...] = ()
        legacy_unknown = False
        if self._sources is not None:
            try:
                statuses = tuple(self._sources.source_status(item.evidence_id) for item in candidates)
                if not candidates and request.historical:
                    assert request.network_scope.fingerprint is not None
                    assert request.client_ip is not None
                    legacy_unknown = self._sources.legacy_ip_observed(
                        request.remote_ip, network_fingerprint=request.network_scope.fingerprint,
                        client_ip=request.client_ip, first_seen=request.first_seen,
                        last_seen=request.last_seen,
                    )
            except Exception:
                if not candidates:
                    return DestinationEvidenceResult(
                        DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context,
                        request.network_scope.status, source_unavailable=True,
                        historical=request.historical, as_of=request.last_seen,
                    )
                statuses = (DnsEvidenceSourceStatus.SOURCE_UNAVAILABLE,) * len(candidates)
        return DestinationEvidenceResult(
            DnsAssociationLookup(status, candidates), context,
            request.network_scope.status, historical=request.historical,
            as_of=request.last_seen, source_statuses=statuses,
            legacy_unknown=legacy_unknown,
        )


def live_request(remote_ip: str | None, client_ip: str | None,
                 network_scope: ConnectionNetworkScope) -> DestinationEvidenceRequest:
    now = datetime.now(UTC)
    return DestinationEvidenceRequest(remote_ip, client_ip, network_scope, now, now)
