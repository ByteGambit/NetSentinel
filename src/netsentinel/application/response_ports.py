"""Narrow NS-102 lifecycle ports. No infrastructure dependency."""

from contextlib import AbstractContextManager
from uuid import UUID

from typing import Protocol

from netsentinel.domain.response import (
    FirewallCreateResult, FirewallReadResult, FirewallRemoveRequest,
    OwnedFirewallRuleManifest, PreparedFirewallOwnershipClaim, PreparedFirewallReadResult, ResponseResult,
)
from netsentinel.domain.response_lifecycle import (
    ResponseAuditEvent, ResponseAuditRecord, ResponseLifecycleDiagnostics, ResponseOperation,
)


class WitnessResponseFirewall(Protocol):
    def create_prepared(self, claim: PreparedFirewallOwnershipClaim) -> FirewallCreateResult: ...
    def read_prepared(self, claim: PreparedFirewallOwnershipClaim) -> PreparedFirewallReadResult: ...
    def read(self, manifest: OwnedFirewallRuleManifest) -> FirewallReadResult: ...
    def remove(self, request: FirewallRemoveRequest) -> ResponseResult: ...


class ResponseLifecycleRepository(Protocol):
    @property
    def store_id(self) -> UUID: ...

    def exclusive(self) -> AbstractContextManager[None]:
        """Nonblocking store-wide crash-released lock, NOT a SQLite transaction."""

    def get(self, operation_id: UUID) -> ResponseOperation | None: ...
    def has_verified_removal(self, rule_id: UUID) -> bool: ...
    def page(self, *, after: UUID | None = None, limit: int = 64) -> tuple[ResponseOperation, ...]: ...
    def save(self, operation: ResponseOperation, event: ResponseAuditEvent) -> ResponseOperation:
        """Atomic revision CAS/state/audit/pruning. Insert requires revision zero."""

    def audit(self, *, after_sequence: int = 0, limit: int = 100) -> tuple[ResponseAuditRecord, ...]: ...
    def diagnostics(self) -> ResponseLifecycleDiagnostics: ...
