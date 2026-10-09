"""NS-102 bounded lifecycle values, independent of SQLite, COM and UI."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID

from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallRemoveRequest, OwnedFirewallRuleManifest,
    PreparedFirewallOwnershipClaim, ResponseAction, ResponseCommand, ResponseOutcome,
    ResponseResult, _utc,
)

MAX_RESPONSE_OPERATIONS = 1024
MAX_RESPONSE_ACTIVE_RULES = 64
MAX_RESPONSE_AUDIT_ROWS = 8192
MAX_RESPONSE_RECONCILE_BATCH = 64


class ResponseOperationStatus(str, Enum):
    PREPARED = "prepared"
    ATTEMPT = "attempt"
    OS_VERIFIED = "os_verified"
    VERIFIED = "verified"
    FAILURE = "failure"
    UNKNOWN = "unknown"
    PARTIAL = "partial"
    NOT_MATERIALIZED = "not_materialized"


class ResponseReconciliation(str, Enum):
    PENDING_CREATE = "pending_create"
    PENDING_REMOVE = "pending_remove"
    EXACT = "exact"
    PROMOTED = "promoted"
    NOT_MATERIALIZED = "not_materialized"
    EXTERNAL_MISSING = "external_missing"
    EXTERNAL_MODIFIED = "external_modified"
    EXTERNALLY_DISABLED = "externally_disabled"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"
    REMOVED = "removed"
    ABSENCE_OBSERVED = "absence_observed"
    EXPIRED = "expired"
    EXPIRY_PENDING = "expiry_pending"


class ResponseRemovalPurpose(str, Enum):
    UNDO = "undo"
    ROLLBACK = "rollback"
    EXPIRY = "expiry"


class ResponseAuditEvent(str, Enum):
    PREPARED = "prepared"
    ATTEMPT = "attempt"
    READBACK_VERIFIED = "readback_verified"
    VERIFIED_SUCCESS = "verified_success"
    FAILURE = "failure"
    UNKNOWN_PARTIAL = "unknown_partial"
    RECOVERY_PROMOTION = "recovery_promotion"
    RECOVERY = "recovery"
    ROLLBACK_ATTEMPT = "rollback_attempt"
    ROLLBACK_SUCCESS = "rollback_success"
    ROLLBACK_FAILURE = "rollback_failure"
    EXTERNAL_DRIFT = "external_drift"
    EXTERNAL_MISSING = "external_missing"
    EXPIRY_PENDING = "expiry_pending"


@dataclass(frozen=True, slots=True)
class ResponseOperation:
    request: FirewallCreateRequest | FirewallRemoveRequest = field(repr=False)
    claim: PreparedFirewallOwnershipClaim | None = field(default=None, repr=False)
    manifest: OwnedFirewallRuleManifest | None = field(default=None, repr=False)
    status: ResponseOperationStatus = ResponseOperationStatus.PREPARED
    reconciliation: ResponseReconciliation = ResponseReconciliation.PENDING_CREATE
    result: ResponseResult | None = None
    updated_at: datetime | None = None
    attempt_at: datetime | None = None
    reconciled_at: datetime | None = None
    expires_at: datetime | None = None
    purpose: ResponseRemovalPurpose = ResponseRemovalPurpose.UNDO
    revision: int = 0

    def __post_init__(self) -> None:
        if type(self.request) not in {FirewallCreateRequest, FirewallRemoveRequest}:
            raise TypeError("lifecycle requires exact confirmed request")
        if (type(self.status) is not ResponseOperationStatus or type(self.reconciliation) is not ResponseReconciliation
                or type(self.purpose) is not ResponseRemovalPurpose):
            raise TypeError("lifecycle classifications must be typed")
        if type(self.revision) is not int or not 0 <= self.revision < 2**63 - 1:
            raise ValueError("invalid lifecycle revision")
        for name in ("updated_at", "attempt_at", "reconciled_at", "expires_at"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _utc(value))
        if self.updated_at is None or self.updated_at < self.request.confirmation.confirmed_at:
            raise ValueError("lifecycle time predates confirmation")
        if self.command.action is ResponseAction.CREATE:
            if self.status is ResponseOperationStatus.OS_VERIFIED:
                raise ValueError("CREATE success requires final custody")
            if type(self.claim) is not PreparedFirewallOwnershipClaim or self.claim.creation != self.request:
                raise ValueError("CREATE lifecycle requires its complete prepared provenance")
            if self.expires_at is not None or self.purpose is not ResponseRemovalPurpose.UNDO:
                raise ValueError("manual CREATE lifetime cannot authorize timed or rollback removal")
            if self.manifest is not None and (
                    self.manifest.manifest_version != 2 or self.manifest.prepared_claim != self.claim):
                raise ValueError("final ownership must bind the durable prepared provenance")
            if self.status is ResponseOperationStatus.VERIFIED and self.manifest is None:
                raise ValueError("verified CREATE requires finalized ownership")
        else:
            if type(self.request) is not FirewallRemoveRequest:
                raise TypeError("REMOVE requires an exact removal request")
            if self.claim is not None or self.manifest != self.request.manifest:
                raise ValueError("REMOVE lifecycle requires exact finalized ownership")
            if (self.expires_at is not None) != (self.purpose is ResponseRemovalPurpose.EXPIRY):
                raise ValueError("expiry requires an explicit confirmed REMOVE intent")
            if self.expires_at is not None and self.expires_at < self.request.confirmation.confirmed_at:
                raise ValueError("expiry cannot predate removal confirmation")
        if self.result is not None:
            if type(self.result) is not ResponseResult or (
                    self.result.command_id != self.command.command_id or self.result.action is not self.command.action):
                raise ValueError("lifecycle outcome does not bind operation")
            if self.result.outcome is ResponseOutcome.VERIFIED and self.status not in {
                    ResponseOperationStatus.VERIFIED, ResponseOperationStatus.OS_VERIFIED}:
                raise ValueError("unfinalized lifecycle cannot claim normal success")
        if self.status in {ResponseOperationStatus.VERIFIED, ResponseOperationStatus.OS_VERIFIED} and (
                self.result is None or self.result.outcome is not ResponseOutcome.VERIFIED):
            raise ValueError("verified lifecycle requires its verified receipt")

    @property
    def command(self) -> ResponseCommand:
        return self.request.command

    @property
    def operation_id(self) -> UUID:
        return self.command.command_id


@dataclass(frozen=True, slots=True)
class ResponseAuditRecord:
    sequence: int
    operation_id: UUID
    rule_id: UUID
    action: ResponseAction
    at: datetime
    event: ResponseAuditEvent
    status: ResponseOperationStatus
    reconciliation: ResponseReconciliation
    outcome: ResponseOutcome | None
    # Requested state/target is obtained from the retained operation, never
    # duplicated as free text/path/witness in historical audit.


@dataclass(frozen=True, slots=True)
class ResponseLifecycleDiagnostics:
    finalized_owned_count: int
    prepared_pending_count: int
    partial_unknown_count: int
    external_drift_missing_count: int
    expiry_pending_count: int
    last_reconciliation_at: datetime | None
    last_reconciliation_result: ResponseReconciliation | None
    reconciliation_error_count: int


class ResponseStorageError(RuntimeError):
    """Sanitized fail-closed durable custody failure."""


class ResponseOperationConflict(ResponseStorageError):
    """Store/operation/request mismatch, capacity, or concurrent custody."""
