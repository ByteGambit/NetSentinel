"""Explicit NS-102 coordinator. No GUI composition, scheduler or elevation.

Durable custody precedes dispatch. Replay reconciles rather than dispatching.
Transient PARTIAL return values are not finalized ownership or normal success.
"""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
import secrets
from uuid import UUID, uuid4

from netsentinel.application.response_ports import ResponseLifecycleRepository, WitnessResponseFirewall
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallCreateResult, FirewallReadResult, FirewallReadStatus, FirewallRemoveRequest,
    OwnedFirewallRuleManifest, PreparedFirewallOwnershipClaim, PreparedFirewallReadResult, ResponseAction,
    ResponseOutcome, ResponseReason, ResponseResult, ResponseRuleState, _utc,
    confirmation_matches, expected_firewall_rule, ownership_description, serialize_owned_firewall_manifest,
)
from netsentinel.domain.response_lifecycle import (
    ResponseAuditEvent as Event, ResponseOperation, ResponseOperationConflict,
    ResponseOperationStatus as Status, ResponseReconciliation as Reconciliation,
    ResponseRemovalPurpose as Purpose, ResponseStorageError,
)


def new_response_rule_identity() -> UUID:
    """Allocate BEFORE preview confirmation; confirmed commands are never rewritten."""
    return uuid4()


class ResponseLifecycleService:
    def __init__(self, repository: ResponseLifecycleRepository, firewall: WitnessResponseFirewall, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._repository = repository
        self._firewall = firewall
        self._clock = clock

    def _now(self) -> datetime:
        return _utc(self._clock())

    def _result(self, operation: ResponseOperation, outcome: ResponseOutcome,
                reason: ResponseReason, state: ResponseRuleState = ResponseRuleState.UNKNOWN) -> ResponseResult:
        return ResponseResult(operation.operation_id, operation.command.action, outcome, reason, state)

    def _partial(self, operation: ResponseOperation) -> ResponseOperation:
        if operation.status is Status.OS_VERIFIED:
            # Keep the already committed verified OS receipt recoverable; its
            # lifecycle remains unfinalized, so this is not normal success.
            try:
                return self._repository.save(replace(operation, updated_at=self._now()), Event.UNKNOWN_PARTIAL)
            except ResponseStorageError:
                return operation
        partial = replace(operation, status=Status.PARTIAL, result=self._result(
            operation, ResponseOutcome.PARTIAL, ResponseReason.OS_DB_DISAGREEMENT), updated_at=self._now())
        try:
            return self._repository.save(partial, Event.UNKNOWN_PARTIAL)
        except ResponseStorageError:
            # Original durable phase remains recoverable. This is an explicitly
            # uncommitted receipt, never a claim of durable ownership/success.
            return partial

    def create(self, request: FirewallCreateRequest) -> ResponseOperation:
        if type(request) is not FirewallCreateRequest:
            raise TypeError("CREATE requires exact confirmed request")
        with self._repository.exclusive():
            existing = self._repository.get(request.command.command_id)
            if existing is not None:
                if existing.request != request:
                    raise ResponseOperationConflict("CREATE replay differs from durable operation.")
                return self._reconcile(existing)
            now = self._now()
            witness = secrets.token_hex(32)
            claim = PreparedFirewallOwnershipClaim(request, replace(expected_firewall_rule(request.command),
                description=ownership_description(request.command.rule_id, witness)), witness, now)
            # Ensure final transport capacity BEFORE dispatch, including duplicated
            # provenance, so an admissible path cannot exceed final storage bounds.
            serialize_owned_firewall_manifest(OwnedFirewallRuleManifest(
                request, claim.expected_rule, now, now, 2, claim, now))
            operation = self._repository.save(ResponseOperation(request, claim, updated_at=now), Event.PREPARED)
            operation = self._repository.save(replace(operation, status=Status.ATTEMPT, attempt_at=self._now(),
                                                     updated_at=self._now()), Event.ATTEMPT)
            return self._dispatch_create(operation)

    def _dispatch_create(self, operation: ResponseOperation) -> ResponseOperation:
        if operation.claim is None:
            raise ResponseOperationConflict("Missing durable CREATE provenance.")
        try:
            receipt = self._firewall.create_prepared(operation.claim)
            if (type(receipt) is not FirewallCreateResult or receipt.request != operation.request):
                raise ValueError("invalid creation receipt")
            result = receipt.result
            manifest = receipt.manifest
            if result.outcome is ResponseOutcome.VERIFIED:
                if (manifest is None or manifest.prepared_claim != operation.claim or manifest.manifest_version != 2
                        or manifest.created_at is None or operation.attempt_at is None
                        or not operation.attempt_at <= manifest.created_at <= manifest.verified_at <= self._now()):
                    raise ValueError("invalid witnessed creation evidence")
                final = replace(operation, manifest=replace(manifest, dispatch_intent_at=operation.attempt_at), status=Status.VERIFIED,
                                reconciliation=Reconciliation.EXACT, result=result, updated_at=self._now())
                try:
                    return self._repository.save(final, Event.VERIFIED_SUCCESS)
                except ResponseStorageError:
                    return self._partial(operation)
        except Exception:
            result = self._result(operation, ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE)
        return self._finish_failure(operation, result)

    def _finish_failure(self, operation: ResponseOperation, result: ResponseResult) -> ResponseOperation:
        status = Status.UNKNOWN if result.outcome in {ResponseOutcome.OUTCOME_UNKNOWN, ResponseOutcome.PARTIAL} else Status.FAILURE
        event = Event.UNKNOWN_PARTIAL if status is Status.UNKNOWN else (
            Event.ROLLBACK_FAILURE if operation.purpose is Purpose.ROLLBACK else Event.FAILURE)
        failed = replace(operation, status=status, result=result, updated_at=self._now())
        try:
            return self._repository.save(failed, event)
        except ResponseStorageError:
            return self._partial(operation)

    def remove(self, request: FirewallRemoveRequest, *, purpose: Purpose = Purpose.UNDO) -> ResponseOperation:
        if type(request) is not FirewallRemoveRequest or purpose not in {Purpose.UNDO, Purpose.ROLLBACK}:
            raise TypeError("REMOVE requires a confirmed finalized manifest and explicit purpose")
        with self._repository.exclusive():
            existing = self._repository.get(request.command.command_id)
            if existing is not None:
                if existing.request != request or existing.purpose is not purpose:
                    raise ResponseOperationConflict("REMOVE replay differs from durable operation.")
                return self._reconcile(existing)
            operation = self._repository.save(ResponseOperation(
                request, manifest=request.manifest, reconciliation=Reconciliation.PENDING_REMOVE,
                updated_at=self._now(), purpose=purpose), Event.PREPARED)
            return self._dispatch_remove(operation)

    def rollback(self, request: FirewallRemoveRequest) -> ResponseOperation:
        """Explicit confirmed Undo of finalized custody; no partial-rule deletion."""
        return self.remove(request, purpose=Purpose.ROLLBACK)

    def schedule_expiry(self, request: FirewallRemoveRequest, expires_at: datetime) -> ResponseOperation:
        """Persist a user-confirmed REMOVE due time, preserving manual v1 lifetime.

        Reconciliation executes only while the original REMOVE confirmation is
        fresh. An overdue/stale confirmation remains expiry-pending for a new
        explicit request; no synthetic confirmation or privileged timer.
        """
        if type(request) is not FirewallRemoveRequest:
            raise TypeError("expiry requires an explicit confirmed REMOVE")
        expires_at = _utc(expires_at)
        with self._repository.exclusive():
            existing = self._repository.get(request.command.command_id)
            if existing is not None:
                if existing.request != request or existing.expires_at != expires_at or existing.purpose is not Purpose.EXPIRY:
                    raise ResponseOperationConflict("Expiry replay differs from durable operation.")
                return self._reconcile(existing)
            return self._repository.save(ResponseOperation(
                request, manifest=request.manifest, reconciliation=Reconciliation.EXPIRY_PENDING,
                updated_at=self._now(), expires_at=expires_at, purpose=Purpose.EXPIRY), Event.PREPARED)

    def _dispatch_remove(self, operation: ResponseOperation) -> ResponseOperation:
        request = operation.request
        if type(request) is not FirewallRemoveRequest:
            raise TypeError("finalized REMOVE required")
        operation = self._repository.save(replace(operation, status=Status.ATTEMPT,
            attempt_at=self._now(), updated_at=self._now()),
            Event.ROLLBACK_ATTEMPT if operation.purpose is Purpose.ROLLBACK else Event.ATTEMPT)
        try:
            result = self._firewall.remove(request)
            if (type(result) is not ResponseResult or result.command_id != operation.operation_id
                    or result.action is not ResponseAction.REMOVE):
                raise ValueError("invalid removal receipt")
        except Exception:
            result = self._result(operation, ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE)
        if result.outcome is not ResponseOutcome.VERIFIED:
            return self._finish_failure(operation, result)
        try:
            # A durable adapter-verified absence receipt allows honest recovery
            # from the following DB finalization gap. Absence alone does not.
            operation = self._repository.save(replace(operation, status=Status.OS_VERIFIED, result=result,
                reconciliation=Reconciliation.REMOVED, updated_at=self._now()), Event.READBACK_VERIFIED)
            return self._repository.save(replace(operation, status=Status.VERIFIED, updated_at=self._now()),
                Event.ROLLBACK_SUCCESS if operation.purpose is Purpose.ROLLBACK else Event.VERIFIED_SUCCESS)
        except ResponseStorageError:
            return self._partial(operation)

    def reconcile(self, *, after: UUID | None = None, limit: int = 64) -> tuple[ResponseOperation, ...]:
        """One bounded restart/manual page. Returned final UUID is next cursor."""
        with self._repository.exclusive():
            return tuple(self._reconcile(operation) for operation in self._repository.page(after=after, limit=limit))

    def _reconcile(self, operation: ResponseOperation) -> ResponseOperation:
        started = self._now()
        if operation.updated_at is not None and started < operation.updated_at:
            # A backwards wall clock cannot establish fresh readback. Keep the
            # prior durable time rather than fabricate a new observation time.
            return self._repository.save(replace(operation, reconciliation=Reconciliation.UNKNOWN), Event.UNKNOWN_PARTIAL)
        is_create = operation.command.action is ResponseAction.CREATE
        try:
            readback: FirewallReadResult | PreparedFirewallReadResult
            if operation.manifest is not None:
                readback = self._firewall.read(operation.manifest)
                if readback.manifest != operation.manifest:
                    raise ValueError("readback manifest mismatch")
            else:
                if operation.claim is None:
                    raise ValueError("missing prepared claim")
                readback = self._firewall.read_prepared(operation.claim)
                if readback.claim != operation.claim:
                    raise ValueError("readback claim mismatch")
            if not started <= readback.checked_at <= self._now():
                raise ValueError("readback is not fresh")
            status = readback.status
            snapshot = readback.snapshot
        except Exception:
            status, snapshot = FirewallReadStatus.READ_UNAVAILABLE, None
        now = self._now()
        current = replace(operation, updated_at=now, reconciled_at=now)
        event = Event.RECOVERY
        if status is FirewallReadStatus.MATCHED:
            if is_create and operation.manifest is None:
                if operation.claim is None or snapshot is None:
                    raise ResponseOperationConflict("Missing fresh witnessed promotion evidence.")
                # Recovery time is verification time, NEVER an invented Add time.
                manifest = OwnedFirewallRuleManifest(operation.claim.creation, snapshot, None, now, 2, operation.claim,
                                                      operation.attempt_at)
                current = replace(current, manifest=manifest, status=Status.VERIFIED,
                    reconciliation=Reconciliation.PROMOTED, result=self._result(operation,
                    ResponseOutcome.VERIFIED, ResponseReason.RULE_READBACK_VERIFIED, ResponseRuleState.PRESENT_ENABLED))
                event = Event.RECOVERY_PROMOTION
            elif is_create:
                if self._repository.has_verified_removal(operation.command.rule_id):
                    current = replace(current, reconciliation=Reconciliation.EXTERNAL_MODIFIED)
                    event = Event.EXTERNAL_DRIFT
                else:
                    current = replace(current, reconciliation=Reconciliation.EXACT)
            elif operation.purpose is Purpose.EXPIRY and operation.status is Status.PREPARED:
                if operation.expires_at is not None and now >= operation.expires_at:
                    if confirmation_matches(operation.command, operation.request.confirmation, now):
                        current = self._repository.save(replace(current, reconciliation=Reconciliation.EXPIRED), Event.RECOVERY)
                        return self._dispatch_remove(current)
                    current = replace(current, reconciliation=Reconciliation.EXPIRY_PENDING,
                        result=self._result(operation, ResponseOutcome.NOT_ATTEMPTED, ResponseReason.STALE_CONFIRMATION))
                    event = Event.EXPIRY_PENDING
                else:
                    current = replace(current, reconciliation=Reconciliation.EXPIRY_PENDING)
            else:
                if operation.status in {Status.VERIFIED, Status.OS_VERIFIED}:
                    current = replace(current, reconciliation=Reconciliation.EXTERNAL_MODIFIED)
                    event = Event.EXTERNAL_DRIFT
                else:
                    current = replace(current, reconciliation=Reconciliation.PENDING_REMOVE)
        elif status is FirewallReadStatus.ABSENT:
            if is_create and operation.manifest is None:
                current = replace(current, status=Status.NOT_MATERIALIZED, reconciliation=Reconciliation.NOT_MATERIALIZED,
                    result=self._result(operation, ResponseOutcome.FAILED, ResponseReason.OPERATION_FAILED))
            elif is_create:
                # A retained finalized removal receipt distinguishes managed
                # cleanup from external loss without dispatching any mutation.
                removed = self._repository.has_verified_removal(operation.command.rule_id)
                current = replace(current, reconciliation=Reconciliation.REMOVED if removed else Reconciliation.EXTERNAL_MISSING)
                event = Event.RECOVERY if removed else Event.EXTERNAL_MISSING
            elif operation.status in {Status.VERIFIED, Status.OS_VERIFIED}:
                current = replace(current, status=Status.VERIFIED, reconciliation=Reconciliation.REMOVED)
                event = (Event.RECOVERY if operation.status is Status.VERIFIED else
                         Event.ROLLBACK_SUCCESS if operation.purpose is Purpose.ROLLBACK else Event.VERIFIED_SUCCESS)
            else:
                current = replace(current, reconciliation=Reconciliation.ABSENCE_OBSERVED)
                # No durable verified receipt => uncertain own/external removal.
                if operation.status is not Status.PREPARED:
                    current = replace(current, status=Status.UNKNOWN, result=self._result(operation,
                        ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE))
        elif status is FirewallReadStatus.MISMATCH:
            current = replace(current, reconciliation=(Reconciliation.EXTERNALLY_DISABLED
                if snapshot is not None and not snapshot.enabled else Reconciliation.EXTERNAL_MODIFIED))
            event = Event.EXTERNAL_DRIFT
        elif status is FirewallReadStatus.DUPLICATE:
            current = replace(current, reconciliation=Reconciliation.AMBIGUOUS)
            event = Event.EXTERNAL_DRIFT
        else:
            current = replace(current, reconciliation=Reconciliation.UNKNOWN)
            event = Event.UNKNOWN_PARTIAL
        try:
            return self._repository.save(current, event)
        except ResponseStorageError:
            # Do not return uncommitted promotion as owned/verified.
            return self._partial(operation)

    def diagnostics(self):
        return self._repository.diagnostics()
