"""NS-101 caller-held ownership adapter. No production composition or elevation.

The injected session owns COM on the calling thread. The target guard is a
trusted, independent file/classification check, never a serialized write grant.
COM cannot atomically compare-and-remove against an external administrator.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol

from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallCreateResult, FirewallReadResult, FirewallReadStatus,
    FirewallRemoveRequest, FirewallRuleSnapshot, OwnedFirewallRuleManifest, ResponseCommand,
    ResponseOutcome, ResponseReason, ResponseResult, ResponseRuleState, ResponseSourceStatus,
    confirmation_matches, expected_firewall_rule, removal_readback_matches,
)


class FirewallApiError(RuntimeError):
    """Sanitized backend classification; uncertain dispatch is never success."""

    def __init__(self, status: FirewallReadStatus, *, definite_failure: bool = False) -> None:
        self.status = status
        self.definite_failure = definite_failure
        super().__init__("Windows Firewall API unavailable")


class TargetValidationError(RuntimeError):
    """Independent target check failed; never echo a path or native exception."""

    def __init__(self, reason: ResponseReason = ResponseReason.TARGET_UNAVAILABLE) -> None:
        if reason not in {ResponseReason.TARGET_UNAVAILABLE, ResponseReason.REVALIDATION_REQUIRED,
                          ResponseReason.ACCESS_DENIED, ResponseReason.BOUNDARY_UNAVAILABLE}:
            raise ValueError("unsupported target refusal")
        self.reason = reason
        super().__init__("Executable target validation unavailable")


class _StaleConfirmation(RuntimeError):
    pass


class FirewallApi(Protocol):
    """Infrastructure-only session. Enumeration must be fresh and exhaustive.

    Matching includes case aliases (Windows name semantics); at most two matches
    are returned, enough to detect ambiguity. A partial enumeration must raise.
    Each unique match includes ALL supported Rule/Rule2/Rule3 fields.
    """

    def matching(self, name: str, spec: FirewallRuleSnapshot) -> tuple[FirewallRuleSnapshot, ...]: ...
    def add(self, rule: FirewallRuleSnapshot, before_submit: Callable[[], None]) -> None: ...
    def remove(self, rule: FirewallRuleSnapshot, before_submit: Callable[[], None]) -> None: ...


ApiFactory = Callable[[], AbstractContextManager[FirewallApi]]
TargetGuard = Callable[[ResponseCommand], AbstractContextManager[None]]


def _reason(status: FirewallReadStatus) -> ResponseReason:
    return {
        FirewallReadStatus.ACCESS_DENIED: ResponseReason.ACCESS_DENIED,
        FirewallReadStatus.BACKEND_UNAVAILABLE: ResponseReason.BACKEND_UNAVAILABLE,
        FirewallReadStatus.UNSUPPORTED: ResponseReason.UNSUPPORTED,
        FirewallReadStatus.INVALID_REQUEST: ResponseReason.INVALID_REQUEST,
        FirewallReadStatus.READ_UNAVAILABLE: ResponseReason.READ_UNAVAILABLE,
    }.get(status, ResponseReason.OWNERSHIP_CONFLICT)


class WindowsResponseFirewall:
    """Synchronous ResponseFirewall implementation for explicit adapter callers.

    A required guard must hold independently validated target metadata stable
    through CREATE. There is no permissive default, target adoption or recovery.
    Native callers use windows_firewall_com.session and a trusted target guard;
    default tests inject both. No COM objects live on this adapter instance.
    """

    def __init__(self, api_factory: ApiFactory, target_guard: TargetGuard, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._factory = api_factory
        self._target_guard = target_guard
        self._clock = clock
        self._lock = Lock()

    def _result(self, command: ResponseCommand, outcome: ResponseOutcome, reason: ResponseReason,
                state: ResponseRuleState = ResponseRuleState.UNKNOWN) -> ResponseResult:
        return ResponseResult(command.command_id, command.action, outcome, reason, state)

    def _matches(self, api: FirewallApi, expected: FirewallRuleSnapshot) -> tuple[FirewallRuleSnapshot, ...]:
        rows = api.matching(expected.name, expected)
        if (type(rows) is not tuple or len(rows) > 2
                or any(type(row) is not FirewallRuleSnapshot for row in rows)):
            raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
        return rows

    def _confirmation(self, command: ResponseCommand, confirmation: object) -> bool:
        # Typed requests already bind the fingerprint. Recheck the clock at dispatch.
        from netsentinel.domain.response import ResponseConfirmation
        return (type(confirmation) is ResponseConfirmation
                and confirmation_matches(command, confirmation, self._clock()))

    def _failure(self, command: ResponseCommand, error: Exception, attempted: bool,
                 submitted: bool = False) -> ResponseResult:
        if attempted:
            if not submitted and isinstance(error, FirewallApiError) and error.definite_failure:
                reason = {FirewallReadStatus.ACCESS_DENIED: ResponseReason.ACCESS_DENIED,
                          FirewallReadStatus.DUPLICATE: ResponseReason.OWNERSHIP_CONFLICT}.get(
                              error.status, ResponseReason.OPERATION_FAILED)
                return self._result(command, ResponseOutcome.FAILED, reason)
            return self._result(command, ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE)
        reason = (ResponseReason.STALE_CONFIRMATION if isinstance(error, _StaleConfirmation) else
                  error.reason if isinstance(error, TargetValidationError) else
                  _reason(error.status) if isinstance(error, FirewallApiError) else ResponseReason.READ_UNAVAILABLE)
        return self._result(command, ResponseOutcome.NOT_ATTEMPTED, reason)

    def create(self, request: FirewallCreateRequest) -> FirewallCreateResult:
        if type(request) is not FirewallCreateRequest:
            raise TypeError("creation requires an exact typed confirmed request")
        command = request.command
        def denied(reason: ResponseReason) -> FirewallCreateResult:
            return FirewallCreateResult(request, self._result(command, ResponseOutcome.NOT_ATTEMPTED, reason))
        if not self._confirmation(command, request.confirmation):
            return denied(ResponseReason.STALE_CONFIRMATION)
        if (command.source.status is not ResponseSourceStatus.AVAILABLE
                or command.source.quality is ObservationQuality.FAILED):
            return denied(ResponseReason.TARGET_UNAVAILABLE)
        if not self._lock.acquire(blocking=False):
            return denied(ResponseReason.BOUNDARY_UNAVAILABLE)
        attempted = False
        submitted = False
        try:
            expected = expected_firewall_rule(command)
            with self._factory() as api:
                if self._matches(api, expected):
                    return denied(ResponseReason.OWNERSHIP_CONFLICT)
                with self._target_guard(command):
                    # Re-read immediately before Add; never blindly overwrite a collision.
                    if self._matches(api, expected):
                        return denied(ResponseReason.OWNERSHIP_CONFLICT)
                    created_at = request.confirmation.confirmed_at  # Replaced at actual submission.
                    def before_submit() -> None:
                        nonlocal attempted, created_at
                        created_at = self._clock()
                        if not confirmation_matches(command, request.confirmation, created_at):
                            raise _StaleConfirmation()
                        attempted = True
                    api.add(expected, before_submit)
                    if not attempted:
                        raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
                    submitted = True
                    rows = self._matches(api, expected)
                    if len(rows) != 1 or rows[0] != expected:
                        return FirewallCreateResult(request, self._result(
                            command, ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE))
                    manifest = OwnedFirewallRuleManifest(request, rows[0], created_at, self._clock())
            # Context cleanup must also succeed before handing ownership to the caller.
            return FirewallCreateResult(request, self._result(command, ResponseOutcome.VERIFIED,
                ResponseReason.RULE_READBACK_VERIFIED, ResponseRuleState.PRESENT_ENABLED), manifest)
        except Exception as error:
            return FirewallCreateResult(request, self._failure(command, error, attempted, submitted))
        finally:
            self._lock.release()

    def _inspect(self, api: FirewallApi, manifest: OwnedFirewallRuleManifest) -> FirewallReadResult:
        try:
            rows = self._matches(api, manifest.rule)
        except FirewallApiError as error:
            if error.status is FirewallReadStatus.DUPLICATE:
                return FirewallReadResult(manifest, FirewallReadStatus.DUPLICATE, self._clock())
            raise
        status = FirewallReadStatus.ABSENT
        snapshot = None
        if len(rows) > 1:
            status = FirewallReadStatus.DUPLICATE
        elif rows:
            snapshot = rows[0]
            status = FirewallReadStatus.MATCHED if snapshot == manifest.rule else FirewallReadStatus.MISMATCH
        return FirewallReadResult(manifest, status, self._clock(), snapshot)

    def read(self, manifest: OwnedFirewallRuleManifest) -> FirewallReadResult:
        if type(manifest) is not OwnedFirewallRuleManifest:
            raise TypeError("inspection requires the originating typed manifest")
        try:
            with self._factory() as api:
                result = self._inspect(api, manifest)
            return result
        except Exception as error:
            status = error.status if isinstance(error, FirewallApiError) else FirewallReadStatus.READ_UNAVAILABLE
            # A backwards clock cannot produce a valid dated read. Never call it fresh.
            checked_at = self._clock()
            if checked_at < manifest.verified_at:
                status, checked_at = FirewallReadStatus.READ_UNAVAILABLE, manifest.verified_at
            return FirewallReadResult(manifest, status, checked_at)

    def remove(self, request: FirewallRemoveRequest) -> ResponseResult:
        if type(request) is not FirewallRemoveRequest:
            raise TypeError("removal requires an exact typed confirmed request and manifest")
        command = request.command
        if not self._confirmation(command, request.confirmation):
            return self._result(command, ResponseOutcome.NOT_ATTEMPTED, ResponseReason.STALE_CONFIRMATION)
        if not self._lock.acquire(blocking=False):
            return self._result(command, ResponseOutcome.NOT_ATTEMPTED, ResponseReason.BOUNDARY_UNAVAILABLE)
        attempted = False
        submitted = False
        try:
            with self._factory() as api:
                read_started_at = self._clock()
                fresh = self._inspect(api, request.manifest)
                if fresh.status is not FirewallReadStatus.MATCHED:
                    state = {FirewallReadStatus.ABSENT: ResponseRuleState.EXTERNALLY_MISSING,
                             FirewallReadStatus.DUPLICATE: ResponseRuleState.OWNERSHIP_CONFLICT,
                             FirewallReadStatus.MISMATCH: ResponseRuleState.EXTERNALLY_MODIFIED}.get(
                                 fresh.status, ResponseRuleState.UNKNOWN)
                    return self._result(command, ResponseOutcome.NOT_ATTEMPTED, _reason(fresh.status), state)
                def before_submit() -> None:
                    nonlocal attempted
                    if not removal_readback_matches(request, fresh, read_started_at=read_started_at,
                                                    now=self._clock()):
                        raise _StaleConfirmation()
                    attempted = True
                api.remove(request.manifest.rule, before_submit)
                if not attempted:
                    raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
                submitted = True
                if self._matches(api, request.manifest.rule):
                    return self._result(command, ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE)
            return self._result(command, ResponseOutcome.VERIFIED, ResponseReason.RULE_READBACK_VERIFIED,
                                ResponseRuleState.ABSENT)
        except Exception as error:
            return self._failure(command, error, attempted, submitted)
        finally:
            self._lock.release()
