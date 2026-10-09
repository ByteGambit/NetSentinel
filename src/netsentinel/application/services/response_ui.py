"""NS-103 manual review/read projection. No Qt, SQL, COM or privilege grant.

Only explicitly injected lifecycle executors can dispatch. The desktop factory
supplies custody reads only: the unresolved production trust gate stays closed.
"""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID, uuid4

from netsentinel.application.response_lifecycle_service import ResponseLifecycleService
from netsentinel.application.response_ports import ResponseLifecycleRepository
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallRemoveRequest, OwnedFirewallRuleManifest,
    ResponseAction, ResponseCommand, ResponseConfirmation, ResponseFileIdentity,
    ResponseLifetime, ResponseLifetimeKind, ResponseOutcome, ResponseProfile,
    ResponseReason, ResponseResult, ResponseRuleSpec, ResponseSource,
    ResponseSourceStatus, ResponseTransport, confirmation_matches,
)
from netsentinel.domain.response_lifecycle import (
    ResponseOperation, ResponseOperationStatus as Status,
    ResponseReconciliation as Reconciliation,
)


WARNINGS = (
    "Evidence is not a malware verdict. Shared/cloud/CDN IPs may serve legitimate services; "
    "blocking may break legitimate application behavior. Existing connections may not terminate immediately.\n"
    "Windows Firewall matches all instances and users at this executable path, including later replacement files. "
    "Local address and port are unrestricted; no NIC filter. The selected Windows profile may be inactive "
    "or change with VPN/network changes; current profile and policy effectiveness are unknown.\n"
    "Flow initiation direction is unobserved. Only matching outbound traffic is targeted. "
    "Possible DNS associations do not establish process/domain causality; no domain blocking. "
    "Disk identity is not loaded-image proof. Risk and retained TI are supporting context in their detail tabs; "
    "no lookup is triggered by this review.\n"
    "Until manually removed: the rule persists after exit, crash and OS restart. No timed removal guarantee. "
    "Undo requires finalized local ownership, an unchanged rule and sufficient administrator permission. "
    "Undo removes only this rule; other rules may still block traffic."
)


@dataclass(frozen=True, slots=True)
class ResponseSelection:
    program_path: str | None = field(repr=False)
    remote_ip: str | None = field(repr=False)
    protocol: str
    remote_port: int | None
    source: ResponseSource | None = field(repr=False)

    def unavailable(self) -> str | None:
        if not self.program_path:
            return "Unavailable: exact executable path is missing."
        if not self.remote_ip or self.remote_port is None:
            return "Unavailable: exact literal remote IP and remote port are required."
        if self.source is None:
            return "Unavailable: exact connection session/lifecycle provenance is missing."
        if self.source.status is not ResponseSourceStatus.AVAILABLE or self.source.quality is ObservationQuality.FAILED:
            return "Unavailable: source is expired/unavailable or collection failed."
        try:
            # Validate the frozen scope; this test profile is never a user default.
            self.spec(ResponseProfile.PRIVATE)
        except (ValueError, TypeError):
            return "Unavailable: target is outside the supported desktop path/public literal IP/transport/port contract."
        return None

    def spec(self, profile: ResponseProfile) -> ResponseRuleSpec:
        return ResponseRuleSpec(self.program_path, self.remote_ip, ResponseTransport(self.protocol),  # type: ignore[arg-type]
            self.remote_port, profile, ResponseLifetime(ResponseLifetimeKind.UNTIL_MANUALLY_REMOVED))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ResponsePreview:
    command: ResponseCommand = field(repr=False)
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ResponseHistoryRow:
    operation_id: UUID
    rule_id: UUID
    text: str = field(repr=False)
    undo_available: bool


@dataclass(frozen=True, slots=True)
class ResponseHistory:
    rows: tuple[ResponseHistoryRow, ...] = ()
    audit: tuple[str, ...] = ()
    next_operation: UUID | None = None
    next_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class ResponseUiReply:
    message: str
    preview: ResponsePreview | None = None
    result: ResponseResult | None = None


def target_text(command: ResponseCommand) -> str:
    s, source = command.spec, command.source
    return (f"Rule: {command.rule_name}\nAction requested: {command.action.value.upper()} Windows Firewall rule\n"
        f"Executable: {s.program_path}\nRemote IP: {s.remote_ip} (IPv{ip_address(s.remote_ip).version})\n"
        f"Protocol: {s.transport.value.upper()}\nRemote port: {s.remote_port}\n"
        f"Windows Firewall profile: {s.profile.value.title()} (current activity/effectiveness unknown)\n"
        "Direction: outbound\nRule action: block\nLifetime: until manually removed; expiry: none\n"
        f"Source: connection; session {source.session_id}; lifecycle {source.lifecycle_id}\n"
        f"Observed UTC: {source.observed_at.isoformat()}\nSource availability: {source.status.value}\n"
        f"Measurement quality: {source.quality.value if source.quality else 'unknown'}\n")


def result_text(result: ResponseResult, *, finalized: bool = True) -> str:
    if result.outcome is ResponseOutcome.VERIFIED and finalized:
        title = ("SUCCESS: rule created and read back; traffic effect not measured."
                 if result.action is ResponseAction.CREATE else "ROLLED BACK / REMOVED: rule absence verified; connectivity not measured.")
    elif result.outcome in {ResponseOutcome.PARTIAL, ResponseOutcome.OUTCOME_UNKNOWN} or (result.outcome is ResponseOutcome.VERIFIED and not finalized):
        title = "UNKNOWN / PARTIAL: reconciliation required. A rule may remain; do not blindly retry creation."
    elif result.reason in {ResponseReason.PRIVILEGE_REQUIRED, ResponseReason.ACCESS_DENIED,
                           ResponseReason.UAC_CANCELLED, ResponseReason.BOUNDARY_UNAVAILABLE,
                           ResponseReason.POLICY_LIMITED, ResponseReason.REVALIDATION_REQUIRED}:
        title = "DENIED / UNAVAILABLE: permission or trusted response boundary required. Local monitoring and trust remain available."
    else:
        title = "FAILURE / NOT ATTEMPTED: review the reason and current rule state before a new preview."
    return f"{title}\nOutcome: {result.outcome.value}; reason: {result.reason.value}; rule state: {result.rule_state.value}."


class ResponseUiService:
    """Worker-owned single-use preview. Custody stays here, never in widgets."""

    def __init__(self, repository: ResponseLifecycleRepository | None = None, *,
                 lifecycle: ResponseLifecycleService | None = None,
                 file_identity: Callable[[ResponseSelection], ResponseFileIdentity] | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.repository, self.lifecycle = repository, lifecycle
        self._identity, self._clock = file_identity, clock
        self._preview: ResponsePreview | None = None
        self._manifest: OwnedFirewallRuleManifest | None = None
        self._revision: int | None = None

    def preview(self, selection: ResponseSelection | None, profile: ResponseProfile | None,
                generation: int, operation_id: UUID | None = None) -> ResponseUiReply:
        self._preview, self._manifest, self._revision = None, None, None
        if operation_id is not None:
            operation = self.repository.get(operation_id) if self.repository else None
            if operation is None or not self._can_undo(operation):
                return ResponseUiReply("Undo unavailable: finalized ownership/current lifecycle/manifest is missing or unresolved.")
            self._manifest, self._revision = operation.manifest, operation.revision
            command = replace(operation.command, command_id=uuid4(), action=ResponseAction.REMOVE,
                              prepared_at=self._clock(), selection_generation=generation)
        else:
            if selection is None:
                return ResponseUiReply("Unavailable: select one exact connection target.")
            unavailable = selection.unavailable()
            if unavailable:
                return ResponseUiReply(unavailable)
            if profile is None:
                return ResponseUiReply("Select exactly one Windows Firewall profile explicitly.")
            if self.repository is None or self._identity is None:
                return ResponseUiReply("BOUNDARY_UNAVAILABLE: trusted executable identity/write deployment is unavailable. No firewall write. Local trust remains available.")
            identity = self._identity(selection)
            rule_id = uuid4()
            command = ResponseCommand(rule_id, rule_id, self.repository.store_id, ResponseAction.CREATE,
                selection.spec(profile), selection.source, identity, self._clock(), generation)  # type: ignore[arg-type]
        text = target_text(command) + f"Preview UTC: {command.prepared_at.isoformat()} (confirmation expires after five minutes)\n" + WARNINGS
        text += "\nPermission: action-time validation required; no automatic elevation."
        if self.lifecycle is None:
            text += " Trusted write boundary unavailable; confirmation will not dispatch a firewall mutation."
        self._preview = ResponsePreview(command, text)
        return ResponseUiReply("Review exact scope, then Confirm or Cancel.", self._preview)

    def confirm(self, preview: ResponsePreview, generation: int, confirmed_at: datetime) -> ResponseUiReply:
        current, self._preview = self._preview, None  # consume even rejected confirmation
        command = preview.command
        confirmation = ResponseConfirmation(command.fingerprint, confirmed_at)
        reason = None
        if current != preview or generation != command.selection_generation or not confirmation_matches(command, confirmation, self._clock()):
            reason = ResponseReason.STALE_CONFIRMATION
        elif self.lifecycle is None:
            reason = ResponseReason.BOUNDARY_UNAVAILABLE
        if reason is not None:
            result = ResponseResult(command.command_id, command.action, ResponseOutcome.NOT_ATTEMPTED, reason)
            return ResponseUiReply(result_text(result), result=result)
        assert self.lifecycle is not None
        if command.action is ResponseAction.CREATE:
            operation = self.lifecycle.create(FirewallCreateRequest(command, confirmation))
        else:
            original = self.repository.get(self._manifest.creation.command.command_id) if self.repository and self._manifest else None
            if (original is None or original.revision != self._revision or not self._can_undo(original)
                    or original.manifest != self._manifest):
                result = ResponseResult(command.command_id, command.action, ResponseOutcome.NOT_ATTEMPTED, ResponseReason.OWNERSHIP_CONFLICT)
                return ResponseUiReply(result_text(result), result=result)
            assert self._manifest is not None
            operation = self.lifecycle.rollback(FirewallRemoveRequest(command, confirmation, self._manifest))
        if operation.result is None:
            return ResponseUiReply("Pending / reconciliation required: no verified completion receipt.")
        return ResponseUiReply(result_text(operation.result, finalized=operation.status is Status.VERIFIED), result=operation.result)

    def _can_undo(self, operation: ResponseOperation) -> bool:
        return (operation.command.action is ResponseAction.CREATE and operation.status is Status.VERIFIED
            and operation.manifest is not None and operation.reconciliation in {Reconciliation.EXACT, Reconciliation.PROMOTED}
            and self.repository is not None and not self.repository.has_verified_removal(operation.command.rule_id))

    def history(self, after: UUID | None = None, sequence: int = 0) -> ResponseHistory:
        if self.repository is None:
            return ResponseHistory()
        operations = self.repository.page(after=after, limit=64)
        rows = tuple(ResponseHistoryRow(o.operation_id, o.command.rule_id,
            target_text(o.command) + f"Requested UTC: {o.request.confirmation.confirmed_at.isoformat()}\n"
            f"Lifecycle: {o.status.value}; current ownership/reconciliation: {o.reconciliation.value}\n"
            f"Last observation UTC: {o.reconciled_at.isoformat() if o.reconciled_at else 'not reconciled'}\n"
            + (result_text(o.result, finalized=o.status is Status.VERIFIED) if o.result else "Pending / reconciliation required")
            + "\nHistorical receipt is separate from current OS state; fresh equality is required for Undo.", self._can_undo(o))
            for o in operations)
        audit = self.repository.audit(after_sequence=sequence, limit=100)
        return ResponseHistory(rows, tuple(f"{r.sequence} | {r.at.isoformat()} | {r.action.value} | rule {r.rule_id} | "
            f"{r.event.value} | {r.status.value} | {r.reconciliation.value} | {r.outcome.value if r.outcome else 'pending'}"
            for r in audit), operations[-1].operation_id if len(operations) == 64 else None,
            audit[-1].sequence if len(audit) == 100 else None)


def unavailable_reply() -> ResponseUiReply:
    return ResponseUiReply("Unavailable: response storage/target service failed. No verified outcome; inspect retained history before retry.")
