"""NS-103 manual review/read projection. No Qt, SQL, COM or privilege grant.

Only explicitly injected lifecycle executors can dispatch. The desktop factory
supplies custody reads only: the unresolved production trust gate stays closed.
"""

from netsentinel.shared.enum_sources import enum_source
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP


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
    QT_TRANSLATE_NOOP('ResponseUi', 'Evidence is not a malware verdict. Shared/cloud/CDN IPs may serve legitimate services; blocking may break legitimate application behavior. Existing connections may not terminate immediately.\nWindows Firewall matches all instances and users at this executable path, including later replacement files. Local address and port are unrestricted; no NIC filter. The selected Windows profile may be inactive or change with VPN/network changes; current profile and policy effectiveness are unknown.\nFlow initiation direction is unobserved. Only matching outbound traffic is targeted. Possible DNS associations do not establish process/domain causality; no domain blocking. Disk identity is not loaded-image proof. Risk and retained TI are supporting context in their detail tabs; no lookup is triggered by this review.\nUntil manually removed: the rule persists after exit, crash and OS restart. No timed removal guarantee. Undo requires finalized local ownership, an unchanged rule and sufficient administrator permission. Undo removes only this rule; other rules may still block traffic.')
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
            return QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: exact executable path is missing.')
        if not self.remote_ip or self.remote_port is None:
            return QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: exact literal remote IP and remote port are required.')
        if self.source is None:
            return QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: exact connection session/lifecycle provenance is missing.')
        if self.source.status is not ResponseSourceStatus.AVAILABLE or self.source.quality is ObservationQuality.FAILED:
            return QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: source is expired/unavailable or collection failed.')
        try:
            # Validate the frozen scope; this test profile is never a user default.
            self.spec(ResponseProfile.PRIVATE)
        except (ValueError, TypeError):
            return QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: target is outside the supported desktop path/public literal IP/transport/port contract.')
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
    return (QT_TRANSLATE_NOOP('ResponseUi', 'Rule: {value1}\nAction requested: {value2} Windows Firewall rule\nExecutable: {value3}\nRemote IP: {value4} (IPv{value5})\nProtocol: {value6}\nRemote port: {value7}\nWindows Firewall profile: {value8} (current activity/effectiveness unknown)\nDirection: outbound\nRule action: block\nLifetime: until manually removed; expiry: none\nSource: connection; session {value9}; lifecycle {value10}\nObserved UTC: {value11}\nSource availability: {value12}\nMeasurement quality: {value13}\n').format(value1=command.rule_name, value2=enum_source(command.action, 'upper'), value3=s.program_path, value4=s.remote_ip, value5=ip_address(s.remote_ip).version, value6=s.transport.value.upper(), value7=s.remote_port, value8=enum_source(s.profile, 'title'), value9=source.session_id, value10=source.lifecycle_id, value11=source.observed_at.isoformat(), value12=enum_source(source.status), value13=enum_source(source.quality) if source.quality else QT_TRANSLATE_NOOP('ResponseUi', 'unknown')))


def result_text(result: ResponseResult, *, finalized: bool = True) -> str:
    if result.outcome is ResponseOutcome.VERIFIED and finalized:
        title = (QT_TRANSLATE_NOOP('ResponseUi', 'SUCCESS: rule created and read back; traffic effect not measured.')
                 if result.action is ResponseAction.CREATE else QT_TRANSLATE_NOOP('ResponseUi', 'ROLLED BACK / REMOVED: rule absence verified; connectivity not measured.'))
    elif result.outcome in {ResponseOutcome.PARTIAL, ResponseOutcome.OUTCOME_UNKNOWN} or (result.outcome is ResponseOutcome.VERIFIED and not finalized):
        title = QT_TRANSLATE_NOOP('ResponseUi', 'UNKNOWN / PARTIAL: reconciliation required. A rule may remain; do not blindly retry creation.')
    elif result.reason in {ResponseReason.PRIVILEGE_REQUIRED, ResponseReason.ACCESS_DENIED,
                           ResponseReason.UAC_CANCELLED, ResponseReason.BOUNDARY_UNAVAILABLE,
                           ResponseReason.POLICY_LIMITED, ResponseReason.REVALIDATION_REQUIRED}:
        title = QT_TRANSLATE_NOOP('ResponseUi', 'DENIED / UNAVAILABLE: permission or trusted response boundary required. Local monitoring and trust remain available.')
    else:
        title = QT_TRANSLATE_NOOP('ResponseUi', 'FAILURE / NOT ATTEMPTED: review the reason and current rule state before a new preview.')
    return QT_TRANSLATE_NOOP('ResponseUi', '{value1}\nOutcome: {value2}; reason: {value3}; rule state: {value4}.').format(value1=title, value2=enum_source(result.outcome), value3=enum_source(result.reason), value4=enum_source(result.rule_state))


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
                return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Undo unavailable: finalized ownership/current lifecycle/manifest is missing or unresolved.'))
            self._manifest, self._revision = operation.manifest, operation.revision
            command = replace(operation.command, command_id=uuid4(), action=ResponseAction.REMOVE,
                              prepared_at=self._clock(), selection_generation=generation)
        else:
            if selection is None:
                return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: select one exact connection target.'))
            unavailable = selection.unavailable()
            if unavailable:
                return ResponseUiReply(unavailable)
            if profile is None:
                return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Select exactly one Windows Firewall profile explicitly.'))
            if self.repository is None or self._identity is None:
                return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'BOUNDARY_UNAVAILABLE: trusted executable identity/write deployment is unavailable. No firewall write. Local trust remains available.'))
            identity = self._identity(selection)
            rule_id = uuid4()
            command = ResponseCommand(rule_id, rule_id, self.repository.store_id, ResponseAction.CREATE,
                selection.spec(profile), selection.source, identity, self._clock(), generation)  # type: ignore[arg-type]
        text = target_text(command) + QT_TRANSLATE_NOOP('ResponseUi', 'Preview UTC: {value1} (confirmation expires after five minutes)\n').format(value1=command.prepared_at.isoformat()) + WARNINGS
        text += QT_TRANSLATE_NOOP('ResponseUi', '\nPermission: action-time validation required; no automatic elevation.')
        if self.lifecycle is None:
            text += QT_TRANSLATE_NOOP('ResponseUi', ' Trusted write boundary unavailable; confirmation will not dispatch a firewall mutation.')
        self._preview = ResponsePreview(command, text)
        return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Review exact scope, then Confirm or Cancel.'), self._preview)

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
            return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Pending / reconciliation required: no verified completion receipt.'))
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
            target_text(o.command) + QT_TRANSLATE_NOOP('ResponseUi', 'Requested UTC: {value1}\nLifecycle: {value2}; current ownership/reconciliation: {value3}\nLast observation UTC: {value4}\n').format(value1=o.request.confirmation.confirmed_at.isoformat(), value2=enum_source(o.status), value3=enum_source(o.reconciliation), value4=o.reconciled_at.isoformat() if o.reconciled_at else QT_TRANSLATE_NOOP('ResponseUi', 'not reconciled'))
            + (result_text(o.result, finalized=o.status is Status.VERIFIED) if o.result else QT_TRANSLATE_NOOP('ResponseUi', 'Pending / reconciliation required'))
            + QT_TRANSLATE_NOOP('ResponseUi', '\nHistorical receipt is separate from current OS state; fresh equality is required for Undo.'), self._can_undo(o))
            for o in operations)
        audit = self.repository.audit(after_sequence=sequence, limit=100)
        return ResponseHistory(rows, tuple(QT_TRANSLATE_NOOP('ResponseUi', '{value1} | {value2} | {value3} | rule {value4} | {value5} | {value6} | {value7} | {value8}').format(value1=r.sequence, value2=r.at.isoformat(), value3=enum_source(r.action), value4=r.rule_id, value5=enum_source(r.event), value6=enum_source(r.status), value7=enum_source(r.reconciliation), value8=enum_source(r.outcome) if r.outcome else QT_TRANSLATE_NOOP('ResponseUi', 'pending'))
            for r in audit), operations[-1].operation_id if len(operations) == 64 else None,
            audit[-1].sequence if len(audit) == 100 else None)


def unavailable_reply() -> ResponseUiReply:
    return ResponseUiReply(QT_TRANSLATE_NOOP('ResponseUi', 'Unavailable: response storage/target service failed. No verified outcome; inspect retained history before retry.'))
