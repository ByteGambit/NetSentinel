"""NS-100 pure manual response contract. No OS calls or mutation authority.

Commands and confirmations are untrusted local values, not administrator consent.
Serialization is for bounded local transport, never logs or support exports.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from ipaddress import IPv6Address, ip_address
import json
import re
import unicodedata
from uuid import UUID

from netsentinel.domain.connections import ObservationQuality

RESPONSE_CONTRACT_VERSION = 1
MAX_RESPONSE_COMMAND_BYTES = 16 * 1024
MAX_RESPONSE_PATH_BYTES = 4096
MAX_CONFIRMATION_AGE = timedelta(minutes=5)


def _uuid(value: UUID) -> None:
    if type(value) is not UUID or value.int == 0:
        raise ValueError("response identity requires a nonzero UUID")


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("response time must be UTC-aware")
    return value.astimezone(UTC)


def _digest(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("response fingerprint requires canonical SHA-256")


def _program_path(value: str) -> None:
    """Syntactic local path checks only; no file access or identity guarantee."""
    if type(value) is not str or not value or any(
        unicodedata.category(c) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in value
    ):
        raise ValueError("response path requires bounded plain text")
    if len(value.encode("utf-8")) > MAX_RESPONSE_PATH_BYTES:
        raise ValueError("response path exceeds byte limit")
    if re.match(r"^[A-Za-z]:\\", value) is None or any(c in value[2:] for c in '<>:"/|?*%'):
        raise ValueError("response path requires an absolute local drive path")
    parts = value[3:].split("\\")
    for part in parts:
        if (not part or part in {".", ".."} or part.endswith((".", " "))
                or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?", part)):
            raise ValueError("response path contains an unsupported component")
    if not parts[-1].lower().endswith(".exe"):
        raise ValueError("response target requires a desktop executable path")


def _remote_ip(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 45 or "%" in value:
        raise ValueError("response target requires one literal public IP")
    try:
        address = ip_address(value)
    except ValueError:
        raise ValueError("response target requires one literal public IP") from None
    if (not address.is_global or address.is_reserved or address.is_multicast
            or address.is_unspecified or address.is_loopback or address.is_link_local
            or isinstance(address, IPv6Address) and address.ipv4_mapped is not None):
        raise ValueError("response target is outside the supported public unicast scope")
    return str(address)


class ResponseTransport(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class ResponseProfile(str, Enum):
    DOMAIN = "domain"
    PRIVATE = "private"
    PUBLIC = "public"


class ResponseLifetimeKind(str, Enum):
    UNTIL_MANUALLY_REMOVED = "until_manually_removed"


@dataclass(frozen=True, slots=True)
class ResponseLifetime:
    kind: ResponseLifetimeKind
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not ResponseLifetimeKind or self.expires_at is not None:
            raise ValueError("only explicit manual removal lifetime is supported")


class ResponseDirection(str, Enum):
    OUTBOUND = "outbound"


class ResponseEffect(str, Enum):
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class ResponseRuleSpec:
    """AND scope across program, IP, transport, port and one Windows profile.

    Every instance/user at this path can match. Local address/port and NIC are
    unconstrained. A network fingerprint, PID, hash or domain is not a filter.
    Path syntax alone does not establish an ordinary desktop file's identity.
    """

    program_path: str = field(repr=False)
    remote_ip: str = field(repr=False)
    transport: ResponseTransport
    remote_port: int
    profile: ResponseProfile
    lifetime: ResponseLifetime
    direction: ResponseDirection = ResponseDirection.OUTBOUND
    effect: ResponseEffect = ResponseEffect.BLOCK

    def __post_init__(self) -> None:
        _program_path(self.program_path)
        object.__setattr__(self, "remote_ip", _remote_ip(self.remote_ip))
        if (type(self.transport) is not ResponseTransport or type(self.profile) is not ResponseProfile
                or type(self.lifetime) is not ResponseLifetime
                or type(self.direction) is not ResponseDirection or type(self.effect) is not ResponseEffect):
            raise TypeError("response scope requires exact typed dimensions")
        if type(self.remote_port) is not int or not 1 <= self.remote_port <= 65535:
            raise ValueError("response requires one explicit remote port")


class ResponseSourceStatus(str, Enum):
    AVAILABLE = "available"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ResponseSource:
    """Exact connection provenance, never a PID-only or incident-wide target."""

    session_id: UUID = field(repr=False)
    lifecycle_id: UUID = field(repr=False)
    observed_at: datetime
    status: ResponseSourceStatus
    quality: ObservationQuality | None

    def __post_init__(self) -> None:
        _uuid(self.session_id)
        _uuid(self.lifecycle_id)
        object.__setattr__(self, "observed_at", _utc(self.observed_at))
        if type(self.status) is not ResponseSourceStatus:
            raise TypeError("response source availability must be typed")
        if self.quality is not None and type(self.quality) is not ObservationQuality:
            raise TypeError("response measurement quality must be typed or unknown")


class ResponseAction(str, Enum):
    CREATE = "create"
    REMOVE = "remove"  # Undo removes the same rule; never adds an ALLOW rule.


@dataclass(frozen=True, slots=True)
class ResponseFileIdentity:
    """Local preview snapshot, not an immutable application or loaded image.

    A future trusted reader must establish final path/no reparse/local drive/
    ordinary desktop class and compare this snapshot immediately before creation.
    Undo keeps original file provenance; removal validates the owned OS rule.
    Serialized metadata is never proof that those checks actually occurred.
    """

    volume_serial: int = field(repr=False)
    file_id: int = field(repr=False)
    size_bytes: int = field(repr=False)
    modified_at: datetime = field(repr=False)

    def __post_init__(self) -> None:
        for value, maximum in ((self.volume_serial, 2**64 - 1), (self.file_id, 2**128 - 1),
                               (self.size_bytes, 2**63 - 1)):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("response file metadata exceeds typed bounds")
        object.__setattr__(self, "modified_at", _utc(self.modified_at))


@dataclass(frozen=True, slots=True)
class ResponseCommand:
    command_id: UUID
    rule_id: UUID
    origin_store_id: UUID = field(repr=False)
    action: ResponseAction
    spec: ResponseRuleSpec = field(repr=False)
    source: ResponseSource = field(repr=False)
    file_identity: ResponseFileIdentity = field(repr=False)
    prepared_at: datetime
    selection_generation: int
    contract_version: int = RESPONSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        for value in (self.command_id, self.rule_id, self.origin_store_id):
            _uuid(value)
        if (type(self.action) is not ResponseAction or type(self.spec) is not ResponseRuleSpec
                or type(self.source) is not ResponseSource or type(self.file_identity) is not ResponseFileIdentity):
            raise TypeError("response command requires exact typed fields")
        if (type(self.contract_version) is not int or self.contract_version != RESPONSE_CONTRACT_VERSION
                or type(self.selection_generation) is not int or not 1 <= self.selection_generation <= 2**63 - 1):
            raise ValueError("invalid response version or selection generation")
        object.__setattr__(self, "prepared_at", _utc(self.prepared_at))
        if self.source.observed_at > self.prepared_at:
            raise ValueError("response observation cannot follow preview preparation")
        if self.action is ResponseAction.CREATE and self.command_id != self.rule_id:
            raise ValueError("creation identity must equal the allocated rule identity")
        if self.action is ResponseAction.REMOVE and self.command_id == self.rule_id:
            raise ValueError("Undo requires a separate command identity")

    @property
    def rule_name(self) -> str:
        return f"NetSentinel:{self.rule_id}"

    @property
    def fingerprint(self) -> str:
        return sha256(serialize_response_command(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class ResponseConfirmation:
    """Local preview binding only. Deserializing this is never privilege consent."""

    command_fingerprint: str = field(repr=False)
    confirmed_at: datetime

    def __post_init__(self) -> None:
        _digest(self.command_fingerprint)
        object.__setattr__(self, "confirmed_at", _utc(self.confirmed_at))


def confirmation_matches(command: ResponseCommand, confirmation: ResponseConfirmation, now: datetime) -> bool:
    if type(command) is not ResponseCommand or type(confirmation) is not ResponseConfirmation:
        raise TypeError("confirmation check requires exact typed values")
    now = _utc(now)
    return (confirmation.command_fingerprint == command.fingerprint
            and command.prepared_at <= confirmation.confirmed_at <= now
            and now - command.prepared_at <= MAX_CONFIRMATION_AGE)


class ResponsePrivilegeStatus(str, Enum):
    PRIVILEGE_REQUIRED = "privilege_required"
    ACCESS_DENIED = "access_denied"
    UAC_CANCELLED = "uac_cancelled"
    READ_UNAVAILABLE = "read_unavailable"
    POLICY_LIMITED = "policy_limited"
    BOUNDARY_UNAVAILABLE = "boundary_unavailable"
    REVALIDATION_REQUIRED = "revalidation_required"  # Never a write grant.


@dataclass(frozen=True, slots=True)
class ResponsePrivilegeAssessment:
    status: ResponsePrivilegeStatus

    def __post_init__(self) -> None:
        if type(self.status) is not ResponsePrivilegeStatus:
            raise TypeError("privilege assessment requires a typed status")


class ResponseOutcome(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    PARTIAL = "partial"
    VERIFIED = "verified"  # Rule postcondition, not traffic effect.


class ResponseRuleState(str, Enum):
    UNKNOWN = "unknown"
    PRESENT_ENABLED = "present_enabled"
    ABSENT = "absent"
    INACTIVE_PROFILE = "inactive_profile"
    EXTERNALLY_DISABLED = "externally_disabled"
    EXTERNALLY_MODIFIED = "externally_modified"
    EXTERNALLY_MISSING = "externally_missing"
    OWNERSHIP_CONFLICT = "ownership_conflict"


class ResponseReason(str, Enum):
    BOUNDARY_UNAVAILABLE = "boundary_unavailable"
    PRIVILEGE_REQUIRED = "privilege_required"
    ACCESS_DENIED = "access_denied"
    UAC_CANCELLED = "uac_cancelled"
    READ_UNAVAILABLE = "read_unavailable"
    POLICY_LIMITED = "policy_limited"
    REVALIDATION_REQUIRED = "revalidation_required"
    CONFIRMATION_REQUIRED = "confirmation_required"
    STALE_CONFIRMATION = "stale_confirmation"
    TARGET_UNAVAILABLE = "target_unavailable"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    READBACK_UNAVAILABLE = "readback_unavailable"
    OS_DB_DISAGREEMENT = "os_db_disagreement"
    RULE_READBACK_VERIFIED = "rule_readback_verified"
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED = "unsupported"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    OPERATION_FAILED = "operation_failed"


@dataclass(frozen=True, slots=True)
class ResponseResult:
    """Sanitized receipt shape; no free exception, target, secret or effect claim.

    Current OS rule state and command outcome are independent. Removal does not
    prove restored connectivity; creation does not prove a connection stopped.
    """

    command_id: UUID
    action: ResponseAction
    outcome: ResponseOutcome
    reason: ResponseReason
    rule_state: ResponseRuleState = ResponseRuleState.UNKNOWN

    def __post_init__(self) -> None:
        _uuid(self.command_id)
        if any(type(value) is not expected for value, expected in (
            (self.action, ResponseAction), (self.outcome, ResponseOutcome),
            (self.reason, ResponseReason), (self.rule_state, ResponseRuleState),
        )):
            raise TypeError("response result requires exact typed dimensions")
        verified = self.outcome is ResponseOutcome.VERIFIED
        if verified != (self.reason is ResponseReason.RULE_READBACK_VERIFIED):
            raise ValueError("verified result requires exact postcondition readback")
        if verified and self.rule_state is not (
            ResponseRuleState.PRESENT_ENABLED if self.action is ResponseAction.CREATE else ResponseRuleState.ABSENT
        ):
            raise ValueError("readback state does not match the command postcondition")
        expected = {
            ResponseOutcome.NOT_ATTEMPTED: {
                ResponseReason.BOUNDARY_UNAVAILABLE, ResponseReason.PRIVILEGE_REQUIRED,
                ResponseReason.ACCESS_DENIED, ResponseReason.UAC_CANCELLED, ResponseReason.READ_UNAVAILABLE,
                ResponseReason.POLICY_LIMITED, ResponseReason.REVALIDATION_REQUIRED,
                ResponseReason.CONFIRMATION_REQUIRED, ResponseReason.STALE_CONFIRMATION,
                ResponseReason.TARGET_UNAVAILABLE, ResponseReason.OWNERSHIP_CONFLICT, ResponseReason.STORAGE_UNAVAILABLE,
                ResponseReason.INVALID_REQUEST, ResponseReason.UNSUPPORTED, ResponseReason.BACKEND_UNAVAILABLE,
            },
            ResponseOutcome.FAILED: {ResponseReason.ACCESS_DENIED, ResponseReason.UAC_CANCELLED,
                                     ResponseReason.POLICY_LIMITED, ResponseReason.OWNERSHIP_CONFLICT,
                                     ResponseReason.BACKEND_UNAVAILABLE, ResponseReason.OPERATION_FAILED},
            ResponseOutcome.OUTCOME_UNKNOWN: {ResponseReason.READBACK_UNAVAILABLE},
            ResponseOutcome.PARTIAL: {ResponseReason.OS_DB_DISAGREEMENT},
            ResponseOutcome.VERIFIED: {ResponseReason.RULE_READBACK_VERIFIED},
        }
        if self.reason not in expected[self.outcome]:
            raise ValueError("response outcome and reason disagree")


def _command_values(command: ResponseCommand) -> dict[str, object]:
    s = command.spec
    return {
        "version": command.contract_version, "command_id": str(command.command_id),
        "rule_id": str(command.rule_id), "origin_store_id": str(command.origin_store_id),
        "action": command.action.value, "prepared_at": command.prepared_at.isoformat(timespec="microseconds"),
        "selection_generation": command.selection_generation,
        "file_identity": {
            "volume_serial": command.file_identity.volume_serial, "file_id": command.file_identity.file_id,
            "size_bytes": command.file_identity.size_bytes,
            "modified_at": command.file_identity.modified_at.isoformat(timespec="microseconds"),
        },
        "spec": {
            "program_path": s.program_path, "remote_ip": s.remote_ip, "transport": s.transport.value,
            "remote_port": s.remote_port, "profile": s.profile.value, "direction": s.direction.value,
            "effect": s.effect.value, "lifetime": {"kind": s.lifetime.kind.value, "expires_at": None},
        },
        "source": {
            "session_id": str(command.source.session_id), "lifecycle_id": str(command.source.lifecycle_id),
            "observed_at": command.source.observed_at.isoformat(timespec="microseconds"),
            "status": command.source.status.value,
            "quality": command.source.quality.value if command.source.quality is not None else None,
        },
    }


def serialize_response_command(command: ResponseCommand) -> bytes:
    if type(command) is not ResponseCommand:
        raise TypeError("serialization requires an exact response command")
    payload = json.dumps(_command_values(command), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_RESPONSE_COMMAND_BYTES:
        raise ValueError("response command exceeds byte limit")
    return payload


def _object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("response object fields mismatch")
    return value


def _text(value: object) -> str:
    if type(value) is not str:
        raise TypeError("response text must be a string")
    return value


def _decode_uuid(value: object) -> UUID:
    text = _text(value)
    parsed = UUID(text)
    if str(parsed) != text:
        raise ValueError("response UUID must be canonical")
    return parsed


def _decode_time(value: object) -> datetime:
    text = _text(value)
    parsed = _utc(datetime.fromisoformat(text))
    if parsed.isoformat(timespec="microseconds") != text:
        raise ValueError("response time must be canonical")
    return parsed


def _integer(value: object) -> int:
    if type(value) is not int:
        raise TypeError("response integer must be exact")
    return value


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def deserialize_response_command(payload: bytes) -> ResponseCommand:
    """Strict bounded UTF-8 JSON. Invalid input never leaks values in errors."""
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_RESPONSE_COMMAND_BYTES:
        raise ValueError("invalid response command payload")
    try:
        data = _object(json.loads(payload.decode("utf-8"), object_pairs_hook=_unique), {
            "version", "command_id", "rule_id", "origin_store_id", "action", "prepared_at",
            "selection_generation", "spec", "source", "file_identity",
        })
        spec = _object(data["spec"], {"program_path", "remote_ip", "transport", "remote_port", "profile", "direction", "effect", "lifetime"})
        lifetime = _object(spec["lifetime"], {"kind", "expires_at"})
        if lifetime["expires_at"] is not None:
            raise ValueError("timed response is unsupported")
        source = _object(data["source"], {"session_id", "lifecycle_id", "observed_at", "status", "quality"})
        identity = _object(data["file_identity"], {"volume_serial", "file_id", "size_bytes", "modified_at"})
        return ResponseCommand(
            _decode_uuid(data["command_id"]), _decode_uuid(data["rule_id"]), _decode_uuid(data["origin_store_id"]),
            ResponseAction(_text(data["action"])),
            ResponseRuleSpec(
                _text(spec["program_path"]), _text(spec["remote_ip"]), ResponseTransport(_text(spec["transport"])),
                _integer(spec["remote_port"]), ResponseProfile(_text(spec["profile"])),
                ResponseLifetime(ResponseLifetimeKind(_text(lifetime["kind"]))),
                ResponseDirection(_text(spec["direction"])), ResponseEffect(_text(spec["effect"])),
            ),
            ResponseSource(
                _decode_uuid(source["session_id"]), _decode_uuid(source["lifecycle_id"]), _decode_time(source["observed_at"]),
                ResponseSourceStatus(_text(source["status"])),
                ObservationQuality(_text(source["quality"])) if source["quality"] is not None else None,
            ),
            ResponseFileIdentity(_integer(identity["volume_serial"]), _integer(identity["file_id"]),
                                 _integer(identity["size_bytes"]), _decode_time(identity["modified_at"])),
            _decode_time(data["prepared_at"]), _integer(data["selection_generation"]), _integer(data["version"]),
        )
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise ValueError("invalid response command payload") from None


# NS-100 ownership handoff clarification. Values only: no backend or storage.
OWNED_FIREWALL_MANIFEST_VERSION = 1
MAX_OWNED_FIREWALL_MANIFEST_BYTES = 16 * 1024


def _rule_text(value: str) -> None:
    if (type(value) is not str or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
            or len(value.encode("utf-8")) > MAX_RESPONSE_PATH_BYTES):
        raise ValueError("firewall readback requires bounded plain text")


@dataclass(frozen=True, slots=True)
class FirewallRuleSnapshot:
    """Complete supported property readback, never a writable rule request.

    Spec contains application, remote address/port, protocol, profile, direction
    and effect. Other properties include the Rule2/Rule3 restrictions. A future
    adapter must reject unavailable/unsupported properties, broader spec shapes
    and unknown rule types rather than substitute defaults into this snapshot.
    Strings are normalized documented API representations, not COM objects.
    """

    name: str
    spec: ResponseRuleSpec = field(repr=False)
    description: str = field(repr=False)
    grouping: str = field(repr=False)
    enabled: bool
    service_name: str = field(repr=False)
    local_addresses: str = field(repr=False)
    local_ports: str = field(repr=False)
    icmp_types_and_codes: str = field(repr=False)
    interfaces: tuple[str, ...] = field(repr=False)
    interface_types: str = field(repr=False)
    edge_traversal: bool
    edge_traversal_options: int
    local_app_package_id: str = field(repr=False)
    local_user_owner: str = field(repr=False)
    local_user_authorized_list: str = field(repr=False)
    remote_user_authorized_list: str = field(repr=False)
    remote_machine_authorized_list: str = field(repr=False)
    secure_flags: int

    def __post_init__(self) -> None:
        if type(self.spec) is not ResponseRuleSpec:
            raise TypeError("firewall readback requires an exact typed scope")
        for value in (self.name, self.description, self.grouping, self.service_name,
                      self.local_addresses, self.local_ports, self.icmp_types_and_codes,
                      self.interface_types, self.local_app_package_id, self.local_user_owner,
                      self.local_user_authorized_list, self.remote_user_authorized_list,
                      self.remote_machine_authorized_list):
            _rule_text(value)
        if not self.name:
            raise ValueError("firewall readback requires a rule name")
        if type(self.interfaces) is not tuple or len(self.interfaces) > 64:
            raise TypeError("firewall interfaces require a bounded immutable tuple")
        for value in self.interfaces:
            _rule_text(value)
        if type(self.enabled) is not bool or type(self.edge_traversal) is not bool:
            raise TypeError("firewall readback booleans must be exact")
        for flag in (self.edge_traversal_options, self.secure_flags):
            if type(flag) is not int or not 0 <= flag <= 2**32 - 1:
                raise ValueError("firewall readback flags exceed typed bounds")


def expected_firewall_rule(command: ResponseCommand) -> FirewallRuleSnapshot:
    """Pure expected full scope. This is not evidence that a rule was created."""
    if type(command) is not ResponseCommand:
        raise TypeError("firewall expectation requires an exact response command")
    return FirewallRuleSnapshot(
        name=command.rule_name, spec=command.spec,
        description=f"NetSentinel response v1 {command.rule_id}", grouping="", enabled=True,
        service_name="", local_addresses="*", local_ports="*", icmp_types_and_codes="",
        interfaces=(), interface_types="All", edge_traversal=False, edge_traversal_options=0,
        local_app_package_id="", local_user_owner="", local_user_authorized_list="",
        remote_user_authorized_list="", remote_machine_authorized_list="", secure_flags=0,
    )


def _confirmed_action(command: ResponseCommand, confirmation: ResponseConfirmation,
                      action: ResponseAction) -> None:
    if (type(command) is not ResponseCommand or type(confirmation) is not ResponseConfirmation
            or command.action is not action):
        raise TypeError("firewall request requires the exact typed action and confirmation")
    if not confirmation_matches(command, confirmation, confirmation.confirmed_at):
        raise ValueError("firewall request confirmation does not bind its command")


@dataclass(frozen=True, slots=True)
class FirewallCreateRequest:
    command: ResponseCommand = field(repr=False)
    confirmation: ResponseConfirmation = field(repr=False)

    def __post_init__(self) -> None:
        _confirmed_action(self.command, self.confirmation, ResponseAction.CREATE)


def ownership_description(rule_id: UUID, witness: str) -> str:
    """Native-verified literal ASCII marker; not authority by itself."""
    _uuid(rule_id)
    _digest(witness)
    return f"NetSentinel response witness v1 {rule_id} {witness}"


@dataclass(frozen=True, slots=True)
class PreparedFirewallOwnershipClaim:
    """Pre-dispatch provenance. NEVER a finalized manifest or REMOVE authority."""

    creation: FirewallCreateRequest = field(repr=False)
    expected_rule: FirewallRuleSnapshot = field(repr=False)
    witness: str = field(repr=False)
    prepared_at: datetime
    claim_version: int = 1

    def __post_init__(self) -> None:
        if type(self.creation) is not FirewallCreateRequest or type(self.expected_rule) is not FirewallRuleSnapshot:
            raise TypeError("prepared ownership requires exact typed creation and snapshot")
        if type(self.claim_version) is not int or self.claim_version != 1:
            raise ValueError("unsupported prepared ownership version")
        object.__setattr__(self, "prepared_at", _utc(self.prepared_at))
        command = self.creation.command
        if command.rule_id.version != 4:
            raise ValueError("prepared ownership requires UUID4 identity")
        if not confirmation_matches(command, self.creation.confirmation, self.prepared_at):
            raise ValueError("prepared ownership confirmation is stale")
        if command.source.status is not ResponseSourceStatus.AVAILABLE or command.source.quality is ObservationQuality.FAILED:
            raise ValueError("prepared ownership requires available creation source")
        expected = replace(expected_firewall_rule(command), description=ownership_description(command.rule_id, self.witness))
        if self.expected_rule != expected:
            raise ValueError("prepared ownership must bind the complete witnessed state")


@dataclass(frozen=True, slots=True)
class OwnedFirewallRuleManifest:
    """Originating verified creation evidence held by the caller, not storage.

    Construction/deserialization cannot authenticate provenance or grant writes.
    NS-101 produces this only after its own create and complete unique readback;
    NS-102 will durably store/recover it. Name/UUID cannot reconstruct ownership.
    """

    creation: FirewallCreateRequest = field(repr=False)
    rule: FirewallRuleSnapshot = field(repr=False)
    created_at: datetime | None
    verified_at: datetime
    manifest_version: int = OWNED_FIREWALL_MANIFEST_VERSION
    prepared_claim: PreparedFirewallOwnershipClaim | None = field(default=None, repr=False)
    dispatch_intent_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.creation) is not FirewallCreateRequest or type(self.rule) is not FirewallRuleSnapshot:
            raise TypeError("ownership requires exact originating creation and full readback")
        if type(self.manifest_version) is not int or self.manifest_version not in {1, 2}:
            raise ValueError("unsupported ownership manifest version")
        object.__setattr__(self, "verified_at", _utc(self.verified_at))
        if self.created_at is not None:
            object.__setattr__(self, "created_at", _utc(self.created_at))
        if self.manifest_version == 1:
            if self.prepared_claim is not None or self.created_at is None or self.dispatch_intent_at is not None:
                raise ValueError("legacy ownership requires actual creation time without a claim")
            expected = expected_firewall_rule(self.creation.command)
        else:
            if (type(self.prepared_claim) is not PreparedFirewallOwnershipClaim
                    or self.prepared_claim.creation != self.creation
                    or self.verified_at < self.prepared_claim.prepared_at):
                raise ValueError("witnessed ownership requires its original prepared claim")
            expected = self.prepared_claim.expected_rule
            if self.created_at is not None and self.created_at < self.prepared_claim.prepared_at:
                raise ValueError("creation predates prepared provenance")
            if self.dispatch_intent_at is not None:
                object.__setattr__(self, "dispatch_intent_at", _utc(self.dispatch_intent_at))
                if not self.prepared_claim.prepared_at <= self.dispatch_intent_at <= (
                        self.created_at if self.created_at is not None else self.verified_at):
                    raise ValueError("dispatch intent disagrees with ownership times")
        if self.created_at is not None and (
                not confirmation_matches(self.creation.command, self.creation.confirmation, self.created_at)
                or self.verified_at < self.created_at):
            raise ValueError("ownership creation and readback times disagree")
        if (self.creation.command.source.status is not ResponseSourceStatus.AVAILABLE
                or self.creation.command.source.quality is ObservationQuality.FAILED):
            raise ValueError("ownership creation requires an available source")
        if self.rule != expected:
            raise ValueError("ownership readback does not match the full expected rule")


@dataclass(frozen=True, slots=True)
class FirewallCreateResult:
    request: FirewallCreateRequest = field(repr=False)
    result: ResponseResult
    manifest: OwnedFirewallRuleManifest | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.request) is not FirewallCreateRequest or type(self.result) is not ResponseResult:
            raise TypeError("firewall creation handoff requires exact typed values")
        if (self.result.action is not ResponseAction.CREATE
                or self.result.command_id != self.request.command.command_id):
            raise ValueError("creation receipt does not bind its request")
        if self.result.outcome is ResponseOutcome.VERIFIED:
            if type(self.manifest) is not OwnedFirewallRuleManifest or self.manifest.creation != self.request:
                raise ValueError("verified creation requires its exact originating manifest")
        elif self.manifest is not None:
            raise ValueError("unverified creation cannot grant ownership")


@dataclass(frozen=True, slots=True)
class FirewallRemoveRequest:
    command: ResponseCommand = field(repr=False)
    confirmation: ResponseConfirmation = field(repr=False)
    manifest: OwnedFirewallRuleManifest = field(repr=False)

    def __post_init__(self) -> None:
        _confirmed_action(self.command, self.confirmation, ResponseAction.REMOVE)
        if type(self.manifest) is not OwnedFirewallRuleManifest:
            raise TypeError("removal requires the originating typed manifest")
        original = self.manifest.creation.command
        if (self.command.rule_id != original.rule_id or self.command.origin_store_id != original.origin_store_id
                or self.command.spec != original.spec or self.command.file_identity != original.file_identity
                or self.command.source.session_id != original.source.session_id
                or self.command.source.lifecycle_id != original.source.lifecycle_id
                or self.command.source.observed_at != original.source.observed_at
                or self.command.source.quality != original.source.quality
                or self.command.prepared_at < self.manifest.verified_at):
            raise ValueError("removal command does not bind the originating manifest")


class FirewallReadStatus(str, Enum):
    MATCHED = "matched"  # Full unique supported readback, not traffic-effect proof.
    ABSENT = "absent"  # Discovery only; never proof of a successful removal.
    MISMATCH = "mismatch"
    DUPLICATE = "duplicate"
    ACCESS_DENIED = "access_denied"
    READ_UNAVAILABLE = "read_unavailable"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    UNSUPPORTED = "unsupported"
    INVALID_REQUEST = "invalid_request"


@dataclass(frozen=True, slots=True)
class FirewallReadResult:
    manifest: OwnedFirewallRuleManifest = field(repr=False)
    status: FirewallReadStatus
    checked_at: datetime
    snapshot: FirewallRuleSnapshot | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.manifest) is not OwnedFirewallRuleManifest or type(self.status) is not FirewallReadStatus:
            raise TypeError("firewall inspection requires exact typed manifest and status")
        object.__setattr__(self, "checked_at", _utc(self.checked_at))
        if self.checked_at < self.manifest.verified_at:
            raise ValueError("firewall inspection cannot predate the originating readback")
        if self.status in {FirewallReadStatus.MATCHED, FirewallReadStatus.MISMATCH}:
            if type(self.snapshot) is not FirewallRuleSnapshot:
                raise TypeError("firewall equality status requires complete supported readback")
            if (self.snapshot == self.manifest.rule) != (self.status is FirewallReadStatus.MATCHED):
                raise ValueError("firewall inspection status contradicts full readback equality")
        elif self.snapshot is not None:
            raise ValueError("unavailable/ambiguous inspection cannot supply an equality snapshot")


def removal_readback_matches(request: FirewallRemoveRequest, readback: FirewallReadResult, *,
                             read_started_at: datetime, now: datetime) -> bool:
    """Pure guard for the future adapter's OWN fresh read in this removal call.

    Caller-supplied/cached readback is never authority. Native implementations
    still own unique enumeration, complete property access and external-edit
    race handling; this predicate cannot authenticate values or perform removal.
    """
    if type(request) is not FirewallRemoveRequest or type(readback) is not FirewallReadResult:
        raise TypeError("removal comparison requires exact typed values")
    read_started_at, now = _utc(read_started_at), _utc(now)
    return (readback.manifest == request.manifest and readback.status is FirewallReadStatus.MATCHED
            and request.confirmation.confirmed_at <= read_started_at <= readback.checked_at <= now
            and confirmation_matches(request.command, request.confirmation, now))


def _manifest_rule_values(rule: FirewallRuleSnapshot) -> dict[str, object]:
    # Scope is stored once inside the original command and bound on decode.
    return {name: getattr(rule, name) for name in FirewallRuleSnapshot.__dataclass_fields__ if name != "spec"}


def serialize_owned_firewall_manifest(manifest: OwnedFirewallRuleManifest) -> bytes:
    """Bounded local sensitive transport, never a log/export or persistence call."""
    if type(manifest) is not OwnedFirewallRuleManifest:
        raise TypeError("serialization requires an exact ownership manifest")
    values = {
        "version": manifest.manifest_version, "command": _command_values(manifest.creation.command),
        "confirmation": {
            "fingerprint": manifest.creation.confirmation.command_fingerprint,
            "confirmed_at": manifest.creation.confirmation.confirmed_at.isoformat(timespec="microseconds"),
        },
        "rule": _manifest_rule_values(manifest.rule),
        "created_at": manifest.created_at.isoformat(timespec="microseconds") if manifest.created_at is not None else None,
        "verified_at": manifest.verified_at.isoformat(timespec="microseconds"),
    }
    if manifest.manifest_version == 2:
        if manifest.prepared_claim is None:
            raise ValueError("missing prepared ownership")
        values["prepared_claim"] = json.loads(serialize_prepared_firewall_claim(manifest.prepared_claim))
        values["dispatch_intent_at"] = (manifest.dispatch_intent_at.isoformat(timespec="microseconds")
                                        if manifest.dispatch_intent_at is not None else None)
    payload = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_OWNED_FIREWALL_MANIFEST_BYTES:
        raise ValueError("ownership manifest exceeds byte limit")
    return payload


def deserialize_owned_firewall_manifest(payload: bytes) -> OwnedFirewallRuleManifest:
    """Strict v1 roundtrip. Valid bytes do not prove trusted originating custody."""
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_OWNED_FIREWALL_MANIFEST_BYTES:
        raise ValueError("invalid ownership manifest payload")
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique)
        if type(raw) is not dict:
            raise ValueError("invalid ownership object")
        keys = {"version", "command", "confirmation", "rule", "created_at", "verified_at"}
        if raw.get("version") == 2:
            keys.update({"prepared_claim", "dispatch_intent_at"})
        data = _object(raw, keys)
        command = deserialize_response_command(json.dumps(data["command"], ensure_ascii=False).encode("utf-8"))
        confirmation = _object(data["confirmation"], {"fingerprint", "confirmed_at"})
        creation = FirewallCreateRequest(command, ResponseConfirmation(
            _text(confirmation["fingerprint"]), _decode_time(confirmation["confirmed_at"]),
        ))
        rule = _object(data["rule"], set(FirewallRuleSnapshot.__dataclass_fields__) - {"spec"})
        interfaces = rule["interfaces"]
        if type(interfaces) is not list:
            raise TypeError("invalid interface transport")
        # Decode each field explicitly so framework objects/untyped casts cannot enter.
        snapshot = FirewallRuleSnapshot(
            name=_text(rule["name"]), spec=command.spec, description=_text(rule["description"]),
            grouping=_text(rule["grouping"]), enabled=_boolean(rule["enabled"]),
            service_name=_text(rule["service_name"]), local_addresses=_text(rule["local_addresses"]),
            local_ports=_text(rule["local_ports"]), icmp_types_and_codes=_text(rule["icmp_types_and_codes"]),
            interfaces=tuple(_text(value) for value in interfaces),
            interface_types=_text(rule["interface_types"]), edge_traversal=_boolean(rule["edge_traversal"]),
            edge_traversal_options=_integer(rule["edge_traversal_options"]),
            local_app_package_id=_text(rule["local_app_package_id"]), local_user_owner=_text(rule["local_user_owner"]),
            local_user_authorized_list=_text(rule["local_user_authorized_list"]),
            remote_user_authorized_list=_text(rule["remote_user_authorized_list"]),
            remote_machine_authorized_list=_text(rule["remote_machine_authorized_list"]),
            secure_flags=_integer(rule["secure_flags"]),
        )
        claim = (deserialize_prepared_firewall_claim(json.dumps(data["prepared_claim"], ensure_ascii=False).encode("utf-8"))
                 if data["version"] == 2 else None)
        return OwnedFirewallRuleManifest(creation, snapshot,
                                         _decode_time(data["created_at"]) if data["created_at"] is not None else None,
                                         _decode_time(data["verified_at"]), _integer(data["version"]), claim,
                                         _decode_time(data["dispatch_intent_at"])
                                         if claim is not None and data["dispatch_intent_at"] is not None else None)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise ValueError("invalid ownership manifest payload") from None


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise TypeError("response boolean must be exact")
    return value


def serialize_prepared_firewall_claim(claim: PreparedFirewallOwnershipClaim) -> bytes:
    if type(claim) is not PreparedFirewallOwnershipClaim:
        raise TypeError("exact prepared claim required")
    # Reuse the strict v1 manifest envelope codec to transport the typed request
    # and full rule, then separately validate PREPARED (never construct ownership).
    values = {
        "claim_version": claim.claim_version, "command": _command_values(claim.creation.command),
        "confirmation": {"fingerprint": claim.creation.confirmation.command_fingerprint,
                         "confirmed_at": claim.creation.confirmation.confirmed_at.isoformat(timespec="microseconds")},
        "rule": _manifest_rule_values(claim.expected_rule), "witness": claim.witness,
        "prepared_at": claim.prepared_at.isoformat(timespec="microseconds"),
    }
    payload = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_OWNED_FIREWALL_MANIFEST_BYTES:
        raise ValueError("prepared claim exceeds byte limit")
    return payload


def deserialize_prepared_firewall_claim(payload: bytes) -> PreparedFirewallOwnershipClaim:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_OWNED_FIREWALL_MANIFEST_BYTES:
        raise ValueError("invalid prepared claim payload")
    try:
        data = _object(json.loads(payload.decode("utf-8"), object_pairs_hook=_unique), {
            "claim_version", "command", "confirmation", "rule", "witness", "prepared_at",
        })
        command = deserialize_response_command(json.dumps(data["command"], ensure_ascii=False).encode("utf-8"))
        confirmation = _object(data["confirmation"], {"fingerprint", "confirmed_at"})
        request = FirewallCreateRequest(command, ResponseConfirmation(
            _text(confirmation["fingerprint"]), _decode_time(confirmation["confirmed_at"])))
        rule = _object(data["rule"], set(FirewallRuleSnapshot.__dataclass_fields__) - {"spec"})
        if type(rule["interfaces"]) is not list:
            raise ValueError("invalid prepared interfaces")
        rule["interfaces"] = tuple(_text(value) for value in rule["interfaces"])
        # All snapshot fields have exact runtime validation in their constructor.
        snapshot = FirewallRuleSnapshot(spec=command.spec, **rule)  # type: ignore[arg-type]
        return PreparedFirewallOwnershipClaim(request, snapshot, _text(data["witness"]),
                                               _decode_time(data["prepared_at"]), _integer(data["claim_version"]))
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise ValueError("invalid prepared claim payload") from None


@dataclass(frozen=True, slots=True)
class PreparedFirewallReadResult:
    claim: PreparedFirewallOwnershipClaim = field(repr=False)
    status: FirewallReadStatus
    checked_at: datetime
    snapshot: FirewallRuleSnapshot | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.claim) is not PreparedFirewallOwnershipClaim or type(self.status) is not FirewallReadStatus:
            raise TypeError("prepared inspection requires exact typed provenance and status")
        object.__setattr__(self, "checked_at", _utc(self.checked_at))
        if self.checked_at < self.claim.prepared_at:
            raise ValueError("prepared inspection predates provenance")
        if self.status in {FirewallReadStatus.MATCHED, FirewallReadStatus.MISMATCH}:
            if type(self.snapshot) is not FirewallRuleSnapshot:
                raise TypeError("prepared equality requires complete supported snapshot")
            if (self.snapshot == self.claim.expected_rule) != (self.status is FirewallReadStatus.MATCHED):
                raise ValueError("prepared inspection contradicts full equality")
        elif self.snapshot is not None:
            raise ValueError("ambiguous prepared inspection cannot supply an equality snapshot")
