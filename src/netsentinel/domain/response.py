"""NS-100 pure manual response contract. No OS calls or mutation authority.

Commands and confirmations are untrusted local values, not administrator consent.
Serialization is for bounded local transport, never logs or support exports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
            },
            ResponseOutcome.FAILED: {ResponseReason.ACCESS_DENIED, ResponseReason.UAC_CANCELLED,
                                     ResponseReason.POLICY_LIMITED, ResponseReason.OWNERSHIP_CONFLICT},
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
