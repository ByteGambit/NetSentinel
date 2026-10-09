"""Test-only witness contract prototype, not ownership/removal authority.

Eligibility describes the proposed non-adversarial origin model only. Existing
production v1 manifests deliberately reject the changed description. No journal,
COM dispatch, privileged boundary or production promotion is implemented here.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
import json
import re
import secrets
from uuid import uuid4

from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallRuleSnapshot, ResponseConfirmation,
    ResponseSourceStatus,
    confirmation_matches, deserialize_response_command, expected_firewall_rule,
    serialize_response_command,
)

MAX_CLAIM_BYTES = 16 * 1024


def new_witness() -> str:
    return secrets.token_hex(32)  # CSPRNG, 256 bits independent of rule/command UUID.


def _utc(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("UTC provenance required")
    return value


def description(rule_id, witness):
    if type(witness) is not str or re.fullmatch(r"[0-9a-f]{64}", witness) is None:
        raise ValueError("canonical 256-bit witness required")
    return f"NetSentinel response witness v1 {rule_id} {witness}"


@dataclass(frozen=True, slots=True)
class WitnessPreparedCandidate:
    creation: FirewallCreateRequest = field(repr=False)
    expected_rule: FirewallRuleSnapshot = field(repr=False)
    witness: str = field(repr=False)
    prepared_at: datetime
    claim_version: int = 1

    def __post_init__(self):
        if (type(self.creation) is not FirewallCreateRequest
                or type(self.expected_rule) is not FirewallRuleSnapshot):
            raise TypeError("complete typed candidate required")
        if type(self.claim_version) is not int or self.claim_version != 1:
            raise ValueError("unsupported candidate version")
        _utc(self.prepared_at)
        if not confirmation_matches(self.creation.command, self.creation.confirmation, self.prepared_at):
            raise ValueError("candidate confirmation must bind provenance time")
        if (self.creation.command.source.status is not ResponseSourceStatus.AVAILABLE
                or self.creation.command.source.quality is ObservationQuality.FAILED):
            raise ValueError("candidate requires valid originating CREATE source")
        expected = replace(expected_firewall_rule(self.creation.command), description=description(
            self.creation.command.rule_id, self.witness))
        if self.expected_rule != expected:
            raise ValueError("candidate must bind every expected rule field and witness")


def prepare(command, at):
    # Standalone review operation: fresh random UUID4 identity and independent
    # witness allocated BEFORE caller persists or mutates anything.
    identity = uuid4()
    command = replace(command, command_id=identity, rule_id=identity)
    request = FirewallCreateRequest(command, ResponseConfirmation(command.fingerprint, at))
    witness = new_witness()
    expected = replace(expected_firewall_rule(command), description=description(identity, witness))
    return WitnessPreparedCandidate(request, expected, witness, at)


def encode(claim):
    if type(claim) is not WitnessPreparedCandidate:
        raise TypeError("complete candidate required")
    rule = {name: getattr(claim.expected_rule, name)
            for name in FirewallRuleSnapshot.__dataclass_fields__ if name != "spec"}
    payload = json.dumps({
        "claim_version": claim.claim_version,
        "command": json.loads(serialize_response_command(claim.creation.command)),
        "confirmation": {
            "fingerprint": claim.creation.confirmation.command_fingerprint,
            "confirmed_at": claim.creation.confirmation.confirmed_at.isoformat(timespec="microseconds"),
        },
        "expected_rule": rule, "witness": claim.witness,
        "prepared_at": claim.prepared_at.isoformat(timespec="microseconds"),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 1 <= len(payload) <= MAX_CLAIM_BYTES:
        raise ValueError("candidate exceeds bound")
    return payload


def _object(value, keys):
    if type(value) is not dict or set(value) != keys:
        raise ValueError("candidate fields mismatch")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate candidate field")
        result[key] = value
    return result


def _time(text):
    if type(text) is not str:
        raise TypeError("canonical UTC text required")
    at = _utc(datetime.fromisoformat(text))
    if at.isoformat(timespec="microseconds") != text:
        raise ValueError("canonical UTC text required")
    return at


def decode(payload):
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_CLAIM_BYTES:
        raise ValueError("invalid witness candidate")
    try:
        data = _object(json.loads(payload.decode("utf-8"), object_pairs_hook=_unique), {
            "claim_version", "command", "confirmation", "expected_rule", "witness", "prepared_at",
        })
        command = deserialize_response_command(json.dumps(data["command"], ensure_ascii=False).encode())
        confirmation = _object(data["confirmation"], {"fingerprint", "confirmed_at"})
        request = FirewallCreateRequest(command, ResponseConfirmation(
            confirmation["fingerprint"], _time(confirmation["confirmed_at"])))
        rule = _object(data["expected_rule"], set(FirewallRuleSnapshot.__dataclass_fields__) - {"spec"})
        if type(rule["interfaces"]) is not list:
            raise TypeError("immutable interfaces required")
        rule["interfaces"] = tuple(rule["interfaces"])
        return WitnessPreparedCandidate(request, FirewallRuleSnapshot(spec=command.spec, **rule),
                                        data["witness"], _time(data["prepared_at"]), data["claim_version"])
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise ValueError("invalid witness candidate") from None


def promotion_eligible(claim, committed_payload, fresh_rows, *, checked_at, now):
    """Test-only predicate, no manifest construction or authentication.

The harness supplies freshly enumerated complete OS snapshots and the original
pre-Add committed bytes. Values alone cannot authenticate either fact.
"""
    if type(claim) is not WitnessPreparedCandidate or type(committed_payload) is not bytes:
        return False
    try:
        if decode(committed_payload) != claim:
            return False
        if not claim.prepared_at <= _utc(checked_at) <= _utc(now):
            return False
    except (ValueError, TypeError):
        return False
    return (type(fresh_rows) is tuple and len(fresh_rows) == 1
            and type(fresh_rows[0]) is FirewallRuleSnapshot
            and fresh_rows[0] == claim.expected_rule)
