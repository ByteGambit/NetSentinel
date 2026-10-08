"""NS-100 adversarial scope/transport/confirmation tests, entirely offline."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
import json
from uuid import UUID

import pytest

from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    MAX_CONFIRMATION_AGE, MAX_RESPONSE_COMMAND_BYTES,
    ResponseAction, ResponseCommand, ResponseConfirmation, ResponseDirection,
    ResponseEffect, ResponseFileIdentity, ResponseLifetime, ResponseLifetimeKind, ResponseOutcome,
    ResponsePrivilegeAssessment, ResponsePrivilegeStatus, ResponseProfile,
    ResponseReason, ResponseResult, ResponseRuleSpec, ResponseRuleState,
    ResponseSource, ResponseSourceStatus, ResponseTransport,
    confirmation_matches, deserialize_response_command, serialize_response_command,
)

NOW = datetime(2026, 10, 8, 12, tzinfo=UTC)
RULE_ID = UUID("10000000-0000-4000-8000-000000000001")
UNDO_ID = UUID("10000000-0000-4000-8000-000000000002")
STORE_ID = UUID("10000000-0000-4000-8000-000000000003")
SESSION_ID = UUID("10000000-0000-4000-8000-000000000004")
LIFECYCLE_ID = UUID("10000000-0000-4000-8000-000000000005")


def spec() -> ResponseRuleSpec:
    # Public literals are syntax fixtures; no socket or DNS call is made.
    return ResponseRuleSpec(
        r"C:\Example\app.exe", "8.8.8.8", ResponseTransport.TCP, 443,
        ResponseProfile.PRIVATE, ResponseLifetime(ResponseLifetimeKind.UNTIL_MANUALLY_REMOVED),
    )


def command() -> ResponseCommand:
    return ResponseCommand(
        RULE_ID, RULE_ID, STORE_ID, ResponseAction.CREATE, spec(),
        ResponseSource(SESSION_ID, LIFECYCLE_ID, NOW - timedelta(seconds=30), ResponseSourceStatus.AVAILABLE,
                       ObservationQuality.COMPLETE),
        ResponseFileIdentity(1234, 5678, 100, NOW - timedelta(days=1)),
        NOW, 1,
    )


@pytest.mark.parametrize("profile", list(ResponseProfile))
@pytest.mark.parametrize("transport", list(ResponseTransport))
def test_explicit_scope_round_trip(profile, transport):
    original = replace(command(), spec=replace(spec(), profile=profile, transport=transport))
    encoded = serialize_response_command(original)
    restored = deserialize_response_command(encoded)
    assert restored == original
    assert serialize_response_command(restored) == encoded
    assert restored.rule_name == f"NetSentinel:{RULE_ID}"
    assert restored.spec.direction is ResponseDirection.OUTBOUND
    assert restored.spec.effect is ResponseEffect.BLOCK
    assert restored.spec.lifetime.expires_at is None


@pytest.mark.parametrize("ip,canonical", [
    ("8.8.8.8", "8.8.8.8"),
    ("2606:4700:4700:0000:0000:0000:0000:1111", "2606:4700:4700::1111"),
])
def test_one_ip_family_canonicalized_without_expansion(ip, canonical):
    target = replace(spec(), remote_ip=ip)
    assert target.remote_ip == canonical
    assert "remote_ips" not in json.loads(serialize_response_command(replace(command(), spec=target)))["spec"]


@pytest.mark.parametrize("value", [
    "", "example.test", "*.example.test", "8.8.8.8/32", "8.8.8.8,1.1.1.1", "*", "Any", "LocalSubnet",
    "8.8.8.8-8.8.8.9", " 8.8.8.8", "8.8.8.8\n", "008.008.008.008", "0.0.0.0", "127.0.0.1",
    "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "203.0.113.10",
    "192.0.2.1", "198.51.100.1", "224.0.0.1", "255.255.255.255", "240.0.0.1", "::", "::1",
    "fe80::1", "fe80::1%3", "ff02::1", "fc00::1", "2001:db8::1", "::ffff:8.8.8.8",
    "[2606:4700:4700::1111]", "8.8.8.8;Remove-Item", None, 123,
])
def test_non_global_nonliteral_or_expanding_destination_rejected(value):
    with pytest.raises(ValueError) as error:
        replace(spec(), remote_ip=value)
    assert "Remove-Item" not in str(error.value)


@pytest.mark.parametrize("value", [
    "", "app.exe", r"C:app.exe", r"\app.exe", r"\\server\share\app.exe", r"\\?\C:\Example\app.exe",
    r"\\.\C:\Example\app.exe", "C:/Example/app.exe", r"C:\Example\..\app.exe", r"C:\.\app.exe",
    r"C:\Example\\app.exe", r"C:\Example \app.exe", r"C:\Example.\app.exe", r"C:\Example\app.exe:stream",
    r"C:\%TEMP%\app.exe", r"C:\Example\*.exe", r"C:\Example\a?.exe", r"C:\Example\a|b.exe",
    r'C:\Example\"app.exe', r"C:\Example\app.dll", r"C:\CON\app.exe", r"C:\COM1.txt\app.exe",
    r"C:\NUL.exe", "C:\\Example\\a\x00.exe", "C:\\Example\\a\n.exe", "C:\\Example\\a\u202e.exe",
    "C:\\Example\\a\ud800.exe", "C:\\" + "a" * 4096 + ".exe", None,
])
def test_unsafe_path_syntax_rejected_without_access(value):
    with pytest.raises(ValueError):
        replace(spec(), program_path=value)


def test_unicode_path_is_exact_and_long_path_not_truncated():
    path = "C:\\Örnek\\" + "\u4e2d" * 180 + "\\app.exe"
    original = replace(command(), spec=replace(spec(), program_path=path))
    assert deserialize_response_command(serialize_response_command(original)).spec.program_path == path
    # The serialization is structured data, not a shell command.
    path_with_shell_chars = r"C:\Example\a;&$(echo).exe"
    assert replace(spec(), program_path=path_with_shell_chars).program_path == path_with_shell_chars


@pytest.mark.parametrize("field,value", [
    ("remote_port", True), ("remote_port", 0), ("remote_port", 65536), ("remote_port", "443"),
    ("remote_port", 443.0), ("profile", "private"), ("profile", 7), ("profile", (ResponseProfile.PRIVATE,)),
    ("transport", "tcp"), ("transport", "any"), ("direction", "inbound"), ("effect", "allow"),
    ("lifetime", None),
])
def test_scope_cannot_silently_widen_or_use_untyped_fields(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(spec(), **{field: value})


@pytest.mark.parametrize("kind,expiry", [
    ("until_manually_removed", None), ("expires_at", NOW), ("until_app_exit", None),
    (ResponseLifetimeKind.UNTIL_MANUALLY_REMOVED, NOW),
])
def test_no_false_temporary_expiry_promise(kind, expiry):
    with pytest.raises(ValueError):
        ResponseLifetime(kind, expiry)


def test_source_quality_and_expiry_remain_honest():
    old_source = replace(command().source, observed_at=NOW - timedelta(days=365),
                         status=ResponseSourceStatus.EXPIRED, quality=None)
    restored = deserialize_response_command(serialize_response_command(replace(command(), source=old_source)))
    assert restored.source == old_source
    assert restored.source.quality is None
    assert restored.source.status is ResponseSourceStatus.EXPIRED


@pytest.mark.parametrize("field,value", [
    ("command_id", UUID(int=0)), ("rule_id", UUID(int=0)), ("origin_store_id", UUID(int=0)),
    ("command_id", "10000000-0000-4000-8000-000000000001"), ("contract_version", True),
    ("contract_version", 2), ("selection_generation", True), ("selection_generation", 0),
    ("selection_generation", 2**63), ("prepared_at", NOW.replace(tzinfo=None)),
    ("prepared_at", NOW.astimezone(timezone(timedelta(hours=3)))),
    ("action", "create"), ("spec", None), ("source", None), ("rule_id", UNDO_ID),
])
def test_command_identity_version_and_time_validation(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(command(), **{field: value})


def test_undo_is_new_command_same_owned_rule_not_allow():
    undo = replace(command(), command_id=UNDO_ID, action=ResponseAction.REMOVE)
    restored = deserialize_response_command(serialize_response_command(undo))
    assert restored.rule_name == command().rule_name
    assert restored.spec == command().spec
    assert restored.command_id != restored.rule_id
    assert restored.action is ResponseAction.REMOVE
    with pytest.raises(ValueError):
        replace(command(), action=ResponseAction.REMOVE)


def test_future_observation_and_invalid_source_rejected():
    with pytest.raises(ValueError):
        replace(command(), source=replace(command().source, observed_at=NOW + timedelta(seconds=1)))
    with pytest.raises(ValueError):
        replace(command().source, session_id=UUID(int=0))
    with pytest.raises(TypeError):
        replace(command().source, status="available")
    with pytest.raises(TypeError):
        replace(command().source, quality="complete")


def test_confirmation_deadline_clock_anomaly_and_immutability():
    c = command()
    confirmation = ResponseConfirmation(c.fingerprint, NOW)
    assert confirmation_matches(c, confirmation, NOW)
    assert confirmation_matches(c, confirmation, NOW + MAX_CONFIRMATION_AGE)
    assert not confirmation_matches(c, confirmation, NOW + MAX_CONFIRMATION_AGE + timedelta(microseconds=1))
    assert not confirmation_matches(c, confirmation, NOW - timedelta(microseconds=1))
    assert not confirmation_matches(c, replace(confirmation, confirmed_at=NOW - timedelta(seconds=1)), NOW)
    with pytest.raises(FrozenInstanceError):
        c.selection_generation = 2
    with pytest.raises(ValueError):
        ResponseConfirmation("bad", NOW)


@pytest.mark.parametrize("change", [
    {"spec": replace(spec(), remote_ip="1.1.1.1")},
    {"spec": replace(spec(), program_path=r"C:\Example\other.exe")},
    {"spec": replace(spec(), remote_port=8443)},
    {"spec": replace(spec(), transport=ResponseTransport.UDP)},
    {"spec": replace(spec(), profile=ResponseProfile.PUBLIC)},
    {"selection_generation": 2},
    {"origin_store_id": UNDO_ID},
    {"prepared_at": NOW + timedelta(seconds=1)},
    {"command_id": UNDO_ID, "action": ResponseAction.REMOVE},
    {"source": replace(command().source, lifecycle_id=UNDO_ID)},
    {"source": replace(command().source, session_id=UNDO_ID)},
    {"source": replace(command().source, status=ResponseSourceStatus.UNAVAILABLE)},
    {"source": replace(command().source, quality=ObservationQuality.REDUCED)},
    {"source": replace(command().source, observed_at=NOW - timedelta(seconds=1))},
    {"file_identity": replace(command().file_identity, file_id=100)},
    {"file_identity": replace(command().file_identity, volume_serial=100)},
    {"file_identity": replace(command().file_identity, size_bytes=101)},
    {"file_identity": replace(command().file_identity, modified_at=NOW)},
])
def test_confirmation_binds_every_target_action_and_source_dimension(change):
    original = command()
    assert not confirmation_matches(replace(original, **change), ResponseConfirmation(original.fingerprint, NOW),
                                    NOW + timedelta(seconds=2))


def test_selection_a_b_a_does_not_reuse_confirmation():
    original = command()
    same_target_new_selection = replace(original, selection_generation=3)
    assert not confirmation_matches(same_target_new_selection, ResponseConfirmation(original.fingerprint, NOW), NOW)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(extra="hidden_secret"),
    lambda d: d.pop("source"),
    lambda d: d.update(version=True),
    lambda d: d.update(version=2),
    lambda d: d.update(selection_generation=True),
    lambda d: d.update(action="automatic"),
    lambda d: d.update(command_id=RULE_ID.hex),
    lambda d: d.update(command_id=str(RULE_ID).upper().replace("10000000", "ABC00000")),
    lambda d: d.update(prepared_at="2026-10-08T12:00:00Z"),
    lambda d: d["source"].update(secret="hidden_secret"),
    lambda d: d["source"].update(quality="assumed_complete"),
    lambda d: d["spec"].update(program_path=["hidden_secret"]),
    lambda d: d["spec"].update(remote_ip="hidden_secret"),
    lambda d: d["spec"].update(direction="inbound"),
    lambda d: d["spec"].update(effect="allow"),
    lambda d: d["spec"].update(profile="all"),
    lambda d: d["spec"].update(remote_port=True),
    lambda d: d["spec"].update(lifetime={"kind": "expires_at", "expires_at": NOW.isoformat()}),
    lambda d: d["spec"]["lifetime"].update(extra="hidden_secret"),
    lambda d: d["file_identity"].update(file_id=True),
    lambda d: d["file_identity"].update(file_id=2**128),
    lambda d: d["file_identity"].update(extra="hidden_secret"),
])
def test_decoder_strict_allowlist_and_sanitized_error(mutation):
    data = json.loads(serialize_response_command(command()))
    mutation(data)
    with pytest.raises(ValueError, match="^invalid response command payload$") as error:
        deserialize_response_command(json.dumps(data).encode())
    assert error.value.__cause__ is None


@pytest.mark.parametrize("payload", [
    b"", b"\xff", b"null", b"[]", b"NaN", b"{", b"[" * 2000,
    b"a" * (MAX_RESPONSE_COMMAND_BYTES + 1), "{}", bytearray(b"{}"),
])
def test_malformed_or_unbounded_payload_rejected(payload):
    with pytest.raises(ValueError, match="^invalid response command payload$"):
        deserialize_response_command(payload)


@pytest.mark.parametrize("old,new", [
    (b'"version":1', b'"version":1,"version":1'),
    (b'"remote_port":443', b'"remote_port":443,"remote_port":80'),
    (b'"expires_at":null', b'"expires_at":null,"expires_at":null'),
])
def test_duplicate_keys_at_every_depth_rejected(old, new):
    payload = serialize_response_command(command()).replace(old, new)
    with pytest.raises(ValueError, match="^invalid response command payload$"):
        deserialize_response_command(payload)


def test_repr_does_not_expose_target_or_origin_store():
    c = command()
    for value in (c, c.spec, c.source, ResponseConfirmation(c.fingerprint, NOW)):
        rendered = repr(value)
        assert c.spec.program_path not in rendered
        assert c.spec.remote_ip not in rendered
        assert str(STORE_ID) not in rendered
        assert c.fingerprint not in rendered


@pytest.mark.parametrize("action,state", [
    (ResponseAction.CREATE, ResponseRuleState.PRESENT_ENABLED),
    (ResponseAction.REMOVE, ResponseRuleState.ABSENT),
])
def test_verified_receipt_requires_correct_readback_not_traffic_claim(action, state):
    receipt = ResponseResult(RULE_ID, action, ResponseOutcome.VERIFIED, ResponseReason.RULE_READBACK_VERIFIED, state)
    assert receipt.rule_state is state
    assert not hasattr(receipt, "traffic_blocked")
    with pytest.raises(ValueError):
        replace(receipt, rule_state=ResponseRuleState.UNKNOWN)
    with pytest.raises(ValueError):
        replace(receipt, reason=ResponseReason.ACCESS_DENIED)


@pytest.mark.parametrize("outcome,reason,state", [
    (ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE, ResponseRuleState.UNKNOWN),
    (ResponseOutcome.PARTIAL, ResponseReason.OS_DB_DISAGREEMENT, ResponseRuleState.PRESENT_ENABLED),
    (ResponseOutcome.FAILED, ResponseReason.ACCESS_DENIED, ResponseRuleState.UNKNOWN),
    (ResponseOutcome.FAILED, ResponseReason.UAC_CANCELLED, ResponseRuleState.UNKNOWN),
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.OWNERSHIP_CONFLICT, ResponseRuleState.OWNERSHIP_CONFLICT),
])
def test_denied_degraded_and_partial_receipts_remain_separate(outcome, reason, state):
    result = ResponseResult(RULE_ID, ResponseAction.REMOVE, outcome, reason, state)
    assert result.outcome is outcome
    assert result.rule_state is state
    assert result.outcome is not ResponseOutcome.VERIFIED


def test_result_and_privilege_status_cannot_be_arbitrary_text():
    with pytest.raises(TypeError):
        ResponsePrivilegeAssessment("hidden_secret")
    with pytest.raises(TypeError):
        ResponseResult(RULE_ID, ResponseAction.CREATE, ResponseOutcome.FAILED, "hidden_secret")
    with pytest.raises(ValueError):
        ResponseResult(RULE_ID, ResponseAction.CREATE, ResponseOutcome.FAILED, ResponseReason.RULE_READBACK_VERIFIED)
    assert ResponsePrivilegeAssessment(ResponsePrivilegeStatus.PRIVILEGE_REQUIRED).status is ResponsePrivilegeStatus.PRIVILEGE_REQUIRED


@pytest.mark.parametrize("field,value", [
    ("volume_serial", -1), ("volume_serial", 2**64), ("file_id", -1), ("file_id", 2**128),
    ("file_id", True), ("size_bytes", -1), ("size_bytes", 2**63), ("size_bytes", 1.0),
    ("modified_at", NOW.replace(tzinfo=None)),
])
def test_file_identity_is_typed_bounded_local_metadata(field, value):
    with pytest.raises(ValueError):
        replace(command().file_identity, **{field: value})
