"""NS-100 ownership handoff values: no COM, storage, sockets or firewall writes."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import json

import pytest

from netsentinel.domain.response import (
    MAX_OWNED_FIREWALL_MANIFEST_BYTES, FirewallCreateRequest, FirewallCreateResult,
    FirewallReadResult, FirewallReadStatus, FirewallRemoveRequest, OwnedFirewallRuleManifest,
    ResponseAction, ResponseConfirmation, ResponseOutcome, ResponseReason, ResponseResult,
    ResponseRuleState, ResponseSourceStatus, ResponseProfile, ResponseTransport,
    deserialize_owned_firewall_manifest,
    expected_firewall_rule, removal_readback_matches, serialize_owned_firewall_manifest,
)
from tests.unit.domain.test_response import NOW, STORE_ID, UNDO_ID, command, spec


def creation():
    c = command()
    return FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, NOW))


def manifest():
    request = creation()
    return OwnedFirewallRuleManifest(request, expected_firewall_rule(request.command),
                                     NOW + timedelta(seconds=1), NOW + timedelta(seconds=2))


def removal(owned=None):
    owned = manifest() if owned is None else owned
    c = replace(owned.creation.command, command_id=UNDO_ID, action=ResponseAction.REMOVE,
                prepared_at=NOW + timedelta(seconds=3), selection_generation=2)
    return FirewallRemoveRequest(c, ResponseConfirmation(c.fingerprint, c.prepared_at), owned)


def receipt(outcome=ResponseOutcome.VERIFIED, reason=ResponseReason.RULE_READBACK_VERIFIED):
    state = ResponseRuleState.PRESENT_ENABLED if outcome is ResponseOutcome.VERIFIED else ResponseRuleState.UNKNOWN
    return ResponseResult(command().command_id, ResponseAction.CREATE, outcome, reason, state)


def test_manifest_and_nested_values_are_immutable():
    owned = manifest()
    for value, attribute, replacement in (
        (owned, "verified_at", NOW), (owned.rule, "enabled", False),
        (owned.creation, "command", None), (owned.creation.command.spec, "remote_ip", "1.1.1.1"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, attribute, replacement)
    assert type(owned.rule.interfaces) is tuple


@pytest.mark.parametrize("field,value", [
    ("name", "OtherRule"), ("description", "Other description"), ("grouping", "OtherGroup"),
    ("enabled", False), ("service_name", "OtherService"), ("local_addresses", "10.0.0.1"),
    ("local_ports", "80"), ("icmp_types_and_codes", "8:*"), ("interfaces", ("OtherNIC",)),
    ("interface_types", "Wireless"), ("edge_traversal", True), ("edge_traversal_options", 1),
    ("local_app_package_id", "OtherPackage"), ("local_user_owner", "OtherOwner"),
    ("local_user_authorized_list", "OtherUsers"), ("remote_user_authorized_list", "OtherUsers"),
    ("remote_machine_authorized_list", "OtherMachines"), ("secure_flags", 1),
    ("spec", replace(spec(), remote_port=80)), ("spec", replace(spec(), remote_ip="1.1.1.1")),
    ("spec", replace(spec(), program_path=r"C:\Example\other.exe")),
    ("spec", replace(spec(), profile=ResponseProfile.PUBLIC)),
    ("spec", replace(spec(), transport=ResponseTransport.UDP)),
])
def test_every_readback_field_is_bound_and_mismatch_denies_removal(field, value):
    owned = manifest()
    changed = replace(owned.rule, **{field: value})
    with pytest.raises(ValueError, match="full expected rule"):
        replace(owned, rule=changed)
    with pytest.raises(ValueError, match="full readback equality"):
        FirewallReadResult(owned, FirewallReadStatus.MATCHED, NOW + timedelta(seconds=4), changed)
    drift = FirewallReadResult(owned, FirewallReadStatus.MISMATCH, NOW + timedelta(seconds=4), changed)
    assert not removal_readback_matches(removal(owned), drift,
                                        read_started_at=NOW + timedelta(seconds=3), now=drift.checked_at)


@pytest.mark.parametrize("field,value", [
    ("name", ""), ("description", "hidden\ntext"), ("grouping", "x" * 4097),
    ("service_name", object()), ("interfaces", ["NIC"]), ("interfaces", ("NIC",) * 65),
    ("interfaces", (object(),)), ("enabled", 1), ("edge_traversal", 0),
    ("edge_traversal_options", True), ("secure_flags", -1), ("secure_flags", 2**32), ("spec", None),
])
def test_snapshot_rejects_malformed_or_mutable_framework_values(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(manifest().rule, **{field: value})


@pytest.mark.parametrize("field,value", [
    ("creation", None), ("rule", None), ("manifest_version", True), ("manifest_version", 2),
    ("created_at", NOW - timedelta(seconds=1)), ("created_at", NOW + timedelta(minutes=6)),
    ("verified_at", NOW), ("verified_at", NOW.replace(tzinfo=None)),
])
def test_manifest_origin_version_and_time_bounds(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(manifest(), **{field: value})


def test_unavailable_creation_source_cannot_become_ownership():
    c = replace(command(), source=replace(command().source, status=ResponseSourceStatus.EXPIRED))
    request = FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, NOW))
    with pytest.raises(ValueError, match="available source"):
        OwnedFirewallRuleManifest(request, expected_firewall_rule(c), NOW, NOW)


def test_verified_creation_carries_only_its_exact_manifest():
    owned = manifest()
    result = FirewallCreateResult(owned.creation, receipt(), owned)
    assert result.manifest is owned
    with pytest.raises(ValueError, match="originating manifest"):
        FirewallCreateResult(owned.creation, receipt())
    other_c = replace(command(), origin_store_id=UNDO_ID)
    other_request = FirewallCreateRequest(other_c, ResponseConfirmation(other_c.fingerprint, NOW))
    with pytest.raises(ValueError, match="originating manifest"):
        FirewallCreateResult(other_request, receipt(), owned)


@pytest.mark.parametrize("outcome,reason", [
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.ACCESS_DENIED),
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.PRIVILEGE_REQUIRED),
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.INVALID_REQUEST),
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.UNSUPPORTED),
    (ResponseOutcome.NOT_ATTEMPTED, ResponseReason.BACKEND_UNAVAILABLE),
    (ResponseOutcome.FAILED, ResponseReason.OPERATION_FAILED),
    (ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE),
    (ResponseOutcome.PARTIAL, ResponseReason.OS_DB_DISAGREEMENT),
])
def test_denied_failed_unknown_partial_creation_cannot_grant_ownership(outcome, reason):
    result = receipt(outcome, reason)
    assert FirewallCreateResult(creation(), result).manifest is None
    with pytest.raises(ValueError, match="unverified creation"):
        FirewallCreateResult(creation(), result, manifest())


@pytest.mark.parametrize("bad", [None, command().rule_name, command().rule_id, STORE_ID, object()])
def test_name_uuid_or_untyped_value_cannot_replace_originating_manifest(bad):
    with pytest.raises(TypeError, match="originating typed manifest"):
        replace(removal(), manifest=bad)
    with pytest.raises(TypeError):
        FirewallReadResult(bad, FirewallReadStatus.ABSENT, NOW)


def test_manifest_is_mandatory_and_command_alone_does_not_authorize_removal():
    request = removal()
    with pytest.raises(TypeError):
        FirewallRemoveRequest(request.command, request.confirmation)
    with pytest.raises(TypeError):
        FirewallCreateRequest(request.command, request.confirmation)
    with pytest.raises(TypeError):
        FirewallCreateRequest(command(), None)
    with pytest.raises(ValueError):
        FirewallCreateRequest(command(), ResponseConfirmation("0" * 64, NOW))


@pytest.mark.parametrize("change", [
    {"rule_id": UNDO_ID}, {"origin_store_id": UNDO_ID},
    {"spec": replace(spec(), remote_ip="1.1.1.1")},
    {"file_identity": replace(command().file_identity, file_id=100)},
    {"source": replace(command().source, lifecycle_id=UNDO_ID)},
    {"prepared_at": NOW},
])
def test_remove_request_cannot_retarget_or_cross_origin_store(change):
    request = removal()
    # A different rule needs a distinct valid Undo command identity too.
    if "rule_id" in change:
        change = {**change, "command_id": STORE_ID}
    c = replace(request.command, **change)
    with pytest.raises(ValueError, match="originating manifest"):
        FirewallRemoveRequest(c, ResponseConfirmation(c.fingerprint, c.prepared_at), request.manifest)


def test_source_expiry_does_not_prevent_owned_undo():
    request = removal()
    c = replace(request.command, source=replace(request.command.source, status=ResponseSourceStatus.EXPIRED))
    restored = FirewallRemoveRequest(c, ResponseConfirmation(c.fingerprint, c.prepared_at), request.manifest)
    assert restored.manifest == request.manifest


def test_remove_requires_fresh_read_during_its_own_call_and_current_confirmation():
    request = removal()
    fresh = FirewallReadResult(request.manifest, FirewallReadStatus.MATCHED,
                               NOW + timedelta(seconds=4), request.manifest.rule)
    assert removal_readback_matches(request, fresh, read_started_at=request.command.prepared_at, now=fresh.checked_at)
    assert not removal_readback_matches(request, fresh, read_started_at=fresh.checked_at + timedelta(seconds=1),
                                        now=fresh.checked_at + timedelta(seconds=2))
    assert not removal_readback_matches(request, fresh, read_started_at=NOW, now=fresh.checked_at)
    assert not removal_readback_matches(request, fresh, read_started_at=request.command.prepared_at, now=NOW)
    assert not removal_readback_matches(request, fresh, read_started_at=request.command.prepared_at,
                                        now=NOW + timedelta(minutes=10))


@pytest.mark.parametrize("status", [s for s in FirewallReadStatus if s not in {FirewallReadStatus.MATCHED, FirewallReadStatus.MISMATCH}])
def test_absent_duplicate_unsupported_and_unavailable_reads_never_permit_removal(status):
    request = removal()
    read = FirewallReadResult(request.manifest, status, NOW + timedelta(seconds=4))
    assert not removal_readback_matches(request, read, read_started_at=request.command.prepared_at, now=read.checked_at)
    with pytest.raises(ValueError):
        replace(read, snapshot=request.manifest.rule)


def test_readback_cannot_claim_partial_or_wrong_origin_equality():
    owned = manifest()
    with pytest.raises(TypeError):
        FirewallReadResult(owned, FirewallReadStatus.MATCHED, owned.verified_at)
    with pytest.raises(ValueError):
        FirewallReadResult(owned, FirewallReadStatus.MISMATCH, owned.verified_at, owned.rule)
    with pytest.raises(ValueError):
        FirewallReadResult(owned, FirewallReadStatus.ABSENT, NOW)
    with pytest.raises(TypeError):
        FirewallReadResult(owned, "matched", owned.verified_at)
    other_command = replace(command(), origin_store_id=UNDO_ID)
    other_creation = FirewallCreateRequest(other_command, ResponseConfirmation(other_command.fingerprint, NOW))
    other = replace(owned, creation=other_creation)
    read = FirewallReadResult(other, FirewallReadStatus.MATCHED, NOW + timedelta(seconds=4), other.rule)
    assert not removal_readback_matches(removal(owned), read, read_started_at=NOW + timedelta(seconds=3), now=read.checked_at)
    with pytest.raises(TypeError):
        removal_readback_matches(owned, read, read_started_at=NOW, now=NOW)


def test_manifest_codec_is_deterministic_sensitive_and_complete():
    owned = manifest()
    payload = serialize_owned_firewall_manifest(owned)
    decoded = deserialize_owned_firewall_manifest(payload)
    assert decoded == owned
    assert serialize_owned_firewall_manifest(decoded) == payload
    assert len(payload) <= MAX_OWNED_FIREWALL_MANIFEST_BYTES
    data = json.loads(payload)
    assert set(data["rule"]) == {f.name for f in fields(owned.rule)} - {"spec"}
    for value in (owned, owned.rule, owned.creation, removal(), FirewallCreateResult(owned.creation, receipt(), owned)):
        assert owned.creation.command.spec.program_path not in repr(value)
        assert owned.creation.command.spec.remote_ip not in repr(value)
        assert str(STORE_ID) not in repr(value)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(extra="hidden_secret"), lambda d: d.pop("rule"),
    lambda d: d.update(version=True), lambda d: d.update(version=2),
    lambda d: d["rule"].update(extra="hidden_secret"), lambda d: d["rule"].pop("secure_flags"),
    lambda d: d["rule"].update(enabled=1), lambda d: d["rule"].update(interfaces="NIC"),
    lambda d: d["rule"].update(interfaces=[object.__name__]), lambda d: d["rule"].update(secure_flags=True),
    lambda d: d["rule"].update(name="OtherRule"), lambda d: d["confirmation"].update(extra="hidden_secret"),
    lambda d: d["confirmation"].update(fingerprint="0" * 64),
    lambda d: d["command"]["spec"].update(profile="all"),
    lambda d: d.update(created_at="2026-10-08T12:00:00Z"),
])
def test_manifest_codec_rejects_future_unknown_missing_or_forged_binding(mutation):
    data = json.loads(serialize_owned_firewall_manifest(manifest()))
    mutation(data)
    with pytest.raises(ValueError, match="^invalid ownership manifest payload$") as error:
        deserialize_owned_firewall_manifest(json.dumps(data).encode())
    assert error.value.__cause__ is None


@pytest.mark.parametrize("payload", [
    b"", b"\xff", b"null", b"[]", b"[" * 2000,
    b"a" * (MAX_OWNED_FIREWALL_MANIFEST_BYTES + 1), "{}", bytearray(b"{}"),
])
def test_manifest_codec_bounds_and_invalid_inputs(payload):
    with pytest.raises(ValueError, match="^invalid ownership manifest payload$"):
        deserialize_owned_firewall_manifest(payload)


def test_manifest_codec_duplicate_fields_and_name_only_reconstruction_rejected():
    payload = serialize_owned_firewall_manifest(manifest()).replace(b'"enabled":true', b'"enabled":true,"enabled":true')
    with pytest.raises(ValueError):
        deserialize_owned_firewall_manifest(payload)
    for partial in ({"name": command().rule_name}, {"rule_id": str(command().rule_id)}):
        with pytest.raises(ValueError):
            deserialize_owned_firewall_manifest(json.dumps(partial).encode())
    with pytest.raises(TypeError):
        serialize_owned_firewall_manifest(command())


@pytest.mark.parametrize("field,value", [
    ("request", None), ("result", None),
    ("result", replace(receipt(), command_id=UNDO_ID)),
    ("result", ResponseResult(UNDO_ID, ResponseAction.REMOVE, ResponseOutcome.VERIFIED,
                              ResponseReason.RULE_READBACK_VERIFIED, ResponseRuleState.ABSENT)),
])
def test_create_receipt_rejects_untyped_or_wrong_command_action(field, value):
    handoff = FirewallCreateResult(creation(), receipt(), manifest())
    with pytest.raises((TypeError, ValueError)):
        replace(handoff, **{field: value})


@pytest.mark.parametrize("remote_ip,transport", [
    ("8.8.8.8", ResponseTransport.TCP), ("2606:4700:4700::1111", ResponseTransport.UDP),
])
def test_complete_manifest_roundtrip_preserves_unicode_long_path_and_ip_family(remote_ip, transport):
    path = "C:\\Örnek with spaces\\" + "\u4e2d" * 180 + "\\app.exe"
    c = replace(command(), spec=replace(spec(), program_path=path, remote_ip=remote_ip, transport=transport))
    request = FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, NOW))
    owned = OwnedFirewallRuleManifest(request, expected_firewall_rule(c), NOW, NOW)
    restored = deserialize_owned_firewall_manifest(serialize_owned_firewall_manifest(owned))
    assert restored == owned
    assert restored.rule.spec.program_path == path
    assert restored.rule.spec.remote_ip == remote_ip
    assert restored.rule.spec.transport is transport


@pytest.mark.parametrize("outcome,reason", [
    (ResponseOutcome.VERIFIED, ResponseReason.INVALID_REQUEST),
    (ResponseOutcome.PARTIAL, ResponseReason.UNSUPPORTED),
    (ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.OPERATION_FAILED),
    (ResponseOutcome.FAILED, ResponseReason.UNSUPPORTED),
])
def test_new_failure_reasons_cannot_fabricate_verified_partial_or_unknown_outcomes(outcome, reason):
    with pytest.raises(ValueError):
        ResponseResult(command().command_id, ResponseAction.CREATE, outcome, reason)
