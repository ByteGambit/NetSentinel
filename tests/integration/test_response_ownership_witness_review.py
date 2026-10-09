"""Offline witness spike: no native imports/mutation or production promotion."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import json
import sqlite3

import pytest

from netsentinel.domain.response import (
    FirewallRemoveRequest, OwnedFirewallRuleManifest, ResponseSourceStatus, expected_firewall_rule,
)
from netsentinel.domain.connections import ObservationQuality
from netsentinel.infrastructure import windows_firewall_com as com
from netsentinel.infrastructure.windows_response_firewall import FirewallApiError
from tests.fixtures.ns102 import ownership_witness as spike
from tests.unit.domain.test_response import NOW, command
from tests.unit.domain.test_response_ownership import removal
from tests.unit.infrastructure.test_windows_firewall_com import ComStub, DispatchStub, native_rule


def _persist(path, claim):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS prepared (operation TEXT PRIMARY KEY, witness TEXT UNIQUE, payload BLOB)")
        db.execute("INSERT INTO prepared VALUES (?, ?, ?)",
                   (str(claim.creation.command.command_id), claim.witness, spike.encode(claim)))


def _load(path, claim):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT payload FROM prepared WHERE operation = ?",
                          (str(claim.creation.command.command_id),)).fetchone()[0]


def eligible(claim, rows, payload=None):
    return spike.promotion_eligible(claim, spike.encode(claim) if payload is None else payload,
                                    rows, checked_at=NOW + timedelta(seconds=1),
                                    now=NOW + timedelta(seconds=2))


def test_csprng_requests_256_bits_and_separate_random_rule_identity(monkeypatch):
    calls = []
    def random_hex(size):
        calls.append(size)
        return "ab" * size
    monkeypatch.setattr(spike.secrets, "token_hex", random_hex)
    claim = spike.prepare(command(), NOW)
    assert calls == [32]
    assert claim.creation.command.rule_id.version == 4
    assert claim.creation.command.command_id == claim.creation.command.rule_id
    assert claim.witness != claim.creation.command.rule_id.hex
    assert len(claim.expected_rule.description) == 133
    assert "|" not in claim.expected_rule.description and not claim.expected_rule.description.startswith("@")


def test_real_generation_allocates_independent_values_per_operation():
    candidates = [spike.prepare(command(), NOW) for _ in range(32)]
    assert len({c.witness for c in candidates}) == 32
    assert len({c.creation.command.rule_id for c in candidates}) == 32
    assert all(len(c.witness) == 64 for c in candidates)


def test_serialization_round_trip_and_commit_before_fake_mutation(tmp_path):
    claim = spike.prepare(command(), NOW)
    path = tmp_path / "witness.sqlite3"
    payload = spike.encode(claim)
    assert spike.decode(payload) == claim
    _persist(path, claim)
    # Independent connection stands for a new service/repository instance.
    assert spike.decode(_load(path, claim)) == claim
    dispatch = DispatchStub()
    api = com.ComFirewallApi(ComStub(), dispatch)
    def before_submit():
        assert _load(path, claim) == payload  # Committed before actual fake Add.
    api.add(claim.expected_rule, before_submit)
    rows = api.matching(claim.expected_rule.name, claim.expected_rule)
    assert eligible(claim, rows, _load(path, claim))
    assert sum(op[0] == "add" for op in dispatch.policy.Rules.calls) == 1
    # Restart reconciliation reads first; eligibility never dispatches Add.
    assert eligible(spike.decode(_load(path, claim)), api.matching(claim.expected_rule.name, claim.expected_rule))
    assert sum(op[0] == "add" for op in dispatch.policy.Rules.calls) == 1


@pytest.mark.parametrize("description", ["legacy", "empty", "wrong-witness"])
def test_equivalent_foreign_selectors_without_exact_witness_never_promote(description):
    claim = spike.prepare(command(), NOW)
    text = {"legacy": expected_firewall_rule(claim.creation.command).description,
            "empty": "", "wrong-witness": spike.description(claim.creation.command.rule_id,
                                                           "0" * 64 if claim.witness != "0" * 64 else "1" * 64)}[description]
    foreign = replace(claim.expected_rule, description=text)
    assert foreign.spec == claim.expected_rule.spec
    fresh = com.snapshot(native_rule(foreign), claim.expected_rule)
    assert not eligible(claim, (fresh,))


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_duplicate_witness_candidates_never_promote(count):
    claim = spike.prepare(command(), NOW)
    assert not eligible(claim, (claim.expected_rule,) * count)


def test_duplicate_witness_across_operations_is_rejected_by_review_ledger(tmp_path):
    first, second = spike.prepare(command(), NOW), spike.prepare(command(), NOW)
    second = replace(second, witness=first.witness, expected_rule=replace(second.expected_rule,
                     description=spike.description(second.creation.command.rule_id, first.witness)))
    path = tmp_path / "unique-witness.sqlite3"
    _persist(path, first)
    with pytest.raises(sqlite3.IntegrityError):
        _persist(path, second)
    assert not eligible(first, (second.expected_rule,))


@pytest.mark.parametrize("property", [f.name for f in fields(spike.prepare(command(), NOW).expected_rule)])
def test_any_ownership_field_drift_denies_promotion(property):
    claim = spike.prepare(command(), NOW)
    expected = claim.expected_rule
    value = getattr(expected, property)
    if property == "spec":
        changed = replace(value, remote_port=80)
    elif type(value) is bool:
        changed = not value
    elif type(value) is int:
        changed = value + 1
    elif type(value) is tuple:
        changed = ("OtherNIC",)
    else:
        changed = value + "changed"
    assert not eligible(claim, (replace(expected, **{property: changed}),))


@pytest.mark.parametrize("weak", [None, "name", "uuid", "witness", "request"])
def test_identity_witness_or_uncommitted_claim_alone_is_insufficient(weak):
    claim = spike.prepare(command(), NOW)
    value = {None: None, "name": claim.expected_rule.name, "uuid": claim.creation.command.rule_id,
             "witness": claim.witness, "request": claim.creation}[weak]
    assert not spike.promotion_eligible(value, spike.encode(claim), (claim.expected_rule,),
                                        checked_at=NOW, now=NOW)
    assert not spike.promotion_eligible(claim, None, (claim.expected_rule,), checked_at=NOW, now=NOW)


def test_forged_exact_witness_is_not_cryptographic_local_admin_protection():
    claim = spike.prepare(command(), NOW)
    clone = replace(claim.expected_rule)  # Privileged attacker copied everything.
    assert eligible(claim, (clone,))  # Explicit threat-boundary counterexample.


def test_candidate_and_witness_cannot_remove_and_v1_manifest_is_not_synthesized():
    claim = spike.prepare(command(), NOW)
    undo = removal()
    for candidate in (claim, claim.witness, spike.encode(claim)):
        with pytest.raises(TypeError, match="originating typed manifest"):
            FirewallRemoveRequest(undo.command, undo.confirmation, candidate)
    with pytest.raises(ValueError, match="full expected rule"):
        OwnedFirewallRuleManifest(claim.creation, claim.expected_rule, NOW, NOW)
    assert type(undo.manifest) is OwnedFirewallRuleManifest


def test_com_boundary_refuses_preexisting_identity_with_or_without_witness():
    claim = spike.prepare(command(), NOW)
    for existing in (claim.expected_rule, expected_firewall_rule(claim.creation.command)):
        dispatch = DispatchStub((native_rule(existing),))
        api = com.ComFirewallApi(ComStub(), dispatch)
        with pytest.raises(FirewallApiError):
            api.add(claim.expected_rule, lambda: pytest.fail("dispatch on collision"))
        assert dispatch.policy.Rules.calls == []


def test_candidate_is_immutable_and_witness_excluded_from_repr():
    claim = spike.prepare(command(), NOW)
    with pytest.raises(FrozenInstanceError):
        claim.witness = "1" * 64
    assert claim.witness not in repr(claim)
    assert claim.witness not in repr(claim.expected_rule)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(witness="bad|token"),
    lambda d: d.update(witness="A" * 64),
    lambda d: d.update(witness="a" * 32),
    lambda d: d.update(claim_version=True),
    lambda d: d.update(claim_version=2),
    lambda d: d.update(extra="unexpected"),
    lambda d: d["expected_rule"].update(description="foreign"),
    lambda d: d["command"].update(rule_id=str(command().rule_id)),
    lambda d: d["confirmation"].update(fingerprint="0" * 64),
    lambda d: d.update(prepared_at="2026-10-08T12:00:00"),
])
def test_corrupt_candidate_cannot_become_provenance(mutate):
    data = json.loads(spike.encode(spike.prepare(command(), NOW)))
    mutate(data)
    with pytest.raises(ValueError, match="^invalid witness candidate$"):
        spike.decode(json.dumps(data).encode())


@pytest.mark.parametrize("payload", [b"", b"x" * (spike.MAX_CLAIM_BYTES + 1), b"\xff", b'{"claim_version":1,"claim_version":1}'])
def test_bad_or_unbounded_payload_is_rejected(payload):
    with pytest.raises(ValueError, match="^invalid witness candidate$"):
        spike.decode(payload)


def test_wrong_operation_or_stale_future_read_is_ineligible():
    first, second = spike.prepare(command(), NOW), spike.prepare(command(), NOW)
    assert not eligible(first, (first.expected_rule,), spike.encode(second))
    for checked_at, now in ((NOW - timedelta(seconds=1), NOW), (NOW + timedelta(seconds=1), NOW)):
        assert not spike.promotion_eligible(first, spike.encode(first), (first.expected_rule,),
                                            checked_at=checked_at, now=now)


@pytest.mark.parametrize("rows", [None, [], (object(),), "unsupported", "read_unavailable"])
def test_unavailable_or_untyped_readback_is_not_equality_proof(rows):
    claim = spike.prepare(command(), NOW)
    assert not eligible(claim, rows)


def test_restart_eligibility_does_not_invent_an_old_creation_timestamp():
    claim = spike.prepare(command(), NOW)
    discovery = NOW + timedelta(days=1)
    assert spike.promotion_eligible(claim, spike.encode(claim), (claim.expected_rule,),
                                    checked_at=discovery, now=discovery)
    # An eligibility decision cannot manufacture a v1 created_at time inside
    # the expired confirmation window or an earlier verified receipt.
    with pytest.raises(ValueError, match="creation and readback times"):
        OwnedFirewallRuleManifest(claim.creation, claim.expected_rule, discovery, discovery)


@pytest.mark.parametrize("status,quality", [
    (ResponseSourceStatus.EXPIRED, ObservationQuality.COMPLETE),
    (ResponseSourceStatus.UNAVAILABLE, ObservationQuality.COMPLETE),
    (ResponseSourceStatus.AVAILABLE, ObservationQuality.FAILED),
])
def test_invalid_originating_create_cannot_be_prepared(status, quality):
    original = command()
    invalid = replace(original, source=replace(original.source, status=status, quality=quality))
    with pytest.raises(ValueError, match="valid originating CREATE source"):
        spike.prepare(invalid, NOW)
