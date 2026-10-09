"""NS-102 contract review: two-phase provenance's remaining collision window.

The candidate below is test-only, not a production claim/codec or repository.
Its complete precommitted bytes plus current OS fields cannot distinguish lost
successful creation from lost collision refusal. No promotion is implemented.
"""

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta
import json
import sqlite3

import pytest

from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallRemoveRequest, FirewallRuleSnapshot,
    ResponseOutcome, ResponseReason, expected_firewall_rule,
    serialize_response_command,
)
from tests.unit.domain.test_response import NOW
from tests.unit.domain.test_response_ownership import creation, removal
from tests.unit.infrastructure.test_windows_response_firewall import FakeApi, adapter


@dataclass(frozen=True, slots=True)
class _ProposedPreparedClaim:
    """Complete candidate evidence; never an OwnedFirewallRuleManifest."""

    creation: FirewallCreateRequest = field(repr=False)
    expected_rule: FirewallRuleSnapshot = field(repr=False)
    prepared_at: datetime
    claim_version: int = 1

    def payload(self) -> bytes:
        return json.dumps({
            "claim_version": self.claim_version,
            "creation": {
                "command": json.loads(serialize_response_command(self.creation.command)),
                "confirmation": {
                    "command_fingerprint": self.creation.confirmation.command_fingerprint,
                    "confirmed_at": self.creation.confirmation.confirmed_at.isoformat(),
                },
            },
            "expected_rule": asdict(self.expected_rule),
            "prepared_at": self.prepared_at.isoformat(),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _Crash(BaseException):
    """Termination injection outside the adapter's sanitized Exception path."""


def _claim():
    request = creation()
    return _ProposedPreparedClaim(request, expected_firewall_rule(request.command), NOW)


def _persist(path, claim):
    # Test-only file-backed ledger; not a new application migration/schema.
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE prepared (operation_id TEXT PRIMARY KEY, payload BLOB NOT NULL)")
        db.execute("INSERT INTO prepared VALUES (?, ?)",
                   (str(claim.creation.command.command_id), claim.payload()))


def _restart_view(path, api, claim):
    # A new connection sees the committed claim. A fresh, exhaustive fake API
    # read compares every supported field, using the NS-101 backend semantics.
    with sqlite3.connect(path) as db:
        payload = db.execute("SELECT payload FROM prepared WHERE operation_id = ?",
                             (str(claim.creation.command.command_id),)).fetchone()[0]
    rows = api.matching(claim.expected_rule.name, claim.expected_rule)
    return payload, rows


def test_claim_is_committed_before_create_and_survives_crash_before_dispatch(tmp_path):
    claim = _claim()
    path = tmp_path / "before-dispatch.sqlite3"
    api = FakeApi()
    _persist(path, claim)
    try:
        raise _Crash()
    except _Crash:
        pass
    assert _restart_view(path, api, claim) == (claim.payload(), ())
    assert not any(op in {"add", "remove"} for op, _ in api.calls)

    def add(rule):
        # Independent connection proves commit, not merely a pending INSERT.
        assert _restart_view(path, api, claim)[0] == claim.payload()
        api.rows = (rule,)
    api.hooks["add"] = add
    result = adapter(api).create(claim.creation)
    assert result.result.outcome is ResponseOutcome.VERIFIED


@pytest.mark.parametrize("foreign_before_dispatch", [True, False])
def test_same_durable_claim_and_full_readback_cannot_prove_creation_origin(
    tmp_path, foreign_before_dispatch,
):
    claim = _claim()
    owned_path = tmp_path / "lost-success.sqlite3"
    collision_path = tmp_path / "lost-refusal.sqlite3"
    _persist(owned_path, claim)
    _persist(collision_path, claim)

    own_api = FakeApi()
    def add_then_crash(rule):
        own_api.rows = (rule,)
        raise _Crash()
    own_api.hooks["add"] = add_then_crash
    with pytest.raises(_Crash):
        adapter(own_api).create(claim.creation)

    # Foreign state after PREPARED, without any application Add. Model both
    # termination before dispatch and termination after an explicit collision
    # refusal but before recording that refusal. No late Remove/admin race is
    # required for this counterexample.
    foreign_api = FakeApi((claim.expected_rule,))
    if not foreign_before_dispatch:
        refused = adapter(foreign_api).create(claim.creation)
        assert refused.result.outcome is ResponseOutcome.NOT_ATTEMPTED
        assert refused.result.reason is ResponseReason.OWNERSHIP_CONFLICT
        assert refused.manifest is None
        del refused  # Process loses the uncommitted refusal receipt.

    own_view = _restart_view(owned_path, own_api, claim)
    foreign_view = _restart_view(collision_path, foreign_api, claim)
    assert own_view == foreign_view == (claim.payload(), (claim.expected_rule,))
    assert sum(op == "add" for op, _ in own_api.calls) == 1
    assert not any(op == "add" for op, _ in foreign_api.calls)

    # A proposed promotion guard using ONLY committed candidate + operation ID
    # + unique full fresh equality necessarily accepts both histories.
    for payload, rows in (own_view, foreign_view):
        assert payload == claim.payload()
        assert rows == (claim.expected_rule,)

    for api in (own_api, foreign_api):
        restarted = adapter(api, now=NOW + timedelta(seconds=1))
        replay = restarted.create(claim.creation)
        assert replay.manifest is None
        assert replay.result.reason is ResponseReason.OWNERSHIP_CONFLICT
        assert not any(op == "remove" for op, _ in api.calls)
    assert sum(op == "add" for op, _ in own_api.calls) == 1
    assert not any(op == "add" for op, _ in foreign_api.calls)


def test_verified_receipt_loss_has_the_same_restart_observations_as_collision(tmp_path):
    claim = _claim()
    path = tmp_path / "lost-verified.sqlite3"
    _persist(path, claim)
    api = FakeApi()
    receipt = adapter(api).create(claim.creation)
    assert receipt.manifest is not None
    del receipt
    assert _restart_view(path, api, claim) == (claim.payload(), (claim.expected_rule,))
    foreign = FakeApi((claim.expected_rule,))
    assert _restart_view(path, foreign, claim) == _restart_view(path, api, claim)


@pytest.mark.parametrize("kind", ["missing", "modified", "disabled", "duplicate"])
def test_missing_drifted_or_ambiguous_candidate_is_never_a_unique_exact_match(tmp_path, kind):
    claim = _claim()
    path = tmp_path / "unresolved.sqlite3"
    _persist(path, claim)
    rows = {
        "missing": (),
        "modified": (replace(claim.expected_rule, local_ports="80"),),
        "disabled": (replace(claim.expected_rule, enabled=False),),
        "duplicate": (claim.expected_rule, claim.expected_rule),
    }[kind]
    api = FakeApi(rows)
    payload, fresh = _restart_view(path, api, claim)
    assert payload == claim.payload()
    assert fresh != (claim.expected_rule,)
    assert not any(op in {"add", "remove"} for op, _ in api.calls)


@pytest.mark.parametrize("evidence", ["claim", "payload", "name", "uuid"])
def test_prepared_candidate_or_weak_identity_cannot_authorize_remove(evidence):
    claim = _claim()
    proposed = {
        "claim": claim,
        "payload": claim.payload(),
        "name": claim.creation.command.rule_name,
        "uuid": claim.creation.command.rule_id,
    }[evidence]
    original = removal()
    with pytest.raises(TypeError, match="originating typed manifest"):
        FirewallRemoveRequest(original.command, original.confirmation, proposed)
