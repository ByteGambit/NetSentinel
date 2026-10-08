"""NS-101 deterministic port acceptance. Every OS boundary is injected."""

from contextlib import contextmanager
from dataclasses import fields, replace
from datetime import timedelta
import inspect
import ast

import pytest

from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallReadStatus, ResponseConfirmation, ResponseOutcome,
    ResponseReason, ResponseRuleState, ResponseProfile, ResponseTransport, ResponseSourceStatus,
    expected_firewall_rule, serialize_owned_firewall_manifest, deserialize_owned_firewall_manifest,
)
from netsentinel.infrastructure import windows_response_firewall as module
from netsentinel.infrastructure.windows_response_firewall import (
    FirewallApiError, TargetValidationError, WindowsResponseFirewall,
)
from tests.unit.domain.test_response import NOW, command
from tests.unit.domain.test_response_ownership import creation, manifest, removal


class FakeApi:
    def __init__(self, rows=()):
        self.rows = rows
        self.calls = []
        self.hooks = {}

    def matching(self, name, spec):
        self.calls.append(("read", name))
        if "read" in self.hooks:
            return self.hooks["read"](name, spec)
        return tuple(row for row in self.rows if row.name.casefold() == name.casefold())

    def add(self, rule, before_submit):
        before_submit()
        self.calls.append(("add", rule))
        if "add" in self.hooks:
            self.hooks["add"](rule)
        else:
            self.rows += (rule,)

    def remove(self, rule, before_submit):
        before_submit()
        name = rule.name
        self.calls.append(("remove", name))
        if "remove" in self.hooks:
            self.hooks["remove"](name)
        else:
            self.rows = tuple(row for row in self.rows if row.name != name)


def adapter(api, *, now=NOW, guard=None):
    @contextmanager
    def session():
        yield api
    @contextmanager
    def validated_target(command):
        yield
    return WindowsResponseFirewall(session, guard or validated_target, clock=lambda: now)


def raises(error):
    def fail(*args):
        raise error
    return fail


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111"])
@pytest.mark.parametrize("protocol", list(ResponseTransport))
@pytest.mark.parametrize("profile", list(ResponseProfile))
@pytest.mark.parametrize("path", [r"C:\Example\app.exe", r"C:\Program Files\Örnek 中 & $()\app.exe"])
def test_create_exact_bounded_semantics_and_manifest(ip, protocol, profile, path):
    c = replace(command(), spec=replace(command().spec, program_path=path, remote_ip=ip,
                                       transport=protocol, profile=profile))
    request = FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, NOW))
    api = FakeApi()
    receipt = adapter(api).create(request)
    assert receipt.result.outcome is ResponseOutcome.VERIFIED
    owned = receipt.manifest
    assert owned.creation is request
    assert owned.rule == expected_firewall_rule(c)
    assert owned.rule.spec.direction.value == "outbound"
    assert owned.rule.spec.effect.value == "block"
    assert owned.rule.enabled is True
    assert owned.created_at == owned.verified_at == NOW
    assert deserialize_owned_firewall_manifest(serialize_owned_firewall_manifest(owned)) == owned
    assert [op for op, _ in api.calls] == ["read", "read", "add", "read"]


@pytest.mark.parametrize("count", [1, 2])
def test_create_refuses_existing_identity_even_full_equal_never_adopts(count):
    api = FakeApi((manifest().rule,) * count)
    receipt = adapter(api).create(creation())
    assert receipt.result.reason is ResponseReason.OWNERSHIP_CONFLICT
    assert receipt.manifest is None
    assert all(op == "read" for op, _ in api.calls)


def test_collision_after_target_check_refuses_add():
    api = FakeApi()
    @contextmanager
    def guard(c):
        api.rows = (expected_firewall_rule(c),)
        yield
    receipt = adapter(api, guard=guard).create(creation())
    assert receipt.result.reason is ResponseReason.OWNERSHIP_CONFLICT
    assert not any(op == "add" for op, _ in api.calls)


@pytest.mark.parametrize("field", [f.name for f in fields(manifest().rule) if f.name != "name"])
def test_create_readback_drift_never_grants_ownership(field):
    expected = manifest().rule
    values = {
        "spec": replace(expected.spec, remote_port=80), "enabled": False,
        "interfaces": ("ForeignNIC",), "edge_traversal": True,
        "edge_traversal_options": 1, "secure_flags": 1,
    }
    changed = replace(expected, **{field: values.get(field, "Other")})
    api = FakeApi()
    api.hooks["add"] = lambda rule: setattr(api, "rows", (changed,))
    result = adapter(api).create(creation())
    assert result.result.outcome is ResponseOutcome.OUTCOME_UNKNOWN
    assert result.manifest is None
    assert not any(op == "remove" for op, _ in api.calls)


@pytest.mark.parametrize("rows", [(), (manifest().rule, manifest().rule)])
def test_absent_or_duplicate_after_add_is_unknown(rows):
    api = FakeApi()
    api.hooks["add"] = lambda rule: setattr(api, "rows", rows)
    receipt = adapter(api).create(creation())
    assert receipt.result.outcome is ResponseOutcome.OUTCOME_UNKNOWN
    assert receipt.manifest is None


@pytest.mark.parametrize("status", [FirewallReadStatus.ACCESS_DENIED, FirewallReadStatus.BACKEND_UNAVAILABLE,
                                  FirewallReadStatus.READ_UNAVAILABLE, FirewallReadStatus.UNSUPPORTED])
def test_preflight_failures_are_typed_and_do_not_mutate(status):
    api = FakeApi()
    api.hooks["read"] = raises(FirewallApiError(status))
    result = adapter(api).create(creation())
    assert result.result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert result.manifest is None
    assert adapter(api, now=NOW + timedelta(seconds=4)).read(manifest()).status is status
    assert adapter(api, now=NOW + timedelta(seconds=4)).remove(removal()).outcome is ResponseOutcome.NOT_ATTEMPTED
    assert all(op == "read" for op, _ in api.calls)


@pytest.mark.parametrize("operation", ["add", "remove"])
@pytest.mark.parametrize("error,outcome,reason", [
    (FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True), ResponseOutcome.FAILED, ResponseReason.ACCESS_DENIED),
    (FirewallApiError(FirewallReadStatus.INVALID_REQUEST, definite_failure=True), ResponseOutcome.FAILED, ResponseReason.OPERATION_FAILED),
    (RuntimeError("synthetic sensitive value"), ResponseOutcome.OUTCOME_UNKNOWN, ResponseReason.READBACK_UNAVAILABLE),
])
def test_mutation_exceptions_are_sanitized_and_never_retried(operation, error, outcome, reason):
    api = FakeApi((manifest().rule,) if operation == "remove" else ())
    api.hooks[operation] = raises(error)
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    receipt = backend.create(creation()) if operation == "add" else backend.remove(removal())
    result = receipt.result if operation == "add" else receipt
    assert result.outcome is outcome and result.reason is reason
    assert "sensitive" not in repr(receipt)
    assert sum(op == operation for op, _ in api.calls) == 1


def test_unknown_exception_after_successful_mutation_stays_unknown():
    api = FakeApi()
    def add_then_throw(rule):
        api.rows = (rule,)
        raise RuntimeError("reply lost")
    api.hooks["add"] = add_then_throw
    receipt = adapter(api).create(creation())
    assert receipt.manifest is None
    assert receipt.result.outcome is ResponseOutcome.OUTCOME_UNKNOWN
    assert api.rows == (expected_firewall_rule(command()),)


@pytest.mark.parametrize("bad", [None, command(), "NetSentinel:foreign", object()])
def test_invalid_request_shapes_cannot_cross_port(bad):
    api = FakeApi()
    backend = adapter(api)
    for method in (backend.create, backend.read, backend.remove):
        with pytest.raises(TypeError):
            method(bad)
    assert api.calls == []


@pytest.mark.parametrize("status", [ResponseSourceStatus.EXPIRED, ResponseSourceStatus.UNAVAILABLE])
def test_create_unavailable_source_and_stale_confirmation_make_zero_api_calls(status):
    api = FakeApi()
    c = replace(command(), source=replace(command().source, status=status))
    request = FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, NOW))
    assert adapter(api).create(request).result.reason is ResponseReason.TARGET_UNAVAILABLE
    assert adapter(api, now=NOW + timedelta(minutes=6)).create(creation()).result.reason is ResponseReason.STALE_CONFIRMATION
    assert adapter(api, now=NOW + timedelta(minutes=6)).remove(removal()).reason is ResponseReason.STALE_CONFIRMATION
    assert api.calls == []


def test_confirmation_rechecked_after_slow_guard_and_before_remove():
    api = FakeApi()
    times = iter([NOW, NOW + timedelta(minutes=6)])
    backend = adapter(api)
    backend._clock = lambda: next(times)
    assert backend.create(creation()).result.reason is ResponseReason.STALE_CONFIRMATION
    assert not any(op == "add" for op, _ in api.calls)
    api.rows = (manifest().rule,)
    times = iter([NOW + timedelta(seconds=4)] * 3 + [NOW + timedelta(minutes=6)])
    assert backend.remove(removal()).reason is ResponseReason.STALE_CONFIRMATION
    assert not any(op == "remove" for op, _ in api.calls)


@pytest.mark.parametrize("seconds", [(4, 2, 4, 4), (4, 4, 5, 4), (4, 5, 4, 5)])
def test_removal_rejects_clock_reversal_or_inconsistent_fresh_read_times(seconds):
    api = FakeApi((manifest().rule,))
    backend = adapter(api)
    times = iter(NOW + timedelta(seconds=s) for s in seconds)
    backend._clock = lambda: next(times)
    result = backend.remove(removal())
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert result.reason is ResponseReason.STALE_CONFIRMATION
    assert all(op == "read" for op, _ in api.calls)


@pytest.mark.parametrize("reason", [ResponseReason.TARGET_UNAVAILABLE, ResponseReason.REVALIDATION_REQUIRED,
                                   ResponseReason.ACCESS_DENIED, ResponseReason.BOUNDARY_UNAVAILABLE])
def test_target_guard_failure_denies_without_widening(reason):
    @contextmanager
    def guard(c):
        raise TargetValidationError(reason)
        yield
    api = FakeApi()
    receipt = adapter(api, guard=guard).create(creation())
    assert receipt.result.reason is reason
    assert receipt.result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert all(op == "read" for op, _ in api.calls)


def test_remove_uses_own_fresh_full_equality_then_independent_absence():
    owned = manifest()
    foreign = replace(owned.rule, name="UnrelatedRule")
    api = FakeApi((foreign, owned.rule))
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    read = backend.read(owned)
    assert read.status is FirewallReadStatus.MATCHED and read.snapshot == owned.rule
    result = backend.remove(removal(owned))
    assert result.outcome is ResponseOutcome.VERIFIED
    assert result.rule_state is ResponseRuleState.ABSENT
    assert api.rows == (foreign,)
    assert [op for op, _ in api.calls] == ["read", "read", "remove", "read"]
    result = backend.remove(removal(owned))
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert result.rule_state is ResponseRuleState.EXTERNALLY_MISSING


@pytest.mark.parametrize("field,value", [
    ("description", "foreign"), ("grouping", "foreign"), ("enabled", False),
    ("service_name", "service"), ("local_addresses", "10.0.0.1"), ("local_ports", "80"),
    ("icmp_types_and_codes", "8:*"), ("interfaces", ("NIC",)), ("interface_types", "Wireless"),
    ("edge_traversal", True), ("edge_traversal_options", 1), ("local_app_package_id", "pkg"),
    ("local_user_owner", "owner"), ("local_user_authorized_list", "users"),
    ("remote_user_authorized_list", "users"), ("remote_machine_authorized_list", "machines"),
    ("secure_flags", 1), ("spec", replace(command().spec, remote_port=80)),
    ("spec", replace(command().spec, remote_ip="1.1.1.1")),
    ("spec", replace(command().spec, program_path=r"C:\Example\other.exe")),
    ("spec", replace(command().spec, transport=ResponseTransport.UDP)),
    ("spec", replace(command().spec, profile=ResponseProfile.PUBLIC)),
])
def test_remove_refuses_every_ownership_field_drift_and_stale_caller_read(field, value):
    owned = manifest()
    api = FakeApi((owned.rule,))
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    assert backend.read(owned).status is FirewallReadStatus.MATCHED
    api.rows = (replace(owned.rule, **{field: value}),)
    assert backend.read(owned).status is FirewallReadStatus.MISMATCH
    result = backend.remove(removal(owned))
    assert result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert not any(op == "remove" for op, _ in api.calls)


@pytest.mark.parametrize("rows,status", [
    ((), FirewallReadStatus.ABSENT),
    ((manifest().rule,) * 2, FirewallReadStatus.DUPLICATE),
    ((replace(manifest().rule, name="Unrelated"),), FirewallReadStatus.ABSENT),
    ((replace(manifest().rule, name=manifest().rule.name.lower()),), FirewallReadStatus.MISMATCH),
])
def test_missing_duplicate_foreign_or_case_alias_never_removed(rows, status):
    api = FakeApi(rows)
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    assert backend.read(manifest()).status is status
    assert backend.remove(removal()).outcome is ResponseOutcome.NOT_ATTEMPTED
    assert api.rows == rows
    assert all(op == "read" for op, _ in api.calls)


def test_remove_success_still_present_or_post_read_failure_is_unknown():
    api = FakeApi((manifest().rule,))
    api.hooks["remove"] = lambda name: None
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    assert backend.remove(removal()).outcome is ResponseOutcome.OUTCOME_UNKNOWN
    def unreadable(name):
        api.hooks["read"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED))
    api.hooks["remove"] = unreadable
    assert backend.remove(removal()).outcome is ResponseOutcome.OUTCOME_UNKNOWN


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_successful_submission_then_definite_read_denial_is_unknown(operation):
    api = FakeApi((manifest().rule,) if operation == "remove" else ())
    def submit_then_deny_read(value):
        api.rows = (value,) if operation == "add" else ()
        api.hooks["read"] = raises(FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True))
    api.hooks[operation] = submit_then_deny_read
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    receipt = backend.create(creation()) if operation == "add" else backend.remove(removal())
    result = receipt.result if operation == "add" else receipt
    assert result.outcome is ResponseOutcome.OUTCOME_UNKNOWN
    assert result.reason is ResponseReason.READBACK_UNAVAILABLE
    if operation == "add":
        assert receipt.manifest is None


@pytest.mark.parametrize("bad", [None, [], (object(),), (manifest().rule,) * 3])
def test_malformed_api_returns_fail_closed(bad):
    api = FakeApi()
    api.hooks["read"] = lambda *args: bad
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    assert backend.create(creation()).result.outcome is ResponseOutcome.NOT_ATTEMPTED
    assert backend.read(manifest()).status is FirewallReadStatus.READ_UNAVAILABLE
    assert backend.remove(removal()).outcome is ResponseOutcome.NOT_ATTEMPTED


def test_missing_backend_and_cleanup_exception_do_not_grant_ownership():
    def absent():
        raise FirewallApiError(FirewallReadStatus.BACKEND_UNAVAILABLE)
    backend = WindowsResponseFirewall(absent, lambda c: None, clock=lambda: NOW + timedelta(seconds=4))
    assert backend.create(creation()).result.reason is ResponseReason.BACKEND_UNAVAILABLE
    assert backend.read(manifest()).status is FirewallReadStatus.BACKEND_UNAVAILABLE
    assert backend.remove(removal()).reason is ResponseReason.BACKEND_UNAVAILABLE
    api = FakeApi()
    @contextmanager
    def failing_close():
        yield api
        raise RuntimeError("close error")
    backend._factory = failing_close
    backend._target_guard = adapter(api)._target_guard
    assert backend.create(creation()).manifest is None


def test_busy_adapter_refuses_concurrent_mutations():
    api = FakeApi()
    backend = adapter(api, now=NOW + timedelta(seconds=4))
    with backend._lock:
        assert backend.create(creation()).result.reason is ResponseReason.BOUNDARY_UNAVAILABLE
        assert backend.remove(removal()).reason is ResponseReason.BOUNDARY_UNAVAILABLE
    assert api.calls == []


def test_no_shell_elevation_or_persistence_imports_and_no_runtime_wiring():
    from pathlib import Path
    from netsentinel.infrastructure import windows_firewall_com, windows_response_target
    forbidden = {"subprocess", "sqlite3", "socket", "winreg", "PyQt6"}
    for source in (module, windows_firewall_com, windows_response_target):
        tree = ast.parse(inspect.getsource(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not ({a.name.split(".")[0] for a in node.names} & forbidden)
            elif isinstance(node, ast.ImportFrom):
                assert node.module.split(".")[0] not in forbidden
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"system", "popen", "ShellExecute", "ShellExecuteEx", "runas"}
    root = Path(__file__).resolve().parents[3] / "src" / "netsentinel"
    for file in (root / "bootstrap.py", root / "__main__.py"):
        assert "windows_response_firewall" not in file.read_text(encoding="utf-8")
