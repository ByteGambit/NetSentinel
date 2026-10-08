"""NS-101 full COM property mapping and apartment lifecycle, no native COM."""

from types import SimpleNamespace
from dataclasses import replace
import sys

import pytest

from netsentinel.domain.response import FirewallReadStatus, ResponseProfile, ResponseTransport
from netsentinel.infrastructure import windows_firewall_com as module
from netsentinel.infrastructure.windows_response_firewall import FirewallApiError
from tests.unit.domain.test_response_ownership import manifest


def native_rule(expected=None):
    expected = manifest().rule if expected is None else expected
    values = {prop: getattr(expected, field) for field, prop in module.TEXT_PROPERTIES.items()}
    values.update(Protocol=module.PROTOCOLS[expected.spec.transport],
                  Profiles=module.PROFILES[expected.spec.profile], Direction=2, Action=0,
                  ApplicationName=expected.spec.program_path, RemoteAddresses=expected.spec.remote_ip,
                  RemotePorts=str(expected.spec.remote_port), Enabled=expected.enabled,
                  Interfaces=expected.interfaces, EdgeTraversal=expected.edge_traversal,
                  EdgeTraversalOptions=expected.edge_traversal_options, SecureFlags=expected.secure_flags)
    return SimpleNamespace(**values)


class Collection:
    def __init__(self, rules=()):
        self.rows = list(rules)
        self.calls = []
        self.bad_count = None
    @property
    def Count(self):
        return len(self.rows) if self.bad_count is None else self.bad_count
    def __iter__(self):
        return iter(self.rows)
    def Add(self, rule):
        self.calls.append(("add", rule))
        self.rows.append(rule)
    def Remove(self, name):
        self.calls.append(("remove", name))
        self.rows = [row for row in self.rows if row.Name != name]


class ComStub:
    IID_IDispatch = "IDispatch"
    COINIT_APARTMENTTHREADED = 2
    def __init__(self):
        self.calls = []
    def MakeIID(self, iid):
        return iid
    def CoInitializeEx(self, flags):
        self.calls.append(("init", flags))
    def CoUninitialize(self):
        self.calls.append(("uninit",))


class DispatchStub:
    def __init__(self, rules=()):
        self.collection = Collection(rules)
        self.policy = SimpleNamespace(Rules=self.collection)
        self.detached = None
        self.qis = []
        for rule in self.collection.rows:
            self(rule)
    def __call__(self, value):
        if value == "HNetCfg.FwPolicy2":
            value = self.policy
        elif value == "HNetCfg.FWRule":
            value = native_rule()
            self.detached = value
        if not hasattr(value, "_oleobj_"):
            value._oleobj_ = SimpleNamespace(QueryInterface=lambda iid, gateway: self.query(value, iid, gateway))
        return value
    def query(self, value, iid, gateway):
        self.qis.append((iid, gateway))
        return value


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111"])
@pytest.mark.parametrize("transport", list(ResponseTransport))
@pytest.mark.parametrize("profile", list(ResponseProfile))
def test_native_mapping_roundtrip_has_exact_selectors_no_widening(ip, transport, profile):
    expected = manifest().rule
    expected = replace(expected, spec=replace(expected.spec, remote_ip=ip, transport=transport,
                        profile=profile, program_path=r"C:\Program Files\Örnek 中 & $()\app.exe"))
    dispatch = DispatchStub()
    api = module.ComFirewallApi(ComStub(), dispatch)
    api.add(expected, lambda: None)
    rule = dispatch.detached
    assert rule.ApplicationName == expected.spec.program_path
    assert rule.RemoteAddresses == ip
    assert rule.RemotePorts == "443"
    assert rule.Protocol == (6 if transport is ResponseTransport.TCP else 17)
    assert rule.Profiles == module.PROFILES[profile]
    assert (rule.Direction, rule.Action, rule.Enabled) == (2, 0, True)
    assert api.matching(expected.name, expected) == (expected,)
    assert (module.POLICY_IID, "IDispatch") in dispatch.qis
    assert (module.RULE3_IID, "IDispatch") in dispatch.qis
    api.remove(expected, lambda: None)
    assert api.matching(expected.name, expected) == ()
    assert [op for op, _ in dispatch.collection.calls] == ["add", "remove"]
    api.close()
    assert api._policy is None


@pytest.mark.parametrize("property", list(vars(native_rule())))
def test_every_supported_getter_must_exist(property):
    rule = native_rule()
    delattr(rule, property)
    dispatch = DispatchStub((rule,))
    api = module.ComFirewallApi(ComStub(), dispatch)
    with pytest.raises(FirewallApiError) as exc:
        api.matching(manifest().rule.name, manifest().rule)
    assert exc.value.status is FirewallReadStatus.UNSUPPORTED


@pytest.mark.parametrize("prop,value", [
    ("Protocol", True), ("Protocol", 256), ("Profiles", 7), ("Profiles", 0),
    ("Direction", 1), ("Action", 1), ("RemotePorts", "*"), ("RemotePorts", "443,80"),
    ("RemotePorts", "443-444"), ("RemotePorts", "0"), ("RemotePorts", "65536"),
    ("RemoteAddresses", "*"), ("RemoteAddresses", "8.8.8.8/24"),
    ("RemoteAddresses", "2606:4700::/64"), ("RemoteAddresses", "example.test"),
    ("ApplicationName", "*"), ("ApplicationName", ""), ("Enabled", 1),
    ("Interfaces", ["NIC"]), ("Interfaces", (object(),)), ("EdgeTraversalOptions", True),
    ("SecureFlags", -1), ("LocalAddresses", None), ("Name", None),
])
def test_malformed_broader_or_inbound_allow_readback_cannot_be_equal(prop, value):
    rule = native_rule()
    setattr(rule, prop, value)
    dispatch = DispatchStub((rule,))
    api = module.ComFirewallApi(ComStub(), dispatch)
    with pytest.raises(FirewallApiError):
        api.matching(manifest().rule.name, manifest().rule)
    assert dispatch.collection.calls == []


@pytest.mark.parametrize("ip", ["8.8.8.8/32", "8.8.8.8/255.255.255.255", "2606:4700:4700::1111/128"])
def test_only_full_host_mask_is_normalized(ip):
    expected = manifest().rule
    if ":" in ip:
        expected = replace(expected, spec=replace(expected.spec, remote_ip="2606:4700:4700::1111"))
    rule = native_rule(expected)
    rule.RemoteAddresses = ip
    assert module.snapshot(rule, expected) == expected


def test_documented_empty_values_do_not_substitute_missing_properties():
    rule = native_rule()
    rule.Interfaces = None
    for field in module.NULL_BSTR_FIELDS:
        if field != "description":
            setattr(rule, module.TEXT_PROPERTIES[field], None)
    assert module.snapshot(rule, manifest().rule) == manifest().rule


@pytest.mark.parametrize("rows", [
    (native_rule(), native_rule()),
    (native_rule(), native_rule(replace(manifest().rule, name=manifest().rule.name.lower()))),
])
def test_case_insensitive_duplicate_identity_refuses_without_fabricating_snapshots(rows):
    dispatch = DispatchStub(rows)
    api = module.ComFirewallApi(ComStub(), dispatch)
    with pytest.raises(FirewallApiError) as exc:
        api.matching(manifest().rule.name, manifest().rule)
    assert exc.value.status is FirewallReadStatus.DUPLICATE
    assert dispatch.collection.calls == []


def test_add_collision_at_last_submission_check_never_overwrites():
    dispatch = DispatchStub((native_rule(),))
    api = module.ComFirewallApi(ComStub(), dispatch)
    with pytest.raises(FirewallApiError) as exc:
        api.add(manifest().rule, lambda: None)
    assert exc.value.status is FirewallReadStatus.DUPLICATE
    assert dispatch.collection.calls == []


def test_detached_unknown_restriction_refuses_before_add():
    dispatch = DispatchStub()
    def altered(value):
        result = dispatch(value)
        if value == "HNetCfg.FWRule":
            result.SecureFlags = 1
        return result
    api = module.ComFirewallApi(ComStub(), altered)
    with pytest.raises(FirewallApiError) as exc:
        api.add(manifest().rule, lambda: None)
    assert exc.value.status is FirewallReadStatus.UNSUPPORTED
    assert dispatch.collection.calls == []


@pytest.mark.parametrize("count", [-1, module.MAX_ENUMERATED_RULES + 1, True, 4])
def test_bounded_complete_enumeration_no_partial_absence(count):
    dispatch = DispatchStub()
    dispatch.collection.bad_count = count
    api = module.ComFirewallApi(ComStub(), dispatch)
    with pytest.raises(FirewallApiError) as exc:
        api.matching(manifest().rule.name, manifest().rule)
    assert exc.value.status is FirewallReadStatus.READ_UNAVAILABLE


class NativeError(Exception):
    def __init__(self, code):
        self.hresult = code
        super().__init__("synthetic private detail")


@pytest.mark.parametrize("error,status,definite", [
    (NativeError(-2147024891), FirewallReadStatus.ACCESS_DENIED, True),
    (PermissionError(), FirewallReadStatus.ACCESS_DENIED, True),
    (ImportError(), FirewallReadStatus.BACKEND_UNAVAILABLE, False),
    (OSError(), FirewallReadStatus.BACKEND_UNAVAILABLE, False),
    (NativeError(0x80040154), FirewallReadStatus.BACKEND_UNAVAILABLE, False),
    (NativeError(0x80070424), FirewallReadStatus.BACKEND_UNAVAILABLE, False),
    (NativeError(0x800706D9), FirewallReadStatus.BACKEND_UNAVAILABLE, False),
    (NativeError(0x800706BA), FirewallReadStatus.READ_UNAVAILABLE, False),
    (NativeError(0x80070057), FirewallReadStatus.INVALID_REQUEST, True),
    (NativeError(0x8000FFFF), FirewallReadStatus.INVALID_REQUEST, True),
    (NativeError(0x80004002), FirewallReadStatus.UNSUPPORTED, True),
    (NativeError(0x80010106), FirewallReadStatus.UNSUPPORTED, True),
    (AttributeError(), FirewallReadStatus.UNSUPPORTED, True),
    (RuntimeError(), FirewallReadStatus.READ_UNAVAILABLE, False),
])
def test_sanitized_hresult_mapping(error, status, definite):
    mapped = module.classify_error(error)
    assert mapped.status is status and mapped.definite_failure is definite
    assert "private" not in str(mapped)


def test_automation_nested_access_denied_retains_real_scode():
    error = NativeError(0x80020009)
    error.excepinfo = (0, "private", "private", None, 0, -2147024891)
    assert module.classify_error(error).status is FirewallReadStatus.ACCESS_DENIED


def install_com(monkeypatch, com=None, dispatch=None):
    com = com or ComStub()
    dispatch = dispatch or DispatchStub()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "pythoncom", com)
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32com.client", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32com.client.dynamic", SimpleNamespace(Dispatch=dispatch))
    return com, dispatch


def test_session_balances_apartment_and_releases_objects_on_success_and_exception(monkeypatch):
    com, _ = install_com(monkeypatch)
    with module.session() as api:
        assert api.matching(manifest().rule.name, manifest().rule) == ()
    assert api._policy is None
    assert com.calls == [("init", 2), ("uninit",)]
    with pytest.raises(RuntimeError, match="private"):
        with module.session():
            raise RuntimeError("private")
    assert com.calls == [("init", 2), ("uninit",)] * 2


def test_session_incompatible_apartment_does_not_uninitialize_or_retry(monkeypatch):
    com = ComStub()
    def incompatible(flags):
        com.calls.append(("init", flags))
        raise NativeError(0x80010106)
    com.CoInitializeEx = incompatible
    install_com(monkeypatch, com)
    with pytest.raises(FirewallApiError) as exc:
        with module.session():
            pytest.fail("entered")
    assert exc.value.status is FirewallReadStatus.UNSUPPORTED
    assert com.calls == [("init", 2)]


def test_session_construction_failure_still_balances_apartment(monkeypatch):
    def unavailable(value):
        raise NativeError(0x80040154)
    com, _ = install_com(monkeypatch, dispatch=unavailable)
    with pytest.raises(FirewallApiError):
        with module.session():
            pytest.fail("entered")
    assert com.calls == [("init", 2), ("uninit",)]


def test_session_unsupported_platform_and_com_not_installed(monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "linux")
    with pytest.raises(FirewallApiError) as exc:
        with module.session():
            pytest.fail("entered")
    assert exc.value.status is FirewallReadStatus.UNSUPPORTED
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "pythoncom", None)
    with pytest.raises(FirewallApiError) as exc:
        with module.session():
            pytest.fail("entered")
    assert exc.value.status is FirewallReadStatus.BACKEND_UNAVAILABLE


@pytest.mark.parametrize("operation", ["matching", "add", "remove"])
def test_native_operation_permission_error_discarded(operation):
    dispatch = DispatchStub()
    api = module.ComFirewallApi(ComStub(), dispatch)
    class DeniedPolicy:
        @property
        def Rules(self):
            raise NativeError(0x80070005)
    api._policy = DeniedPolicy()
    with pytest.raises(FirewallApiError) as exc:
        if operation == "matching":
            api.matching(manifest().rule.name, manifest().rule)
        elif operation == "add":
            api.add(manifest().rule, lambda: None)
        else:
            api.remove(manifest().rule, lambda: None)
    assert exc.value.status is FirewallReadStatus.ACCESS_DENIED
    assert exc.value.__cause__ is None


def test_native_session_cannot_be_used_or_released_on_another_thread(monkeypatch):
    dispatch = DispatchStub()
    api = module.ComFirewallApi(ComStub(), dispatch)
    monkeypatch.setattr(module, "get_ident", lambda: api._thread + 1)
    for operation in (
        lambda: api.matching(manifest().rule.name, manifest().rule),
        lambda: api.add(manifest().rule, lambda: None),
        lambda: api.remove(manifest().rule, lambda: None), api.close,
    ):
        with pytest.raises(FirewallApiError) as exc:
            operation()
        assert exc.value.status is FirewallReadStatus.UNSUPPORTED
    assert dispatch.collection.calls == []
