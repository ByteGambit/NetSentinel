"""Offline NS-101 lab isolation checks; no native API, compiler or sockets."""

from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace
import weakref

import pytest

from netsentinel.domain import response
from netsentinel.domain.response import ResponseProfile
from netsentinel.infrastructure import windows_firewall_com
from tests.integration import test_response_firewall_vm as harness
from tests.unit.domain.test_response import spec
from tests.unit.domain.test_response_ownership import creation
from tests.unit.infrastructure.test_windows_firewall_com import native_rule
from tests.unit.infrastructure.test_windows_response_firewall import FakeApi, adapter


def lab():
    return harness.LabTarget("192.168.140.130", "192.168.140.131", "192.168.140.0/24", 49191, ResponseProfile.PUBLIC)


@pytest.mark.parametrize("ip", ["10.0.0.2", "172.16.0.2", "172.31.255.254", "192.168.140.130"])
def test_only_canonical_rfc1918_literals_are_lab_inputs(ip):
    assert harness._lab_ip(ip) == ip


@pytest.mark.parametrize("ip", ["", "localhost", "192.168.140.130/32", "192.168.140.130,192.168.140.131",
    "192.168.140.130-192.168.140.131", "192.168.140.130 ", "*", "Any", "8.8.8.8", "203.0.113.1",
    "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", None, 123])
def test_special_public_nonliteral_or_expanding_lab_input_rejected(ip):
    with pytest.raises(ValueError):
        harness._lab_ip(ip)


@pytest.mark.parametrize("changes", [
    {"ip": "192.168.140.0"}, {"ip": "192.168.140.255"}, {"ip": "192.168.140.131"},
    {"ip": "192.168.141.130"}, {"windows_ip": "192.168.140.0"},
    {"subnet": "192.168.140.1/24"}, {"subnet": "0.0.0.0/0"},
    {"port": 0}, {"port": 80}, {"port": 65536}, {"port": True}, {"port": "49191"}, {"profile": "public"},
])
def test_lab_pair_subnet_port_and_profile_are_exact_bounded(changes):
    with pytest.raises(ValueError):
        replace(lab(), **changes)


@pytest.mark.parametrize("fail", [False, True])
def test_validator_is_exact_and_restored_on_success_and_exception(monkeypatch, fail):
    original = response._remote_ip
    original_spec = spec()
    with pytest.raises(ValueError):
        replace(spec(), remote_ip=lab().ip)
    try:
        with harness._exact_lab_validation(monkeypatch, lab().ip):
            assert replace(original_spec, remote_ip=lab().ip).remote_ip == lab().ip
            for value in (lab().windows_ip, "8.8.8.8", lab().subnet, None):
                with pytest.raises(ValueError):
                    response._remote_ip(value)
            if fail:
                raise RuntimeError("Synthetic teardown path")
    except RuntimeError:
        assert fail
    assert response._remote_ip is original
    with pytest.raises(ValueError):
        replace(spec(), remote_ip=lab().ip)
    assert spec().remote_ip == "8.8.8.8"


def test_exact_lab_command_native_snapshot_manifest_and_remove_keep_all_other_guards(monkeypatch):
    original = creation()
    with harness._exact_lab_validation(monkeypatch, lab().ip):
        command = replace(original.command, spec=replace(original.command.spec, remote_ip=lab().ip))
        request = response.FirewallCreateRequest(command, response.ResponseConfirmation(
            command.fingerprint, original.confirmation.confirmed_at))
        expected = response.expected_firewall_rule(command)
        assert windows_firewall_com.snapshot(native_rule(expected), expected) == expected
        api = FakeApi()
        backend = adapter(api)
        receipt = backend.create(request)
        assert receipt.manifest.creation == request
        assert receipt.manifest.rule == expected
        assert backend.read(receipt.manifest).status is response.FirewallReadStatus.MATCHED
        undo = replace(command, action=response.ResponseAction.REMOVE,
                       command_id=original.command.origin_store_id)
        result = backend.remove(response.FirewallRemoveRequest(undo, response.ResponseConfirmation(
            undo.fingerprint, original.confirmation.confirmed_at), receipt.manifest))
        assert result.outcome is response.ResponseOutcome.VERIFIED
        assert backend.read(receipt.manifest).status is response.FirewallReadStatus.ABSENT


def test_fixture_default_skip_occurs_before_any_seam_or_native_work(monkeypatch):
    monkeypatch.delenv("NETSENTINEL_NS101_HOST_ONLY_AUTHORIZED", raising=False)
    original = response._remote_ip
    called = []
    monkeypatch.setattr(harness, "_verify_guest", lambda target: called.append(target))
    generator = harness.ns101_lab_scope.__wrapped__(monkeypatch)
    with pytest.raises(pytest.skip.Exception):
        next(generator)
    assert not called and response._remote_ip is original


def test_guest_checks_finish_before_activation_and_failure_never_installs_exception(monkeypatch):
    monkeypatch.setattr(harness.sys, "platform", "win32")
    values = {"HOST_ONLY_AUTHORIZED": "YES", "LAB_IP": lab().ip,
              "WINDOWS_LAB_IP": lab().windows_ip, "LAB_SUBNET": lab().subnet,
              "LAB_PORT": str(lab().port), "PROFILE": lab().profile.value}
    for key, value in values.items():
        monkeypatch.setenv("NETSENTINEL_NS101_" + key, value)
    original = response._remote_ip
    def refuse(target):
        assert response._remote_ip is original
        assert target == lab()
        raise RuntimeError("Unverified guest")
    monkeypatch.setattr(harness, "_verify_guest", refuse)
    generator = harness.ns101_lab_scope.__wrapped__(monkeypatch)
    with pytest.raises(RuntimeError, match="Unverified guest"):
        next(generator)
    assert response._remote_ip is original


def test_indexed_policy_read_uses_dispatch_get_with_exact_profile_arguments(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(DISPATCH_PROPERTYGET=2))
    dispatch = SimpleNamespace(GetIDsOfNames=lambda name: name,
        Invoke=lambda *args: calls.append(args) or 1)
    state = harness._policy_state(SimpleNamespace(_oleobj_=dispatch))
    assert set(state) == {"1", "2", "4"}
    assert len(calls) == 12 and all(call[1:4] == (0, 2, True) for call in calls)
    assert {call[-1] for call in calls} == {1, 2, 4}


def test_guest_com_proxies_are_released_before_apartment_teardown(monkeypatch):
    references = []
    events = []
    class Proxy:
        def __init__(self, **values):
            self.__dict__.update(values)
            references.append(weakref.ref(self))
    def query(text):
        if "Win32_ComputerSystem" in text:
            return [Proxy(Manufacturer="VMware, Inc.", Model="VMware20,1")]
        return [Proxy(IPAddress=(lab().windows_ip,), IPSubnet=("255.255.255.0",), DefaultIPGateway=None)]
    def dispatch(name):
        if name == "HNetCfg.FwPolicy2":
            return Proxy(CurrentProfileTypes=4)
        return Proxy(ConnectServer=lambda *args: Proxy(ExecQuery=query))
    def uninitialize():
        assert references and all(reference() is None for reference in references)
        events.append("uninitialize")
    monkeypatch.setattr(harness.sys, "platform", "win32")
    for name in ("VM_AUTHORIZED", "VM_SNAPSHOT_READY", "HOST_ONLY_AUTHORIZED"):
        monkeypatch.setenv("NETSENTINEL_NS101_" + name, "YES")
    monkeypatch.setenv("NETSENTINEL_NS101_VM_NAME", "NS101-SYNTHETIC-VM")
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(COINIT_APARTMENTTHREADED=2,
        CoInitializeEx=lambda flag: events.append("initialize"), CoUninitialize=uninitialize))
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetComputerName=lambda: "NS101-SYNTHETIC-VM"))
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32com.client", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32com.client.dynamic", SimpleNamespace(Dispatch=dispatch))
    harness._verify_guest(lab())
    assert events == ["initialize", "uninitialize"]


def test_client_build_binds_one_validated_literal_and_port_using_argument_list(monkeypatch, tmp_path):
    compiler = tmp_path / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"
    compiler.parent.mkdir(parents=True)
    compiler.touch()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    calls = []
    def compile_client(args, **kwargs):
        calls.append((args, kwargs))
        Path(args[4][5:]).write_bytes(b"Synthetic offline executable")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(harness.subprocess, "run", compile_client)
    path = harness._build_client(tmp_path, lab())
    assert path.is_file()
    source = (tmp_path / "NetSentinel-NS101-TCP-client.cs").read_text()
    assert lab().ip in source and str(lab().port) in source
    assert "__LAB_IP__" not in source and "__LAB_PORT__" not in source
    assert len(calls) == 1 and calls[0][0][0] == str(compiler)
    assert calls[0][1] == {"capture_output": True, "timeout": 30, "check": False}
    assert "BeginConnect(new IPEndPoint(address, LabPort)" in source
    assert "SocketError.AccessDenied" in source and "Dns." not in source
