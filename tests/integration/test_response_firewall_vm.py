"""NS-101 explicitly authorized host-only VMware test; NEVER use the host.

Only this function-scoped pytest fixture overrides private-address validation.
No production switch, DNS, public endpoint, ownership storage or elevation.
"""

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from uuid import uuid4

import pytest

from netsentinel.domain import response
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallRemoveRequest, FirewallReadStatus, ResponseAction,
    ResponseCommand, ResponseConfirmation, ResponseLifetime, ResponseLifetimeKind,
    ResponseOutcome, ResponseProfile, ResponseRuleSpec, ResponseSource,
    ResponseSourceStatus, ResponseTransport,
)
from netsentinel.infrastructure import windows_firewall_com
from netsentinel.infrastructure.windows_response_firewall import WindowsResponseFirewall
from netsentinel.infrastructure.windows_response_target import WindowsExecutableTarget, file_identity


RFC1918 = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _lab_ip(value):
    if type(value) is not str:
        raise ValueError("Lab requires canonical RFC1918 IPv4 literal")
    address = IPv4Address(value)
    if str(address) != value or not any(address in network for network in RFC1918):
        raise ValueError("Lab requires canonical RFC1918 IPv4 literal")
    return value


@dataclass(frozen=True)
class LabTarget:
    ip: str
    windows_ip: str
    subnet: str
    port: int
    profile: ResponseProfile

    def __post_init__(self):
        _lab_ip(self.ip)
        _lab_ip(self.windows_ip)
        network = IPv4Network(self.subnet, strict=True)
        if (str(network) != self.subnet or not any(network.subnet_of(n) for n in RFC1918)
                or self.ip == self.windows_ip
                or any(IPv4Address(ip) not in network
                       or IPv4Address(ip) in (network.network_address, network.broadcast_address)
                       for ip in (self.ip, self.windows_ip))
                or type(self.port) is not int or not 1024 <= self.port <= 65535
                or type(self.profile) is not ResponseProfile):
            raise ValueError("Lab requires distinct on-link unicast hosts, high port and exact profile")


@contextmanager
def _exact_lab_validation(monkeypatch, ip):
    """Test-process-only exception; keep active through manifest-only cleanup."""
    ip = _lab_ip(ip)
    original = response._remote_ip
    with pytest.raises(ValueError):
        original(ip)
    def exact(value):
        if type(value) is not str or value != ip:
            raise ValueError("Native lab permits only its exact configured endpoint")
        return ip
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(response, "_remote_ip", exact)
            yield
    finally:
        assert response._remote_ip is original, "Lab validator restoration failed"
        with pytest.raises(ValueError):
            original(ip)


def _verify_guest(target):
    """No seam activation until explicit authorization and native VM checks pass."""
    vm_name = os.environ.get("NETSENTINEL_NS101_VM_NAME")
    if (sys.platform != "win32" or not vm_name or any(os.environ.get(key) != "YES" for key in (
        "NETSENTINEL_NS101_VM_AUTHORIZED", "NETSENTINEL_NS101_VM_SNAPSHOT_READY",
        "NETSENTINEL_NS101_HOST_ONLY_AUTHORIZED",
    ))):
        pytest.skip("NS-101 requires explicit dedicated host-only Windows VM and recovery access")
    pythoncom = pytest.importorskip("pythoncom", reason="Native COM dependency unavailable")
    import win32api
    from win32com.client.dynamic import Dispatch
    assert win32api.GetComputerName().casefold() == vm_name.casefold(), "Not the authorized VM"
    pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
    wmi = policy = adapter = None
    systems = adapters = matching = []
    try:
        wmi = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
        systems = list(wmi.ExecQuery("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
        assert len(systems) == 1 and "vmware" in str(systems[0].Manufacturer).casefold(), "VMware VM required"
        adapters = list(wmi.ExecQuery("SELECT IPAddress, IPSubnet, DefaultIPGateway FROM "
                                     "Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"))
        matching = [adapter for adapter in adapters if target.windows_ip in (adapter.IPAddress or ())]
        assert len(matching) == 1, "Exact local lab interface unavailable"
        adapter = matching[0]
        index = tuple(adapter.IPAddress).index(target.windows_ip)
        assert IPv4Network((target.windows_ip, adapter.IPSubnet[index]), strict=False) == IPv4Network(target.subnet)
        assert not adapter.DefaultIPGateway, "Lab interface must not have a default gateway"
        policy = Dispatch("HNetCfg.FwPolicy2")
        assert policy.CurrentProfileTypes & windows_firewall_com.PROFILES[target.profile], "Selected profile inactive"
    finally:
        # WMI proxies must be released while their apartment is still alive.
        # Otherwise Windows can emit first-chance access violations on teardown.
        policy = adapter = None
        systems = adapters = matching = []
        wmi = None
        pythoncom.CoUninitialize()


@pytest.fixture
def ns101_lab_scope(monkeypatch):
    # Guard BEFORE parsing/overriding. Default collection never uses native COM.
    if sys.platform != "win32" or os.environ.get("NETSENTINEL_NS101_HOST_ONLY_AUTHORIZED") != "YES":
        pytest.skip("Explicit host-only native test only")
    target = LabTarget(os.environ.get("NETSENTINEL_NS101_LAB_IP", ""),
        os.environ.get("NETSENTINEL_NS101_WINDOWS_LAB_IP", ""),
        os.environ.get("NETSENTINEL_NS101_LAB_SUBNET", ""),
        int(os.environ.get("NETSENTINEL_NS101_LAB_PORT", "0")),
        ResponseProfile(os.environ.get("NETSENTINEL_NS101_PROFILE", "")))
    _verify_guest(target)
    with _exact_lab_validation(monkeypatch, target.ip):
        yield target


def _inventory(policy):
    import pythoncom
    from win32com.client.dynamic import Dispatch
    props = tuple(windows_firewall_com.TEXT_PROPERTIES.values()) + (
        "Protocol", "Profiles", "Direction", "Action", "ApplicationName", "RemoteAddresses",
        "RemotePorts", "Enabled", "Interfaces", "EdgeTraversal", "EdgeTraversalOptions", "SecureFlags",
    )
    rows = []
    rules = policy.Rules
    before = rules.Count
    if type(before) is not int or not 0 <= before <= windows_firewall_com.MAX_ENUMERATED_RULES:
        pytest.fail("Native inventory unavailable; no mutation")
    for rule in rules:
        if len(rows) >= windows_firewall_com.MAX_ENUMERATED_RULES:
            pytest.fail("Native inventory budget exhausted")
        rule = Dispatch(rule._oleobj_.QueryInterface(pythoncom.MakeIID(
            windows_firewall_com.RULE3_IID), pythoncom.IID_IDispatch))
        rows.append({key: getattr(rule, key) for key in props})
    assert len(rows) == before == rules.Count, "Native inventory changed during enumeration"
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def _policy_state(policy):
    import pythoncom
    # Indexed PROPERTYGET, without a zero-argument getter or generated makepy.
    return {str(profile): {key: policy._oleobj_.Invoke(
        policy._oleobj_.GetIDsOfNames(key), 0, pythoncom.DISPATCH_PROPERTYGET, True, profile)
        for key in ("FirewallEnabled", "DefaultInboundAction", "DefaultOutboundAction", "BlockAllInboundTraffic")
    } for profile in (1, 2, 4)}


def _build_client(folder, target):
    source = Path(__file__).parents[1] / "fixtures" / "ns101" / "TcpClient.cs"
    text = source.read_text(encoding="utf-8").replace("__LAB_IP__", target.ip).replace("__LAB_PORT__", str(target.port))
    local_source = folder / "NetSentinel-NS101-TCP-client.cs"
    executable = folder / "NetSentinel-NS101-TCP-client.exe"
    local_source.write_text(text, encoding="utf-8")
    compiler = Path(os.environ["SystemRoot"]) / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"
    if not compiler.is_file():
        pytest.fail("Trusted guest Framework compiler unavailable; no firewall mutation")
    completed = subprocess.run([str(compiler), "/nologo", "/target:exe", "/optimize+",
        f"/out:{executable}", str(local_source)], capture_output=True, timeout=30, check=False)
    assert completed.returncode == 0 and executable.is_file(), "TCP fixture compilation failed; no mutation"
    return executable


def _run_client(path):
    return subprocess.run([str(path)], capture_output=True, timeout=15, check=False)


def _control(target):
    # Independent program, on-link literal only; require controlled endpoint echo.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect((target.ip, target.port))
        client.sendall(b"N")
        assert client.recv(1) == b"N", "Controlled listener unavailable"


@pytest.mark.windows_live
@pytest.mark.lab_live
def test_ns101_isolated_vm_create_read_manifest_remove_and_cleanup(tmp_path, ns101_lab_scope):
    target = ns101_lab_scope
    import pythoncom
    import win32file
    from win32com.client.dynamic import Dispatch
    pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
    owned = None
    policy = None
    fixture_files = []
    record = {"result": "FAIL", "manifest_persisted": False}
    try:
        policy = Dispatch("HNetCfg.FwPolicy2")
        before, before_policy = _inventory(policy), _policy_state(policy)
        assert not any(str(row["Name"]).casefold().startswith("netsentinel:") for row in before), "Stale prefix rule; STOP"
        (tmp_path / "firewall-pre-state.local.json").write_text(
            json.dumps({"rules": before, "policy": before_policy}, sort_keys=True), encoding="utf-8")
        # A fresh process still uses the unchanged public-only production default.
        probe = subprocess.run([sys.executable, "-c", "from netsentinel.domain.response import _remote_ip; "
            "import sys; _remote_ip(sys.argv[1])", target.ip], capture_output=True, timeout=15, check=False)
        assert probe.returncode != 0 and b"outside the supported public unicast scope" in probe.stderr
        fixture_files = [tmp_path / "NetSentinel-NS101-TCP-client.cs", tmp_path / "NetSentinel-NS101-TCP-client.exe"]
        path = _build_client(tmp_path, target)
        fixture = path.read_bytes()
        assert _run_client(path).returncode == 0, "PRE connectivity failed; no mutation"
        _control(target)
        handle = win32file.CreateFile(str(path), 0x80, 1, None, 3, 0x00200000, None)
        try:
            identity = file_identity(win32file.GetFileInformationByHandle(handle))
        finally:
            handle.Close()
        at = datetime.now(UTC)
        rule_id = uuid4()
        c = ResponseCommand(rule_id, rule_id, uuid4(), ResponseAction.CREATE,
            ResponseRuleSpec(str(path), target.ip, ResponseTransport.TCP, target.port, target.profile,
                             ResponseLifetime(ResponseLifetimeKind.UNTIL_MANUALLY_REMOVED)),
            ResponseSource(uuid4(), uuid4(), at, ResponseSourceStatus.AVAILABLE, ObservationQuality.COMPLETE),
            identity, at, 1)
        guard = WindowsExecutableTarget(lambda p: p == str(path) and Path(p).read_bytes() == fixture)
        backend = WindowsResponseFirewall(windows_firewall_com.session, guard)
        try:
            request = FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, datetime.now(UTC)))
            receipt = backend.create(request)
            if receipt.result.outcome is not ResponseOutcome.VERIFIED:
                (tmp_path / "native-refusal.local.json").write_text(json.dumps({
                    "outcome": receipt.result.outcome.value, "reason": receipt.result.reason.value,
                    "rule_name": c.rule_name, "state_unchanged": _inventory(policy) == before,
                }), encoding="utf-8")
                pytest.fail(f"Native CREATE unverified: {receipt.result.reason.value}; no ownership for blind cleanup")
            owned = receipt.manifest
            assert owned is not None and owned.creation == request
            assert backend.read(owned).status is FirewallReadStatus.MATCHED
            during = _inventory(policy)
            assert [row for row in during if row["Name"] != c.rule_name] == before
            assert len([row for row in during if row["Name"] == c.rule_name]) == 1
            assert _policy_state(policy) == before_policy
            _control(target)
            blocked = _run_client(path)
            # WSAEACCES, rather than generic unreachable/listener failure.
            assert blocked.returncode == 3 and b"NS101_SOCKET_ERROR:10013" in blocked.stdout, "Scoped native BLOCK unproven"
            _control(target)
            record.update(pre_connectivity=True, create=True, readback=True,
                manifest=True, scoped_block=True, unrelated_control=True)
        finally:
            if owned is not None:
                undo = replace(c, command_id=uuid4(), action=ResponseAction.REMOVE,
                               prepared_at=datetime.now(UTC), selection_generation=2)
                result = backend.remove(FirewallRemoveRequest(undo, ResponseConfirmation(
                    undo.fingerprint, datetime.now(UTC)), owned))
                assert result.outcome is ResponseOutcome.VERIFIED, "Native cleanup unverified; retain VM for recovery"
                assert backend.read(owned).status is FirewallReadStatus.ABSENT
                assert _inventory(policy) == before
                assert _policy_state(policy) == before_policy
                assert _run_client(path).returncode == 0, "Post-remove connectivity not restored"
                _control(target)
                record.update(remove=True, absence=True, restored_connectivity=True,
                    unrelated_rules_unchanged=True, global_policy_unchanged=True,
                    inventory_sha256=sha256(json.dumps(before, sort_keys=True).encode()).hexdigest())
    finally:
        try:
            for file in fixture_files:
                file.unlink(missing_ok=True)
            record["fixture_files_removed"] = all(not file.exists() for file in fixture_files)
            required = ("pre_connectivity", "create", "readback", "manifest", "scoped_block", "unrelated_control",
                        "remove", "absence", "restored_connectivity", "unrelated_rules_unchanged",
                        "global_policy_unchanged", "fixture_files_removed")
            if all(record.get(key) is True for key in required):
                record["result"] = "PASS"
            (tmp_path / "native-result.local.json").write_text(json.dumps(record), encoding="utf-8")
        finally:
            policy = None
            pythoncom.CoUninitialize()
