"""Explicit NS-104 dedicated VMware acceptance operator; never shipped.

Requires NS-101 VM/lab authorization and its original hardware/network guard.
Separate invocations exercise actual process restart and durable SQLite custody.
The exact private-IP exception is active only in this test process, as in NS-101.
"""

from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4


ROOT = Path(__file__).resolve().parents[3]
PACKAGES = ROOT / "packages"
sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(PACKAGES), str(PACKAGES / "win32"), str(PACKAGES / "win32/lib")]
DLL_DIRECTORY = os.add_dll_directory(str(PACKAGES / "pywin32_system32")) if PACKAGES.exists() else None

import pytest  # noqa: E402

from netsentinel.application.response_lifecycle_service import ResponseLifecycleService  # noqa: E402
from netsentinel.domain.connections import ObservationQuality  # noqa: E402
from netsentinel.domain.response import (  # noqa: E402
    FirewallCreateRequest, FirewallRemoveRequest, FirewallReadStatus, ResponseAction,
    ResponseCommand, ResponseConfirmation, ResponseLifetime, ResponseLifetimeKind,
    ResponseOutcome, ResponseProfile, ResponseRuleSpec, ResponseSource,
    ResponseSourceStatus, ResponseTransport,
)
from netsentinel.domain.response_lifecycle import (  # noqa: E402
    ResponseAuditEvent as Audit, ResponseOperationStatus as Status,
    ResponseReconciliation as Reconciliation,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase  # noqa: E402
from netsentinel.infrastructure.sqlite.response_repository import SQLiteResponseLifecycleRepository  # noqa: E402
from netsentinel.infrastructure import windows_firewall_com  # noqa: E402
from netsentinel.infrastructure.windows_response_firewall import WindowsResponseFirewall  # noqa: E402
from netsentinel.infrastructure.windows_response_target import WindowsExecutableTarget, file_identity  # noqa: E402
from netsentinel.infrastructure.windows_installer import windows_local_app_data  # noqa: E402
from tests.integration.test_response_firewall_vm import (  # noqa: E402
    LabTarget, _verify_guest, _exact_lab_validation, _inventory, _policy_state,
    _build_client, _run_client, _control,
)


def now():
    return datetime.now(UTC)


def audit_records(repo):
    """Read the finite NS-102 audit by cursor; never mistake one page for history."""
    rows = []
    sequence = 0
    for _ in range(83):  # 8192-row contract / 100-row pages, plus termination.
        page = repo.audit(after_sequence=sequence, limit=100)
        rows.extend(page)
        if len(page) < 100:
            assert len(rows) <= 8192
            return rows
        sequence = page[-1].sequence
    raise AssertionError("Audit exceeds the frozen bound")


def run(action, custody):
    # Authorization variables must be supplied by the explicit VM operator.
    target = LabTarget("192.168.140.129", "192.168.140.128", "192.168.140.0/24", 49191, ResponseProfile.PUBLIC)
    _verify_guest(target)
    import pythoncom
    import win32file
    import ctypes
    from win32com.client.dynamic import Dispatch

    state_root = ROOT / ("install-state" if custody == "installed" else "lab-state")
    state_root.mkdir(exist_ok=True)
    state_file = state_root / "operator.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {"names": []}
    state["sequence"] = state.get("sequence", 0) + 1
    path = state_root / "NetSentinel-NS101-TCP-client.exe"
    private = custody == "lab"
    seam = _exact_lab_validation(pytest.MonkeyPatch(), target.ip) if private else nullcontext()
    with seam:
        dbpath = (windows_local_app_data() / "NetSentinel/netsentinel.sqlite3") if not private else state_root / "response.sqlite3"
        repo = SQLiteResponseLifecycleRepository(SQLiteDatabase(dbpath))
        fixture = path.read_bytes() if path.exists() else None
        backend = WindowsResponseFirewall(windows_firewall_com.session,
            WindowsExecutableTarget(lambda p: p == str(path) and Path(p).read_bytes() == fixture))
        service = ResponseLifecycleService(repo, backend)
        pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
        policy = None
        result = {"action": action, "custody": custody, "result": "FAIL", "sequence": state["sequence"]}
        result["elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        if action == "deny-remove":
            assert not result["elevated"], "Denial test requires a real non-elevated token"
        try:
            policy = Dispatch("HNetCfg.FwPolicy2")
            if action == "init":
                before = _inventory(policy)
                assert not any(str(row["Name"]).casefold().startswith("netsentinel:") for row in before), "Stale rule; no prefix cleanup"
                assert not repo.page(), "Acceptance requires clean isolated custody"
                (state_root / "inventory.local.json").write_text(json.dumps({"rules": before, "policy": _policy_state(policy)}, sort_keys=True))
                path = _build_client(state_root, target)
                fixture = path.read_bytes()
                assert _run_client(path).returncode == 0
                _control(target)
                result["normal_connectivity"] = True
            elif action in {"create", "interrupt-create"}:
                handle = win32file.CreateFile(str(path), 0x80, 1, None, 3, 0x00200000, None)
                try:
                    identity = file_identity(win32file.GetFileInformationByHandle(handle))
                finally:
                    handle.Close()
                at, rule_id = now(), uuid4()
                c = ResponseCommand(rule_id, rule_id, repo.store_id, ResponseAction.CREATE,
                    ResponseRuleSpec(str(path), target.ip if private else "8.8.8.8", ResponseTransport.TCP,
                        target.port, target.profile, ResponseLifetime(ResponseLifetimeKind.UNTIL_MANUALLY_REMOVED)),
                    ResponseSource(uuid4(), uuid4(), at, ResponseSourceStatus.AVAILABLE, ObservationQuality.COMPLETE), identity, at, 1)
                state["names"].append(c.rule_name)
                state["create_id"] = str(rule_id)
                state_file.write_text(json.dumps(state))  # Test operator recovery identity, not authority.
                native_create = backend.create_prepared
                def observed_create(claim):
                    durable = repo.get(rule_id)
                    assert durable.status is Status.ATTEMPT and durable.claim == claim and durable.manifest is None
                    assert [row.event for row in audit_records(repo) if row.operation_id == rule_id] == [Audit.PREPARED, Audit.ATTEMPT]
                    result["prepared_before_native"] = True
                    return native_create(claim)
                backend.create_prepared = observed_create
                save = repo.save
                def fail_final(operation, event):
                    if event is Audit.VERIFIED_SUCCESS:
                        raise SystemExit("NS104 deterministic interruption after native verified CREATE")
                    return save(operation, event)
                if action == "interrupt-create":
                    repo.save = fail_final
                try:
                    created = service.create(FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, now())))
                    result.update(status=created.status.value, outcome=created.result.outcome.value,
                                  reason=created.result.reason.value)
                    assert created.status is Status.VERIFIED and created.manifest is not None
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    assert repo.get(rule_id) == created
                    result["final_durable"] = True
                except SystemExit:
                    created = repo.get(rule_id)
                    assert created.status is Status.ATTEMPT and created.manifest is None
                    assert backend.read_prepared(created.claim).status is FirewallReadStatus.MATCHED
                    result["interruption_durable"] = True
                if private:
                    blocked = _run_client(path)
                    assert blocked.returncode == 3 and b"NS101_SOCKET_ERROR:10013" in blocked.stdout
                    result["actual_block"] = True
                _control(target)
                result["unrelated_control"] = True
            else:
                created = repo.get(UUID(state["create_id"]))
                successes = sum(row.event is Audit.VERIFIED_SUCCESS and row.action is ResponseAction.CREATE for row in audit_records(repo))
                inventory_before = _inventory(policy)
                if action == "restart":
                    reconciled = service.reconcile()
                    current = repo.get(created.operation_id)
                    assert current.manifest is not None and current.reconciliation in {Reconciliation.EXACT, Reconciliation.PROMOTED}
                    assert backend.read(current.manifest).status is FirewallReadStatus.MATCHED
                    assert _inventory(policy) == inventory_before
                    assert sum(row.event is Audit.VERIFIED_SUCCESS and row.action is ResponseAction.CREATE for row in audit_records(repo)) == successes
                    result.update(reconciliation=current.reconciliation.value, create_audit_not_replayed=True,
                                  recovered_unknown_add_time=current.manifest.created_at is None)
                    assert reconciled
                elif action in {"undo", "interrupt-remove", "interrupt-before-remove", "interrupt-remove-receipt", "deny-remove"}:
                    manifest = created.manifest
                    assert manifest is not None
                    c = replace(manifest.creation.command, command_id=uuid4(), action=ResponseAction.REMOVE,
                                prepared_at=now(), selection_generation=2)
                    request = FirewallRemoveRequest(c, ResponseConfirmation(c.fingerprint, now()), manifest)
                    state["remove_id"] = str(c.command_id)
                    state_file.write_text(json.dumps(state))
                    save = repo.save
                    failure_event = {"interrupt-remove": Audit.ROLLBACK_SUCCESS,
                                     "interrupt-before-remove": Audit.ROLLBACK_ATTEMPT,
                                     "interrupt-remove-receipt": Audit.READBACK_VERIFIED}.get(action)
                    def stop(operation, event):
                        if event is failure_event:
                            raise SystemExit("NS104 deterministic removal interruption")
                        return save(operation, event)
                    if failure_event:
                        repo.save = stop
                    try:
                        removed = service.rollback(request)
                        if action == "deny-remove":
                            assert removed.result.outcome is not ResponseOutcome.VERIFIED
                            assert removed.result.reason.value == "access_denied"
                            assert backend.read(manifest).status is FirewallReadStatus.MATCHED
                            result["typed_denial"] = removed.result.reason.value
                        else:
                            assert removed.status is Status.VERIFIED and removed.result.outcome is ResponseOutcome.VERIFIED
                            assert backend.read(manifest).status is FirewallReadStatus.ABSENT
                            result["verified_rollback"] = True
                    except SystemExit:
                        pending = repo.get(c.command_id)
                        result["durable_remove_status"] = pending.status.value
                        result["native_read"] = backend.read(manifest).status.value
                    if private and action != "deny-remove" and action != "interrupt-before-remove":
                        assert _run_client(path).returncode == 0
                        _control(target)
                        result["restored_connectivity"] = True
                elif action == "recover-remove":
                    service.reconcile()
                    removed = repo.get(UUID(state["remove_id"]))
                    assert _inventory(policy) == inventory_before
                    result.update(status=removed.status.value, reconciliation=removed.reconciliation.value,
                                  outcome=removed.result.outcome.value if removed.result else None)
                elif action == "external-edit":
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    policy.Rules.Item(created.command.rule_name).Description = "NS104 explicit external test edit"
                    service.reconcile()
                    assert repo.get(created.operation_id).reconciliation is Reconciliation.EXTERNAL_MODIFIED
                    assert policy.Rules.Item(created.command.rule_name).Description == "NS104 explicit external test edit"
                    result["external_modified_no_repair"] = True
                elif action == "cleanup-edit":
                    observed = backend.read(created.manifest)
                    assert observed.status is FirewallReadStatus.MISMATCH
                    assert observed.snapshot == replace(created.manifest.rule, description="NS104 explicit external test edit")
                    # Explicit TEST OPERATOR restores only its documented exact edit,
                    # then normal separately confirmed strict rollback is required.
                    policy.Rules.Item(created.command.rule_name).Description = created.manifest.rule.description
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    result["test_operator_exact_edit_restored"] = True
                elif action == "observe-edited":
                    observed = backend.read(created.manifest)
                    assert observed.status is FirewallReadStatus.MISMATCH
                    assert observed.snapshot == replace(created.manifest.rule, description="NS104 explicit external test edit")
                    assert repo.get(created.operation_id).reconciliation is Reconciliation.EXTERNAL_MODIFIED
                    assert _inventory(policy) == inventory_before
                    result["edited_rule_preserved_through_uninstall"] = True
                elif action == "external-missing":
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    with windows_firewall_com.session() as api:
                        api.remove(created.manifest.rule, lambda: None)
                    service.reconcile()
                    assert repo.get(created.operation_id).reconciliation is Reconciliation.EXTERNAL_MISSING
                    assert backend.read(created.manifest).status is FirewallReadStatus.ABSENT
                    result["external_missing_no_recreate"] = True
                elif action == "duplicate-add":
                    assert not private and backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    internal = str(uuid4())
                    state["duplicate_internal"] = internal
                    state_file.write_text(json.dumps(state))
                    command = ("$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '" + internal
                               + "' -DisplayName '" + created.command.rule_name
                               + "' -Description 'NS104 explicitly unrelated duplicate specimen'"
                               + " -Direction Outbound -Action Block -Program '" + str(path)
                               + "' -Protocol TCP -RemoteAddress 8.8.8.8 -RemotePort 49191 -Profile Public -Enabled False | Out-Null")
                    child = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                                           capture_output=True, timeout=30, check=False)
                    assert child.returncode == 0
                    assert backend.read(created.manifest).status is FirewallReadStatus.DUPLICATE
                    duplicate_inventory = _inventory(policy)
                    assert len([row for row in duplicate_inventory if row["Name"] == created.command.rule_name]) == 2
                    service.reconcile()
                    assert repo.get(created.operation_id).reconciliation is Reconciliation.AMBIGUOUS
                    assert _inventory(policy) == duplicate_inventory
                    result["ambiguous_no_adoption_or_cleanup"] = True
                elif action == "duplicate-cleanup":
                    assert not private and backend.read(created.manifest).status is FirewallReadStatus.DUPLICATE
                    # TEST OPERATOR only: literal independently recorded internal UUID,
                    # full fresh bounded-state comparison, no friendly-name/prefix remove.
                    candidates = [row for row in _inventory(policy) if row["Name"] == created.command.rule_name]
                    assert len(candidates) == 2
                    edits = [row for row in candidates if row["Description"] == "NS104 explicitly unrelated duplicate specimen"]
                    assert len(edits) == 1 and edits[0]["Enabled"] is False
                    command = ("$ErrorActionPreference='Stop'; $r=Get-NetFirewallRule -Name '" + state["duplicate_internal"]
                               + "'; if (@($r).Count -ne 1 -or $r.DisplayName -cne '" + created.command.rule_name
                               + "' -or $r.Description -cne 'NS104 explicitly unrelated duplicate specimen'"
                               + " -or $r.Enabled -ne 'False' -or $r.Direction -ne 'Outbound' -or $r.Action -ne 'Block'"
                               + " -or $r.Profile -ne 'Public') {throw 'Operator specimen mismatch'};"
                               + " $p=$r|Get-NetFirewallApplicationFilter; $a=$r|Get-NetFirewallAddressFilter;"
                               + " $port=$r|Get-NetFirewallPortFilter; if ($p.Program -cne '" + str(path)
                               + "' -or $a.RemoteAddress -ne '8.8.8.8' -or $port.Protocol -ne 'TCP'"
                               + " -or $port.RemotePort -ne '49191') {throw 'Operator scope mismatch'};"
                               + " Remove-NetFirewallRule -Name '" + state["duplicate_internal"] + "'")
                    child = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                                           capture_output=True, timeout=30, check=False)
                    assert child.returncode == 0
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    assert _inventory(policy) == [row for row in inventory_before if row != edits[0]]
                    result["test_operator_literal_internal_duplicate_removed"] = True
                elif action == "observe-cleanup":
                    assert backend.read(created.manifest).status is FirewallReadStatus.ABSENT
                    assert repo.has_verified_removal(created.command.rule_id)
                    assert _run_client(path).returncode == 0
                    _control(target)
                    result["verified_absence_restored_connectivity"] = True
                elif action == "observe-block":
                    assert backend.read(created.manifest).status is FirewallReadStatus.MATCHED
                    blocked = _run_client(path)
                    assert blocked.returncode == 3 and b"NS101_SOCKET_ERROR:10013" in blocked.stdout
                    _control(target)
                    result.update(actual_block=True, unrelated_control=True)
                else:
                    raise ValueError("Unknown acceptance action")
            baseline = json.loads((state_root / "inventory.local.json").read_text())
            current = _inventory(policy)
            unrelated = [row for row in current if row["Name"] not in state["names"]]
            assert unrelated == baseline["rules"], "Unrelated firewall inventory changed; STOP"
            assert _policy_state(policy) == baseline["policy"], "Firewall profile changed; STOP"
            result.update(result="PASS", unrelated_count=len(unrelated),
                          owned_count=len(current) - len(unrelated),
                          inventory_sha256=sha256(json.dumps(unrelated, sort_keys=True).encode()).hexdigest())
            state_file.write_text(json.dumps(state))
        finally:
            (state_root / (action + ".result.json")).write_text(json.dumps(result, sort_keys=True))
            (state_root / (f"{state['sequence']:03}-" + action + ".result.json")).write_text(json.dumps(result, sort_keys=True))
            policy = None
            pythoncom.CoUninitialize()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in {"lab", "installed"}:
        raise SystemExit("Explicit action and lab/installed custody required")
    run(sys.argv[1], sys.argv[2])
