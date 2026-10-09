"""NS-104 offline uninstall safety: real custody, injected OS, no native writes."""

from contextlib import nullcontext
import ast
from dataclasses import replace
from pathlib import Path
import runpy
import sqlite3
import sys
from uuid import uuid4
from types import SimpleNamespace

import pytest

from netsentinel.application.response_lifecycle_service import ResponseLifecycleService
from netsentinel.domain.response import FirewallCreateRequest, ResponseConfirmation
from netsentinel.domain.response_lifecycle import ResponseAuditEvent, ResponseOperationStatus, ResponseStorageError
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
from netsentinel.infrastructure.sqlite.response_repository import SQLiteResponseLifecycleRepository
from netsentinel.infrastructure.uninstall_data import uninstall_local_data
from netsentinel.infrastructure.uninstall_response import inspect_response_custody, write_uninstall_response_report
from netsentinel.infrastructure import windows_installer
from tests.integration.test_response_lifecycle import Clock, remove_request
from tests.unit.domain.test_response import STORE_ID, command
from tests.unit.infrastructure.test_windows_response_firewall import FakeApi, adapter


def test_native_acceptance_audit_reads_all_bounded_pages():
    # The VM harness must see new PREPARED events after the first 100-row page.
    # Extract its pure function without importing its Windows-only operator.
    source = Path(__file__).parents[1] / "fixtures/ns104/native_lifecycle.py"
    function = next(node for node in ast.parse(source.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == "audit_records")
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    records = [SimpleNamespace(sequence=index) for index in range(1, 204)]
    calls = []

    def audit(*, after_sequence, limit):
        calls.append((after_sequence, limit))
        return records[after_sequence:after_sequence + limit]

    assert namespace["audit_records"](SimpleNamespace(audit=audit)) == records
    assert calls == [(0, 100), (100, 100), (200, 100)]


@pytest.fixture
def custody(tmp_path, monkeypatch):
    root = tmp_path / "NetSentinel"
    database = SQLiteDatabase(root / "netsentinel.sqlite3")
    repo = SQLiteResponseLifecycleRepository(database, STORE_ID)
    api = FakeApi()
    clock = Clock()
    firewall = adapter(api)
    firewall._clock = clock
    service = ResponseLifecycleService(repo, firewall, clock=clock)
    monkeypatch.setattr(windows_installer, "stopped_desktop", nullcontext)
    monkeypatch.setattr(windows_installer, "windows_local_app_data", lambda: tmp_path)
    return tmp_path, database, repo, api, service


def create(service):
    identity = uuid4()
    c = replace(command(), command_id=identity, rule_id=identity)
    return service.create(FirewallCreateRequest(c, ResponseConfirmation(c.fingerprint, c.prepared_at)))


def test_report_and_delete_no_custody_do_not_create_database(tmp_path, monkeypatch):
    monkeypatch.setattr(windows_installer, "stopped_desktop", nullcontext)
    monkeypatch.setattr(windows_installer, "windows_local_app_data", lambda: tmp_path)
    report = inspect_response_custody(tmp_path)
    assert report.permits_data_delete and "No ownership claim" in report.text
    assert write_uninstall_response_report() == 0
    assert not (tmp_path / "NetSentinel").exists()
    assert uninstall_local_data() == 0


@pytest.mark.parametrize("version", [8, 18, 19, 20])
def test_report_never_migrates_or_initializes_database(tmp_path, version):
    db = SQLiteDatabase(tmp_path / "NetSentinel/netsentinel.sqlite3",
                        migration_runner=MigrationRunner(builtin_migrations()[:version]))
    with db.connection():
        pass
    before = db.path.read_bytes()
    assert inspect_response_custody(tmp_path).permits_data_delete
    assert db.path.read_bytes() == before
    with sqlite3.connect(db.path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == version
        if version == 20:
            assert connection.execute("SELECT count(*) FROM response_store").fetchone()[0] == 0


def test_preserve_list_exact_scope_no_witness_or_mutation(custody):
    base, db, repo, api, service = custody
    owned = create(service)
    with db.connection() as connection:
        before = tuple(connection.iterdump())
    calls = tuple(api.calls)
    report = inspect_response_custody(base)
    assert report.available and report.remaining_count == 1 and not report.permits_data_delete
    for value in (owned.command.rule_name, owned.command.spec.program_path,
                  owned.command.spec.remote_ip, "443", "tcp", "private", "FINAL", "UNKNOWN", "NOT ATTEMPTED"):
        assert value in report.text
    assert owned.claim.witness not in report.text and owned.claim.expected_rule.description not in report.text
    assert owned.command.spec.program_path not in repr(report)
    assert tuple(api.calls) == calls
    with db.connection() as connection:
        assert tuple(connection.iterdump()) == before
    assert write_uninstall_response_report() == 0
    assert (base / "NetSentinel/firewall-uninstall-report.txt").read_text(encoding="utf-8-sig") == report.text
    assert uninstall_local_data() == 1
    assert db.path.exists() and len(api.rows) == 1


def test_verified_confirmed_cleanup_then_delete(custody):
    base, db, _, api, service = custody
    owned = create(service)
    removed = service.rollback(remove_request(owned.manifest))
    assert removed.status is ResponseOperationStatus.VERIFIED
    report = inspect_response_custody(base)
    assert report.permits_data_delete and report.remaining_count == 0
    assert uninstall_local_data() == 0 and not db.path.exists() and not api.rows


@pytest.mark.parametrize("state", ["missing", "modified", "duplicate", "denied", "interrupted"])
def test_unverified_cleanup_preserves_custody_and_lists_rule(custody, state):
    base, db, repo, api, service = custody
    owned = create(service)
    if state == "missing":
        api.rows = ()
    elif state == "modified":
        api.rows = (replace(api.rows[0], description="External administrator edit"),)
    elif state == "duplicate":
        api.rows = (api.rows[0], api.rows[0])
    elif state == "denied":
        from netsentinel.domain.response import FirewallReadStatus
        from netsentinel.infrastructure.windows_response_firewall import FirewallApiError
        def denied(*args):
            raise FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True)
        api.hooks["remove"] = denied
    else:
        save = repo.save
        def interrupted(operation, event):
            if event is ResponseAuditEvent.READBACK_VERIFIED:
                raise ResponseStorageError("Interrupted receipt")
            return save(operation, event)
        repo.save = interrupted
    removed = service.rollback(remove_request(owned.manifest))
    assert removed.status is not ResponseOperationStatus.VERIFIED
    calls = tuple(api.calls)
    report = inspect_response_custody(base)
    assert report.remaining_count == 1 and not report.permits_data_delete
    assert owned.command.rule_name in report.text
    assert uninstall_local_data() == 1 and db.path.exists()
    assert tuple(api.calls) == calls  # report/deletion guard cannot dispatch/retry


@pytest.mark.parametrize("damage", ["future", "corrupt", "summary", "foreign_store", "over_budget"])
def test_unenumerable_custody_is_unknown_never_empty_success(custody, damage):
    base, db, _, api, service = custody
    create(service)
    with db.connection() as connection:
        if damage == "future":
            connection.execute("INSERT INTO schema_migrations VALUES (21, 'future', 1)")
        elif damage == "corrupt":
            connection.execute("UPDATE response_operations SET request=?", (b"{}",))
        elif damage == "summary":
            connection.execute("UPDATE response_operations SET fingerprint=?", ("0" * 64,))
        elif damage == "foreign_store":
            connection.execute("UPDATE response_store SET store_id=?", (str(uuid4()),))
        else:
            connection.execute("DROP INDEX response_create_identity")
            row = connection.execute("SELECT * FROM response_operations").fetchone()
            for _ in range(1024):
                values = list(row)
                values[0], values[6] = str(uuid4()), None
                connection.execute("INSERT INTO response_operations VALUES (" + ",".join("?" for _ in values) + ")", values)
    report = inspect_response_custody(base)
    assert not report.available and not report.permits_data_delete and "UNKNOWN" in report.text
    assert write_uninstall_response_report() == 1
    assert uninstall_local_data() == 1 and db.path.exists() and len(api.rows) == 1


def test_report_maintenance_mode_cannot_start_gui_or_accept_output_path(monkeypatch):
    from netsentinel.infrastructure import uninstall_response
    monkeypatch.setattr(uninstall_response, "write_uninstall_response_report", lambda: 17)
    entry = runpy.run_path(str(Path(__file__).parents[2] / "packaging/entry.py"))
    monkeypatch.setattr(sys, "argv", ["NetSentinel.exe", "--uninstall-report-firewall"])
    assert entry["main"]() == 17
    monkeypatch.setattr(sys, "argv", ["NetSentinel.exe", "--uninstall-report-firewall", "arbitrary-path"])
    assert entry["main"]() == 2
