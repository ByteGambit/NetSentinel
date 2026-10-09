"""NS-096 offline contracts. These are not native installer/VM acceptance."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
from uuid import uuid4

import pytest

from netsentinel.bootstrap import runtime_config_path
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, default_database_path
from netsentinel.infrastructure.sqlite.migrations import DatabaseSchemaTooNew, MigrationRunner, builtin_migrations
from netsentinel.infrastructure.uninstall_data import UnsafeDataRoot, delete_owned_data
from netsentinel.shared.config import AppConfig, WindowCloseBehavior, load_config_file, save_config_file
from netsentinel.shared.paths import user_data_paths
from netsentinel.version import __version__


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("runtime", ["development", "portable", "installed"])
@pytest.mark.parametrize("folder", ["user data", "Berke-İzmir Test Kullanıcı Çalışma"])
def test_paths_are_separate_from_program_and_bundle(tmp_path, monkeypatch, runtime, folder):
    base = tmp_path / folder
    program = base / "Programs" / "NetSentinel"
    program.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(base))
    monkeypatch.chdir(program)
    monkeypatch.setattr(sys, "frozen", runtime != "development", raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(program / "_internal"), raising=False)
    paths = user_data_paths()
    assert paths.root == base / "NetSentinel"
    assert default_database_path() == paths.database
    assert runtime_config_path() == paths.config
    assert paths.log == paths.root / "netsentinel.log"
    assert not paths.root.exists()  # resolution never creates persistent data
    save_config_file(paths.config, AppConfig())
    with SQLiteDatabase().connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
    assert not list(program.iterdir())


def test_explicit_test_override_does_not_touch_environment_root(tmp_path, monkeypatch):
    real = tmp_path / "do not touch"
    monkeypatch.setenv("LOCALAPPDATA", str(real))
    paths = user_data_paths(local_app_data=tmp_path / "isolated")
    assert default_database_path(local_app_data=tmp_path / "isolated") == paths.database
    assert not real.exists()


def test_missing_localappdata_uses_profile_never_executable(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert user_data_paths().root == tmp_path / "AppData/Local/NetSentinel"


@pytest.mark.parametrize("old_schema", [8, 18, 19])
def test_old_current_schema_upgrade_preserves_existing_history_and_config(tmp_path, old_schema):
    paths = user_data_paths(local_app_data=tmp_path / "Test Kullanıcı")
    config = replace(AppConfig(), onboarding_completed=True, desktop_notifications_enabled=True,
        window_close_behavior=WindowCloseBehavior.HIDE_TO_TRAY, storage_retention_enabled=True)
    save_config_file(paths.config, config)
    before = paths.config.read_bytes()
    with SQLiteDatabase(paths.database, migration_runner=MigrationRunner(builtin_migrations()[:old_schema])).connection() as connection:
        connection.execute("""INSERT INTO connection_history
            (id, protocol, local_address, local_port, pid, process_name, process_status,
             connection_state, first_seen_utc_us, last_seen_utc_us)
            VALUES ('12345678-1234-1234-1234-123456789abc', 'tcp', '127.0.0.1', 5000, 42, 'old.exe', 'available', 'listen', 1, 1)""")
    with SQLiteDatabase(paths.database).connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
        assert connection.execute("SELECT process_name FROM connection_history").fetchone()[0] == "old.exe"
    assert paths.config.read_bytes() == before
    assert load_config_file(paths.config).config == config


def test_future_schema_refuses_without_reset(tmp_path):
    path = tmp_path / "future.sqlite3"
    with SQLiteDatabase(path).connection() as connection:
        connection.execute("INSERT INTO schema_migrations VALUES (21, 'future', 1)")
    with pytest.raises(DatabaseSchemaTooNew):
        SQLiteDatabase(path).connect()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 21


def test_old_config_keeps_safe_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"onboarding_completed":true}', encoding="utf-8")
    config = load_config_file(path).config
    assert not config.desktop_notifications_enabled
    assert not config.storage_retention_enabled
    assert not config.threat_intel_consents
    assert config.window_close_behavior is WindowCloseBehavior.QUIT_APPLICATION


@pytest.mark.parametrize("target", ["", ".", "..", "other", "NetSentinel/.."])
def test_delete_rejects_noncanonical_or_broad_roots(tmp_path, target):
    owned = tmp_path / "NetSentinel"
    owned.mkdir()
    sentinel = owned / "config.json"
    sentinel.write_text("preserve")
    with pytest.raises(UnsafeDataRoot):
        delete_owned_data(tmp_path / target, local_app_data=tmp_path, confirmed=True)
    assert sentinel.read_text() == "preserve"


def test_delete_requires_confirmation(tmp_path):
    owned = tmp_path / "NetSentinel"
    owned.mkdir()
    with pytest.raises(UnsafeDataRoot):
        delete_owned_data(owned, local_app_data=tmp_path)
    assert owned.is_dir()


def test_confirmed_delete_only_removes_owned_root(tmp_path):
    owned = tmp_path / "NetSentinel"
    (owned / "nested").mkdir(parents=True)
    (owned / "nested/history.sqlite3").write_bytes(b"fixture")
    exported = tmp_path / "support-export.json"
    exported.write_text("external")
    unrelated = tmp_path / "Programs/NetSentinel"
    unrelated.mkdir(parents=True)
    delete_owned_data(owned, local_app_data=tmp_path, confirmed=True)
    assert not owned.exists()
    assert tmp_path.is_dir() and unrelated.is_dir() and exported.read_text() == "external"
    delete_owned_data(owned, local_app_data=tmp_path, confirmed=True)  # absent idempotent
    save_config_file(owned / "config.json", AppConfig())
    assert load_config_file(owned / "config.json").config == AppConfig()  # fresh after DELETE


@pytest.mark.skipif(os.name != "nt", reason="Windows junction fixture")
@pytest.mark.parametrize("link_at", ["root", "child", "ancestor"])
def test_delete_refuses_junction_without_traversing(tmp_path, link_at):
    outside = tmp_path / "external"
    outside.mkdir()
    sentinel = outside / "important.txt"
    sentinel.write_text("unrelated")
    base = tmp_path / "LocalAppData"
    base.mkdir()
    owned = base / "NetSentinel"
    if link_at == "root":
        link = owned
    elif link_at == "ancestor":
        base.rmdir()
        link = base
    else:
        owned.mkdir()
        (owned / "keep.txt").write_text("no partial mutation")
        link = owned / "linked"
    # cmd builtin is solely for creating this explicit, isolated junction fixture.
    subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(outside)], check=True, capture_output=True)
    try:
        with pytest.raises(UnsafeDataRoot):
            delete_owned_data(owned, local_app_data=base, confirmed=True)
        assert sentinel.read_text() == "unrelated"
        if link_at == "child":
            assert (owned / "keep.txt").is_file()
    finally:
        link.rmdir()  # removes the junction itself, never its external target


@pytest.fixture
def payload_module(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    import installer_payload
    return installer_payload


@pytest.fixture
def payload(tmp_path):
    bundle = tmp_path / "payload Türkçe"
    bundle.mkdir()
    for name in ("NetSentinel.exe", "THIRD_PARTY_NOTICES.md", "INSTALLER_POLICY.md", "licenses/Python/LICENSE.txt"):
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture")
    schema = bundle / "_internal/netsentinel/infrastructure/sqlite/schema"
    schema.mkdir(parents=True)
    for source in (ROOT / "src/netsentinel/infrastructure/sqlite/schema").glob("*.sql"):
        (schema / source.name).write_bytes(source.read_bytes())
    return bundle


@pytest.mark.parametrize("name", ["data.sqlite3", "config.json", "app.log", ".git/config", "tests/test.py", ".env",
    "exports/support.json", "secrets.json", "credentials.json", "capture.pcap", "secret.pem", "key.pfx", "npcap.exe", "winpcap.dll", "history.sqlite3-wal", "netsentinel.log.1", "history.sqlite3-journal", "partial.tmp", "wpcap.dll", "Packet.dll", "driver.sys"])
def test_payload_excludes_private_driver_development_files(payload, payload_module, name):
    path = payload / "_internal" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("forbidden")
    with pytest.raises(ValueError):
        payload_module.payload_files(payload)


def test_payload_inventory_hashes_and_license_manifest(payload, payload_module, tmp_path):
    files = payload_module.payload_files(payload)
    manifest = tmp_path / "manifest.json"
    payload_module.write_manifest(manifest, payload, files, __version__)
    result = json.loads(manifest.read_text())
    assert result["version"] == __version__ and result["schema"] == 20 and result["unsigned"]
    for entry in result["files"]:
        assert entry["sha256"] == payload_module.file_digest(payload / entry["path"])
        assert not Path(entry["path"]).is_absolute()
    assert "licenses/Python/LICENSE.txt" in {entry["path"] for entry in result["files"]}


@pytest.mark.parametrize("missing", ["NetSentinel.exe", "THIRD_PARTY_NOTICES.md", "INSTALLER_POLICY.md", "licenses/Python/LICENSE.txt"])
def test_payload_refuses_missing_required_content(payload, payload_module, missing):
    (payload / missing).unlink()
    with pytest.raises(ValueError):
        payload_module.payload_files(payload)


def test_compiler_missing_is_explicit_and_version_identity_are_single_source(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    import build_installer
    assert build_installer.application_version() == __version__
    with pytest.raises(FileNotFoundError, match="No automatic download"):
        build_installer.compiler_path(tmp_path / "missing.exe")
    script = (ROOT / "packaging/NetSentinel.iss").read_text()
    assert build_installer.APP_ID in script.replace("{{", "{")
    assert "AppVersion={#AppVersion}" in script and "PrivilegesRequired=lowest" in script
    assert "VersionInfoVersion={#AppVersion}" in script
    assert "CloseApplications=no" in script and "RestartApplications=no" in script
    assert "Flags: unchecked" in script and "UninstallLogMode=append" in script
    assert "DeleteLocalData := False" in script and "if UninstallSilent then" in script
    assert "MB_DEFBUTTON2" in script and "--uninstall-delete-local-data-confirmed" in script
    assert "[UninstallDelete]" not in script  # no broad recursive delete by Inno
    assert "[Run]" not in script and "[Registry]" not in script
    for forbidden in ("requireAdministrator", "runas", "schtasks", "netsh", "Add-MpPreference", "https://", "http://"):
        assert forbidden not in script
    assert "uac_admin=False" in (ROOT / "packaging/NetSentinel.spec").read_text()


@pytest.mark.skipif(os.name != "nt", reason="Windows build orchestration")
@pytest.mark.parametrize("project_packages", [False, True])
def test_build_orchestration_checks_payload_and_emits_checksum(payload, payload_module, tmp_path, monkeypatch, project_packages):
    import shutil
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    import build_installer

    fixture_root = tmp_path / "repo with Çalışma"
    (fixture_root / "src/netsentinel").mkdir(parents=True)
    (fixture_root / "src/netsentinel/version.py").write_text(f'__version__ = "{__version__}"')
    (fixture_root / "build").mkdir()
    bundle = fixture_root / "dist/NetSentinel"
    shutil.copytree(payload, bundle)
    target = fixture_root / "dist" / f"NetSentinel-{__version__}-Setup.exe"
    target.write_bytes(b"stale output")
    calls = []

    def run(arguments, **options):
        assert options["check"] and options["cwd"] == fixture_root
        calls.append(arguments)
        if len(calls) == 2:
            assert not target.exists()
            assert any(argument == f"/DAppVersion={__version__}" for argument in arguments)
            assert any(argument == f"/DPayloadDir={bundle}" for argument in arguments)
            target.write_bytes(b"mock compiler fixture, not real installer")

    monkeypatch.setattr(build_installer, "ROOT", fixture_root)
    monkeypatch.setattr(build_installer, "compiler_path", lambda explicit: tmp_path / "ISCC.exe")
    monkeypatch.setattr(build_installer.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["build_installer.py"] + (["--use-project-packages"] if project_packages else []))
    assert build_installer.main() == 0
    assert len(calls) == 2 and calls[0][1] == str(fixture_root / "packaging/build_windows.py")
    assert ("--use-project-packages" in calls[0]) is project_packages
    assert target.with_name(target.name + ".sha256").read_text().split()[0] == payload_module.file_digest(target)
    manifest = json.loads(target.with_name(target.name + ".manifest.json").read_text())
    assert manifest["version"] == __version__ and manifest["schema"] == 20
    inventory = (fixture_root / "build/payload-files.txt").read_text(encoding="utf-8-sig")
    assert "licenses/Python/LICENSE.txt" in inventory and "config.json" not in inventory


def test_build_dependency_injection_keeps_invoking_runtime_and_fixed_repo_path(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    import build_windows

    monkeypatch.setattr(build_windows, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "path", list(sys.path))
    assert build_windows.pyinstaller_command()[:3] == [sys.executable, "-m", "PyInstaller"]
    with pytest.raises(FileNotFoundError, match="locked packaging"):
        build_windows.pyinstaller_command(use_project_packages=True)
    package = tmp_path / ".venv/Lib/site-packages/PyInstaller"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("fixture")
    command = build_windows.pyinstaller_command(use_project_packages=True)
    assert command[0] == sys.executable and command[1] == "-c"
    assert command[3] == str(package.parent)
    assert "run_module('PyInstaller'" in command[2]
    assert "sys.prefix" not in command[2] and "sys.base_prefix" not in command[2]


def test_unknown_frozen_arguments_never_delete_or_launch(monkeypatch):
    entry = runpy.run_path(str(ROOT / "packaging/entry.py"))
    monkeypatch.setattr(sys, "argv", ["NetSentinel.exe", "--uninstall-delete-local-data-confirmed", "C:\\"])
    assert entry["main"]() == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutexes")
def test_native_mutex_detects_hidden_desktop_and_gate_blocks_start(monkeypatch):
    from netsentinel.infrastructure import windows_installer as adapter
    identity = str(uuid4())
    monkeypatch.setattr(adapter, "APP_MUTEX", "Global\\NetSentinel.test-app-" + identity)
    monkeypatch.setattr(adapter, "GATE_MUTEX", "Global\\NetSentinel.test-gate-" + identity)
    monkeypatch.setattr(adapter, "SETUP_MUTEX", "Global\\NetSentinel.test-setup-" + identity)
    handles = []
    monkeypatch.setattr(adapter, "_DESKTOP_HANDLES", handles)
    adapter.mark_desktop_running()
    try:
        with pytest.raises(adapter.InstallerSafetyError, match="Quit"):
            with adapter.stopped_desktop():
                pytest.fail("running desktop must be rejected")
    finally:
        for handle in handles:
            adapter._kernel().CloseHandle(handle)
    with adapter.stopped_desktop():
        # Another thread/process is needed to contend for a Windows recursive mutex.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(adapter.InstallerSafetyError, match="maintenance"):
                pool.submit(adapter.mark_desktop_running).result()
    setup = adapter._kernel().CreateMutexW(None, False, adapter.SETUP_MUTEX)
    assert setup
    try:
        with pytest.raises(adapter.InstallerSafetyError, match="maintenance"):
            adapter.mark_desktop_running()
    finally:
        adapter._kernel().CloseHandle(setup)


def test_uninstall_helper_uses_known_folder_not_mutable_environment(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from netsentinel.infrastructure import windows_installer as adapter
    from netsentinel.infrastructure.uninstall_data import uninstall_local_data

    trusted = tmp_path / "knownfolder"
    owned = trusted / "NetSentinel"
    owned.mkdir(parents=True)
    (owned / "history.sqlite3").write_bytes(b"owned fixture")
    untrusted = tmp_path / "environment-root"
    (untrusted / "NetSentinel").mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(untrusted))
    monkeypatch.setattr(adapter, "windows_local_app_data", lambda: trusted)
    monkeypatch.setattr(adapter, "stopped_desktop", nullcontext)
    assert uninstall_local_data() == 0
    assert not owned.exists()
    assert (untrusted / "NetSentinel").is_dir()


def test_helper_running_failure_preserves_all_data(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from netsentinel.infrastructure import windows_installer as adapter
    from netsentinel.infrastructure.uninstall_data import uninstall_local_data

    owned = tmp_path / "NetSentinel"
    owned.mkdir()
    (owned / "config.json").write_text("preserve")

    @contextmanager
    def running():
        raise adapter.InstallerSafetyError("Quit")
        yield

    monkeypatch.setattr(adapter, "stopped_desktop", running)
    monkeypatch.setattr(adapter, "windows_local_app_data", lambda: tmp_path)
    assert uninstall_local_data() == 1
    assert (owned / "config.json").read_text() == "preserve"
