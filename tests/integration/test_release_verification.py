"""NS-097 fail-closed offline integrity fixtures, with no signing credentials."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import socket
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "packaging/verify_release.py"
MODULE = runpy.run_path(str(TOOL))
verify = MODULE["verify"]
read_manifest = MODULE["read_manifest"]
Exit = MODULE["Exit"]


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "NetSentinel-0.1.0-Setup.exe"
    path.write_bytes(b"NS097 offline fixture\x00\x01" * 512)
    return path


def manifest_for(path, **changes):
    reference = "https://github.com/ByteGambit/NetSentinel/releases/tag/v0.1.0-pilot.1"
    result = {"format_version": 1, "product": "NetSentinel", "version": "0.1.0",
              "channel": "pilot", "published_at": "2026-10-06T00:00:00Z",
              "filename": path.name, "size_bytes": path.stat().st_size,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "signature_policy": "unsigned-pilot", "signing_state": "unsigned",
              "source_commit": "e22ad5ca6c1bea3b80acbabec018986c23e397cb",
              "release_url": reference, "release_notes": reference}
    result.update(changes)
    return result


def write_manifest(path, item):
    output = path.parent / "release.json"
    output.write_text(json.dumps(item, sort_keys=True), encoding="utf-8")
    return output


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_correct_hash_offline_and_read_only(artifact, monkeypatch):
    before = artifact.read_bytes()
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network attempted"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("subprocess attempted"))
    assert verify(artifact, digest(artifact).upper()) == Exit.INTEGRITY_OK
    assert artifact.read_bytes() == before


def test_wrong_hash(artifact):
    assert verify(artifact, "0" * 64) == Exit.HASH_MISMATCH


def test_one_byte_tamper_preserves_original(artifact):
    original = artifact.read_bytes()
    copy = artifact.with_name("tampered.exe")
    changed = bytearray(original)
    changed[10] ^= 1
    copy.write_bytes(changed)
    assert verify(copy, digest(artifact)) == Exit.HASH_MISMATCH
    assert artifact.read_bytes() == original


def test_missing_file(tmp_path):
    assert verify(tmp_path / "missing.exe", "a" * 64) == Exit.IO_ERROR


@pytest.mark.parametrize("value", ["", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"])
def test_invalid_hash(artifact, value):
    assert verify(artifact, value) == Exit.INVALID_INPUT


@pytest.mark.parametrize("changes", [
    {"format_version": True}, {"format_version": 2}, {"product": "Other"},
    {"version": "1.2"}, {"version": "65536.0.0"}, {"version": "01.0.0"},
    {"channel": "nightly"}, {"channel": "beta"}, {"filename": "../a.exe"},
    {"size_bytes": True}, {"size_bytes": 0}, {"sha256": "a" * 63},
    {"source_commit": "main"}, {"published_at": "2026-99-06T00:00:00Z"},
    {"published_at": "2026-10-06"}, {"release_url": "https://evil.example/v0.1.0"},
    {"release_notes": "https://evil.example/notes"}, {"signing_state": "trusted"},
    {"signature_policy": "none"}, {"unexpected": "field"}, {"product": {"nested": 1}},
])
def test_invalid_manifest_rejects(artifact, changes):
    manifest = write_manifest(artifact, manifest_for(artifact, **changes))
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.INVALID_MANIFEST


@pytest.mark.parametrize("raw", ["{}", "[]", "null", "{", '{"product":"x","product":"y"}', "[" * 2000])
def test_malformed_manifest(artifact, raw):
    manifest = artifact.parent / "release.json"
    manifest.write_text(raw, encoding="utf-8")
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.INVALID_MANIFEST


def test_manifest_size_bound(artifact):
    manifest = artifact.parent / "release.json"
    manifest.write_bytes(b" " * 65537)
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.INVALID_MANIFEST


def test_deterministic_fields_and_manifest_version_check(artifact, monkeypatch):
    item = manifest_for(artifact)
    path = write_manifest(artifact, item)
    assert read_manifest(path) == item
    monkeypatch.setitem(verify.__globals__, "file_version", lambda path: "0.1.0")
    assert verify(artifact, digest(artifact), manifest=path) == Exit.INTEGRITY_OK
    assert verify(artifact, digest(artifact), manifest=path, expected_version="0.1.1") == Exit.VERSION_MISMATCH


def test_pe_version_mismatch(artifact, monkeypatch):
    monkeypatch.setitem(verify.__globals__, "file_version", lambda path: "0.1.1")
    assert verify(artifact, digest(artifact), expected_version="0.1.0") == Exit.VERSION_MISMATCH


def test_manifest_cannot_supply_its_own_trusted_hash(artifact):
    manifest = write_manifest(artifact, manifest_for(artifact, sha256="b" * 64))
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.HASH_MISMATCH


def test_manifest_size_mismatch(artifact):
    manifest = write_manifest(artifact, manifest_for(artifact, size_bytes=1))
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.SIZE_MISMATCH


def test_signed_manifest_never_grants_trust(artifact, monkeypatch):
    monkeypatch.setitem(verify.__globals__, "file_version", lambda path: "0.1.0")
    manifest = write_manifest(artifact, manifest_for(artifact, signing_state="signed",
                              signature_policy="authenticode-sha256-rfc3161"))
    assert verify(artifact, digest(artifact), manifest=manifest) == Exit.AUTHENTICODE_REQUIRED


def test_changed_file_rejects(artifact, monkeypatch):
    def version(path):
        path.write_bytes(path.read_bytes() + b"change")
        return "0.1.0"
    monkeypatch.setitem(verify.__globals__, "file_version", version)
    assert verify(artifact, digest(artifact), expected_version="0.1.0") == Exit.FILE_CHANGED


def test_file_size_and_deadline_bounds(artifact, monkeypatch):
    monkeypatch.setitem(verify.__globals__, "MAX_FILE", 1)
    assert verify(artifact, digest(artifact)) == Exit.LIMIT_EXCEEDED
    monkeypatch.setitem(verify.__globals__, "MAX_FILE", 1024**3)
    ticks = iter([0, 31])
    monkeypatch.setitem(verify.__globals__, "monotonic", lambda: next(ticks))
    assert verify(artifact, digest(artifact)) == Exit.LIMIT_EXCEEDED


def test_remote_path_rejects():
    assert verify(Path("//server/share/file.exe"), "a" * 64) == Exit.INVALID_INPUT


def test_cli_exit_and_sanitized_output(tmp_path):
    result = subprocess.run([sys.executable, str(TOOL), str(tmp_path / "private missing.exe"),
                             "--sha256", "a" * 64], capture_output=True, text=True, timeout=20)
    assert result.returncode == Exit.IO_ERROR
    output = json.loads(result.stdout)
    assert output["signature_state"] == "NOT_CHECKED"
    assert output["result"] == "IO_ERROR"
    assert "private" not in result.stdout and not result.stderr


def test_version_subprocess_timeout_and_static_source(artifact, monkeypatch):
    def run(command, **kwargs):
        assert str(artifact) not in command[-1]
        assert kwargs["timeout"] == 15
        assert kwargs["env"]["NS097_ARTIFACT"] == str(artifact)
        raise subprocess.TimeoutExpired(command, 15)
    monkeypatch.setitem(verify.__globals__, "os", type("Windows", (), {"name": "nt", "environ": {}}))
    monkeypatch.setattr(subprocess, "run", run)
    assert verify(artifact, digest(artifact), expected_version="0.1.0") == Exit.TOOL_UNAVAILABLE
