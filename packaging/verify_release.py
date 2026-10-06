"""NS-097 offline integrity check; this does NOT authenticate a publisher or release."""

from __future__ import annotations

import argparse
from datetime import datetime
from enum import IntEnum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from time import monotonic
from typing import Any


MAX_FILE = 1024**3
MAX_MANIFEST = 65536
RELEASE_BASE = "https://github.com/ByteGambit/NetSentinel/releases/tag/"
VERSION = r"(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})"
FIELDS = {"format_version", "product", "version", "channel", "published_at", "filename",
          "size_bytes", "sha256", "signature_policy", "signing_state", "source_commit",
          "release_url", "release_notes"}


class Exit(IntEnum):
    INTEGRITY_OK = 0
    HASH_MISMATCH = 1
    INVALID_INPUT = 2
    VERSION_MISMATCH = 3
    IO_ERROR = 4
    TOOL_UNAVAILABLE = 5
    INVALID_MANIFEST = 6
    SIZE_MISMATCH = 7
    AUTHENTICODE_REQUIRED = 8
    FILE_CHANGED = 9
    LIMIT_EXCEEDED = 10


class VerificationFailure(Exception):
    def __init__(self, code: Exit):
        self.code = code


def local_file(path: Path) -> Path:
    path = path.absolute()
    # Refuse network paths and every reparse ancestor, not just a final symlink.
    if str(path).startswith(("\\\\", "//")) or (os.name == "nt" and ":" in str(path)[2:]):
        raise VerificationFailure(Exit.INVALID_INPUT)
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise VerificationFailure(Exit.INVALID_INPUT)
    if not path.is_file():
        raise VerificationFailure(Exit.IO_ERROR)
    return path


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict[str, Any]:
    path = local_file(path)
    with path.open("rb") as source:
        raw = source.read(MAX_MANIFEST + 1)
    try:
        if len(raw) > MAX_MANIFEST:
            raise ValueError("size")
        item = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise ValueError("fields")
        if type(item["format_version"]) is not int or item["format_version"] != 1 or item["product"] != "NetSentinel":
            raise ValueError("format")
        if any(not isinstance(item[key], str) for key in FIELDS - {"format_version", "size_bytes"}):
            raise ValueError("type")
        version = item["version"]
        if not re.fullmatch(VERSION, version) or any(int(part) > 65535 for part in version.split(".")):
            raise ValueError("version")
        if item["channel"] not in {"pilot", "beta", "stable"} or item["filename"] != f"NetSentinel-{version}-Setup.exe":
            raise ValueError("channel/filename")
        if type(item["size_bytes"]) is not int or not 0 < item["size_bytes"] <= MAX_FILE:
            raise ValueError("size")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", item["sha256"]) or not re.fullmatch(r"[0-9a-f]{40}", item["source_commit"]):
            raise ValueError("digest/commit")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", item["published_at"]):
            raise ValueError("time")
        datetime.fromisoformat(item["published_at"].replace("Z", "+00:00"))
        tag = f"v{version}" + ("" if item["channel"] == "stable" else f"-{item['channel']}.1")
        if item["release_url"] != RELEASE_BASE + tag or item["release_notes"] != item["release_url"]:
            raise ValueError("release reference")
        policy = (item["signing_state"], item["signature_policy"])
        if policy not in {("unsigned", "unsigned-pilot"), ("signed", "authenticode-sha256-rfc3161")}:
            raise ValueError("policy")
        if item["signing_state"] == "unsigned" and item["channel"] != "pilot":
            raise ValueError("unsigned scope")
        return dict(item)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise VerificationFailure(Exit.INVALID_MANIFEST) from None


def file_version(path: Path) -> str:
    if os.name != "nt":
        raise VerificationFailure(Exit.TOOL_UNAVAILABLE)
    # Static command, no user text in PowerShell source, no target execution/trust call.
    command = "$ErrorActionPreference='Stop'; [Diagnostics.FileVersionInfo]::GetVersionInfo($env:NS097_ARTIFACT).FileVersion.Trim()"
    environment = os.environ.copy()
    environment["NS097_ARTIFACT"] = str(path)
    shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    try:
        result = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-Command", command],
                                env=environment, capture_output=True, text=True, timeout=15, check=True)
        value = result.stdout.strip()
        if not re.fullmatch(VERSION, value):
            raise VerificationFailure(Exit.VERSION_MISMATCH)
        return value
    except (OSError, subprocess.SubprocessError):
        raise VerificationFailure(Exit.TOOL_UNAVAILABLE) from None


def verify(path: Path, expected_hash: str, *, manifest: Path | None = None,
           expected_version: str | None = None) -> Exit:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
        return Exit.INVALID_INPUT
    try:
        path = local_file(path)
        item = read_manifest(manifest) if manifest else None
        before = path.stat()
        if not 0 < before.st_size <= MAX_FILE:
            return Exit.LIMIT_EXCEEDED
        if item:
            if item["sha256"].lower() != expected_hash.lower():
                return Exit.HASH_MISMATCH
            if item["filename"] != path.name:
                return Exit.INVALID_MANIFEST
            if item["size_bytes"] != before.st_size:
                return Exit.SIZE_MISMATCH
            if expected_version is not None and item["version"] != expected_version:
                return Exit.VERSION_MISMATCH
        digest = hashlib.sha256()
        deadline = monotonic() + 30
        count = 0
        with path.open("rb") as source:
            while block := source.read(1024**2):
                count += len(block)
                if count > MAX_FILE or monotonic() > deadline:
                    return Exit.LIMIT_EXCEEDED
                digest.update(block)
        wanted_version = expected_version or (str(item["version"]) if item else None)
        if digest.hexdigest() != expected_hash.lower():
            return Exit.HASH_MISMATCH
        if wanted_version is not None and file_version(path) != wanted_version:
            return Exit.VERSION_MISMATCH
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or count != after.st_size:
            return Exit.FILE_CHANGED
        if item and item["signing_state"] == "signed":
            return Exit.AUTHENTICODE_REQUIRED  # Never turn a manifest's assertion into trust.
        return Exit.INTEGRITY_OK
    except VerificationFailure as error:
        return error.code
    except OSError:
        return Exit.IO_ERROR


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--sha256", required=True, help="Expected hash from the canonical release, not calculated from the download")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    result = verify(args.artifact, args.sha256, manifest=args.manifest, expected_version=args.expected_version)
    print(json.dumps({"result": result.name, "exit_code": int(result),
                      "signature_state": "NOT_CHECKED", "provenance": "USER_MUST_CHECK_CANONICAL_CHANNEL"}, sort_keys=True))
    return int(result)


if __name__ == "__main__":
    raise SystemExit(main())
