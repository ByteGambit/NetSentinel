"""Allowlisted payload layout and forbidden private/driver content checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat


ROOT_FILES = {"NetSentinel.exe", "THIRD_PARTY_NOTICES.md", "INSTALLER_POLICY.md"}
ROOT_DIRECTORIES = {"_internal", "licenses"}
FORBIDDEN_PARTS = {"tests", ".git", ".venv", "exports", "logs", "cache", "__pycache__"}
FORBIDDEN_SUFFIXES = {".db", ".db3", ".sqlite", ".sqlite3", ".log", ".pcap", ".pcapng", ".pem", ".key", ".pfx", ".p12", ".tmp", ".old", ".bak"}


def payload_files(bundle: Path) -> tuple[Path, ...]:
    """Refuse unexpected inputs rather than silently filtering build user data."""
    if not bundle.is_dir() or bundle.is_symlink() or bundle.is_junction():
        raise ValueError("Payload must be a real onedir bundle")
    files = []
    for path in sorted(bundle.rglob("*")):
        relative = path.relative_to(bundle)
        parts = tuple(part.lower() for part in relative.parts)
        attributes = path.lstat()
        if path.is_symlink() or getattr(attributes, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Payload links/reparse points are forbidden")
        if parts[0] not in ROOT_DIRECTORIES and str(relative) not in ROOT_FILES:
            raise ValueError("Unexpected payload root entry")
        if any(part in FORBIDDEN_PARTS or part.startswith((".env", "npcap", "winpcap")) for part in parts) or path.name.lower() in {"wpcap.dll", "packet.dll"} or path.suffix.lower() == ".sys":
            raise ValueError("Private/development/driver payload is forbidden")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name.lower() in {"config.json", "secrets.json", "credentials.json"} or ".log." in path.name.lower() or path.name.lower().endswith(("-wal", "-shm", "-journal")):
            raise ValueError("Persistent/private payload is forbidden")
        if path.is_file():
            files.append(path)
    for name in ROOT_FILES:
        if not (bundle / name).is_file():
            raise ValueError("Required executable/notices/policy missing")
    if not any(path.relative_to(bundle).parts[0] == "licenses" for path in files):
        raise ValueError("Third-party licenses missing")
    schemas = [path for path in files if path.suffix == ".sql"]
    if sorted(path.name[:3] for path in schemas) != [f"{i:03}" for i in range(1, 21)]:
        raise ValueError("Payload must contain migrations 001 through 020")
    return tuple(files)


def file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_manifest(path: Path, bundle: Path, files: tuple[Path, ...], version: str) -> None:
    path.write_text(json.dumps({"version": version, "schema": 20, "unsigned": True,
        "files": [{"path": file.relative_to(bundle).as_posix(), "sha256": file_digest(file)} for file in files]}, indent=2) + "\n", encoding="utf-8")
