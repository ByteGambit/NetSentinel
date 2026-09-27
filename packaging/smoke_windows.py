"""Offline smoke of the built zip from a foreign cwd and Unicode path."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"


def _run(exe: Path, cwd: Path, data: Path, report: Path) -> dict[str, object]:
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(data)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment.pop("PYTHONPATH", None)
    try:
        process = subprocess.Popen([str(exe), "--self-test", str(report)], cwd=cwd, env=environment)
    except OSError as error:
        if getattr(error, "winerror", None) == 4551:
            raise RuntimeError("Windows Smart App Control blocked the unsigned executable; use an authorized clean VM for smoke validation") from None
        raise
    try:
        code = process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("Packaged smoke timed out") from None
    if code != 0 or not report.exists():
        raise RuntimeError(f"Packaged smoke exited {code}")
    result = json.loads(report.read_text(encoding="utf-8"))
    if result.get("ok") is not True:
        raise RuntimeError("Packaged self-test failed")
    return result


def main() -> int:
    if os.name != "nt":
        raise SystemExit("Smoke requires Windows")
    __version__ = runpy.run_path(str(ROOT / "src" / "netsentinel" / "version.py"))["__version__"]

    archive = DIST / f"NetSentinel-{__version__}-windows-x64.zip"
    expected = (DIST / (archive.name + ".sha256")).read_text(encoding="ascii").split()[0]
    with archive.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError("Archive checksum mismatch")
    smoke = (BUILD / "smoke-windows").resolve()
    smoke.relative_to(BUILD.resolve())
    if smoke.exists():
        shutil.rmtree(smoke)
    install = smoke / "Net Sentinel Türkçe"
    install.mkdir(parents=True)
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(install)
    exe = install / "NetSentinel" / "NetSentinel.exe"
    elsewhere = smoke / "different cwd"
    elsewhere.mkdir()
    data = smoke / "user-local-data"
    data.mkdir()
    installed_before = {str(path.relative_to(install)) for path in install.rglob("*")}
    first = _run(exe, elsewhere, data, smoke / "first.json")
    second = _run(exe, elsewhere, data, smoke / "second.json")
    if not first.get("onboarding_visible") or second.get("onboarding_visible"):
        raise RuntimeError("Onboarding did not persist across packaged launches")
    if not (data / "NetSentinel" / "config.json").is_file() or not (data / "NetSentinel" / "netsentinel.sqlite3").is_file():
        raise RuntimeError("User data was not stored under LOCALAPPDATA")
    if installed_before != {str(path.relative_to(install)) for path in install.rglob("*")}:
        raise RuntimeError("Executable wrote into its install directory")
    if any(path.name.lower().startswith("npcap") for path in install.rglob("*")):
        raise RuntimeError("Npcap unexpectedly bundled")
    print(json.dumps({"checksum": actual, "first": first, "second": second, "install_unchanged": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
