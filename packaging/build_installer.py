"""Explicit offline Inno Setup compiler invocation over a freshly built payload."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

from installer_payload import file_digest, payload_files, write_manifest


ROOT = Path(__file__).resolve().parent.parent
APP_ID = "{62E3BFC6-ACAD-4FC3-94D8-46927D015096}"


def application_version() -> str:
    version = runpy.run_path(str(ROOT / "src/netsentinel/version.py"))["__version__"]
    if not isinstance(version, str) or not 1 <= len(version.split(".")) <= 4 or any(not part.isdecimal() or int(part) > 65535 for part in version.split(".")):
        raise ValueError("Installer needs a numeric Windows application version")
    return version


def compiler_path(explicit: Path | None = None) -> Path:
    candidates = [explicit] if explicit else [Path(found) if (found := shutil.which("ISCC.exe")) else None,
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6/ISCC.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6/ISCC.exe"]
    for path in candidates:
        if path is not None and path.is_file():
            return path.resolve()
    raise FileNotFoundError("Inno Setup 6 ISCC.exe missing. Install the approved Unicode compiler explicitly, then use --iscc <path>. No automatic download.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iscc", type=Path)
    parser.add_argument("--use-project-packages", action="store_true",
        help="Use existing repo venv packages with an approved same-version Python runtime")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Build the installer on Windows x64")
    try:
        compiler = compiler_path(args.iscc)  # Fail before expensive build if absent.
    except FileNotFoundError as error:
        parser.error(str(error))
    version = application_version()
    portable_command = [sys.executable, str(ROOT / "packaging/build_windows.py")]
    if args.use_project_packages:
        portable_command.append("--use-project-packages")
    subprocess.run(portable_command, cwd=ROOT, check=True)
    bundle = ROOT / "dist/NetSentinel"
    files = payload_files(bundle)
    # Inventory drives exact owned-file upgrade pruning; no wildcard directory deletion.
    inventory = ROOT / "build/payload-files.txt"
    inventory.write_text("\n".join(file.relative_to(bundle).as_posix() for file in files) + "\n", encoding="utf-8-sig")
    target = ROOT / "dist" / f"NetSentinel-{version}-Setup.exe"
    # Do not mistake stale output for a successful compiler invocation.
    for stale in (target, target.with_name(target.name + ".sha256"), target.with_name(target.name + ".manifest.json")):
        stale.unlink(missing_ok=True)
    subprocess.run([str(compiler), f"/DAppVersion={version}", f"/DPayloadDir={bundle}",
        f"/DOutputDir={ROOT / 'dist'}", f"/DInventoryFile={inventory}", str(ROOT / "packaging/NetSentinel.iss")], cwd=ROOT, check=True)
    if not target.is_file():
        raise RuntimeError("Compiler did not produce the expected installer")
    digest = file_digest(target)
    target.with_name(target.name + ".sha256").write_text(f"{digest}  {target.name}\n", encoding="ascii")
    write_manifest(target.with_name(target.name + ".manifest.json"), bundle, files, version)
    print(f"Unsigned pilot installer: {target}\nSHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
