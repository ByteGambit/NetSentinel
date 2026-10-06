"""Build the portable Windows bundle, notices, transport zip and SHA-256."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"


def pyinstaller_command(*, use_project_packages: bool = False) -> list[str]:
    """Keep native runtime from the invoking interpreter; optionally use repo deps.

    The fixed venv package directory supplies dependencies, never a replacement
    Python stdlib/runtime. PYTHONPATH remains removed from the native build child.
    """
    arguments = ["--noconfirm", "--clean", "--workpath", str(BUILD / "pyinstaller"),
        "--distpath", str(DIST), str(ROOT / "packaging/NetSentinel.spec")]
    if not use_project_packages:
        return [sys.executable, "-m", "PyInstaller", *arguments]
    packages = ROOT / ".venv/Lib/site-packages"
    if not (packages / "PyInstaller/__init__.py").is_file():
        raise FileNotFoundError("Install locked packaging dependencies in the project venv first")
    # Also used by the parent for license metadata; no runtime files are copied/changed.
    sys.path.insert(0, str(packages))
    bootstrap = "import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module('PyInstaller', run_name='__main__')"
    return [sys.executable, "-c", bootstrap, str(packages), *arguments]


def _version_file(path: Path, version: str) -> None:
    parts = [int(item) for item in version.split(".")]
    if len(parts) > 4:
        raise ValueError("Windows version must have at most four numeric parts")
    parts.extend([0] * (4 - len(parts)))
    numeric = repr(tuple(parts))
    path.write_text(
        "VSVersionInfo(ffi=FixedFileInfo(filevers=" + numeric + ", prodvers=" + numeric +
        ", mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)), "
        "kids=[StringFileInfo([StringTable('040904B0', ["
        "StringStruct('CompanyName', 'NetSentinel project'), "
        "StringStruct('FileDescription', 'NetSentinel network security monitor'), "
        "StringStruct('FileVersion', '" + version + "'), "
        "StringStruct('InternalName', 'NetSentinel'), "
        "StringStruct('OriginalFilename', 'NetSentinel.exe'), "
        "StringStruct('ProductName', 'NetSentinel'), "
        "StringStruct('ProductVersion', '" + version + "')])]), "
        "VarFileInfo([VarStruct('Translation', [1033, 1200])])])\n",
        encoding="utf-8",
    )


def _notices(bundle: Path) -> None:
    names = ("PyQt6", "PyQt6-Qt6", "PyQt6-sip", "psutil", "scapy", "PyInstaller")
    rows = ["# NetSentinel bundled dependency and license inventory", "", "Generated from the build environment; verify license terms before redistribution.", "", "| Component | Version | License metadata |", "|---|---|---|"]
    for name in names:
        dist = metadata.distribution(name)
        label = dist.metadata.get("License-Expression") or dist.metadata.get("License") or ", ".join(item.removeprefix("License :: ") for item in dist.metadata.get_all("Classifier", []) if item.startswith("License :: ")) or "See included license files"
        label = " ".join(label.split())[:240].replace("|", "/")
        rows.append(f"| {name} | {dist.version} | {label} |")
        for item in dist.files or ():
            if item.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
                source = Path(str(dist.locate_file(item)))
                if source.is_file():
                    target = bundle / "licenses" / name / item.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    rows.extend(["| Python runtime | " + sys.version.split()[0] + " | PSF License; see licenses/Python if available |", "", "Npcap is not bundled or installed by NetSentinel."])
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        target = bundle / "licenses" / "Python" / "LICENSE.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(python_license, target)
    (bundle / "THIRD_PARTY_NOTICES.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--use-project-packages", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Build on Windows")
    version = runpy.run_path(str(ROOT / "src" / "netsentinel" / "version.py"))["__version__"]
    BUILD.mkdir(exist_ok=True)
    _version_file(BUILD / "version_info.txt", version)
    # PyInstaller searches PATH for native imports. Keep unrelated developer
    # applications' DLLs out of the bundle (notably incompatible ICU copies).
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join((str(Path(sys.executable).parent), str(windows / "System32"), str(windows)))
    environment.pop("PYTHONPATH", None)
    environment["PYINSTALLER_CONFIG_DIR"] = str(BUILD / "pyinstaller-cache")
    subprocess.run(pyinstaller_command(use_project_packages=args.use_project_packages), cwd=ROOT, env=environment, check=True)
    bundle = DIST / "NetSentinel"
    _notices(bundle)
    shutil.copyfile(ROOT / "packaging/INSTALLER_POLICY.md", bundle / "INSTALLER_POLICY.md")
    from installer_payload import payload_files

    payload_files(bundle)  # Mandatory private-data/driver exclusion gate for both formats.
    archive = shutil.make_archive(str(DIST / f"NetSentinel-{version}-windows-x64"), "zip", root_dir=DIST, base_dir="NetSentinel")
    with open(archive, "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    (DIST / (Path(archive).name + ".sha256")).write_text(f"{digest}  {Path(archive).name}\n", encoding="ascii")
    print(f"Bundle: {bundle}\nArchive: {archive}\nSHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
