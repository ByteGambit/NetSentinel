"""NS-099 explicit built-payload audit; no launch, extraction or network calls.

Run with the existing packaging dependencies from the repository root.
This is not an installed-client or signature trust acceptance test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
from types import CodeType

from PyInstaller.archive.readers import CArchiveReader


def code_paths(code: CodeType):
    yield code.co_filename
    for value in code.co_consts:
        if isinstance(value, CodeType):
            yield from code_paths(value)


def audit(root: Path) -> dict[str, object]:
    payload = runpy.run_path(str(root / "packaging/installer_payload.py"))
    bundle = root / "dist/NetSentinel"
    files = payload["payload_files"](bundle)
    manifest = json.loads((root / "dist/NetSentinel-0.1.0-Setup.exe.manifest.json").read_text())
    inventory = {row["path"]: row["sha256"] for row in manifest["files"]}
    assert len(inventory) == len(files)
    for file in files:
        assert payload["file_digest"](file) == inventory[file.relative_to(bundle).as_posix()]
    archive = CArchiveReader(str(bundle / "NetSentinel.exe")).open_embedded_archive("PYZ.pyz")
    checked = []
    for name in archive.toc:
        if name != "netsentinel" and not name.startswith("netsentinel."):
            continue
        code = archive.extract(name)
        if code is None:
            continue
        relative = Path(*name.split("."))
        source = root / "src" / relative.with_suffix(".py")
        if not source.is_file():
            source = root / "src" / relative / "__init__.py"
        assert code == compile(source.read_bytes(), code.co_filename, "exec", dont_inherit=True), name
        assert all(not Path(path).is_absolute() and "users" not in path.lower()
                   for path in code_paths(code)), name
        checked.append(name)
    required = {"netsentinel.presentation.widgets.onboarding",
                "netsentinel.presentation.views.diagnostics",
                "netsentinel.presentation.widgets.storage_privacy",
                "netsentinel.shared.config"}
    assert required <= set(checked)
    executable = root / "dist/NetSentinel-0.1.0-Setup.exe"
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert digest == executable.with_name(executable.name + ".sha256").read_text().split()[0]
    return {"payload_files": len(files), "payload_hashes_match": True,
            "compiled_source_modules": len(checked), "compiled_sources_match": True,
            "application_code_paths_relative": True, "ns098_modules_present": True,
            "schema": manifest["schema"], "version": manifest["version"],
            "filename": executable.name, "sha256": digest,
            "size_bytes": executable.stat().st_size}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(Path(__file__).resolve().parents[2]), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(result + "\n", encoding="utf-8")
    print(result)


if __name__ == "__main__":
    main()
