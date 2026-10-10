"""Windows onedir GUI bundle. Run through packaging/build_windows.py."""

from pathlib import Path
import sys


root = Path(SPECPATH).resolve().parent
schema = root / "src" / "netsentinel" / "infrastructure" / "sqlite" / "schema"
icon = root / "src" / "netsentinel" / "assets" / "netsentinel.ico"
i18n = root / "src" / "netsentinel" / "assets" / "i18n"
# Validate offline resources before invoking the bundler. Build helpers are
# neither runtime imports nor packaged code.
sys.path[:0] = [str(root), str(root / "src")]
from tools.localization import verify_resources
verify_resources(i18n)
sql_files = sorted(schema.glob("[0-9][0-9][0-9]_*.sql"))
if [int(path.name[:3]) for path in sql_files] != list(range(1, 21)):
    raise RuntimeError("Expected SQLite migrations 001 through 020")

analysis = Analysis(
    [str(root / "packaging" / "entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[(str(path), "netsentinel/infrastructure/sqlite/schema") for path in sql_files] + [(str(icon), "netsentinel/assets"), (str(i18n / "manifest.json"), "netsentinel/assets/i18n")] + [(str(path), "netsentinel/assets/i18n") for path in sorted(i18n.glob("*.qm"))],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "PySide6", "shiboken6"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="NetSentinel",
    console=False,
    icon=str(icon),
    version=str(root / "build" / "version_info.txt"),
    uac_admin=False,
    disable_windowed_traceback=True,
)
coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    name="NetSentinel",
)
