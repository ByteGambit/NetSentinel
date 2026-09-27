"""Windows onedir GUI bundle. Run through packaging/build_windows.py."""

from pathlib import Path


root = Path(SPECPATH).resolve().parent
schema = root / "src" / "netsentinel" / "infrastructure" / "sqlite" / "schema"
icon = root / "src" / "netsentinel" / "assets" / "netsentinel.ico"
sql_files = sorted(schema.glob("[0-9][0-9][0-9]_*.sql"))
if [int(path.name[:3]) for path in sql_files] != list(range(1, 10)):
    raise RuntimeError("Expected SQLite migrations 001 through 009")

analysis = Analysis(
    [str(root / "packaging" / "entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[(str(path), "netsentinel/infrastructure/sqlite/schema") for path in sql_files] + [(str(icon), "netsentinel/assets")],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest"],
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
