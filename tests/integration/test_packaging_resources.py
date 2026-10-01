"""NS-050 source-side contract for package data and per-user paths."""

from __future__ import annotations

from pathlib import Path

from netsentinel.bootstrap import runtime_config_path
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, default_database_path
from netsentinel.infrastructure.sqlite.migrations import builtin_migrations


def test_migrations_and_user_paths_do_not_depend_on_cwd(tmp_path: Path, monkeypatch) -> None:
    data = tmp_path / "user data"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(data))
    monkeypatch.chdir(elsewhere)

    assert [item.version for item in builtin_migrations()] == list(range(1, 13))
    assert default_database_path() == data / "NetSentinel" / "netsentinel.sqlite3"
    assert runtime_config_path() == data / "NetSentinel" / "config.json"
    with SQLiteDatabase().connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 12
    assert not any(elsewhere.iterdir())
