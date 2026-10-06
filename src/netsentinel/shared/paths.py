"""One per-user persistent path policy for dev, portable and installed runtimes.

Resource lookup belongs to package APIs, never to this writable path resolver.
Resolution performs no I/O. Explicit LocalAppData injection isolates tests.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


APPLICATION_DIRECTORY_NAME = "NetSentinel"
DATABASE_FILENAME = "netsentinel.sqlite3"


@dataclass(frozen=True, slots=True)
class UserDataPaths:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / DATABASE_FILENAME

    @property
    def config(self) -> Path:
        return self.root / "config.json"

    @property
    def log(self) -> Path:
        return self.root / "netsentinel.log"


def user_data_paths(*, local_app_data: str | os.PathLike[str] | None = None) -> UserDataPaths:
    base = local_app_data if local_app_data is not None else os.environ.get("LOCALAPPDATA")
    directory = Path(base) if base else Path.home() / "AppData" / "Local"
    return UserDataPaths(directory.expanduser().resolve() / APPLICATION_DIRECTORY_NAME)
