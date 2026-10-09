"""Confirmed owned-root deletion, independent from GUI, config and SQLite.

Only the uninstaller calls the production entry; ordinary uninstall defaults KEEP.
Reject reparse points throughout the path/tree before any mutation. Windows
shutil.rmtree does not recurse into directory junctions. This is ordinary local
deletion, not secure erasure or protection against hostile concurrent filesystem
replacement by another process running as the same user.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat

from netsentinel.shared.paths import APPLICATION_DIRECTORY_NAME, user_data_paths


class UnsafeDataRoot(RuntimeError):
    """Refuse deletion with a sanitized error."""


def _reject_link(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise UnsafeDataRoot("User data contains an unsupported link or reparse point.")


def delete_owned_data(root: Path, *, local_app_data: Path, confirmed: bool = False) -> None:
    """Explicit injected base supports isolated tests; production uses Windows API.

    Do not resolve the input root before checking links: that could legitimize a
    junction to somebody else's directory. Validate every existing ancestor too.
    """
    if not confirmed:
        raise UnsafeDataRoot("Local data deletion requires explicit confirmation.")
    if not root.is_absolute() or not local_app_data.is_absolute():
        raise UnsafeDataRoot("User data path must be absolute.")
    expected = local_app_data / APPLICATION_DIRECTORY_NAME
    if root != expected or root.name != APPLICATION_DIRECTORY_NAME:
        raise UnsafeDataRoot("User data path is not the canonical owned root.")
    for path in (*reversed(root.parents), root):
        try:
            _reject_link(path)
        except FileNotFoundError:
            continue
    # Resolution must not change the expected lexical root (including '..').
    if root.resolve() != expected or user_data_paths(local_app_data=local_app_data).root != expected:
        raise UnsafeDataRoot("User data path is not canonical.")
    if not root.exists():
        return
    if not root.is_dir():
        raise UnsafeDataRoot("User data root is not a directory.")
    for directory, directories, files in os.walk(root, followlinks=False, onerror=_walk_error):
        _reject_link(Path(directory))
        for name in (*directories, *files):
            _reject_link(Path(directory) / name)
    shutil.rmtree(root)


def _walk_error(error: OSError) -> None:
    raise UnsafeDataRoot("User data could not be checked safely.") from None


def uninstall_local_data() -> int:
    """The only production deletion entry; no path argument/environment override."""
    from netsentinel.infrastructure.windows_installer import (
        InstallerSafetyError, stopped_desktop, windows_local_app_data,
    )

    try:
        with stopped_desktop():
            base = windows_local_app_data()
            from netsentinel.infrastructure.uninstall_response import inspect_response_custody

            if not inspect_response_custody(base).permits_data_delete:
                return 1  # Preserve recovery custody; never equate data deletion with Undo.
            delete_owned_data(base / APPLICATION_DIRECTORY_NAME, local_app_data=base, confirmed=True)
    except (OSError, UnsafeDataRoot, InstallerSafetyError):
        return 1
    return 0
