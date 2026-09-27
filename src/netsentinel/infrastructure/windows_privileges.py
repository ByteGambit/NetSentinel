"""Read-only process privilege context. No elevation request is made."""

from __future__ import annotations

import sys


def is_process_elevated() -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        from ctypes import windll

        return bool(windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None


__all__ = ("is_process_elevated",)
