"""NS-101 independent, handle-held local executable metadata check.

An injected trusted classifier must establish ordinary desktop provenance (not
service/package/shared-host/self). There is deliberately no permissive classifier.
The isolated harness can classify its own disposable fixture. This is not a UI,
privilege boundary, process identity resolver or production write authorization.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager, ExitStack
from datetime import UTC, datetime
import ntpath
import os
import sys
from typing import Any

from netsentinel.domain.response import ResponseCommand, ResponseFileIdentity, ResponseReason
from netsentinel.infrastructure.windows_response_firewall import TargetValidationError

HOST_NAMES = {"svchost.exe", "dllhost.exe", "rundll32.exe", "conhost.exe", "taskhostw.exe",
              "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
              "python.exe", "pythonw.exe", "netsentinel.exe"}


def file_identity(info: tuple[Any, ...]) -> ResponseFileIdentity:
    """BY_HANDLE_FILE_INFORMATION, using the same metadata recipe for preview."""
    return ResponseFileIdentity(info[4], (info[8] << 32) | info[9],
                                (info[5] << 32) | info[6],
                                datetime.fromtimestamp(info[3].timestamp(), UTC))


class WindowsExecutableTarget:
    """Guard factory; metadata reads only, no execution, DNS, hashing or caching."""

    def __init__(self, ordinary_desktop: Callable[[str], bool]) -> None:
        self._classify = ordinary_desktop

    @contextmanager
    def __call__(self, command: ResponseCommand) -> Iterator[None]:
        with ExitStack() as stack:
            self._validate(command, stack)
            yield

    def _validate(self, command: ResponseCommand, stack: ExitStack) -> None:
        if type(command) is not ResponseCommand or sys.platform != "win32":
            raise TargetValidationError(ResponseReason.BOUNDARY_UNAVAILABLE)
        try:
            import win32api
            import win32file
            path = command.spec.program_path
            root = path[:3]
            # DRIVE_FIXED only, before opening any component (no remote traversal).
            if win32file.GetDriveType(root) != 3:
                raise TargetValidationError()
            protected = (win32api.GetWindowsDirectory(), os.path.dirname(sys.executable))
            if (ntpath.basename(path).casefold() in HOST_NAMES
                    or any(ntpath.commonpath([path, p]).casefold() == p.casefold()
                           for p in protected if ntpath.splitdrive(p)[0].casefold() == root[:2].casefold())
                    or any(p.casefold() == "windowsapps" for p in path.split("\\"))):
                raise TargetValidationError()
            # Pin all ancestors against deletion/rename and reject junctions,
            # symlinks and other reparse points without following them.
            components = path[3:].split("\\")
            handle = None
            for index in range(len(components) + 1):
                component = root + "\\".join(components[:index])
                final = index == len(components)
                # FILE_READ_ATTRIBUTES / FILE_SHARE_READ (+ WRITE for directories)
                # OPEN_EXISTING / OPEN_REPARSE_POINT / BACKUP_SEMANTICS.
                handle = win32file.CreateFile(component, 0x80, 1 if final else 3, None,
                                              3, 0x00200000 | 0x02000000, None)
                stack.callback(handle.Close)
                info = win32file.GetFileInformationByHandle(handle)
                if info[0] & 0x400 or bool(info[0] & 0x10) == final:
                    raise TargetValidationError()
                final_path = win32file.GetFinalPathNameByHandle(handle, 0)
                if final_path != "\\\\?\\" + component:
                    # Preserve exact spelling; require a new preview for aliases.
                    raise TargetValidationError(ResponseReason.REVALIDATION_REQUIRED)
            if handle is None or file_identity(info) != command.file_identity:
                raise TargetValidationError(ResponseReason.REVALIDATION_REQUIRED)
            # Classifiers may inspect the file. Invoke only AFTER local path,
            # reparse and identity checks, with components pinned throughout.
            if self._classify(path) is not True:
                raise TargetValidationError()
        except TargetValidationError:
            raise
        except PermissionError:
            raise TargetValidationError(ResponseReason.ACCESS_DENIED) from None
        except Exception as error:
            code = getattr(error, "winerror", None)
            reason = ResponseReason.ACCESS_DENIED if code == 5 else ResponseReason.TARGET_UNAVAILABLE
            raise TargetValidationError(reason) from None
