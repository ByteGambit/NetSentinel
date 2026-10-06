"""Frozen desktop/installer coordination; no elevation, network or driver I/O."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
from ctypes import wintypes
from collections.abc import Iterator
from pathlib import Path
from typing import Any


# Global namespace also sees hidden tray processes in other logon sessions.
# Another user's inaccessible object conservatively refuses the operation.
APP_MUTEX = r"Global\NetSentinel.Desktop"
GATE_MUTEX = r"Global\NetSentinel.Maintenance"
SETUP_MUTEX = r"Global\NetSentinel.Setup"
_DESKTOP_HANDLES: list[int] = []  # Keep until process exit, including fatal shutdown.


class InstallerSafetyError(RuntimeError):
    """Fixed-message failure: callers must preserve user data."""


def _kernel() -> Any:
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    api.CreateMutexW.restype = wintypes.HANDLE
    api.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    api.OpenMutexW.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.ReleaseMutex.argtypes = [wintypes.HANDLE]
    api.ReleaseMutex.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


@contextmanager
def _gate() -> Iterator[Any]:
    api = _kernel()
    handle = api.CreateMutexW(None, False, GATE_MUTEX)
    if not handle:
        raise InstallerSafetyError("Installer coordination unavailable.")
    acquired = False
    try:
        # WAIT_OBJECT_0 / WAIT_ABANDONED both transfer ownership.
        acquired = api.WaitForSingleObject(handle, 0) in (0, 0x80)
        if not acquired:
            raise InstallerSafetyError("Installer maintenance is active.")
        yield api
    finally:
        if acquired:
            api.ReleaseMutex(handle)
        api.CloseHandle(handle)


def mark_desktop_running() -> None:
    """Create the installer marker before any app writer starts; allow multiple apps."""
    with _gate() as api:
        ctypes.set_last_error(0)
        setup = api.OpenMutexW(0x00100000, False, SETUP_MUTEX)
        if setup:
            api.CloseHandle(setup)
            raise InstallerSafetyError("Installer maintenance is active.")
        if ctypes.get_last_error() != 2:
            raise InstallerSafetyError("Installer coordination unavailable.")
        handle = api.CreateMutexW(None, False, APP_MUTEX)
        if not handle:
            raise InstallerSafetyError("Installer coordination unavailable.")
        _DESKTOP_HANDLES.append(handle)


@contextmanager
def stopped_desktop() -> Iterator[None]:
    """Block new frozen app startup and refuse if any desktop marker exists."""
    with _gate() as api:
        ctypes.set_last_error(0)
        handle = api.OpenMutexW(0x00100000, False, APP_MUTEX)  # SYNCHRONIZE
        if handle:
            api.CloseHandle(handle)
            raise InstallerSafetyError("Quit NetSentinel before deleting local data.")
        if ctypes.get_last_error() != 2:  # ERROR_FILE_NOT_FOUND only
            raise InstallerSafetyError("Cannot verify NetSentinel is stopped.")
        _reject_legacy_desktop()
        yield


def _reject_legacy_desktop() -> None:
    """Also protect data shared with pre-NS-096 portable exe lacking the mutex."""
    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    api = _kernel()
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ("Process32FirstW", "Process32NextW"):
        function = getattr(api, name)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        function.restype = wintypes.BOOL
    snapshot = api.CreateToolhelp32Snapshot(2, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise InstallerSafetyError("Cannot verify NetSentinel is stopped.")
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = api.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32ProcessID != os.getpid() and entry.szExeFile.lower() == "netsentinel.exe":
                raise InstallerSafetyError("Quit NetSentinel before deleting local data.")
            found = api.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise InstallerSafetyError("Cannot verify NetSentinel is stopped.")
    finally:
        api.CloseHandle(snapshot)


def windows_local_app_data() -> Path:
    """Trusted current-user folder for deletion; ignore mutable environment/config."""
    api = ctypes.WinDLL("shell32", use_last_error=True)
    function = api.SHGetFolderPathW
    function.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR]
    function.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(260)
    if function(None, 0x001C, None, 0, buffer) != 0 or not buffer.value:
        raise InstallerSafetyError("User data folder unavailable.")
    return Path(buffer.value)
