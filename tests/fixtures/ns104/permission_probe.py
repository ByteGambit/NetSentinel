"""Disposable VM permission test; current thread's token is reduced, never elevated."""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import runpy
import sys

root = Path(__file__).resolve().parents[3]
custody = sys.argv[1] if len(sys.argv) == 2 else "lab"
assert custody in {"lab", "installed"}
p = root / "packages"
sys.path[:0] = [str(p), str(p / "win32"), str(p / "win32/lib")]
native_dir = os.add_dll_directory(str(p / "pywin32_system32"))
import win32api  # noqa: E402
import win32con  # noqa: E402
import win32security  # noqa: E402

assert win32api.GetComputerName() == "DESKTOP-B18OKSK"
advapi = ctypes.WinDLL("advapi32", use_last_error=True)
kernel = ctypes.WinDLL("kernel32", use_last_error=True)


class SidAttribute(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


advapi.ConvertStringSidToSidW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
advapi.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(SidAttribute),
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi.CreateRestrictedToken.restype = wintypes.BOOL
kernel.LocalFree.argtypes = [ctypes.c_void_p]
kernel.LocalFree.restype = ctypes.c_void_p
token = win32security.OpenProcessToken(
    win32api.GetCurrentProcess(), win32con.TOKEN_ALL_ACCESS
)
sid = ctypes.c_void_p()
restricted = wintypes.HANDLE()
try:
    assert advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid))
    disable = SidAttribute(sid, 0)
    assert advapi.CreateRestrictedToken(
        int(token),
        1,
        1,
        ctypes.byref(disable),
        0,
        None,
        0,
        None,
        ctypes.byref(restricted),
    )
    module = runpy.run_path(str(root / "tests/fixtures/ns104/native_lifecycle.py"))
    win32security.ImpersonateLoggedOnUser(int(restricted.value))
    try:
        assert not ctypes.windll.shell32.IsUserAnAdmin()
        module["run"]("deny-remove", custody)
        if custody == "installed":
            from netsentinel.infrastructure.uninstall_response import inspect_response_custody
            from netsentinel.infrastructure.windows_installer import windows_local_app_data

            report = inspect_response_custody(windows_local_app_data())
            assert report.available and report.remaining_count == 1 and not report.permits_data_delete
            assert "Current presence: UNKNOWN; removal: NOT ATTEMPTED" in report.text
    finally:
        win32security.RevertToSelf()
    (root / "restricted-thread.json").write_text(
        json.dumps(
            {
                "effective_admin": False,
                "admin_sid_deny_only": True,
                "privileges_disabled": True,
                "security_bypass": False,
                "restored_original_thread_token": True,
                "remaining_rules_explicitly_listed": custody == "installed",
            }
        )
    )
finally:
    if restricted.value:
        win32api.CloseHandle(int(restricted.value))
    if sid.value:
        kernel.LocalFree(sid)
    token.Close()
