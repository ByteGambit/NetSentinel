"""VM-only operator for real Inno uninstall confirmation dialogs; never shipped.

Only windows owned by the launched, canonical uninstaller process tree are used.
DELETE is two explicit confirmations; timeout or unexpected dialog fails closed.
"""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(decision):
    assert os.name == "nt" and os.environ["COMPUTERNAME"] == "DESKTOP-B18OKSK"
    assert os.environ.get("NETSENTINEL_NS101_VM_AUTHORIZED") == "YES"
    assert decision in {"KEEP", "DELETE"}
    root = Path(__file__).resolve().parents[3]
    app = Path(os.environ["LOCALAPPDATA"]) / "Programs/NetSentinel"
    uninstaller = app / "unins000.exe"
    assert uninstaller.is_file()
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback, wintypes.LPARAM]
    user.EnumChildWindows.argtypes = [wintypes.HWND, callback, wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.SendMessageW.restype = wintypes.LPARAM
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                    ("exe", wintypes.WCHAR * 260)]

    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    process = subprocess.Popen([str(uninstaller), "/NORESTART", f"/LOG={root / ('uninstall-ui-' + decision + '.log')}"])
    owners = {process.pid}
    observations = []
    step = 0
    completed = False

    def text(handle, cls=False):
        buffer = ctypes.create_unicode_buffer(512)
        (user.GetClassNameW if cls else user.GetWindowTextW)(handle, buffer, len(buffer))
        return buffer.value

    try:
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
            entry = ProcessEntry(size=ctypes.sizeof(ProcessEntry))
            entries = []
            try:
                valid = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
                while valid:
                    entries.append((entry.pid, entry.parent))
                    valid = kernel.Process32NextW(snapshot, ctypes.byref(entry))
            finally:
                kernel.CloseHandle(snapshot)
            for _ in range(4):
                owners.update(pid for pid, parent in entries if parent in owners)
            windows = []

            @callback
            def collect(handle, unused):
                owner = wintypes.DWORD()
                user.GetWindowThreadProcessId(handle, ctypes.byref(owner))
                if owner.value in owners and text(handle):
                    windows.append(handle)
                return True

            user.EnumWindows(collect, 0)
            for window in windows:
                title = text(window)
                if "NetSentinel" not in title and title != "Uninstall":
                    continue
                buttons = []

                @callback
                def child(handle, unused):
                    if text(handle, True).casefold() in {"button", "tnewbutton"}:
                        label = text(handle).replace("&", "")
                        # Windows MessageBox buttons use the OS display language.
                        label = {"Evet": "Yes", "Hayır": "No", "İptal": "Cancel", "Tamam": "OK"}.get(label, label)
                        buttons.append((label, handle))
                    return True

                user.EnumChildWindows(window, child, 0)
                captions = [label for label, _ in buttons]
                desired = None
                if step == 0 and title == "NetSentinel firewall rules - preserved" and "Continue" in captions:
                    desired = "Continue"
                elif step == 1 and {"Yes", "No", "Cancel"}.issubset(captions):
                    desired = "Yes" if decision == "DELETE" else "No"
                elif step == 2 and decision == "DELETE" and {"OK", "Cancel"}.issubset(captions):
                    desired = "OK"
                elif step == (3 if decision == "DELETE" else 2) and {"Yes", "No"} == set(captions):
                    desired = "Yes"  # Inno's final remove-program confirmation.
                elif step == (4 if decision == "DELETE" else 3) and captions == ["OK"]:
                    # A completed uninstall message, never a failed cleanup receipt.
                    desired = "OK"
                if desired:
                    observations.append({"step": step, "title": title, "buttons": captions, "selected": desired})
                    user.SendMessageW(next(handle for label, handle in buttons if label == desired), 0xF5, 0, 0)
                    step += 1
                    break
            if (step >= (4 if decision == "DELETE" else 3) and not uninstaller.exists()
                    and process.poll() is not None and not any(pid in owners for pid, _ in entries)):
                completed = True
                break
            time.sleep(0.1)
        assert completed, f"Unexpected dialog/timeout, reached step {step}"
        assert not (app / "NetSentinel.exe").exists()
        if decision == "DELETE":
            assert not (Path(os.environ["LOCALAPPDATA"]) / "NetSentinel").exists()
        else:
            assert (Path(os.environ["LOCALAPPDATA"]) / "NetSentinel/netsentinel.sqlite3").is_file()
    finally:
        (root / ("uninstall-ui-" + decision + ".result.json")).write_text(json.dumps({
            "decision": decision, "completed": completed, "steps": observations, "root_pid": process.pid,
            "program_removed": not (app / "NetSentinel.exe").exists(),
            "data_exists": (Path(os.environ["LOCALAPPDATA"]) / "NetSentinel").exists(),
        }, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Explicit KEEP/DELETE required")
    run(sys.argv[1])
