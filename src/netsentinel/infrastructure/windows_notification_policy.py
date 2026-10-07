"""Read-only policy for Qt's Shell_NotifyIcon balloon backend, not WinRT toasts.

TaskbarNoNotification is the documented Taskbar.admx user-policy mapping.
Absence is not permission proof. SHQueryUserNotificationState reports session
restrictions, not app/global toast permissions or comprehensive DND coverage.
"""

from collections.abc import Callable
import ctypes
import sys

from netsentinel.application.services.notifications import NotificationPlatformState as State


def _balloon_policy_disabled() -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, "TaskbarNoNotification")
    except FileNotFoundError:
        return False
    if kind != winreg.REG_DWORD or type(value) is not int or value not in (0, 1):
        raise ValueError("unsupported balloon policy value")
    return value == 1


def _shell_notification_state() -> tuple[int, int]:
    library = ctypes.WinDLL("shell32.dll")
    query = library.SHQueryUserNotificationState
    query.argtypes = [ctypes.POINTER(ctypes.c_int)]
    query.restype = ctypes.c_long
    state = ctypes.c_int()
    return int(query(ctypes.byref(state))), state.value


def windows_notification_policy(*, platform: str = sys.platform,
        read_disabled: Callable[[], bool] = _balloon_policy_disabled,
        query_session: Callable[[], tuple[int, int]] = _shell_notification_state) -> State:
    if platform != "win32":
        return State.DELIVERY_UNKNOWN
    try:
        if read_disabled():
            return State.DISABLED_BY_OS
        result, state = query_session()
    except (OSError, AttributeError, ValueError):
        return State.DELIVERY_UNKNOWN
    if result != 0:
        return State.DELIVERY_UNKNOWN
    if state in (1, 2, 3, 4, 6, 7):
        return State.SESSION_RESTRICTED
    # Even QUNS_ACCEPTS_NOTIFICATIONS does not prove global/app permission or
    # visible delivery. Unsupported/new values also remain unknown.
    return State.DELIVERY_UNKNOWN
