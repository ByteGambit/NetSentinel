"""Documented balloon policy/session checks; no live host setting changes."""
import pytest
from types import SimpleNamespace

from netsentinel.application.services.notifications import NotificationPlatformState as State
from netsentinel.infrastructure.windows_notification_policy import windows_notification_policy


@pytest.mark.parametrize("state", [1, 2, 3, 4, 6, 7])
def test_native_session_restrictions(state):
    assert windows_notification_policy(platform="win32", read_disabled=lambda: False,
        query_session=lambda: (0, state)) is State.SESSION_RESTRICTED


@pytest.mark.parametrize("result,state", [(0, 5), (0, 0), (0, 8), (-1, 1), (1, 1)])
def test_accepts_unknown_enum_and_hresult_never_prove_display(result, state):
    assert windows_notification_policy(platform="win32", read_disabled=lambda: False,
        query_session=lambda: (result, state)) is State.DELIVERY_UNKNOWN


def test_documented_configured_balloon_restriction_precedes_session():
    def forbidden():
        raise AssertionError("must not query session when policy disabled")
    assert windows_notification_policy(platform="win32", read_disabled=lambda: True,
        query_session=forbidden) is State.DISABLED_BY_OS


@pytest.mark.parametrize("error", [OSError, AttributeError, ValueError])
def test_inaccessible_policy_or_api_returns_unknown_without_raw_error(error):
    def fail():
        raise error("private identity must not enter diagnostics")
    assert windows_notification_policy(platform="win32", read_disabled=fail) is State.DELIVERY_UNKNOWN
    assert windows_notification_policy(platform="win32", read_disabled=lambda: False,
        query_session=fail) is State.DELIVERY_UNKNOWN


def test_other_platform_does_not_access_windows():
    def forbidden():
        raise AssertionError("native access on unsupported platform")
    assert windows_notification_policy(platform="linux", read_disabled=forbidden,
        query_session=forbidden) is State.DELIVERY_UNKNOWN


@pytest.mark.parametrize("value,kind,expected", [
    (1, 4, State.DISABLED_BY_OS), (0, 4, State.DELIVERY_UNKNOWN),
    (2, 4, State.DELIVERY_UNKNOWN), ("1", 1, State.DELIVERY_UNKNOWN),
])
def test_only_exact_documented_dword_policy_is_recognized(monkeypatch, value, kind, expected):
    class Key:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    calls = []
    def open_key(hive, name, reserved, access):
        calls.append((hive, name, access))
        return Key()
    def query(key, name):
        assert name == "TaskbarNoNotification"
        return value, kind
    module = SimpleNamespace(HKEY_CURRENT_USER=1, KEY_READ=2, REG_DWORD=4,
        OpenKey=open_key, QueryValueEx=query)
    monkeypatch.setitem(__import__('sys').modules, "winreg", module)
    assert windows_notification_policy(platform="win32", query_session=lambda: (0, 5)) is expected
    assert calls == [(1, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 2)]
