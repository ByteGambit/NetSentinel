"""NS-094 disabled defaults, safe malformed inputs and atomic field-only save."""

from dataclasses import replace
import pytest

from netsentinel.shared.config import (
    AppConfig, WindowCloseBehavior, load_config_file, load_config_values,
    save_config_file, save_notification_preference,
)


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}, 1.0])
def test_invalid_notification_preference_disabled(value):
    result = load_config_values({"desktop_notifications_enabled": value})
    assert not result.config.desktop_notifications_enabled
    assert result.issues[0].field == "desktop_notifications_enabled"
    with pytest.raises(ValueError):
        AppConfig(desktop_notifications_enabled=value)


def test_old_config_and_unreadable_malformed_files_disabled(tmp_path):
    path = tmp_path / "config.json"
    assert not load_config_file(path).config.desktop_notifications_enabled
    assert not load_config_values({"onboarding_completed": True}).config.desktop_notifications_enabled
    for content in ("{", "[]", "null", "x" * 16385):
        path.write_text(content)
        assert not load_config_file(path).config.desktop_notifications_enabled


@pytest.mark.parametrize("enabled", [True, False])
def test_atomic_roundtrip_preserves_all_other_fields(tmp_path, enabled):
    path = tmp_path / "config.json"
    original = AppConfig(window_close_behavior=WindowCloseBehavior.HIDE_TO_TRAY,
                         polling_interval=3, onboarding_completed=True)
    save_config_file(path, original)
    save_notification_preference(path, enabled)
    assert load_config_file(path).config == replace(original, desktop_notifications_enabled=enabled)
    assert not list(tmp_path.glob(".config-*.tmp"))


def test_atomic_write_failure_leaves_file_and_runtime_preference(tmp_path, monkeypatch):
    from netsentinel.shared import config
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig())
    before = path.read_bytes()
    def fail(source, destination):
        raise OSError("private path")
    monkeypatch.setattr(config.os, "replace", fail)
    with pytest.raises(OSError):
        save_notification_preference(path, True)
    assert path.read_bytes() == before and not list(tmp_path.glob(".config-*.tmp"))
