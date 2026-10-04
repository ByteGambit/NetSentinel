"""NS-093 typed upgrade/default/malformed and restart persistence."""

import pytest

from netsentinel.shared.config import (
    AppConfig, WindowCloseBehavior as Close, load_config_file, load_config_values,
    save_config_file, save_window_close_behavior,
)


@pytest.mark.parametrize("values", [{}, {"window_close_behavior": "bad"},
    {"window_close_behavior": None}, {"window_close_behavior": 1},
    {"window_close_behavior": []}, {"window_close_behavior": {}}])
def test_missing_malformed_close_preference_uses_quit_default(values):
    result = load_config_values(values)
    assert result.config.window_close_behavior is Close.QUIT_APPLICATION
    assert bool(result.issues) == bool(values)
    if values:
        assert result.issues[0].field == "window_close_behavior"


@pytest.mark.parametrize("behavior", list(Close))
def test_typed_config_roundtrip_and_field_only_save(tmp_path, behavior):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(onboarding_completed=True, polling_interval=3))
    save_window_close_behavior(path, behavior)
    loaded = load_config_file(path)
    assert not loaded.issues
    assert loaded.config.window_close_behavior is behavior
    assert loaded.config.onboarding_completed and loaded.config.polling_interval == 3
    assert f'"window_close_behavior":"{behavior.value}"' in path.read_text()


def test_model_rejects_arbitrary_string_even_when_enum_value_matches():
    with pytest.raises(ValueError):
        AppConfig(window_close_behavior="hide_to_tray")
