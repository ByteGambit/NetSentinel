"""NS-106 allowlisted fields, independent migration and atomic merge."""

from dataclasses import replace
import json

import pytest

from netsentinel.shared import config as module
from netsentinel.shared.config import AppConfig, load_config_file, load_config_values, save_config_file, save_ui_language
from netsentinel.shared.locales import PLANNED_LOCALES
from tests.fixtures.threat_intelligence import grant as consent


@pytest.mark.parametrize('locale', [item.id for item in PLANNED_LOCALES])
def test_frozen_ids_roundtrip(locale, tmp_path):
    path = tmp_path / 'config.json'
    save_ui_language(path, locale)
    result = load_config_file(path)
    assert not result.issues
    assert result.config.ui_language == locale
    assert result.config.ui_language_confirmed is True


@pytest.mark.parametrize('field,value', [('ui_language', None), ('ui_language', []),
    ('ui_language', 'tr_TR'), ('ui_language', '../tr'), ('ui_language', 'removed'),
    ('ui_language', 'x' * 100), ('ui_language_confirmed', 1), ('ui_language_confirmed', 'yes')])
def test_invalid_fields_fall_back_with_bounded_issues(field, value):
    result = load_config_values({field: value})
    assert result.config.ui_language == 'en'
    assert not result.config.ui_language_confirmed
    assert result.issues[0].field == field
    assert result.issues[0].code == 'invalid_value'


def test_legacy_and_concurrent_update_preserve_independent_state(tmp_path):
    path = tmp_path / 'config.json'
    before = AppConfig(onboarding_completed=True, onboarding_completed_version=999,
                       onboarding_dismissed_version=998, desktop_notifications_enabled=True,
                       storage_retention_enabled=True, threat_intel_consents=(consent(),))
    # Use the existing codec for UUIDs, then remove only the two new fields.
    save_config_file(path, before)
    values = json.loads(path.read_text())
    values.pop('ui_language')
    values.pop('ui_language_confirmed')
    path.write_text(json.dumps(values))
    assert not load_config_file(path).config.ui_language_confirmed
    # Another settings action finishes while the language dialog is open.
    module.save_notification_preference(path, False)
    after = save_ui_language(path, 'en')
    assert after == replace(before, desktop_notifications_enabled=False,
                            ui_language_confirmed=True)


def test_atomic_failure_keeps_exact_config_and_no_temp(tmp_path, monkeypatch):
    path = tmp_path / 'config.json'
    save_config_file(path, AppConfig(polling_interval=0.2, threat_intel_consents=(consent(),)))
    before = path.read_bytes()
    def fail(*args):
        raise OSError('private path and secret')
    monkeypatch.setattr(module.os, 'replace', fail)
    with pytest.raises(OSError):
        save_ui_language(path, 'tr')
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize('content', ['{', '[]', 'null', 'x' * 16385])
def test_corrupt_document_is_never_overwritten(content, tmp_path):
    path = tmp_path / 'config.json'
    path.write_text(content)
    with pytest.raises(ValueError):
        save_ui_language(path, 'en')
    assert path.read_text() == content


def test_forward_fields_preserved_and_damaged_config_still_fails_ti_closed(tmp_path):
    path = tmp_path / 'config.json'
    save_config_file(path, AppConfig(threat_intel_consents=(consent(),)))
    values = json.loads(path.read_text())
    values['future_setting'] = {'nested': ['kept', 3]}
    path.write_text(json.dumps(values))
    after = save_ui_language(path, 'en')
    assert after.threat_intel_consents == ()
    assert json.loads(path.read_text())['future_setting'] == values['future_setting']
    assert load_config_file(path).config.threat_intel_consents == ()


def test_invalid_explicit_choice_never_writes(tmp_path):
    path = tmp_path / 'config.json'
    with pytest.raises(ValueError):
        save_ui_language(path, 'unsupported')
    assert not path.exists()
