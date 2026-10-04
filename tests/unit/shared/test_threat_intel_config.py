"""Consent JSON defaults, strict loading, persistence and inert unknown IDs."""

from dataclasses import replace
import json

import pytest

from netsentinel.bootstrap import create_threat_intel_consent_service
from netsentinel.domain.threat_intelligence import ThreatIntelProviderId
from netsentinel.domain.threat_intelligence import ThreatIntelDataType
from netsentinel.shared.config import (
    AppConfig, complete_onboarding, load_config_file, load_config_values, save_config_file,
)
from tests.fixtures.threat_intelligence import DESCRIPTORS, grant


def test_fresh_old_missing_malformed_and_oversized_config_default_disabled(tmp_path):
    path = tmp_path / "config.json"
    assert load_config_file(path).config.threat_intel_consents == ()
    for content in ('{"onboarding_completed":true}', "{bad", "null", "[]", "x" * 16_385):
        path.write_text(content, encoding="utf-8")
        assert load_config_file(path).config.threat_intel_consents == ()


def test_consent_roundtrip_onboarding_preservation_and_revoke(tmp_path):
    path = tmp_path / "config.json"
    consent = grant()
    service = create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS)
    save_config_file(path, AppConfig(polling_interval=2, onboarding_completed=True))
    service.save((consent,))
    config = load_config_file(path).config
    assert config.polling_interval == 2 and config.onboarding_completed
    assert config.threat_intel_consents == (consent,)
    assert create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS).current() == (consent,)
    complete_onboarding(path, config)
    assert load_config_file(path).config.threat_intel_consents == (consent,)
    service.save(())
    assert load_config_file(path).config.threat_intel_consents == ()


@pytest.mark.parametrize("mutation", [
    lambda e: e.update(data_type="unexpected"),
    lambda e: e.update(consent_id=None),
    lambda e: e.update(consent_id="bad uuid"),
    lambda e: e.update(consent_id=[]),
    lambda e: e.update(provider={"value": "arbitrary-url"}),
    lambda e: e.update(provider=None),
    lambda e: e.update(trigger="automatic"),
    lambda e: e.update(policy_version=2),
    lambda e: e.update(policy_version=True),
    lambda e: e.update(secret="API_KEY_SENTINEL"),
    lambda e: e.pop("trigger"),
])
def test_corrupt_entry_disables_entire_ti_section_without_leak(tmp_path, mutation):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(threat_intel_consents=(grant(),)))
    values = json.loads(path.read_text(encoding="utf-8"))
    mutation(values["threat_intel_consents"][0])
    result = load_config_values(values)
    assert result.config.threat_intel_consents == ()
    assert "API_KEY_SENTINEL" not in repr(result)
    assert any(issue.field == "threat_intel_consents" for issue in result.issues)


@pytest.mark.parametrize("bad", [None, True, {}, "enabled", [False], ["secret"]])
def test_malformed_section_defaults_off(bad):
    assert load_config_values({"threat_intel_consents": bad}).config.threat_intel_consents == ()


def test_unknown_provider_is_inert_and_cannot_be_saved_as_known(tmp_path):
    path = tmp_path / "config.json"
    unknown = grant(ThreatIntelProviderId("unknown_provider"))
    save_config_file(path, AppConfig(threat_intel_consents=(unknown,)))
    service = create_threat_intel_consent_service(config_path=path, descriptors=DESCRIPTORS)
    assert service.current() == ()
    with pytest.raises(ValueError):
        service.save((unknown,))
    # Production has no registered provider, including those named in a local file.
    assert create_threat_intel_consent_service(config_path=path).current() == ()


def test_other_corrupt_config_field_also_disables_valid_consent(tmp_path):
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(threat_intel_consents=(grant(),)))
    values = json.loads(path.read_text(encoding="utf-8"))
    values["polling_interval"] = -1
    result = load_config_values(values)
    assert result.config.threat_intel_consents == ()
    assert any(i.code == "disabled_due_to_config_issue" for i in result.issues)


def test_save_cannot_produce_file_that_loader_would_reject(tmp_path):
    consents = tuple(grant(ThreatIntelProviderId("p" + str(i).zfill(63)), t)
                     for i in range(16) for t in ThreatIntelDataType)
    config = AppConfig(destination_dataset_path="ü" * 4096, threat_intel_consents=consents)
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig())
    previous = path.read_bytes()
    with pytest.raises(ValueError, match="loader bound"):
        save_config_file(path, config)
    assert path.read_bytes() == previous


def test_atomic_save_failure_preserves_previous_permissions_and_cleans_temp(tmp_path, monkeypatch):
    import netsentinel.shared.config as module
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig())
    previous = path.read_bytes()

    def fail(*_):
        raise OSError("API_KEY_SENTINEL")

    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(OSError):
        save_config_file(path, replace(AppConfig(), threat_intel_consents=(grant(),)))
    assert path.read_bytes() == previous
    assert list(tmp_path.glob(".config-*.tmp")) == []
