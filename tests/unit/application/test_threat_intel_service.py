"""NS-084 policy before provider, two-provider contract and revocation."""

from dataclasses import fields, replace
import json
from typing import get_type_hints

import pytest

from netsentinel.application.ports import ThreatIntelligenceProvider, ThreatIntelSecretStore
from netsentinel.application.services.threat_intelligence import ThreatIntelLookupService
from netsentinel.domain.threat_intelligence import (
    ThreatIntelDataType, ThreatIntelDenial, ThreatIntelError, ThreatIntelResultStatus,
    ThreatIntelTrigger, ThreatIntelQuery, ThreatIntelResult, ThreatIntelSubject,
)
from netsentinel.shared.config import AppConfig, save_config_file
from tests.fixtures.threat_intelligence import A, B, NOW, FakeProviderA, FakeProviderB, grant, query


def test_fresh_default_does_not_call_either_provider():
    a, b = FakeProviderA(), FakeProviderB()
    service = ThreatIntelLookupService((a, b), lambda: AppConfig().threat_intel_consents)
    for provider in (A, B):
        outcome = service.lookup_selected(query(provider, consent=grant(provider)))
        assert outcome.denial is ThreatIntelDenial.NO_CONSENT and outcome.result is None
    assert a.calls == b.calls == []


@pytest.mark.parametrize("provider,data_type,trigger,value", [
    (B, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, None),
    (A, ThreatIntelDataType.DOMAIN_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, None),
    (A, ThreatIntelDataType.HASH_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, None),
    (A, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.AUTOMATIC, None),
    (A, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, "10.0.0.1"),
    (A, ThreatIntelDataType.DOMAIN_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, "host.local"),
])
def test_every_denial_keeps_both_providers_uncalled(provider, data_type, trigger, value):
    a, b = FakeProviderA(), FakeProviderB()
    consent = grant()
    service = ThreatIntelLookupService((a, b), lambda: (consent,))
    outcome = service.lookup_selected(query(provider, data_type, consent=consent, trigger=trigger, value=value))
    assert outcome.denial is not None and outcome.result is None
    assert a.calls == b.calls == []


@pytest.mark.parametrize("provider_class,provider,expected", [
    (FakeProviderA, A, ThreatIntelResultStatus.HIT),
    (FakeProviderB, B, ThreatIntelResultStatus.NO_HIT),
])
def test_two_independent_providers_work_through_same_port(provider_class, provider, expected):
    adapter: ThreatIntelligenceProvider = provider_class()
    consent = grant(provider)
    service = ThreatIntelLookupService((adapter,), lambda: (consent,), lambda: NOW)
    request = query(provider, consent=consent)
    result = service.lookup_selected(request).result
    assert result is not None and result.status is expected and result.query == request
    assert adapter.calls == [request]


@pytest.mark.parametrize("status", list(ThreatIntelResultStatus))
def test_no_hit_and_error_remain_distinct_operational_states(status):
    adapter = FakeProviderA(status)
    consent = grant()
    service = ThreatIntelLookupService((adapter,), lambda: (consent,), lambda: NOW)
    result = service.lookup_selected(query(consent=consent)).result
    assert result.status is status
    assert result.error is (ThreatIntelError.TIMEOUT if status is ThreatIntelResultStatus.ERROR else None)
    assert not hasattr(result, "safe") and not hasattr(result, "is_malware")


def test_revocation_is_immediate_and_old_reference_cannot_reauthorize():
    adapter = FakeProviderA()
    consent = grant()
    current = [consent]
    service = ThreatIntelLookupService((adapter,), lambda: tuple(current))
    request = query(consent=consent)
    assert service.lookup_selected(request).result is not None
    current.clear()
    assert service.lookup_selected(request).denial is ThreatIntelDenial.NO_CONSENT
    current.append(grant())
    assert service.lookup_selected(request).denial is ThreatIntelDenial.NO_CONSENT
    assert len(adapter.calls) == 1


def test_unknown_unsupported_invalid_and_corrupt_policy_never_call_provider():
    adapter = FakeProviderA()
    consent = grant()
    limited = replace(adapter.descriptor, supported_data_types=frozenset({ThreatIntelDataType.HASH_REPUTATION}))
    adapter.descriptor = limited
    service = ThreatIntelLookupService((adapter,), lambda: (consent,))
    assert service.lookup_selected(query(consent=consent)).denial is ThreatIntelDenial.UNSUPPORTED_DATA_TYPE
    assert service.lookup_selected(query(B, consent=grant(B))).denial is ThreatIntelDenial.UNSUPPORTED_PROVIDER
    with pytest.raises(TypeError):
        service.lookup_selected("invalid raw subject")
    corrupt = ThreatIntelLookupService((adapter,), lambda: [consent])
    assert corrupt.lookup_selected(query(consent=consent)).denial is ThreatIntelDenial.NO_CONSENT
    assert adapter.calls == []


def test_provider_exception_is_sanitized_and_wrong_provenance_is_error():
    class Broken(FakeProviderA):
        def query(self, request):
            raise RuntimeError("API_KEY_SENTINEL secret subject path")

    consent = grant()
    service = ThreatIntelLookupService((Broken(),), lambda: (consent,), lambda: NOW)
    result = service.lookup_selected(query(consent=consent)).result
    assert result.status is ThreatIntelResultStatus.ERROR
    assert result.error is ThreatIntelError.UNAVAILABLE
    assert "API_KEY_SENTINEL" not in repr(result)

    class Mismatched(FakeProviderA):
        def query(self, request):
            return ThreatIntelResult(query(B), ThreatIntelResultStatus.NO_HIT, NOW)

    service = ThreatIntelLookupService((Mismatched(),), lambda: (consent,), lambda: NOW)
    assert service.lookup_selected(query(consent=consent)).result.error is ThreatIntelError.INVALID_RESPONSE


def test_contracts_have_no_secret_or_arbitrary_payload_boundary(tmp_path, caplog):
    assert set(get_type_hints(ThreatIntelSecretStore.get_secret)) == {"provider", "return"}
    assert {f.name for f in fields(ThreatIntelSubject)} == {"kind", "value", "algorithm"}
    assert {f.name for f in fields(ThreatIntelQuery)} == {
        "request_id", "provider", "subject", "data_type", "trigger", "consent", "queried_at", "policy_version",
    }
    assert {f.name for f in fields(ThreatIntelResult)} == {
        "query", "status", "received_at", "error", "ip_facts", "rate_limit",
    }
    path = tmp_path / "config.json"
    save_config_file(path, AppConfig(threat_intel_consents=(grant(),)))
    serialized = path.read_text(encoding="utf-8")
    assert "secret" not in serialized and "credential" not in serialized
    assert "API_KEY_SENTINEL" not in serialized + repr(query()) + caplog.text
    assert set(json.loads(serialized)["threat_intel_consents"][0]) == {
        "consent_id", "provider", "data_type", "trigger", "policy_version",
    }
