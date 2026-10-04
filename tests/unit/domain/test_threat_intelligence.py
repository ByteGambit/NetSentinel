"""NS-084 subject validation, external eligibility and consent matrix."""

from dataclasses import replace
from datetime import datetime

import pytest

from netsentinel.domain.threat_intelligence import (
    HashAlgorithm, ThreatIntelDataType, ThreatIntelDenial, ThreatIntelError,
    ThreatIntelProviderDescriptor, ThreatIntelProviderId, ThreatIntelResult,
    ThreatIntelResultStatus, ThreatIntelSubject, ThreatIntelSubjectKind,
    ThreatIntelTrigger, consent_denial, externally_eligible, validate_consents,
)
from tests.fixtures.threat_intelligence import A, B, DESCRIPTORS, NOW, grant, query


@pytest.mark.parametrize("value,canonical", [
    ("8.8.8.8", "8.8.8.8"),
    ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888"),
])
def test_ip_reuses_endpoint_canonical_identity(value, canonical):
    assert ThreatIntelSubject(ThreatIntelSubjectKind.IP, value).value == canonical
    assert query(value=value).subject == query(value=canonical).subject


@pytest.mark.parametrize("value", [
    "127.0.0.1", "10.1.2.3", "172.16.1.1", "192.168.1.1", "169.254.1.2",
    "224.0.0.1", "239.1.2.3", "0.0.0.0", "100.64.0.1", "192.0.2.1", "198.51.100.1",
    "203.0.113.1", "240.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "2001:db8::1",
    "::ffff:127.0.0.1", "::ffff:192.168.1.1", "100::1",
])
def test_private_special_and_documentation_addresses_are_never_eligible(value):
    request = query(value=value, consent=grant())
    assert not externally_eligible(request.subject)
    assert consent_denial(request, DESCRIPTORS[0], (request.consent,)) is ThreatIntelDenial.LOCAL_SUBJECT


@pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"])
def test_known_global_unicast_addresses_eligible(value):
    assert externally_eligible(query(value=value).subject)


@pytest.mark.parametrize("kind,value,algorithm", [
    (ThreatIntelSubjectKind.IP, "", None), (ThreatIntelSubjectKind.IP, "999.1.1.1", None),
    (ThreatIntelSubjectKind.IP, "fe80::1%eth0", None), (ThreatIntelSubjectKind.IP, b"8.8.8.8", None),
    (ThreatIntelSubjectKind.DOMAIN, "", None), (ThreatIntelSubjectKind.DOMAIN, ".", None),
    (ThreatIntelSubjectKind.DOMAIN, "8.8.8.8", None), (ThreatIntelSubjectKind.DOMAIN, "::1", None),
    (ThreatIntelSubjectKind.DOMAIN, "a..com", None), (ThreatIntelSubjectKind.DOMAIN, "-a.com", None),
    (ThreatIntelSubjectKind.DOMAIN, "a-.com", None), (ThreatIntelSubjectKind.DOMAIN, "_srv.example", None),
    (ThreatIntelSubjectKind.DOMAIN, "https://example.com", None),
    (ThreatIntelSubjectKind.DOMAIN, "a" * 64 + ".com", None),
    (ThreatIntelSubjectKind.DOMAIN, ".".join(["a" * 63] * 4), None),
    (ThreatIntelSubjectKind.DOMAIN, "bücher.example", None),
    (ThreatIntelSubjectKind.HASH, "a" * 63, HashAlgorithm.SHA256),
    (ThreatIntelSubjectKind.HASH, "a" * 65, HashAlgorithm.SHA256),
    (ThreatIntelSubjectKind.HASH, "g" * 64, HashAlgorithm.SHA256),
    (ThreatIntelSubjectKind.HASH, "a" * 64, None),
    (ThreatIntelSubjectKind.HASH, "a" * 64, "sha256"),
    (ThreatIntelSubjectKind.HASH, b"a" * 64, HashAlgorithm.SHA256),
    (ThreatIntelSubjectKind.HASH, "C:\\private\\app.exe", HashAlgorithm.SHA256),
    (ThreatIntelSubjectKind.IP, "8.8.8.8", HashAlgorithm.SHA256),
])
def test_invalid_subjects_rejected_without_input_in_error(kind, value, algorithm):
    with pytest.raises((TypeError, ValueError)) as error:
        ThreatIntelSubject(kind, value, algorithm)
    if value:
        assert str(value) not in str(error.value)


@pytest.mark.parametrize("value", ["EXAMPLE.COM", "Example.Com.", "example.com"])
def test_domain_reuses_ascii_trailing_dot_convention(value):
    assert query(data_type=ThreatIntelDataType.DOMAIN_REPUTATION, value=value).subject.value == "example.com."
    assert externally_eligible(query(data_type=ThreatIntelDataType.DOMAIN_REPUTATION, value=value).subject)
    assert query(data_type=ThreatIntelDataType.DOMAIN_REPUTATION, value="xn--bcher-kva.example").subject.value == "xn--bcher-kva.example."


@pytest.mark.parametrize("value", ["localhost", "host.local", "LOCALHOST.", "printer", "foo.localhost"])
def test_local_domains_denied(value):
    assert not externally_eligible(query(data_type=ThreatIntelDataType.DOMAIN_REPUTATION, value=value).subject)


def test_sha256_normalizes_without_file_metadata():
    assert query(data_type=ThreatIntelDataType.HASH_REPUTATION, value="AB" * 32).subject.value == "ab" * 32


@pytest.mark.parametrize("provider,data_type,trigger,expected", [
    (A, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, None),
    (A, ThreatIntelDataType.DOMAIN_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, ThreatIntelDenial.NO_CONSENT),
    (A, ThreatIntelDataType.HASH_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, ThreatIntelDenial.NO_CONSENT),
    (B, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.MANUAL_SELECTED, ThreatIntelDenial.NO_CONSENT),
    (A, ThreatIntelDataType.IP_REPUTATION, ThreatIntelTrigger.AUTOMATIC, ThreatIntelDenial.TRIGGER_NOT_SUPPORTED),
])
def test_consent_matrix_isolates_provider_data_and_trigger(provider, data_type, trigger, expected):
    consent = grant()
    request = query(provider, data_type, trigger=trigger, consent=consent)
    assert consent_denial(request, DESCRIPTORS[0 if provider == A else 1], (consent,)) is expected


def test_unsupported_capabilities_stale_context_and_automatic_grants_fail_closed():
    consent = grant()
    request = query(consent=consent)
    assert consent_denial(request, None, (consent,)) is ThreatIntelDenial.UNSUPPORTED_PROVIDER
    limited = replace(DESCRIPTORS[0], supported_data_types=frozenset({ThreatIntelDataType.HASH_REPUTATION}))
    assert consent_denial(request, limited, (consent,)) is ThreatIntelDenial.UNSUPPORTED_DATA_TYPE
    assert consent_denial(request, DESCRIPTORS[0], (grant(),)) is ThreatIntelDenial.NO_CONSENT
    assert consent_denial(request, DESCRIPTORS[0], ()) is ThreatIntelDenial.NO_CONSENT
    with pytest.raises(ValueError):
        validate_consents((grant(trigger=ThreatIntelTrigger.AUTOMATIC),))


def test_typed_contract_bounds_and_status_invariants():
    with pytest.raises(ValueError):
        ThreatIntelProviderId("https://provider.example")
    with pytest.raises(ValueError):
        ThreatIntelProviderDescriptor(A, "bad\nname", frozenset(ThreatIntelDataType))
    with pytest.raises(ValueError):
        replace(DESCRIPTORS[0], supported_data_types=set(ThreatIntelDataType))
    with pytest.raises(ValueError):
        validate_consents((grant(), grant()))
    with pytest.raises(ValueError):
        replace(query(), data_type=ThreatIntelDataType.DOMAIN_REPUTATION)
    with pytest.raises(ValueError):
        replace(query(), queried_at=datetime(2026, 10, 4))
    with pytest.raises(ValueError):
        ThreatIntelResult(query(), ThreatIntelResultStatus.ERROR, NOW)
    with pytest.raises(ValueError):
        ThreatIntelResult(query(), ThreatIntelResultStatus.NO_HIT, NOW, ThreatIntelError.TIMEOUT)
    assert {s.value for s in ThreatIntelResultStatus} == {"hit", "no_hit", "error"}
