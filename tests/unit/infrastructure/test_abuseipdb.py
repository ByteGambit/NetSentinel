"""NS-086 offline contract, consent, privacy, bounds and cache acceptance."""

from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from netsentinel.application.services.threat_intelligence import ThreatIntelLookupService
from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
from netsentinel.domain.threat_intelligence import (
    TI_RESULT_CONTRACT_VERSION, ThreatIntelDataType as D, ThreatIntelDenial,
    ThreatIntelError as E, ThreatIntelRateLimit, ThreatIntelResultStatus as S,
    ThreatIntelTrigger,
)
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheKey, ThreatIntelCacheMutationStatus as M
from netsentinel.infrastructure.abuseipdb import ABUSEIPDB_DESCRIPTOR, AbuseIpDbAdapter
from netsentinel.infrastructure.sqlite import SQLiteDatabase
from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
from netsentinel.infrastructure.threat_intel_http import (
    MAX_HTTP_BODY_BYTES, MAX_SECRET_LENGTH, HttpResponse, HttpTransportFailure,
)
from tests.fixtures.threat_intelligence import NOW, FakeProviderB, grant, query


FIXTURES = Path(__file__).parents[2] / "fixtures" / "abuseipdb"
PROVIDER = ABUSEIPDB_DESCRIPTOR.provider
DUMMY_KEY = "dummy-secret-for-offline-testing"


class Secrets:
    def __init__(self, value=DUMMY_KEY, failure=None):
        self.value = value
        self.failure = failure
        self.calls = 0

    def get_secret(self, provider):
        assert provider == PROVIDER
        self.calls += 1
        if self.failure:
            raise self.failure
        return self.value

    def __repr__(self):
        return "Secrets(<redacted>)"


class FakeTransport:
    def __init__(self, response=None, failure=None):
        self.response = response or fixture()
        self.failure = failure
        self.calls = []

    def send(self, request):
        # Verify header secret locally, retain only a redacted request record.
        assert request.headers == {"Accept": "application/json", "Key": DUMMY_KEY}
        request.validate()
        self.calls.append(replace(request, headers={"Accept": "application/json", "Key": "<redacted>"}))
        if self.failure:
            raise self.failure
        return self.response


def fixture(name="hit_ipv4", **kwargs):
    return HttpResponse(kwargs.get("status", 200), kwargs.get("headers", {"Content-Type": "application/json"}),
                        (FIXTURES / (name + ".json")).read_bytes())


def request(data_type=D.IP_REPUTATION, value=None):
    return query(PROVIDER, data_type, value, consent=grant(PROVIDER, data_type))


def run(response=None, *, selected=None, secret=DUMMY_KEY, failure=None):
    transport = FakeTransport(response, failure)
    adapter = AbuseIpDbAdapter(Secrets(secret), transport, lambda: NOW)
    return adapter.query(selected or request()), transport, adapter


def altered(**fields):
    data = json.loads(fixture().body)
    data["data"].update(fields)
    return HttpResponse(200, {"content-type": "application/json"}, json.dumps(data).encode())


def test_descriptor_construction_and_no_startup_io():
    secrets, transport = Secrets(), FakeTransport()
    adapter = AbuseIpDbAdapter(secrets, transport, lambda: NOW)
    assert adapter.descriptor.display_name == "AbuseIPDB"
    assert adapter.descriptor.supported_data_types == frozenset({D.IP_REPUTATION})
    assert adapter.mapping_version == 1 and adapter.descriptor.retention == "unknown"
    assert secrets.calls == 0 and transport.calls == []
    assert DUMMY_KEY not in repr(adapter)


@pytest.mark.parametrize("name,ip,version,score", [
    ("hit_ipv4", "8.8.8.8", 4, 75), ("hit_ipv6", "2606:4700:4700::1111", 6, 100),
])
def test_request_and_core_facts(name, ip, version, score):
    result, transport, _ = run(fixture(name), selected=request(value=ip))
    assert result.status is S.HIT and result.error is None
    facts = result.ip_facts
    assert facts.abuse_confidence_score == score and facts.lookback_days == 30
    assert facts.mapping_version == 1 and facts.last_reported_at == datetime(2026, 10, 3, 12, 30, tzinfo=UTC)
    assert result.received_at == NOW and result.query.subject.value == ip
    sent = transport.calls[0]
    parsed = urlsplit(sent.url)
    assert parsed.scheme == "https" and parsed.netloc == "api.abuseipdb.com" and parsed.path == "/api/v2/check"
    assert sent.method == "GET" and sent.timeout == 8 and sent.max_body_bytes == 65536
    assert parse_qs(parsed.query) == {"ipAddress": [ip], "maxAgeInDays": ["30"]}
    if version == 6:
        assert "%3A" in sent.url
    assert "verbose" not in sent.url and DUMMY_KEY not in sent.url
    assert DUMMY_KEY not in repr(sent) + repr(result) + repr(transport.calls)


def test_no_hit_is_no_reports_not_safe():
    result, _, _ = run(fixture("no_hit"))
    assert result.status is S.NO_HIT and result.ip_facts.total_reports == 0
    assert result.ip_facts.last_reported_at is None
    assert not hasattr(result, "safe") and not hasattr(result, "risk_score")


@pytest.mark.parametrize("fields", [dict(abuseConfidenceScore=0), dict(isWhitelisted=True),
                                    dict(lastReportedAt=None), dict(totalReports=0)])
def test_zero_score_whitelist_and_context_do_not_mean_safe(fields):
    result, _, _ = run(altered(**fields))
    assert result.status is S.HIT


@pytest.mark.parametrize("data_type", [D.DOMAIN_REPUTATION, D.HASH_REPUTATION])
def test_unsupported_subject_no_http(data_type):
    selected = request(data_type)
    result, transport, adapter = run(selected=selected)
    assert result.error is E.UNSUPPORTED and transport.calls == []
    service = ThreatIntelLookupService((adapter,), lambda: (selected.consent,))
    assert service.lookup_selected(selected).denial is ThreatIntelDenial.UNSUPPORTED_DATA_TYPE


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "192.168.0.1", "169.254.1.1", "100.64.0.1",
                               "::1", "fc00::1", "fe80::1", "ff02::1", "192.0.2.1"])
def test_local_subject_service_and_adapter_no_http(ip):
    selected = request(value=ip)
    result, transport, adapter = run(selected=selected)
    assert result.error is E.UNSUPPORTED
    outcome = ThreatIntelLookupService((adapter,), lambda: (selected.consent,)).lookup_selected(selected)
    assert outcome.denial is ThreatIntelDenial.LOCAL_SUBJECT and transport.calls == []


def test_current_consent_revoke_enable_alone_and_interchangeable_fake_b():
    selected = request()
    transport = FakeTransport()
    adapter = AbuseIpDbAdapter(Secrets(), transport, lambda: NOW)
    grants = []
    service = ThreatIntelLookupService((adapter, FakeProviderB()), lambda: tuple(grants))
    assert service.lookup_selected(selected).denial is ThreatIntelDenial.NO_CONSENT
    grants.append(selected.consent)
    assert transport.calls == []
    assert service.lookup_selected(selected).result.status is S.HIT
    assert len(transport.calls) == 1
    grants.clear()
    assert service.lookup_selected(selected).denial is ThreatIntelDenial.NO_CONSENT
    assert len(transport.calls) == 1


@pytest.mark.parametrize("change", [dict(consent=None), dict(trigger=ThreatIntelTrigger.AUTOMATIC)])
def test_direct_ungranted_or_automatic_query_is_rejected(change):
    result, transport, _ = run(selected=replace(request(), **change))
    assert result.error is E.UNSUPPORTED and not transport.calls


@pytest.mark.parametrize("key", [None, "", " ", "x" * (MAX_SECRET_LENGTH + 1), "key\r\nevil", "x\x00", "ş"])
def test_missing_or_invalid_secret_no_request(key):
    result, transport, _ = run(secret=key)
    assert result.status is S.ERROR and result.error is E.CREDENTIAL_UNAVAILABLE
    assert not transport.calls


def test_secret_store_failure_redacts_exception(caplog):
    adapter = AbuseIpDbAdapter(Secrets(failure=RuntimeError(DUMMY_KEY)), FakeTransport(), lambda: NOW)
    result = adapter.query(request())
    assert result.error is E.CREDENTIAL_UNAVAILABLE and DUMMY_KEY not in repr(result) + caplog.text


@pytest.mark.parametrize("status,error", [(401, E.AUTHENTICATION), (403, E.AUTHENTICATION),
    (402, E.SUBSCRIPTION_RESTRICTED), (422, E.INVALID_REQUEST), (429, E.RATE_LIMITED),
    (500, E.UNAVAILABLE), (502, E.UNAVAILABLE), (503, E.UNAVAILABLE), (400, E.HTTP_ERROR),
    (404, E.HTTP_ERROR), (301, E.REDIRECT_REJECTED), (302, E.REDIRECT_REJECTED),
    (307, E.REDIRECT_REJECTED), (308, E.REDIRECT_REJECTED), (204, E.HTTP_ERROR)])
def test_http_error_mapping_once_and_redaction(status, error, caplog):
    response = HttpResponse(status, {"content-type": "application/json", "Location": "https://evil.invalid"},
                            json.dumps({"errors": [{"status": status, "detail": DUMMY_KEY}]}).encode())
    result, transport, _ = run(response)
    assert result.status is S.ERROR and result.error is error and result.ip_facts is None
    assert len(transport.calls) == 1
    assert DUMMY_KEY not in repr(result) + repr(response) + caplog.text


@pytest.mark.parametrize("value,expected", [("60", 60), ("0", 0), ("999999", 86400),
    ("-1", None), ("NaN", None), ("1.5", None), ("9" * 1000, None), (None, None),
    ("Sun, 04 Oct 2026 00:00:00 GMT", None), ("١", None)])
def test_retry_after_bounded_numeric_only(value, expected):
    headers = {"Retry-After": value} if value is not None else {}
    result, transport, _ = run(fixture("error", status=429, headers=headers))
    assert result.error is E.RATE_LIMITED and result.rate_limit.retry_after_seconds == expected
    assert len(transport.calls) == 1


@pytest.mark.parametrize("value,expected", [("123", 123), ("0", 0), ("-1", None),
    (str(2**31), None), ("9" * 1000, None), ("xx", None)])
def test_rate_limit_headers_are_optional_bounded_integers(value, expected):
    result, _, _ = run(fixture("error", status=429, headers={"X-RateLimit-Limit": value,
        "X-RateLimit-Remaining": value, "X-RateLimit-Reset": "1791072000"}))
    assert result.rate_limit.limit == expected and result.rate_limit.remaining == expected
    assert result.rate_limit.reset_epoch == 1791072000


@pytest.mark.parametrize("failure,error", [(HttpTransportFailure(E.TIMEOUT), E.TIMEOUT),
    (HttpTransportFailure(E.NETWORK_ERROR), E.NETWORK_ERROR),
    (HttpTransportFailure(E.TRANSPORT_SECURITY_ERROR), E.TRANSPORT_SECURITY_ERROR),
    (TimeoutError(DUMMY_KEY), E.TIMEOUT), (RuntimeError(DUMMY_KEY), E.NETWORK_ERROR)])
def test_transport_failure_never_retries_or_becomes_no_hit(failure, error, caplog):
    result, transport, _ = run(failure=failure)
    assert result.error is error and result.status is S.ERROR and len(transport.calls) == 1
    assert DUMMY_KEY not in repr(result) + caplog.text


@pytest.mark.parametrize("field,value", [("abuseConfidenceScore", -1), ("abuseConfidenceScore", 101),
    ("abuseConfidenceScore", True), ("abuseConfidenceScore", 1.5), ("abuseConfidenceScore", "75"),
    ("totalReports", -1), ("totalReports", 2**31), ("numDistinctUsers", -1),
    ("numDistinctUsers", True), ("numDistinctUsers", 2**31), ("lastReportedAt", "invalid"),
    ("lastReportedAt", "2026-10-03T00:00:00"), ("lastReportedAt", 17),
    ("lastReportedAt", "2027-01-01T00:00:00Z"), ("ipAddress", "1.1.1.1"),
    ("ipAddress", "2606:4700:4700::1111"), ("ipVersion", 6), ("ipVersion", True),
    ("isPublic", False), ("isWhitelisted", "true")])
def test_invalid_required_fields_rejected(field, value):
    result, _, _ = run(altered(**{field: value}))
    assert result.error is E.INVALID_RESPONSE and result.ip_facts is None


@pytest.mark.parametrize("field", ["ipAddress", "ipVersion", "isPublic", "abuseConfidenceScore",
                                  "totalReports", "numDistinctUsers", "lastReportedAt"])
def test_missing_required_fields_rejected(field):
    data = json.loads(fixture().body)
    del data["data"][field]
    result, _, _ = run(HttpResponse(200, {"content-type": "application/json"}, json.dumps(data).encode()))
    assert result.error is E.INVALID_RESPONSE


@pytest.mark.parametrize("body", [b"{", b"[]", b"null", b"{}", b'{"data":null}', b'{"data":[]}',
    b'{"data":{},"data":{}}', b'{"x":NaN}', b'{"errors":[{}]}', b"\xff",
    b"[" * 2000 + b"]" * 2000])
def test_strict_json_shapes_and_encoding(body):
    result, _, _ = run(HttpResponse(200, {"content-type": "application/json"}, body))
    assert result.error is E.INVALID_RESPONSE


@pytest.mark.parametrize("headers", [{}, {"content-type": "text/html"},
    {"content-type": "application/problem+json"}, {"content-type": "application/json", "content-encoding": "gzip"}])
def test_mime_policy(headers):
    result, _, _ = run(HttpResponse(200, headers, fixture().body))
    assert result.error is E.INVALID_RESPONSE


def test_extra_metadata_and_reports_not_retained_and_exact_body_boundary():
    response = altered(isp=DUMMY_KEY, domain="example.com", reports=[{"comment": DUMMY_KEY}], extra={"x": 1})
    body = response.body + b" " * (MAX_HTTP_BODY_BYTES - len(response.body))
    result, _, _ = run(HttpResponse(200, {"content-type": "application/json; charset=utf-8"}, body))
    assert result.status is S.HIT and DUMMY_KEY not in repr(result)
    too_large, _, _ = run(HttpResponse(200, {"content-type": "application/json"}, body + b" "))
    assert too_large.error is E.RESPONSE_TOO_LARGE


def test_ipv6_canonical_match_and_mismatch():
    selected = request(value="2606:4700:4700::1111")
    data = json.loads(fixture("hit_ipv6").body)
    data["data"]["ipAddress"] = "2606:4700:4700:0:0:0:0:1111"
    good, _, _ = run(HttpResponse(200, {"content-type": "application/json"}, json.dumps(data).encode()), selected=selected)
    assert good.status is S.HIT
    bad, _, _ = run(fixture("hit_ipv4"), selected=selected)
    assert bad.error is E.INVALID_RESPONSE


@pytest.mark.parametrize("fixture_name", ["hit_ipv4", "no_hit"])
def test_cache_roundtrip_restart_version_isolation_and_error_skip(tmp_path, fixture_name):
    database = SQLiteDatabase(tmp_path / "adapter.sqlite3")
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), (ABUSEIPDB_DESCRIPTOR,))
    result, _, _ = run(fixture(fixture_name))
    assert service.put(result, NOW).status is M.STORED
    key = ThreatIntelCacheKey.from_result(result)
    assert key.result_version == TI_RESULT_CONTRACT_VERSION == 2
    restarted = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), (ABUSEIPDB_DESCRIPTOR,))
    entry = restarted.get(key, NOW).entry
    assert entry.result.ip_facts == result.ip_facts and entry.result.status is result.status
    assert restarted.get(replace(key, result_version=1), NOW).entry is None
    assert restarted.get(replace(key, result_version=3), NOW).entry is None
    for error in (E.TIMEOUT, E.RATE_LIMITED, E.INVALID_RESPONSE):
        failed, _, _ = run(failure=HttpTransportFailure(error))
        assert restarted.put(failed, NOW).status is M.ERROR_SKIPPED
    assert restarted.get(key, NOW).entry == entry
    with database.connection() as connection:
        payload = connection.execute("SELECT normalized_result FROM threat_intel_cache").fetchone()[0]
        assert len(payload.encode()) < 4096 and DUMMY_KEY not in payload and '"reports"' not in payload
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 18


@pytest.mark.parametrize("fields", [dict(retry_after_seconds=-1), dict(limit=2**31),
                                    dict(remaining=True), dict(reset_epoch=253402300800)])
def test_operational_metadata_model_validation(fields):
    with pytest.raises(ValueError):
        ThreatIntelRateLimit(**fields)


def test_fixture_privacy_and_scheduler_only_runtime_wiring():
    for path in FIXTURES.glob("*.json"):
        assert DUMMY_KEY not in path.read_text() and '"Key"' not in path.read_text()
    source = Path(__file__).parents[3] / "src" / "netsentinel"
    assert "AbuseIpDbAdapter" not in (source / "application" / "engine.py").read_text()
    bootstrap = (source / "bootstrap.py").read_text()
    assert "create_threat_intel_scheduler" in bootstrap
    assert "ThreatIntelLookupService" not in bootstrap and ".query(" not in bootstrap
    module = (source / "infrastructure" / "abuseipdb.py").read_text()
    for absent in ("RiskEvidence", "AlertService", "Thread(", "firewall", "/report", "/blacklist", "/check-block"):
        assert absent not in module


@pytest.mark.parametrize("fields", [dict(mapping_version=2), dict(lookback_days=0),
    dict(abuse_confidence_score=True), dict(total_reports=-1), dict(distinct_users=2**31),
    dict(is_whitelisted="yes"), dict(last_reported_at=NOW.replace(tzinfo=None))])
def test_ip_facts_domain_is_typed_and_bounded(fields):
    result, _, _ = run()
    with pytest.raises((TypeError, ValueError)):
        replace(result.ip_facts, **fields)


@pytest.mark.parametrize("fields", [dict(status=S.NO_HIT), dict(status=S.ERROR, error=E.TIMEOUT),
    dict(rate_limit={"arbitrary": "blob"}), dict(ip_facts={"arbitrary": "blob"})])
def test_result_rejects_arbitrary_metadata_and_contradictory_facts(fields):
    result, _, _ = run()
    with pytest.raises((TypeError, ValueError)):
        replace(result, **fields)


@pytest.mark.parametrize("change", [dict(mapping_version=2), dict(total_reports=True),
    dict(last_reported_at="invalid"), dict(is_whitelisted="yes"), dict(extra="blob")])
def test_corrupt_cache_facts_not_interpreted_as_reputation(tmp_path, change):
    from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness
    database = SQLiteDatabase(tmp_path / "corrupt.sqlite3")
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), (ABUSEIPDB_DESCRIPTOR,))
    result, _, _ = run()
    assert service.put(result, NOW).status is M.STORED
    with database.connection() as connection:
        payload = json.loads(connection.execute("SELECT normalized_result FROM threat_intel_cache").fetchone()[0])
        payload["ip_facts"].update(change)
        connection.execute("UPDATE threat_intel_cache SET normalized_result=?",
                           (json.dumps(payload, sort_keys=True, separators=(",", ":")),))
    assert service.get(ThreatIntelCacheKey.from_result(result), NOW).freshness is ThreatIntelCacheFreshness.CORRUPT


def test_mapping_v2_keeps_old_cache_rows_separate(tmp_path):
    from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness
    database = SQLiteDatabase(tmp_path / "old.sqlite3")
    service = ThreatIntelCacheService(SQLiteThreatIntelCacheRepository(database), (ABUSEIPDB_DESCRIPTOR,))
    result, _, _ = run()
    assert service.put(result, NOW).status is M.STORED
    with database.connection() as connection:
        connection.execute("UPDATE threat_intel_cache SET result_version=1, format_version=1")
    assert service.get(ThreatIntelCacheKey.from_result(result), NOW).freshness is ThreatIntelCacheFreshness.MISS
    assert service.put(result, NOW).status is M.STORED
    with database.connection() as connection:
        assert connection.execute("SELECT result_version FROM threat_intel_cache ORDER BY result_version").fetchall()
        assert connection.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0] == 2
