"""Offline stdlib transport tests use fake sockets/responses, never internet."""

from dataclasses import replace
import http.client
import ssl
from urllib.parse import urlencode

import pytest

from netsentinel.domain.threat_intelligence import ThreatIntelError as E
from netsentinel.infrastructure.threat_intel_http import (
    ABUSEIPDB_ENDPOINT, HTTP_TIMEOUT_SECONDS, MAX_HTTP_BODY_BYTES,
    HttpRequest, HttpTransportFailure, StdlibHttpTransport,
)
from tests.unit.infrastructure.test_abuseipdb import DUMMY_KEY, fixture


class Stream:
    def __init__(self, body, headers=(), status=200):
        self.body = body
        self.status = status
        self.headers = headers
        self.read_sizes = []
        self.closed = False

    def getheaders(self):
        return self.headers

    def read1(self, size):
        self.read_sizes.append(size)
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class Socket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class Connection:
    def __init__(self, stream, failure=None):
        self.stream = stream
        self.failure = failure
        self.sock = Socket()
        self.closed = False
        self.requests = []

    def request(self, method, path, headers):
        assert method == "GET" and headers["Key"] == DUMMY_KEY
        self.requests.append((method, path, {"Key": "<redacted>", "Accept": headers["Accept"]}))
        if self.failure:
            raise self.failure

    def getresponse(self):
        return self.stream

    def close(self):
        self.closed = True


def request():
    return HttpRequest(ABUSEIPDB_ENDPOINT + "?" + urlencode({"ipAddress": "8.8.8.8", "maxAgeInDays": 30}),
                       {"Accept": "application/json", "Key": DUMMY_KEY})


def install(monkeypatch, stream, failure=None):
    connection = Connection(stream, failure)
    calls = []

    def factory(host, timeout, context):
        assert host == "api.abuseipdb.com" and 0 < timeout <= HTTP_TIMEOUT_SECONDS
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        calls.append(host)
        return connection

    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    return connection, calls


def test_verified_tls_fixed_host_header_key_no_proxy_or_redirect(monkeypatch):
    stream = Stream(fixture().body, [("Content-Type", "application/json"), ("Location", "https://evil.invalid")])
    connection, calls = install(monkeypatch, stream)
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.invalid")
    response = StdlibHttpTransport().send(request())
    assert response.body == fixture().body and "location" not in response.headers
    assert calls == ["api.abuseipdb.com"] and connection.closed and stream.closed
    assert len(connection.requests) == 1 and DUMMY_KEY not in repr(response) + repr(request())
    assert all(0 < t <= 8 for t in connection.sock.timeouts)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_returned_without_follow_or_header_forwarding(monkeypatch, status):
    stream = Stream(b"unused", [("Location", "https://evil.invalid"), ("Content-Length", "999999")], status)
    connection, calls = install(monkeypatch, stream)
    response = StdlibHttpTransport().send(request())
    assert response.status == status and len(calls) == len(connection.requests) == 1
    assert stream.read_sizes == []


@pytest.mark.parametrize("length", [None, str(MAX_HTTP_BODY_BYTES + 1)])
def test_large_error_body_does_not_hide_rate_limit_status(monkeypatch, length):
    stream = Stream(b"x" * (MAX_HTTP_BODY_BYTES + 1), [("Content-Length", length)] if length else [], 429)
    install(monkeypatch, stream)
    response = StdlibHttpTransport().send(request())
    assert response.status == 429 and response.body == b""
    if length:
        assert stream.read_sizes == []


def test_oversized_content_length_not_read(monkeypatch):
    stream = Stream(b"unused", [("Content-Length", str(MAX_HTTP_BODY_BYTES + 1))])
    connection, _ = install(monkeypatch, stream)
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is E.RESPONSE_TOO_LARGE
    assert not stream.read_sizes and stream.closed and connection.closed


@pytest.mark.parametrize("length", [None, "10"])
def test_stream_read_cap_without_trusting_length(monkeypatch, length):
    stream = Stream(b"x" * (MAX_HTTP_BODY_BYTES + 10000), [("Content-Length", length)] if length else [])
    connection, _ = install(monkeypatch, stream)
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is E.RESPONSE_TOO_LARGE and connection.closed
    assert sum(stream.read_sizes) <= MAX_HTTP_BODY_BYTES + 1
    assert len(stream.body) == 9999


def test_exact_body_cap_accepted(monkeypatch):
    stream = Stream(b"x" * MAX_HTTP_BODY_BYTES, [("Content-Length", str(MAX_HTTP_BODY_BYTES))])
    install(monkeypatch, stream)
    assert len(StdlibHttpTransport().send(request()).body) == MAX_HTTP_BODY_BYTES
    assert max(stream.read_sizes) <= 4096


@pytest.mark.parametrize("length", ["-1", "invalid", "9" * 100, "١"])
def test_malformed_content_length_rejected(monkeypatch, length):
    stream = Stream(b"", [("Content-Length", length)])
    install(monkeypatch, stream)
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is E.INVALID_RESPONSE and not stream.read_sizes


def test_truncated_content_length_rejected(monkeypatch):
    install(monkeypatch, Stream(b"short", [("Content-Length", "100")]))
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is E.INVALID_RESPONSE


@pytest.mark.parametrize("failure,error", [(TimeoutError(DUMMY_KEY), E.TIMEOUT),
    (OSError(DUMMY_KEY), E.NETWORK_ERROR), (ssl.SSLError(DUMMY_KEY), E.TRANSPORT_SECURITY_ERROR),
    (http.client.IncompleteRead(b"bad"), E.NETWORK_ERROR)])
def test_failures_sanitized_once_close_connection(monkeypatch, failure, error, caplog):
    connection, calls = install(monkeypatch, Stream(b""), failure)
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is error and DUMMY_KEY not in str(caught.value) + repr(caught.value) + caplog.text
    assert connection.closed and len(calls) == 1


def test_monotonic_read_deadline(monkeypatch):
    from netsentinel.infrastructure import threat_intel_http
    connection, _ = install(monkeypatch, Stream(b"data"))
    times = iter([0, 9])
    monkeypatch.setattr(threat_intel_http, "monotonic", lambda: next(times))
    with pytest.raises(HttpTransportFailure) as caught:
        StdlibHttpTransport().send(request())
    assert caught.value.category is E.TIMEOUT and connection.closed


@pytest.mark.parametrize("url", ["http://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30",
    "https://evil.invalid/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30",
    "https://api.abuseipdb.com/api/v2/report?ipAddress=8.8.8.8&maxAgeInDays=30",
    ABUSEIPDB_ENDPOINT + "?ipAddress=8.8.8.8&maxAgeInDays=30&verbose=1",
    ABUSEIPDB_ENDPOINT + "?ipAddress=10.0.0.1&maxAgeInDays=30",
    ABUSEIPDB_ENDPOINT + "?ipAddress=8.8.8.8&ipAddress=1.1.1.1&maxAgeInDays=30",
    ABUSEIPDB_ENDPOINT + "?ipAddress=8.8.8.8%26Key%3Devil&maxAgeInDays=30",
    ABUSEIPDB_ENDPOINT + "?ipAddress=8.8.8.8&maxAgeInDays=30#bad"])
def test_invalid_endpoint_or_query_never_connects(monkeypatch, url):
    _, calls = install(monkeypatch, Stream(b""))
    with pytest.raises(HttpTransportFailure):
        StdlibHttpTransport().send(replace(request(), url=url))
    assert calls == []


@pytest.mark.parametrize("changes", [dict(timeout=0), dict(timeout=float("inf")),
    dict(timeout=9), dict(max_body_bytes=65537), dict(method="POST"),
    dict(headers={"Accept": "application/json", "Key": "x\r\nInjected"})])
def test_invalid_limits_or_headers_never_connects(monkeypatch, changes):
    _, calls = install(monkeypatch, Stream(b""))
    with pytest.raises(HttpTransportFailure):
        StdlibHttpTransport().send(replace(request(), **changes))
    assert calls == []
