"""NS-086 AbuseIPDB API v2 CHECK-only mapping v1; no composition or scheduling."""

from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import ip_address
import json
from urllib.parse import urlencode

from netsentinel.application.ports import ThreatIntelSecretStore
from netsentinel.domain.threat_intelligence import (
    ThreatIntelDataType, ThreatIntelError as E, ThreatIntelIpFacts,
    ThreatIntelProviderDescriptor, ThreatIntelProviderId, ThreatIntelQuery,
    ThreatIntelRateLimit, ThreatIntelResult, ThreatIntelResultStatus as S, consent_denial,
)
from netsentinel.infrastructure.threat_intel_http import (
    ABUSEIPDB_ENDPOINT, MAX_HTTP_BODY_BYTES, HttpRequest, HttpResponse,
    HttpTransport, HttpTransportFailure, StdlibHttpTransport, valid_secret,
)


ABUSEIPDB_MAPPING_VERSION = 1
ABUSEIPDB_LOOKBACK_DAYS = 30
ABUSEIPDB_DESCRIPTOR = ThreatIntelProviderDescriptor(
    ThreatIntelProviderId("abuseipdb"), "AbuseIPDB", frozenset({ThreatIntelDataType.IP_REPUTATION}),
)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError("nonfinite response number")


def _json(response: HttpResponse) -> dict:
    mime = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if (mime != "application/json"
            or response.headers.get("content-encoding", "identity").lower() != "identity"):
        raise ValueError("unexpected provider content type/encoding")
    data = json.loads(response.body.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
    if not isinstance(data, dict):
        raise ValueError("unexpected response shape")
    return data


def _integer(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid provider number")
    return value


def _header_integer(value: str | None, maximum: int, *, clamp: bool = False) -> int | None:
    if value is None or len(value) > 20 or not value.isascii() or not value.isdecimal():
        return None
    number = int(value)
    return min(number, maximum) if clamp else number if number <= maximum else None


def _rate(headers: dict[str, str]) -> ThreatIntelRateLimit:
    return ThreatIntelRateLimit(
        _header_integer(headers.get("retry-after"), 86400, clamp=True),
        _header_integer(headers.get("x-ratelimit-limit"), 2**31 - 1),
        _header_integer(headers.get("x-ratelimit-remaining"), 2**31 - 1),
        _header_integer(headers.get("x-ratelimit-reset"), 253402300799),
    )


def _status_error(status: int) -> E | None:
    if status == 200:
        return None
    if 300 <= status < 400:
        return E.REDIRECT_REJECTED
    return {401: E.AUTHENTICATION, 403: E.AUTHENTICATION, 402: E.SUBSCRIPTION_RESTRICTED,
            422: E.INVALID_REQUEST, 429: E.RATE_LIMITED}.get(
                status, E.UNAVAILABLE if 500 <= status <= 599 else E.HTTP_ERROR)


class AbuseIpDbAdapter:
    descriptor = ABUSEIPDB_DESCRIPTOR
    mapping_version = ABUSEIPDB_MAPPING_VERSION

    def __init__(self, secrets: ThreatIntelSecretStore, transport: HttpTransport | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._secrets = secrets
        self._transport = transport if transport is not None else StdlibHttpTransport()
        self._clock = clock

    def query(self, request: ThreatIntelQuery) -> ThreatIntelResult:
        # Current persisted consent is checked by the application service. The
        # adapter also rejects unsupported/local/automatic/ungranted direct calls.
        if consent_denial(request, self.descriptor, (request.consent,) if request.consent else ()):
            return self._result(request, error=E.UNSUPPORTED)
        try:
            secret = self._secrets.get_secret(self.descriptor.provider)
        except Exception:
            return self._result(request, error=E.CREDENTIAL_UNAVAILABLE)
        if not valid_secret(secret):
            return self._result(request, error=E.CREDENTIAL_UNAVAILABLE)
        assert isinstance(secret, str)
        http_request = HttpRequest(
            ABUSEIPDB_ENDPOINT + "?" + urlencode({"ipAddress": request.subject.value,
                                                 "maxAgeInDays": ABUSEIPDB_LOOKBACK_DAYS}),
            {"Accept": "application/json", "Key": secret},
        )
        try:
            response = self._transport.send(http_request)
        except HttpTransportFailure as failure:
            return self._result(request, error=failure.category)
        except TimeoutError:
            return self._result(request, error=E.TIMEOUT)
        except Exception:
            return self._result(request, error=E.NETWORK_ERROR)
        # Defend the semantic boundary even when an injected transport bypasses caps.
        headers = {k.lower(): v for k, v in response.headers.items()}
        response = HttpResponse(response.status, headers, response.body)
        rate = _rate(headers)
        error = _status_error(response.status)
        if error is not None:
            # Status is authoritative even for HTML/malformed provider errors.
            # Inspect only the bounded errors-array shape; never expose detail.
            if len(response.body) <= MAX_HTTP_BODY_BYTES:
                try:
                    errors = _json(response).get("errors")
                    if not isinstance(errors, list) or any(not isinstance(e, dict) for e in errors):
                        raise ValueError("invalid provider errors shape")
                except (ValueError, TypeError, RecursionError):
                    pass
            return self._result(request, error=error, rate=rate)
        if len(response.body) > MAX_HTTP_BODY_BYTES:
            return self._result(request, error=E.RESPONSE_TOO_LARGE, rate=rate)
        try:
            data = _json(response)
            if "errors" in data:
                raise ValueError("provider application error")
            facts = self._facts(request, data["data"])
            status = S.NO_HIT if facts.total_reports == 0 and facts.last_reported_at is None else S.HIT
            return self._result(request, status=status, facts=facts, rate=rate)
        except (KeyError, ValueError, TypeError, OverflowError, RecursionError):
            return self._result(request, error=E.INVALID_RESPONSE, rate=rate)

    def _facts(self, request: ThreatIntelQuery, data: object) -> ThreatIntelIpFacts:
        if not isinstance(data, dict) or not isinstance(data.get("ipAddress"), str):
            raise ValueError("invalid IP response")
        address = ip_address(data["ipAddress"])
        if (str(address) != request.subject.value or data["isPublic"] is not True
                or type(data["ipVersion"]) is not int or data["ipVersion"] != address.version):
            raise ValueError("response subject mismatch")
        timestamp = data["lastReportedAt"]
        reported = None
        if timestamp is not None:
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                raise ValueError("invalid report time")
            reported = datetime.fromisoformat(timestamp)
            if reported.tzinfo is None:
                raise ValueError("naive report time")
            reported = reported.astimezone(UTC)
        return ThreatIntelIpFacts(
            self.mapping_version, ABUSEIPDB_LOOKBACK_DAYS,
            _integer(data["abuseConfidenceScore"], 100),
            _integer(data["totalReports"], 2**31 - 1),
            _integer(data["numDistinctUsers"], 2**31 - 1), reported, data.get("isWhitelisted"),
        )

    def _result(self, request: ThreatIntelQuery, *, status: S = S.ERROR,
                error: E | None = None, facts: ThreatIntelIpFacts | None = None,
                rate: ThreatIntelRateLimit | None = None) -> ThreatIntelResult:
        return ThreatIntelResult(request, status, max(self._clock(), request.queried_at),
                                 error, facts, rate)
