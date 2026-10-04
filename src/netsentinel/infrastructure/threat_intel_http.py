"""NS-086 one fixed HTTPS request, verified TLS, no redirects/retries/proxies.

Only transient request/response objects contain headers/body; repr hides them.
No raw exception text crosses this boundary. Tests inject a fake connection.
"""

from dataclasses import dataclass, field
import http.client
from ipaddress import ip_address
import math
import ssl
from time import monotonic
from typing import Protocol
from urllib.parse import parse_qs, urlsplit

from netsentinel.domain.threat_intelligence import ThreatIntelError


ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
HTTP_TIMEOUT_SECONDS = 8.0
MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_SECRET_LENGTH = 4096
_RESPONSE_HEADERS = frozenset(("content-type", "content-length", "content-encoding",
                              "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
                              "x-ratelimit-reset"))


def valid_secret(value: object) -> bool:
    # Validate header safety, not an invented provider-specific key format.
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= MAX_SECRET_LENGTH
            and all(32 <= ord(c) < 127 for c in value))


@dataclass(frozen=True, slots=True)
class HttpRequest:
    url: str = field(repr=False)
    headers: dict[str, str] = field(repr=False)
    timeout: float = HTTP_TIMEOUT_SECONDS
    max_body_bytes: int = MAX_HTTP_BODY_BYTES
    method: str = "GET"

    def validate(self) -> None:
        parts = urlsplit(self.url)
        params = parse_qs(parts.query, strict_parsing=True)
        if (self.method != "GET" or parts.scheme != "https"
                or parts.netloc != "api.abuseipdb.com" or parts.path != "/api/v2/check"
                or parts.fragment or set(params) != {"ipAddress", "maxAgeInDays"}
                or params["maxAgeInDays"] != ["30"] or len(params["ipAddress"]) != 1
                or set(self.headers) != {"Accept", "Key"}
                or self.headers["Accept"] != "application/json"
                or not valid_secret(self.headers["Key"])
                or type(self.timeout) not in (int, float) or not math.isfinite(self.timeout)
                or not 0 < self.timeout <= HTTP_TIMEOUT_SECONDS
                or type(self.max_body_bytes) is not int
                or not 0 < self.max_body_bytes <= MAX_HTTP_BODY_BYTES):
            raise ValueError("invalid bounded provider request")
        address = ip_address(params["ipAddress"][0])
        if (str(address) != params["ipAddress"][0] or not address.is_global
                or address.is_multicast or address.is_reserved or "%" in str(address)):
            raise ValueError("invalid external IP request")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    body: bytes = field(default=b"", repr=False)


class HttpTransportFailure(Exception):
    def __init__(self, category: ThreatIntelError):
        self.category = category
        super().__init__(category.value)


class HttpTransport(Protocol):
    def send(self, request: HttpRequest) -> HttpResponse: ...


class StdlibHttpTransport:
    def send(self, request: HttpRequest) -> HttpResponse:
        connection = None
        try:
            request.validate()
            deadline = monotonic() + request.timeout
            # Fixed authority; HTTPSConnection never follows redirects and does
            # not consult proxy environment variables. Default TLS verifies certs.
            connection = http.client.HTTPSConnection("api.abuseipdb.com", timeout=request.timeout,
                                                     context=ssl.create_default_context())
            parts = urlsplit(request.url)
            connection.request("GET", parts.path + "?" + parts.query, headers=request.headers)
            response = connection.getresponse()
            with response:
                headers = {name.lower(): value for name, value in response.getheaders()
                           if name.lower() in _RESPONSE_HEADERS}
                # Redirects are rejected without consuming/following Location.
                if 300 <= response.status < 400:
                    return HttpResponse(response.status, headers)
                length = headers.get("content-length")
                expected = None
                if length is not None:
                    if len(length) > 20 or not length.isascii() or not length.isdecimal():
                        raise HttpTransportFailure(ThreatIntelError.INVALID_RESPONSE)
                    expected = int(length)
                    if expected > request.max_body_bytes:
                        if response.status != 200:
                            return HttpResponse(response.status, headers)
                        raise HttpTransportFailure(ThreatIntelError.RESPONSE_TOO_LARGE)
                chunks: list[bytes] = []
                size = 0
                while True:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise HttpTransportFailure(ThreatIntelError.TIMEOUT)
                    if connection.sock is not None:
                        connection.sock.settimeout(remaining)
                    # read1 returns after one buffered/socket read: slow-drip
                    # bodies cannot reset the overall read deadline indefinitely.
                    chunk = response.read1(min(4096, request.max_body_bytes + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > request.max_body_bytes:
                        if response.status != 200:
                            return HttpResponse(response.status, headers)
                        raise HttpTransportFailure(ThreatIntelError.RESPONSE_TOO_LARGE)
                    chunks.append(chunk)
                if expected is not None and size != expected:
                    raise HttpTransportFailure(ThreatIntelError.INVALID_RESPONSE)
                return HttpResponse(response.status, headers, b"".join(chunks))
        except HttpTransportFailure:
            raise
        except TimeoutError:
            raise HttpTransportFailure(ThreatIntelError.TIMEOUT) from None
        except ssl.SSLError:
            raise HttpTransportFailure(ThreatIntelError.TRANSPORT_SECURITY_ERROR) from None
        except (OSError, http.client.HTTPException):
            raise HttpTransportFailure(ThreatIntelError.NETWORK_ERROR) from None
        except (TypeError, ValueError):
            raise HttpTransportFailure(ThreatIntelError.INVALID_REQUEST) from None
        finally:
            if connection is not None:
                connection.close()
