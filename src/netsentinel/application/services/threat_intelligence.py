"""NS-084 explicit single-subject lookup and local consent commands.

No runtime provider is composed yet; no startup, history or engine hook exists.
Reading/saving consent never calls a provider. Each lookup reads current consent
so revocation (including reopening settings) denies subsequent requests.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from netsentinel.application.ports import ThreatIntelligenceProvider
from netsentinel.domain.threat_intelligence import (
    MAX_TI_PROVIDERS, ThreatIntelConsent, ThreatIntelDenial, ThreatIntelError,
    ThreatIntelProviderDescriptor, ThreatIntelQuery, ThreatIntelResult,
    ThreatIntelResultStatus, consent_denial, validate_consents,
)


def validate_descriptors(descriptors: tuple[ThreatIntelProviderDescriptor, ...]) -> None:
    if (not isinstance(descriptors, tuple) or len(descriptors) > MAX_TI_PROVIDERS
            or any(not isinstance(d, ThreatIntelProviderDescriptor) for d in descriptors)
            or len({d.provider for d in descriptors}) != len(descriptors)):
        raise ValueError("provider registry must be bounded, typed and unique")


class ThreatIntelConsentService:
    """Local settings boundary; knows descriptors, never provider ports/secrets."""

    def __init__(self, descriptors: tuple[ThreatIntelProviderDescriptor, ...],
                 read: Callable[[], tuple[ThreatIntelConsent, ...]],
                 save: Callable[[tuple[ThreatIntelConsent, ...]], None]) -> None:
        validate_descriptors(descriptors)
        self.descriptors = descriptors
        self._read = read
        self._save = save

    def current(self) -> tuple[ThreatIntelConsent, ...]:
        try:
            consents = self._read()
            validate_consents(consents)
        except (OSError, TypeError, ValueError):
            return ()
        return tuple(c for c in consents if any(
            d.provider == c.provider and c.data_type in d.supported_data_types
            for d in self.descriptors
        ))

    def save(self, consents: tuple[ThreatIntelConsent, ...]) -> None:
        validate_consents(consents)
        if any(not any(d.provider == c.provider and c.data_type in d.supported_data_types
                       for d in self.descriptors) for c in consents):
            raise ValueError("unsupported provider consent")
        self._save(consents)


@dataclass(frozen=True, slots=True)
class ThreatIntelLookupOutcome:
    denial: ThreatIntelDenial | None = None
    result: ThreatIntelResult | None = None

    def __post_init__(self) -> None:
        if (self.denial is None) == (self.result is None):
            raise ValueError("lookup has either a policy denial or provider result")


class ThreatIntelLookupService:
    """Policy first, then exactly one selected-subject provider call.

    Deliberately absent from desktop/engine composition until later M15 tasks.
    NS-084 validates this boundary with interchangeable provider fakes.
    """

    def __init__(self, providers: tuple[ThreatIntelligenceProvider, ...],
                 read_consents: Callable[[], tuple[ThreatIntelConsent, ...]],
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        validate_descriptors(tuple(p.descriptor for p in providers))
        self._providers = {p.descriptor.provider: p for p in providers}
        self._read_consents = read_consents
        self._clock = clock

    def lookup_selected(self, request: ThreatIntelQuery) -> ThreatIntelLookupOutcome:
        if not isinstance(request, ThreatIntelQuery):
            raise TypeError("lookup requires a validated single-subject query")
        provider = self._providers.get(request.provider)
        try:
            consents = self._read_consents()
            denial = consent_denial(request, provider.descriptor if provider else None, consents)
        except (OSError, TypeError, ValueError):
            denial = ThreatIntelDenial.NO_CONSENT
        if denial is not None:
            return ThreatIntelLookupOutcome(denial=denial)
        assert provider is not None
        try:
            result = provider.query(request)
        except Exception:
            # Do not retain/log raw exception text, subjects or credentials.
            result = self._error(request, ThreatIntelError.UNAVAILABLE)
        if not isinstance(result, ThreatIntelResult) or result.query != request:
            result = self._error(request, ThreatIntelError.INVALID_RESPONSE)
        return ThreatIntelLookupOutcome(result=result)

    def _error(self, query: ThreatIntelQuery, error: ThreatIntelError) -> ThreatIntelResult:
        return ThreatIntelResult(query, ThreatIntelResultStatus.ERROR,
                                 max(self._clock(), query.queried_at), error)
