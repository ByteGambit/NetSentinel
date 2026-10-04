"""NS-084 explicit single-subject lookup and local consent commands.

NS-087 uses a memory consent snapshot; no startup/history/engine lookup exists.
Reading/saving consent never calls a provider. Each lookup reads current consent
so revocation (including reopening settings) denies subsequent requests.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock

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
        self._snapshot: tuple[ThreatIntelConsent, ...] = ()
        self._lock = RLock()
        self._on_change: Callable[[], None] | None = None

    def snapshot(self) -> tuple[ThreatIntelConsent, ...]:
        """Memory-only current grants for NS-087 admission/execution gates."""
        with self._lock:
            return self._snapshot

    def bind_scheduler_wakeup(self, callback: Callable[[], None]) -> None:
        """One component notification slot; no per-request subscriber list."""
        if not callable(callback):
            raise TypeError("scheduler notification must be callable")
        with self._lock:
            self._on_change = callback

    def _update_snapshot(self, consents: tuple[ThreatIntelConsent, ...]) -> None:
        with self._lock:
            changed = consents != self._snapshot
            self._snapshot = consents
            callback = self._on_change if changed else None
        if callback is not None:
            try:
                callback()
            except Exception:
                pass  # optional worker failure must not break saved consent

    def current(self) -> tuple[ThreatIntelConsent, ...]:
        try:
            consents = self._read()
            validate_consents(consents)
        except (OSError, TypeError, ValueError):
            consents = ()
        filtered = tuple(c for c in consents if any(
            d.provider == c.provider and c.data_type in d.supported_data_types
            for d in self.descriptors
        ))
        self._update_snapshot(filtered)
        return filtered

    def save(self, consents: tuple[ThreatIntelConsent, ...]) -> None:
        validate_consents(consents)
        if any(not any(d.provider == c.provider and c.data_type in d.supported_data_types
                       for d in self.descriptors) for c in consents):
            raise ValueError("unsupported provider consent")
        self._save(consents)
        self._update_snapshot(consents)


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
