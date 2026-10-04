"""Two independent offline providers implement the same NS-084 port."""

from datetime import UTC, datetime
from uuid import uuid4

from netsentinel.domain.threat_intelligence import (
    ThreatIntelConsent, ThreatIntelDataType, ThreatIntelError,
    ThreatIntelProviderDescriptor, ThreatIntelProviderId, ThreatIntelQuery,
    ThreatIntelResult, ThreatIntelResultStatus, ThreatIntelSubject,
    ThreatIntelSubjectKind, ThreatIntelTrigger,
)


NOW = datetime(2026, 10, 4, tzinfo=UTC)
A = ThreatIntelProviderId("fake_provider_a")
B = ThreatIntelProviderId("fake_provider_b")
DESCRIPTORS = tuple(ThreatIntelProviderDescriptor(p, p.value, frozenset(ThreatIntelDataType)) for p in (A, B))


class FakeProviderA:
    descriptor = DESCRIPTORS[0]

    def __init__(self, status=ThreatIntelResultStatus.HIT):
        self.status = status
        self.calls: list[ThreatIntelQuery] = []

    def query(self, request: ThreatIntelQuery) -> ThreatIntelResult:
        self.calls.append(request)
        return ThreatIntelResult(request, self.status, NOW,
                                 ThreatIntelError.TIMEOUT if self.status is ThreatIntelResultStatus.ERROR else None)


class FakeProviderB:
    descriptor = DESCRIPTORS[1]

    def __init__(self):
        self.calls: list[ThreatIntelQuery] = []

    def query(self, request: ThreatIntelQuery) -> ThreatIntelResult:
        self.calls.append(request)
        return ThreatIntelResult(request, ThreatIntelResultStatus.NO_HIT, NOW)


def grant(provider=A, data_type=ThreatIntelDataType.IP_REPUTATION,
          trigger=ThreatIntelTrigger.MANUAL_SELECTED):
    return ThreatIntelConsent(uuid4(), provider, data_type, trigger)


def query(provider=A, data_type=ThreatIntelDataType.IP_REPUTATION,
          value=None, consent=None, trigger=ThreatIntelTrigger.MANUAL_SELECTED):
    kind = data_type.subject_kind
    value = value if value is not None else {
        ThreatIntelSubjectKind.IP: "8.8.8.8",
        ThreatIntelSubjectKind.DOMAIN: "example.com",
        ThreatIntelSubjectKind.HASH: "a" * 64,
    }[kind]
    from netsentinel.domain.threat_intelligence import HashAlgorithm
    subject = ThreatIntelSubject(kind, value, HashAlgorithm.SHA256 if kind is ThreatIntelSubjectKind.HASH else None)
    return ThreatIntelQuery(uuid4(), provider, subject, data_type, trigger, consent, NOW)
