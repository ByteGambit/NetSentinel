"""Optional one-IP CHECK smoke; never runs in default/CI suites."""

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from netsentinel.application.services.threat_intelligence import ThreatIntelLookupService
from netsentinel.domain.threat_intelligence import (
    ThreatIntelConsent, ThreatIntelDataType, ThreatIntelQuery, ThreatIntelSubject,
    ThreatIntelSubjectKind, ThreatIntelTrigger, ThreatIntelResultStatus, externally_eligible,
)
from netsentinel.infrastructure.abuseipdb import ABUSEIPDB_DESCRIPTOR, AbuseIpDbAdapter


@pytest.mark.live_threat_intel
def test_explicit_live_check_contract():
    if os.environ.get("NETSENTINEL_LIVE_THREAT_INTEL") != "1":
        pytest.skip("Explicit live-provider consent is required")
    value = os.environ.get("NETSENTINEL_ABUSEIPDB_TEST_IP")
    if not value or not os.environ.get("NETSENTINEL_ABUSEIPDB_API_KEY"):
        pytest.skip("Selected public IP and private credential are required")
    subject = ThreatIntelSubject(ThreatIntelSubjectKind.IP, value)
    if not externally_eligible(subject):
        pytest.skip("Live CHECK requires an eligible public IP")

    class EnvironmentSecrets:
        def get_secret(self, provider):
            return os.environ.get("NETSENTINEL_ABUSEIPDB_API_KEY")

    provider = ABUSEIPDB_DESCRIPTOR.provider
    consent = ThreatIntelConsent(uuid4(), provider, ThreatIntelDataType.IP_REPUTATION)
    request = ThreatIntelQuery(uuid4(), provider, subject, consent.data_type,
                               ThreatIntelTrigger.MANUAL_SELECTED, consent, datetime.now(UTC))
    service = ThreatIntelLookupService((AbuseIpDbAdapter(EnvironmentSecrets()),), lambda: (consent,))
    outcome = service.lookup_selected(request)
    assert outcome.denial is None
    assert outcome.result.query == request
    assert outcome.result.status in tuple(ThreatIntelResultStatus)
