"""NS-028 mapping and clock boundary with a fake repository."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.alerts import AlertService
from netsentinel.domain.alerts import (
    AlertCandidate, ArpIdentityConflictDetected, ArpIdentityEvidence,
    ArpIdentityReason, ArpIdentityRule, ArpRiskAssessment,
    ArpScoreComponent, ArpScoreRule, NewDeviceDetected,
)
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding
from netsentinel.domain.observations import MacAddress


NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
NETWORK = "a" * 64


class FakeRepository:
    def __init__(self):
        self.calls = []

    def record(self, candidate, now, rate_window):
        self.calls.append((candidate, now, rate_window))
        return candidate, True


def test_arp_assessment_mapping_preserves_severity_confidence_and_breakdown():
    old = MacAddress("00:11:22:33:44:55")
    new = MacAddress("00:11:22:33:44:66")
    source = ArpIdentityConflictDetected(
        ArpIdentityRule.IP_MAC_CONFLICT, ArpIdentityReason.RECENT_SENDER_CONFLICT,
        ArpIdentityEvidence(NETWORK, "192.168.1.20", old, new, NOW - timedelta(seconds=1), NOW),
        "low", "low",
    )
    parts = (ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2),
             ArpScoreComponent(ArpScoreRule.REPEATED_OBSERVATION, 1))
    assessment = ArpRiskAssessment(source, NOW, NOW + timedelta(seconds=2), 3, parts, 3, "moderate")
    fake = FakeRepository()
    candidate, notify = AlertService(fake, clock=lambda: NOW + timedelta(seconds=3)).record(assessment)
    assert notify and isinstance(candidate, AlertCandidate)
    assert candidate.fingerprint == source.event_fingerprint
    assert (candidate.severity, candidate.confidence) == ("low", "moderate")
    assert (candidate.evidence.score, candidate.evidence.breakdown, candidate.evidence.observation_count) == (3, parts, 3)
    assert fake.calls[0][2] == timedelta(seconds=120)


def test_new_device_mapping_is_informational_and_clock_is_utc():
    mac = MacAddress("00:11:22:33:44:55")
    device = DeviceIdentity(NETWORK, mac, NOW, NOW)
    binding = IdentityBinding(NETWORK, mac, "192.168.1.30", NOW, NOW)
    event = NewDeviceDetected(device, binding, NOW)
    fake = FakeRepository()
    candidate, _ = AlertService(fake, clock=lambda: NOW).record(event)
    assert (candidate.rule_id, candidate.severity, candidate.confidence) == ("new_device", "info", "passive_observation")
    assert candidate.entity_id == str(device.device_id)
    with pytest.raises(ValueError):
        AlertService(fake, clock=lambda: NOW.replace(tzinfo=None)).record(event)
    assert len(fake.calls) == 1
