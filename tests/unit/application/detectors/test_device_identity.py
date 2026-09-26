"""NS-040 conservative, scoped identity decisions without capture or SQLite."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from netsentinel.application.detectors.device_identity import (
    CONTEXT_RULE, IP_CHURN_RULE, MAC_RULE, MAX_STATES, DeviceIdentityChangeDetector,
)
from netsentinel.domain.devices import (
    DeviceIdentity, DeviceProfile, DeviceTrust, IdentityBinding, NetworkContext,
    NetworkInterfaceKind,
)
from netsentinel.domain.observations import MacAddress


T0 = datetime(2026, 9, 26, 12, tzinfo=UTC)
EXPECTED = MacAddress("00:11:22:33:44:55")
OTHER = MacAddress("00:11:22:33:44:66")
PRIVATE = MacAddress("02:11:22:33:44:77")


def context(name="A"):
    return NetworkContext(name, 1, name, NetworkInterfaceKind.WIFI,
                          "192.168.1.10", "192.168.1.0/24", None, (), T0)


def profile(ctx, macs=(EXPECTED,), ips=("192.168.1.20",), trust=DeviceTrust.TRUSTED):
    return DeviceProfile(uuid4(), ctx.fingerprint, "Laptop", "private note", trust,
                         T0, T0, T0 if trust is not DeviceTrust.UNKNOWN else None, macs, ips)


def observed(ctx, mac, ip, seconds, *, last_seconds=None):
    at = T0 + timedelta(seconds=seconds)
    last = T0 + timedelta(seconds=last_seconds if last_seconds is not None else seconds)
    return DeviceIdentity(ctx.fingerprint, mac, at, last), IdentityBinding(ctx.fingerprint, mac, ip, at, last), at


def setup(ctx, owner, members=(), history=()):
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((owner, tuple(members), tuple(history)),), T0 + timedelta(minutes=1))
    return detector


def test_empty_baseline_and_other_network_are_silent():
    ctx = context()
    device, binding, at = observed(ctx, OTHER, "192.168.1.20", 10)
    detector = setup(ctx, profile(ctx, macs=(), ips=()), (device.device_id,))
    assert detector.observe(ctx, device, binding, at) == ()
    detector.replace_snapshot(context("B").fingerprint, (), at)
    assert detector.tracked_states == 0
    assert detector.observe(context("B"), *observed(context("B"), OTHER, "192.168.1.20", 10)) == ()


def test_expected_mac_set_and_locally_administered_mac_are_normal():
    ctx = context()
    for expected in (EXPECTED, PRIVATE):
        device, binding, at = observed(ctx, expected, "192.168.1.20", 10)
        detector = setup(ctx, profile(ctx, macs=(EXPECTED, PRIVATE)), (device.device_id,))
        assert detector.observe(ctx, device, binding, at) == ()
    device, binding, at = observed(ctx, EXPECTED, "192.168.1.99", 11)
    detector = setup(ctx, profile(ctx, macs=(EXPECTED,), ips=()), (device.device_id,))
    assert detector.observe(ctx, device, binding, at) == ()


def test_unknown_mac_at_expected_ip_has_bounded_evidence_and_stable_identity():
    ctx = context()
    owner = profile(ctx)
    old, old_binding, _ = observed(ctx, EXPECTED, "192.168.1.20", 5)
    detector = setup(ctx, owner, (old.device_id,), (old_binding,))
    device, binding, at = observed(ctx, OTHER, "192.168.1.20", 10)
    (candidate,) = detector.observe(ctx, device, binding, at)
    assert candidate.rule_id == MAC_RULE
    assert candidate.severity == "medium" and candidate.confidence == "moderate"
    assert candidate.evidence.expected_mac == EXPECTED
    assert dict(candidate.evidence.details)["confidence_basis"] == "recent_expected_binding"
    assert "private note" not in str(candidate)
    assert len(candidate.evidence.details) <= 8
    renamed = replace(owner, label="Renamed", note="new note", updated_at=T0 + timedelta(seconds=6))
    detector.replace_snapshot(ctx.fingerprint, ((renamed, (old.device_id,), (old_binding,)),), T0 + timedelta(seconds=11))
    (renamed_candidate,) = detector.observe(ctx, device, binding, at)
    assert renamed_candidate.fingerprint == candidate.fingerprint
    detector.mark_persisted(renamed_candidate)
    assert detector.observe(ctx, device, binding, at) == ()


def test_detector_never_mutates_user_profile_and_next_snapshot_uses_explicit_edit():
    ctx = context()
    owner = profile(ctx)
    original_fields = (owner.label, owner.note, owner.expected_macs,
                       owner.expected_ips, owner.trust, owner.trust_changed_at)
    expected_device, expected_binding, _ = observed(ctx, EXPECTED, "192.168.1.20", 5)
    changed_device, changed_binding, at = observed(ctx, OTHER, "192.168.1.20", 10)
    detector = setup(ctx, owner, (expected_device.device_id, changed_device.device_id), (expected_binding,))
    assert detector.observe(ctx, changed_device, changed_binding, at)[0].rule_id == MAC_RULE
    assert (owner.label, owner.note, owner.expected_macs,
            owner.expected_ips, owner.trust, owner.trust_changed_at) == original_fields
    edited = replace(owner, expected_macs=(EXPECTED, OTHER), updated_at=T0 + timedelta(seconds=12))
    detector.replace_snapshot(ctx.fingerprint,
                              ((edited, (expected_device.device_id, changed_device.device_id), (expected_binding,)),),
                              T0 + timedelta(seconds=13))
    later_device, later_binding, later = observed(ctx, OTHER, "192.168.1.20", 14)
    assert detector.observe(ctx, later_device, later_binding, later) == ()


def test_private_mac_is_low_and_stale_binding_cannot_raise_confidence():
    ctx = context()
    owner = profile(ctx)
    old, old_binding, _ = observed(ctx, EXPECTED, "192.168.1.20", 1)
    device, binding, at = observed(ctx, PRIVATE, "192.168.1.20", 200)
    candidate = setup(ctx, owner, (old.device_id,), (old_binding,)).observe(ctx, device, binding, at)[0]
    assert candidate.rule_id == MAC_RULE
    assert candidate.severity == "low" and candidate.confidence == "low"


def test_member_mismatch_and_out_of_order_rejected():
    ctx = context()
    owner = profile(ctx)
    device, binding, at = observed(ctx, OTHER, "192.168.1.99", 10)
    detector = setup(ctx, owner, (device.device_id,))
    assert detector.observe(ctx, device, binding, at)[0].rule_id == MAC_RULE
    stale_device, stale_binding, stale_at = observed(ctx, OTHER, "192.168.1.99", 9, last_seconds=10)
    assert detector.observe(ctx, stale_device, stale_binding, stale_at) == ()


def test_ip_churn_requires_three_distinct_recent_ips_and_same_expected_mac():
    ctx = context()
    owner = profile(ctx)
    device, first, at = observed(ctx, EXPECTED, "192.168.1.21", 10)
    detector = setup(ctx, owner, (device.device_id,))
    assert detector.observe(ctx, device, first, at) == ()
    assert detector.observe(ctx, device, first, at) == ()
    device, second, at = observed(ctx, EXPECTED, "192.168.1.22", 20)
    assert detector.observe(ctx, device, second, at) == ()
    device, third, at = observed(ctx, EXPECTED, "192.168.1.23", 30)
    (candidate,) = detector.observe(ctx, device, third, at)
    assert candidate.rule_id == IP_CHURN_RULE
    assert candidate.severity == "low" and candidate.confidence == "moderate"
    assert candidate.evidence.observation_count == 3


def test_ip_history_window_and_expected_ip_suppress_churn():
    ctx = context()
    owner = profile(ctx)
    device, old, _ = observed(ctx, EXPECTED, "192.168.1.21", 5)
    recent = observed(ctx, EXPECTED, "192.168.1.22", 310)[1]
    detector = setup(ctx, owner, (device.device_id,), (old, recent))
    device, current, at = observed(ctx, EXPECTED, "192.168.1.23", 320)
    assert detector.observe(ctx, device, current, at) == ()
    device, expected, at = observed(ctx, EXPECTED, "192.168.1.20", 321)
    assert detector.observe(ctx, device, expected, at) == ()


def test_recent_persisted_bindings_support_churn_after_detector_restart():
    ctx = context()
    owner = profile(ctx, ips=("192.168.1.20", "192.168.1.30"))
    device, first, _ = observed(ctx, EXPECTED, "192.168.1.21", 10)
    second = observed(ctx, EXPECTED, "192.168.1.22", 20)[1]
    detector = setup(ctx, owner, (device.device_id,), (first, second))
    device, current, at = observed(ctx, EXPECTED, "192.168.1.23", 30)
    assert detector.observe(ctx, device, current, at)[0].rule_id == IP_CHURN_RULE
    device, expected, at = observed(ctx, EXPECTED, "192.168.1.30", 40)
    assert detector.observe(ctx, device, expected, at) == ()


def test_old_packet_is_not_a_fresh_identity_change():
    ctx = context()
    owner = profile(ctx)
    device, binding, at = observed(ctx, OTHER, "192.168.1.20", 10)
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((owner, (), ()),), T0 + timedelta(minutes=6))
    assert detector.observe(ctx, device, binding, at) == ()


def test_same_mac_at_another_profiles_expected_ip_is_context_signal():
    ctx = context()
    first = profile(ctx)
    second = profile(ctx, macs=(OTHER,), ips=("192.168.1.30",))
    device, binding, at = observed(ctx, EXPECTED, "192.168.1.30", 10)
    detector = DeviceIdentityChangeDetector()
    detector.replace_snapshot(ctx.fingerprint, ((first, (device.device_id,), ()), (second, (), ())), at)
    (candidate,) = detector.observe(ctx, device, binding, at)
    assert candidate.rule_id == CONTEXT_RULE
    assert candidate.severity == "low" and candidate.confidence == "low"


def test_merge_single_logical_profile_and_bounded_eviction():
    ctx = context()
    owner = profile(ctx, macs=(EXPECTED, OTHER))
    a = observed(ctx, EXPECTED, "192.168.1.20", 10)[0]
    b = observed(ctx, OTHER, "192.168.1.20", 10)[0]
    detector = setup(ctx, owner, (a.device_id, b.device_id))
    for mac in (EXPECTED, OTHER):
        device, binding, at = observed(ctx, mac, "192.168.1.20", 10)
        assert detector.observe(ctx, device, binding, at) == ()
    # Many distinct unexpected identities retain a fixed memory budget.
    fingerprints = []
    for number in range(MAX_STATES + 2):
        mac = MacAddress(f"04:00:{number >> 8:02x}:{number & 255:02x}:00:01")
        device, binding, at = observed(ctx, mac, "192.168.1.20", 20)
        fingerprints.append(detector.observe(ctx, device, binding, at)[0].fingerprint)
    assert detector.tracked_states == MAX_STATES
    assert set(detector._states) == set(sorted(fingerprints)[-MAX_STATES:])


def test_profile_change_invalidates_pending_signal_without_mutating_trust():
    ctx = context()
    owner = profile(ctx)
    device, binding, at = observed(ctx, OTHER, "192.168.1.20", 10)
    detector = setup(ctx, owner)
    assert detector.observe(ctx, device, binding, at)
    trusted_at = owner.trust_changed_at
    updated = replace(owner, expected_macs=(EXPECTED, OTHER), updated_at=T0 + timedelta(seconds=11))
    detector.replace_snapshot(ctx.fingerprint, ((updated, (), ()),), T0 + timedelta(seconds=12))
    assert detector.tracked_states == 0
    assert owner.trust is DeviceTrust.TRUSTED and updated.trust_changed_at == trusted_at
    assert detector.observe(ctx, *observed(ctx, OTHER, "192.168.1.20", 12)) == ()
