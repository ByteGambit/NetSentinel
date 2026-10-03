"""NS-072 synthetic pre-appearance snapshots; no network, clocks or workers."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest

from netsentinel.application.detectors.destination_novelty import evaluate_destination_novelty
from netsentinel.application.services.behavior_baseline import (
    BaselineWriter, BehaviorBaselineService, baseline_state, merge_learning,
)
from netsentinel.application.services.behavior_features import BehaviorCapacity
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.behavior_baseline import (
    BaselineLoad, BaselineOrigin, BaselineRead, BaselineSnapshot, BaselineState,
    BaselineStorageState, BaselineSummary, MAX_BASELINE_COUNTER,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import NetworkScopeStatus, ObservationOrigin, ObservationQuality, TransportProtocol
from netsentinel.domain.destination_novelty import (
    DestinationNoveltyClassification as C,
    DestinationNoveltyEvidence,
    DestinationNoveltyInput,
    DestinationNoveltyLimitation as L,
    DestinationNoveltyPolicy,
    DestinationNoveltyReason as R,
)
from netsentinel.shared.config import BehaviorBaselineConfig

NOW = datetime(2026, 10, 3, tzinfo=UTC)
KNOWN_IP = "203.0.113.1"
NEW_IP = "203.0.113.2"
SCOPE = BehaviorScopeKey(r"winpath:v1:c:\apps\browser.exe", ApplicationIdentityQuality.STABLE,
                         None, NetworkScopeStatus.RESOLVED, "a" * 64)


def snapshot(*, total=200, count=2, scope=SCOPE, state=BaselineState.READY,
             ip=KNOWN_IP, seconds=600.0, reduced=0, overflow=0, unknown=0, loss=False):
    destinations = []
    if count:
        destinations.append(FeatureCount(str(ip_address(ip)), count))
    remainder = total - count - overflow - unknown
    if remainder:
        destinations.append(FeatureCount("198.51.100.1", remainder))
    remote_samples = total - unknown
    features = BehaviorFeatureSnapshot(
        scope, total, reduced, seconds, tuple(destinations),
        (FeatureCount(443, remote_samples),) if remote_samples else (),
        (FeatureCount(TransportProtocol.TCP, total),) if total else (),
        overflow, 0, 0, unknown, len(destinations), int(remote_samples > 0),
        int(total > 0), False, loss or bool(overflow),
    )
    return BaselineSnapshot(scope, state, BaselineOrigin.NEW, BaselineStorageState.AVAILABLE,
                            BaselineSummary(features, NOW, NOW, "synthetic-policy-v1"))


def observation(baseline=None, *, ip=NEW_IP, scope=SCOPE, origin=ObservationOrigin.OBSERVED,
                quality=ObservationQuality.COMPLETE, stamp=NOW):
    return DestinationNoveltyInput(scope, ip, stamp, origin, quality, baseline)


def evaluate(baseline=None, **kwargs):
    return evaluate_destination_novelty(observation(baseline, **kwargs))


@pytest.mark.parametrize("state,classification,reason", [
    (BaselineState.LEARNING, C.INSUFFICIENT_DATA, R.BASELINE_LEARNING),
    (BaselineState.INSUFFICIENT_DATA, C.INSUFFICIENT_DATA, R.BASELINE_INSUFFICIENT_DATA),
    (BaselineState.INSUFFICIENT_QUALITY, C.INSUFFICIENT_QUALITY, R.BASELINE_INSUFFICIENT_QUALITY),
    (BaselineState.STALE, C.NOT_EVALUATED, R.BASELINE_STALE),
    (BaselineState.EXPIRED, C.NOT_EVALUATED, R.BASELINE_EXPIRED),
    (BaselineState.CLOCK_ANOMALY, C.NOT_EVALUATED, R.BASELINE_CLOCK_ANOMALY),
    (BaselineState.CORRUPT, C.NOT_EVALUATED, R.BASELINE_CORRUPT),
    (BaselineState.UNSUPPORTED_VERSION, C.NOT_EVALUATED, R.BASELINE_UNSUPPORTED_VERSION),
    (BaselineState.POLICY_MISMATCH, C.NOT_EVALUATED, R.BASELINE_POLICY_MISMATCH),
    (BaselineState.UNAVAILABLE, C.NOT_EVALUATED, R.BASELINE_UNAVAILABLE),
])
@pytest.mark.parametrize("ip", [NEW_IP, KNOWN_IP])
def test_lifecycle_never_promoted(state, classification, reason, ip):
    result = evaluate(snapshot(state=state), ip=ip)
    assert (result.classification, result.reason, result.baseline_state) == (classification, reason, state)
    assert result.baseline_sample_count == 200
    assert result.destination_appearances == (2 if ip == KNOWN_IP else 0)


def test_cold_start_and_missing_baseline():
    cold = snapshot(total=0, count=0, seconds=0, state=BaselineState.LEARNING)
    result = evaluate(cold)
    assert (result.classification, result.baseline_sample_count) == (C.INSUFFICIENT_DATA, 0)
    assert evaluate().reason is R.BASELINE_UNAVAILABLE
    assert evaluate().baseline_sample_count is None


@pytest.mark.parametrize("count,total,classification,reason", [
    (0, 20, C.FIRST_SEEN, R.DESTINATION_NOT_PREVIOUSLY_OBSERVED),
    (1, 20, C.INSUFFICIENT_DATA, R.RARITY_MINIMUM_SAMPLES),
    (1, 99, C.INSUFFICIENT_DATA, R.RARITY_MINIMUM_SAMPLES),
    (1, 100, C.RARE, R.DESTINATION_RARELY_OBSERVED),
    (2, 199, C.KNOWN, R.DESTINATION_ESTABLISHED),
    (2, 200, C.RARE, R.DESTINATION_RARELY_OBSERVED),
    (2, 201, C.RARE, R.DESTINATION_RARELY_OBSERVED),
    (3, 1000, C.KNOWN, R.DESTINATION_ESTABLISHED),
    (100, 200, C.KNOWN, R.DESTINATION_ESTABLISHED),
    (10**12, 10**12, C.KNOWN, R.DESTINATION_ESTABLISHED),
])
def test_first_seen_rare_known_and_inclusive_boundaries(count, total, classification, reason):
    result = evaluate(snapshot(count=count, total=total), ip=KNOWN_IP)
    assert (result.classification, result.reason) == (classification, reason)
    assert result.destination_appearances == count
    assert result.baseline_sample_count == result.total_eligible_baseline_appearances == total
    assert result.monitored_seconds == 600.0


@pytest.mark.parametrize("kwargs,reason", [
    ({"total": 19}, R.MINIMUM_SAMPLES),
    ({"seconds": 599.9}, R.MINIMUM_MONITORED_DURATION),
])
def test_minimum_policy_even_if_upstream_ready_is_looser(kwargs, reason):
    result = evaluate(snapshot(**kwargs))
    assert (result.classification, result.reason) == (C.INSUFFICIENT_DATA, reason)


@pytest.mark.parametrize("kwargs,reason", [
    ({"loss": True}, R.CAPACITY_LOSS),
    ({"overflow": 1}, R.DESTINATION_OVERFLOW),
    ({"reduced": 1}, R.BASELINE_INSUFFICIENT_QUALITY),
    ({"unknown": 1}, R.BASELINE_INSUFFICIENT_QUALITY),
    ({"total": MAX_BASELINE_COUNTER}, R.COUNTER_SATURATED),
])
@pytest.mark.parametrize("ip", [NEW_IP, KNOWN_IP])
def test_quality_defenses_on_ready_snapshot(kwargs, reason, ip):
    result = evaluate(snapshot(**kwargs), ip=ip)
    assert (result.classification, result.reason) == (C.INSUFFICIENT_QUALITY, reason)
    assert result.baseline_sample_count == kwargs.get("total", 200)


@pytest.mark.parametrize("origin", [BaselineOrigin.PREVIOUS_UNAVAILABLE, BaselineOrigin.SESSION_ONLY])
def test_incomplete_history_origin(origin):
    result = evaluate(replace(snapshot(), origin=origin))
    assert (result.classification, result.reason) == (C.INSUFFICIENT_QUALITY, R.HISTORY_INCOMPLETE)


@pytest.mark.parametrize("storage", list(BaselineStorageState))
def test_valid_memory_history_remains_usable_despite_storage_status(storage):
    result = evaluate(replace(snapshot(), storage=storage, origin=BaselineOrigin.RESTORED))
    assert result.classification is C.FIRST_SEEN
    assert result.baseline_storage is storage


@pytest.mark.parametrize("changed,reason", [
    ({"application_key": r"winpath:v1:d:\apps\browser.exe"}, R.APPLICATION_SCOPE_MISMATCH),
    ({"revision_digest": "b" * 64}, R.REVISION_MISMATCH),
    ({"network_token": "b" * 64}, R.NETWORK_SCOPE_MISMATCH),
])
def test_no_borrowing_other_application_revision_or_network(changed, reason):
    result = evaluate(snapshot(), ip=KNOWN_IP, scope=replace(SCOPE, **changed))
    assert (result.classification, result.reason) == (C.NOT_EVALUATED, reason)
    assert result.destination_appearances is result.baseline_sample_count is None


@pytest.mark.parametrize("old,new", [(None, "b" * 64), ("a" * 64, None), ("a" * 64, "b" * 64)])
def test_revision_absence_never_merges_with_known_hash(old, new):
    assert evaluate(snapshot(scope=replace(SCOPE, revision_digest=old)),
                    scope=replace(SCOPE, revision_digest=new)).reason is R.REVISION_MISMATCH


@pytest.mark.parametrize("change", [
    {"application_key": r"winpath:v1:d:\apps\browser.exe"},
    {"network_token": "b" * 64},
    {"revision_digest": "b" * 64},
])
def test_shared_destination_is_known_only_in_its_own_scope(change):
    other = replace(SCOPE, **change)
    assert evaluate(snapshot(count=100), ip=KNOWN_IP).classification is C.KNOWN
    assert evaluate(snapshot(scope=other, count=0), scope=other, ip=KNOWN_IP).classification is C.FIRST_SEEN


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_unknown_network_cannot_borrow_resolved_baseline(status):
    result = evaluate(snapshot(), scope=replace(SCOPE, network_status=status, network_token="session-only"))
    assert (result.classification, result.reason) == (C.NOT_EVALUATED, R.NETWORK_SCOPE_UNAVAILABLE)


@pytest.mark.parametrize("scope", [None, replace(SCOPE, identity_quality=ApplicationIdentityQuality.PROVISIONAL,
                                               application_key="instance:v1:7:123")])
def test_unknown_or_provisional_application(scope):
    assert evaluate(snapshot(), scope=scope).reason is R.APPLICATION_SCOPE_UNAVAILABLE


@pytest.mark.parametrize("ip", [None, "invalid", "0.0.0.0", "::", "fe80::1%3", "x" * 1000])
def test_invalid_missing_or_unspecified_destination(ip):
    result = evaluate(snapshot(), ip=ip)
    assert (result.classification, result.reason, result.destination_ip) == (C.NOT_EVALUATED, R.REMOTE_UNAVAILABLE, None)


@pytest.mark.parametrize("ip", ["203.0.113.1", "2001:0DB8:0000:0000:0000:0000:0000:0001", "10.0.0.1", "127.0.0.1", "::1"])
def test_canonical_ipv4_ipv6_private_and_loopback(ip):
    result = evaluate(snapshot(count=100, ip=ip), ip=ip)
    assert result.classification is C.KNOWN
    assert result.destination_ip == str(ip_address(ip))


def test_initial_startup_never_produces_first_seen_storm():
    results = [evaluate(snapshot(), ip=f"203.0.113.{index}", origin=ObservationOrigin.INITIAL)
               for index in range(2, 102)]
    assert all(item.classification is C.NOT_EVALUATED and item.reason is R.INITIAL_OBSERVATION for item in results)


def test_failed_is_ineligible_and_reduced_preserves_quality_without_reinterpreting_baseline():
    assert evaluate(snapshot(), quality=ObservationQuality.FAILED).reason is R.FAILED_ROUND
    result = evaluate(snapshot(), quality=ObservationQuality.REDUCED)
    assert result.classification is C.FIRST_SEEN
    assert result.quality is ObservationQuality.REDUCED
    assert L.REDUCED_CURRENT_OBSERVATION in result.limitations
    assert evaluate(snapshot(state=BaselineState.INSUFFICIENT_QUALITY),
                    quality=ObservationQuality.REDUCED).classification is C.INSUFFICIENT_QUALITY


@pytest.mark.parametrize("changes,reason", [
    ({"summary_version": 2}, R.BASELINE_UNSUPPORTED_VERSION),
    ({"feature_policy_version": 2}, R.BASELINE_POLICY_MISMATCH),
    ({"persisted_at": NOW + timedelta(seconds=1)}, R.BASELINE_CLOCK_ANOMALY),
    ({"last_observed_at": NOW + timedelta(seconds=1)}, R.BASELINE_CLOCK_ANOMALY),
])
def test_ready_defensively_checks_versions_and_clock(changes, reason):
    base = snapshot()
    assert evaluate(replace(base, summary=replace(base.summary, **changes))).reason is reason


def test_missing_invalid_or_wrong_scope_summary_is_not_interpreted_as_empty_history():
    base = snapshot()
    assert evaluate(replace(base, summary=None)).reason is R.BASELINE_CORRUPT
    bad = replace(base.summary.features, destinations=())
    assert evaluate(replace(base, summary=replace(base.summary, features=bad))).reason is R.BASELINE_CORRUPT
    bad = replace(base.summary.features, scope=replace(SCOPE, network_token="b" * 64))
    result = evaluate(replace(base, summary=replace(base.summary, features=bad)))
    assert result.reason is R.BASELINE_CORRUPT
    assert result.baseline_sample_count is None


def test_cdn_address_rotation_is_ip_evidence_without_hostname_or_service_attribution():
    result = evaluate(snapshot())
    assert result.classification is C.FIRST_SEEN
    assert L.IP_ONLY_SERVICE_NOT_INFERRED in result.limitations
    # Domain associations (including multiple candidates) are outside the input:
    # no domain history exists in NS-071, so none can become a hostname here.
    names = {field.name for field in fields(result)}
    assert not names & {"hostname", "service", "malicious", "safe", "risk_score", "probability", "severity"}


def test_policy_and_evidence_are_immutable_deterministic_and_explicit():
    base = snapshot()
    base = replace(base, summary=replace(base.summary, features=replace(base.summary.features, gap_seen=True)))
    request = observation(base)
    first = evaluate_destination_novelty(request)
    assert first == evaluate_destination_novelty(request)
    assert first.policy_version == 1
    assert first.baseline_policy_key == "synthetic-policy-v1"
    assert first.gap_seen
    assert L.REVISION_UNVERIFIED in first.limitations
    with pytest.raises(FrozenInstanceError):
        first.reason = R.BASELINE_CORRUPT
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(result == first for result in pool.map(evaluate_destination_novelty, [request] * 20))
    assert request.baseline == base
    assert isinstance(first, DestinationNoveltyEvidence)


def test_explicit_policy_changes_rarity_without_global_config():
    request = observation(snapshot(count=3, total=200), ip=KNOWN_IP)
    policy = DestinationNoveltyPolicy(rare_maximum_appearances=3, rare_maximum_percent=2)
    result = evaluate_destination_novelty(request, policy)
    assert result.classification is C.RARE
    assert result.policy == policy


@pytest.mark.parametrize("changes", [
    {"version": 2}, {"version": True}, {"minimum_samples": 0},
    {"minimum_samples": True}, {"minimum_samples": 1_000_001},
    {"minimum_monitored_seconds": float("nan")}, {"minimum_monitored_seconds": float("inf")},
    {"minimum_monitored_seconds": True}, {"rarity_minimum_samples": 19},
    {"rare_maximum_percent": 0}, {"rare_maximum_percent": 101},
    {"rare_maximum_appearances": 0},
])
def test_policy_bounds(changes):
    with pytest.raises(ValueError):
        DestinationNoveltyPolicy(**changes)


def unused_repository():
    raise AssertionError("detector/service snapshot must not perform I/O")


def service(*, capacity=None):
    return BehaviorBaselineService(BaselineWriter(unused_repository), capacity=capacity,
                                  clock=lambda: NOW, monotonic_clock=lambda: 0.0)


def test_service_snapshot_before_mutation_preserves_first_seen_then_rare():
    owner = service()
    base = snapshot(count=0)
    owner.restore(BaselineLoad((BaselineRead(SCOPE, BaselineState.READY,
                                            replace(base.summary, policy_key=owner.policy_key)),)))
    before = owner.snapshot(SCOPE)
    assert evaluate(before, ip=KNOWN_IP).classification is C.FIRST_SEEN
    delta = snapshot(total=1, count=1, seconds=0).summary.features
    owner.observe((delta,), NOW, ObservationQuality.COMPLETE)
    after = owner.snapshot(SCOPE)
    result = evaluate(after, ip=KNOWN_IP)
    assert (result.classification, result.destination_appearances, result.baseline_sample_count) == (C.RARE, 1, 201)
    assert before.summary.features.observed_appearances == 200
    assert evaluate(before, ip=KNOWN_IP).classification is C.FIRST_SEEN


def test_real_memory_eviction_and_disk_load_loss_do_not_invent_first_seen():
    owner = service(capacity=BehaviorCapacity(scopes=1))
    base = snapshot()
    owner.restore(BaselineLoad((BaselineRead(SCOPE, BaselineState.READY,
                                            replace(base.summary, policy_key=owner.policy_key)),)))
    other = replace(SCOPE, application_key=r"winpath:v1:c:\apps\other.exe")
    owner.observe((snapshot(scope=other).summary.features,), NOW, ObservationQuality.COMPLETE)
    result = evaluate(owner.snapshot(SCOPE))
    assert (result.classification, result.reason) == (C.NOT_EVALUATED, R.BASELINE_UNAVAILABLE)
    for load in (BaselineLoad((), capacity_loss=True), None):
        lost = service()
        lost.restore(load)
        assert evaluate(lost.snapshot(SCOPE)).reason is R.BASELINE_UNAVAILABLE
        lost.observe((base.summary.features,), NOW, ObservationQuality.COMPLETE)
        assert evaluate(lost.snapshot(SCOPE)).classification is C.INSUFFICIENT_QUALITY


def test_actual_destination_cap_overflow_and_counter_saturation_are_conservative():
    initial = snapshot(count=200).summary.features
    incoming = snapshot(total=1, count=1, ip=NEW_IP, seconds=0).summary.features
    merged = merge_learning(initial, incoming, BehaviorCapacity(destinations=1))
    assert merged.other_destinations == 1 and merged.capacity_loss
    base = snapshot()
    assert evaluate(replace(base, summary=replace(base.summary, features=merged))).reason is R.DESTINATION_OVERFLOW
    maximum = snapshot(total=MAX_BASELINE_COUNTER).summary.features
    merged = merge_learning(maximum, incoming, BehaviorCapacity())
    assert merged.capacity_loss and merged.observed_appearances == MAX_BASELINE_COUNTER
    assert evaluate(replace(base, summary=replace(base.summary, features=merged))).classification is C.INSUFFICIENT_QUALITY


@pytest.mark.parametrize("days,state,reason", [(30, BaselineState.STALE, R.BASELINE_STALE),
                                             (90, BaselineState.EXPIRED, R.BASELINE_EXPIRED)])
def test_lifecycle_owns_stale_expired_and_detector_respects_fresh_snapshot(days, state, reason):
    base = snapshot()
    as_of = NOW + timedelta(days=days)
    assert baseline_state(base.summary, as_of, BehaviorBaselineConfig()) is state
    result = evaluate(replace(base, state=state), stamp=as_of)
    assert (result.classification, result.reason) == (C.NOT_EVALUATED, reason)
