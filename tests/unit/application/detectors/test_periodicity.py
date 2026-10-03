"""NS-074 offline fake clocks; observed appearances are not OS timers."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from math import isfinite
from uuid import UUID

import pytest

from netsentinel.application.detectors.periodicity import evaluate_periodicity
from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.application.services.periodicity import PeriodicityService
from netsentinel.domain.application_identity import ApplicationRevision, ApplicationScope
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionLifecycleEvent, ConnectionNetworkScope, ConnectionOpened, ConnectionRoundObservation,
    ConnectionSnapshot, ConnectionState, ConnectionUpdated, Endpoint,
    NetworkAttributionMethod, NetworkScopeStatus, ObservationOrigin, ObservationQuality,
    ProcessIdentity, ProcessInfo, ProcessInfoStatus, TransportProtocol,
)
from netsentinel.domain.executable_hash import ExecutableHashStatus
from netsentinel.domain.periodicity import (
    RULE_ID, PeriodicityClassification as Classification, PeriodicityEvidence,
    PeriodicityLimitation as Limitation, PeriodicityPolicy, PeriodicityReason as Reason,
    PeriodicityReset as Reset, PeriodicityScope, PeriodicitySequence,
)

UTC_TIME = datetime(2026, 10, 3, tzinfo=UTC)
SESSION = UUID(int=1)
POLICY = PeriodicityPolicy()
NETWORK = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "eth", 1,
                                 NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
PROCESS = ProcessInfo(identity=ProcessIdentity(12, UTC_TIME), name="updater", status=ProcessInfoStatus.AVAILABLE,
                      executable_path=r"C:\Apps\updater.exe")


def connection(*, remote: Endpoint | None = Endpoint("203.0.113.7", 443),
               process: ProcessInfo = PROCESS, network: ConnectionNetworkScope = NETWORK,
               protocol: TransportProtocol = TransportProtocol.TCP) -> ConnectionSnapshot:
    local = Endpoint("2001:db8::2" if remote and remote.ip_version == 6 else "192.168.1.2", 50000)
    state = ConnectionState.NONE if protocol is TransportProtocol.UDP else ConnectionState.ESTABLISHED
    return ConnectionSnapshot(protocol, local, remote, state,
                              process, UTC_TIME, network)


def scope(snapshot: ConnectionSnapshot | None = None) -> PeriodicityScope:
    snapshot = snapshot or connection()
    app = resolve_application_scope(snapshot.process)
    assert app.identity.key is not None and snapshot.process.identity is not None
    assert snapshot.remote_endpoint is not None and snapshot.network_scope.fingerprint is not None
    behavior = BehaviorScopeKey(app.identity.key, app.identity.quality, app.revision.digest,
                                snapshot.network_scope.status, snapshot.network_scope.fingerprint)
    return PeriodicityScope(behavior, snapshot.process.identity, snapshot.remote_endpoint, snapshot.protocol)


def sequence(intervals: tuple[float, ...], *, poll: float = 5) -> PeriodicitySequence:
    return PeriodicitySequence(scope(), SESSION, intervals, poll, UTC_TIME)


def evidence(intervals: tuple[float, ...], *, poll: float = 5,
             policy: PeriodicityPolicy = POLICY) -> PeriodicityEvidence:
    return evaluate_periodicity(sequence(intervals, poll=poll), policy)


class FakeClock:
    def __init__(self, *, policy: PeriodicityPolicy = POLICY, poll: float = 5) -> None:
        self.now = 0.0
        self.utc = UTC_TIME
        self.session = SESSION
        self.serial = 100
        self.poll = poll
        self.service = PeriodicityService(polling_interval_seconds=poll, policy=policy)

    def round(self, events: tuple[ConnectionLifecycleEvent, ...] = (), quality: ObservationQuality = ObservationQuality.COMPLETE,
              discarded: int = 0) -> tuple[PeriodicityEvidence, ...]:
        return self.service.observe_round(ConnectionRoundObservation(self.session, self.utc, quality, discarded),
                                          events, now_monotonic=self.now)

    def advance(self, seconds: float) -> None:
        target = self.now + seconds
        while self.now + self.poll < target:
            self.now += self.poll
            self.round()
        self.now = target

    def opened(self, snapshot: ConnectionSnapshot | None = None,
               origin: ObservationOrigin = ObservationOrigin.OBSERVED) -> ConnectionOpened:
        self.serial += 1
        return ConnectionOpened(snapshot or connection(), origin, self.session, UUID(int=self.serial))

    def appearance(self, seconds: float = 0, snapshot: ConnectionSnapshot | None = None) -> PeriodicityEvidence:
        self.advance(seconds)
        return self.round((self.opened(snapshot),))[0]

    def periodic(self) -> PeriodicityEvidence:
        self.appearance()
        for _ in range(5):
            result = self.appearance(60)
        return result


@pytest.mark.parametrize("count", range(5))
def test_below_minimum(count: int) -> None:
    result = evidence((60,) * count)
    assert result.classification is Classification.INSUFFICIENT_DATA
    assert result.base_interval_seconds is None
    assert result.retained_interval_count == count


@pytest.mark.parametrize("intervals", [(60,) * 5, (59, 61, 60, 60, 60), (57, 60, 60, 60, 63)])
def test_minimum_periodic_and_inclusive_jitter(intervals: tuple[float, ...]) -> None:
    result = evidence(intervals)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.base_interval_seconds == 60
    assert result.tolerance_seconds == 3
    assert result.normalized_jitter == max(abs(v - 60) for v in intervals) / 60


@pytest.mark.parametrize("intervals", [
    (56, 60, 60, 60, 64), (60, 60, 60, 60, 63.001),
    (13, 47, 29, 81, 17), (10, 20, 30, 40, 50),
    (0.1, 0.1, 60, 0.1, 0.1, 60), (60, 60, 240, 60, 60),
    (60, 120, 120, 180, 180),
])
def test_irregular_random_trends_bursts_and_large_multiples(intervals: tuple[float, ...]) -> None:
    assert evidence(intervals).classification is Classification.IRREGULAR


def test_median_and_metric_exact() -> None:
    result = evidence((59, 60, 60, 61, 120))
    assert (result.base_interval_seconds, result.maximum_deviation_seconds,
            result.normalized_jitter, result.compatible_multiple_count) == (60, 1, 1 / 60, 1)
    assert result.reason is Reason.MULTIPLES_COMPATIBLE
    assert Limitation.MISSED_MULTIPLE_COMPATIBLE in result.limitations


@pytest.mark.parametrize("multiple", [2, 3])
def test_missed_samples_are_compatible_not_proven(multiple: int) -> None:
    result = evidence((60, 60, multiple * 60, 60, 60))
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.compatible_multiple_count == 1
    assert "not_proven" in Limitation.MISSED_MULTIPLE_COMPATIBLE.value


def test_multiples_can_be_disabled_and_need_majority() -> None:
    assert evidence((60, 60, 120, 60, 60), policy=replace(POLICY, maximum_multiple=1)).classification is Classification.IRREGULAR
    assert evidence((60, 60, 60, 120, 180, 180)).classification is Classification.IRREGULAR


@pytest.mark.parametrize("period,poll,expected", [
    (10, 5, Classification.RESOLUTION_LIMITED), (15, 5, Classification.RESOLUTION_LIMITED),
    (15.1, 5, Classification.PERIODIC_CANDIDATE), (60, 5, Classification.PERIODIC_CANDIDATE),
    (5, 1, Classification.IRREGULAR), (3600, 5, Classification.PERIODIC_CANDIDATE),
    (3601, 5, Classification.IRREGULAR), (5e-324, 5, Classification.IRREGULAR),
])
def test_period_and_resolution_gates(period: float, poll: float, expected: Classification) -> None:
    result = evidence((period,) * 5, poll=poll)
    assert result.classification is expected
    assert Limitation.POLLING_QUANTIZED in result.limitations
    for f in fields(result):
        value = getattr(result, f.name)
        if isinstance(value, float):
            assert isfinite(value)


def test_aliasing_and_wall_clock_metadata() -> None:
    # Non-exact real appearances sampled at 5s can look exactly 60s apart.
    actual = (0, 58, 119, 178, 238, 299)
    sampled = tuple(((v + 4) // 5) * 5 for v in actual)
    intervals = tuple(b - a for a, b in zip(sampled, sampled[1:]))
    result = evidence(intervals)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert Limitation.POLLING_QUANTIZED in result.limitations
    original = sequence(intervals)
    for delta in (-86400, 86400):
        changed = evaluate_periodicity(replace(original, observed_at=UTC_TIME + timedelta(seconds=delta)))
        assert replace(changed, observed_at=result.observed_at) == result


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), -float("inf"), True, 10801])
def test_invalid_intervals_rejected(value: float) -> None:
    with pytest.raises(ValueError):
        sequence((value,) * 5)


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), True, 1e13])
def test_invalid_explicit_clock(value: float) -> None:
    with pytest.raises(ValueError):
        FakeClock().service.observe_round(ConnectionRoundObservation(SESSION, UTC_TIME, ObservationQuality.COMPLETE), now_monotonic=value)


@pytest.mark.parametrize("changes", [
    {"version": 2}, {"minimum_intervals": 4}, {"maximum_intervals": 33},
    {"maximum_intervals": 5, "minimum_intervals": 6}, {"maximum_scopes": 129},
    {"maximum_multiple": 4}, {"relative_jitter": float("nan")},
    {"absolute_jitter_seconds": float("inf")}, {"resolution_factor": 2},
    {"maximum_period_seconds": 3601}, {"inactivity_seconds": 100},
    {"horizon_seconds": 100}, {"minimum_intervals": True},
])
def test_invalid_bounded_policy(changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(POLICY, **changes)


@pytest.mark.parametrize("poll", [0, -1, True, float("nan"), float("inf"), 3601])
def test_invalid_polling_cadence(poll: float) -> None:
    with pytest.raises(ValueError):
        FakeClock(poll=poll)


def test_initial_close_update_no_remote_or_unknown_never_track() -> None:
    clock = FakeClock()
    opened = clock.opened(origin=ObservationOrigin.INITIAL)
    assert clock.round((opened,)) == ()
    snap = connection()
    closed = ConnectionClosed(snap, UTC_TIME, session_id=SESSION, lifecycle_id=opened.lifecycle_id)
    updated = ConnectionUpdated(snap, snap, SESSION, opened.lifecycle_id)
    assert clock.round((closed, updated)) == ()
    assert clock.round((clock.opened(connection(remote=None)),)) == ()
    assert clock.service.scope_count == 0
    assert clock.appearance().classification is Classification.INSUFFICIENT_DATA


@pytest.mark.parametrize("quality,reason", [(ObservationQuality.FAILED, Reset.MONITORING_GAP),
                                           (ObservationQuality.REDUCED, Reset.REDUCED_QUALITY)])
def test_gap_quality_break_then_rebuild(quality: ObservationQuality, reason: Reset) -> None:
    clock = FakeClock()
    before = clock.periodic()
    clock.advance(5)
    assert clock.round((clock.opened(),), quality) == ()
    assert clock.round(quality=quality) == ()
    interrupted = clock.service.snapshot(before.scope, round_observation=ConnectionRoundObservation(SESSION, UTC_TIME, quality))
    assert interrupted is not None and interrupted.retained_interval_count == 0
    assert interrupted.last_reset is reason
    result = clock.appearance(120)
    assert result.retained_interval_count == 0 and result.classification is Classification.INSUFFICIENT_DATA
    for _ in range(4):
        result = clock.appearance(60)
    assert result.classification is Classification.INSUFFICIENT_DATA
    assert clock.appearance(60).classification is Classification.PERIODIC_CANDIDATE


def test_discarded_round_and_delayed_poll_are_not_missed_multiples() -> None:
    clock = FakeClock()
    clock.periodic()
    clock.round(discarded=1)
    assert clock.appearance().last_reset is Reset.CAPACITY_LOSS
    clock = FakeClock()
    clock.periodic()
    clock.now += 120  # No monitored rounds during the gap.
    result = clock.appearance()
    assert result.retained_interval_count == 0
    assert result.last_reset is Reset.MONITORING_GAP
    assert result.compatible_multiple_count == 0


def test_clean_missed_multiple_and_monitoring_gap_are_different() -> None:
    clock = FakeClock()
    clock.appearance()
    for value in (60, 60, 120, 60, 60):
        result = clock.appearance(value)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.compatible_multiple_count == 1
    clock.round(quality=ObservationQuality.FAILED)
    result = clock.appearance(120)
    assert result.classification is Classification.INSUFFICIENT_DATA
    assert result.compatible_multiple_count == 0


def test_session_change_and_new_service_do_not_restore_intervals() -> None:
    clock = FakeClock()
    before = clock.periodic()
    clock.session = UUID(int=2)
    clock.now = 0
    result = clock.appearance()
    assert result.retained_interval_count == 0 and result.last_reset is Reset.SESSION_CHANGED
    assert result.session_id != before.session_id
    assert FakeClock().appearance().retained_interval_count == 0


def test_clock_regression_resets_conservatively() -> None:
    clock = FakeClock()
    clock.periodic()
    clock.now -= 1
    assert clock.round((clock.opened(),)) == ()
    result = clock.appearance(5)
    assert result.retained_interval_count == 0 and result.last_reset is Reset.CLOCK_REGRESSION


def test_duplicate_lifecycle_and_same_timestamp_concurrency() -> None:
    clock = FakeClock()
    original = clock.opened()
    clock.round((original, original))
    clock.advance(60)
    assert clock.round((original,)) == ()
    result = clock.round((clock.opened(),))[0]
    assert result.retained_interval_count == 1
    result = clock.round((clock.opened(),))[0]
    assert result.retained_interval_count == 0
    assert result.last_reset is Reset.CONCURRENT_APPEARANCES
    assert clock.appearance(60).retained_interval_count == 1


def test_old_duplicate_after_gap_does_not_reappear() -> None:
    clock = FakeClock()
    original = clock.opened()
    clock.round((original,))
    clock.round(quality=ObservationQuality.FAILED)
    clock.advance(60)
    assert clock.round((original,)) == ()
    assert clock.appearance().retained_interval_count == 0


@pytest.mark.parametrize("changed", [
    connection(remote=Endpoint("203.0.113.8", 443)),
    connection(remote=Endpoint("203.0.113.7", 53)),
    connection(protocol=TransportProtocol.UDP),
    connection(process=replace(PROCESS, executable_path=r"C:\Other\updater.exe")),
    connection(process=replace(PROCESS, identity=ProcessIdentity(13, UTC_TIME))),
    connection(process=replace(PROCESS, identity=ProcessIdentity(12, UTC_TIME + timedelta(seconds=1)))),
    connection(network=replace(NETWORK, fingerprint="b" * 64)),
])
def test_endpoint_app_runtime_restart_and_network_scopes_separate(changed: ConnectionSnapshot) -> None:
    clock = FakeClock()
    before = clock.periodic()
    result = clock.appearance(60, changed)
    assert result.retained_interval_count == 0
    assert result.scope != before.scope
    assert clock.service.scope_count == 2


@pytest.mark.parametrize("network", [ConnectionNetworkScope.unknown(), ConnectionNetworkScope.ambiguous()])
def test_unresolved_network_does_not_borrow(network: ConnectionNetworkScope) -> None:
    clock = FakeClock()
    clock.periodic()
    assert clock.round((clock.opened(connection(network=network)),)) == ()
    assert clock.service.scope_count == 1


@pytest.mark.parametrize("process", [
    replace(PROCESS, executable_path=None, executable_path_status=ProcessInfoStatus.UNAVAILABLE),
    replace(PROCESS, identity=ProcessIdentity(12), create_time_status=ProcessInfoStatus.UNAVAILABLE),
    ProcessInfo.unavailable(),
])
def test_unavailable_application_or_instance_is_not_evaluated(process: ProcessInfo) -> None:
    clock = FakeClock()
    assert clock.round((clock.opened(connection(process=process)),)) == ()
    assert clock.service.scope_count == 0


def test_known_unknown_revision_never_borrow() -> None:
    clock = FakeClock()
    digest: list[str | None] = ["a" * 64]

    def resolve(process: ProcessInfo) -> ApplicationScope:
        app = resolve_application_scope(process)
        revision = ApplicationRevision(digest[0], ExecutableHashStatus.AVAILABLE if digest[0] else None)
        return replace(app, revision=revision)

    clock.service = PeriodicityService(polling_interval_seconds=5, application_scope_resolver=resolve)
    known = clock.periodic()
    assert Limitation.REVISION_UNVERIFIED not in known.limitations
    for value in ("b" * 64, None):
        digest[0] = value
        result = clock.appearance(60)
        assert result.retained_interval_count == 0
        assert result.scope.behavior.revision_digest == value
    assert Limitation.REVISION_UNVERIFIED in result.limitations
    assert clock.service.scope_count == 3


@pytest.mark.parametrize("address", ["203.0.113.7", "2001:0db8::0007", "192.168.1.10", "127.0.0.1", "::1"])
def test_canonical_ip_private_and_loopback(address: str) -> None:
    clock = FakeClock()
    snap = connection(remote=Endpoint(address, 443))
    clock.appearance(snapshot=snap)
    for _ in range(5):
        result = clock.appearance(60, snap)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.scope.remote_endpoint.address == snap.remote_endpoint.address


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "fe80::1%3"])
def test_unavailable_remote_not_evaluated(address: str) -> None:
    clock = FakeClock()
    assert clock.round((clock.opened(connection(remote=Endpoint(address, 443))),)) == ()


def test_bounded_intervals_capacity_flag_and_exact_oldest_eviction() -> None:
    clock = FakeClock(policy=replace(POLICY, maximum_scopes=2, maximum_intervals=5))
    first = clock.periodic()
    for _ in range(20):
        result = clock.appearance(60)
    assert result.retained_interval_count == 5
    assert Limitation.SEQUENCE_TRUNCATED in result.limitations
    second_snap = connection(remote=Endpoint("203.0.113.8", 443))
    second = clock.appearance(5, second_snap)
    clock.appearance(5)  # Touch first; second is now oldest.
    third_snap = connection(remote=Endpoint("203.0.113.9", 443))
    clock.appearance(5, third_snap)
    assert clock.service.scope_count == 2
    reference = ConnectionRoundObservation(SESSION, UTC_TIME, ObservationQuality.COMPLETE)
    assert clock.service.snapshot(second.scope, round_observation=reference) is None
    assert clock.service.snapshot(first.scope, round_observation=reference) is not None
    returned = clock.appearance(5, second_snap)
    assert returned.retained_interval_count == 0
    assert Limitation.PRIOR_HISTORY_UNAVAILABLE in returned.limitations


def test_inactivity_expiry_and_horizon_truncation() -> None:
    clock = FakeClock()
    clock.periodic()
    clock.advance(10800)
    clock.round()
    assert clock.service.scope_count == 1  # Inclusive boundary.
    clock.advance(5)
    clock.round()
    assert clock.service.scope_count == 0
    result = clock.appearance()
    assert result.last_reset is Reset.INACTIVITY and result.retained_interval_count == 0
    assert Limitation.PRIOR_HISTORY_UNAVAILABLE in result.limitations
    clock = FakeClock(policy=replace(POLICY, horizon_seconds=18000))
    clock.appearance()
    for _ in range(6):
        result = clock.appearance(3600)
    assert result.retained_interval_count == 5
    assert Limitation.SEQUENCE_TRUNCATED in result.limitations


def test_round_event_capacity_is_bounded_and_results_not_emitted() -> None:
    clock = FakeClock()
    clock.periodic()
    assert clock.round(tuple(clock.opened() for _ in range(8193))) == ()
    assert clock.appearance(60).retained_interval_count == 0


def test_scope_reset_is_narrow_and_wrong_session_is_ignored() -> None:
    clock = FakeClock()
    before = clock.periodic()
    other = clock.appearance(5, connection(remote=Endpoint("203.0.113.9", 443)))
    clock.service.reset(before.scope)
    assert clock.service.scope_count == 1
    assert clock.round((replace(clock.opened(), session_id=UUID(int=99)),)) == ()
    reference = ConnectionRoundObservation(SESSION, UTC_TIME, ObservationQuality.COMPLETE)
    assert clock.service.snapshot(other.scope, round_observation=reference) is not None


def test_tracker_long_lived_flow_initial_close_reappearance_regression() -> None:
    clock = FakeClock()
    tracker = ConnectionTrackingService(clock=lambda: clock.utc)
    clock.session = tracker.session_id
    snapshot = connection()

    def tracked(snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[PeriodicityEvidence, ...]:
        events = tracker.track(snapshots, observed_at=clock.utc)
        assert tracker.last_round is not None
        return clock.service.observe_round(tracker.last_round, events, now_monotonic=clock.now)

    assert tracked((snapshot,)) == ()  # INITIAL startup flow.
    for _ in range(300):
        clock.now += 5
        clock.utc += timedelta(seconds=5)
        snapshot = replace(snapshot, observed_at=clock.utc)
        assert tracked((snapshot,)) == ()
    assert clock.service.scope_count == 0  # 300 polls do not become heartbeats.
    for _ in range(6):
        clock.now += 5
        clock.utc += timedelta(seconds=5)
        assert tracked(()) == ()  # CLOSE never appends.
        for _ in range(11):
            clock.now += 5
            clock.utc += timedelta(seconds=5)
            tracked(())
        snapshot = replace(snapshot, observed_at=clock.utc)
        result = tracked((snapshot,))[0]
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.retained_interval_count == 5
    tracker.reset_session()
    clock.session = tracker.session_id
    assert tracked((snapshot,)) == ()
    assert clock.service.scope_count == 0


def test_policy_version_context_only_immutable_deterministic() -> None:
    result = FakeClock().periodic()
    other = FakeClock().periodic()
    assert result == other
    assert result.rule_id == RULE_ID and result.policy_version == 1
    assert Limitation.BENIGN_SCHEDULE_COMPATIBLE in result.limitations
    assert Limitation.BEHAVIORAL_ONLY_LOW_SECURITY_SIGNIFICANCE in result.limitations
    assert {f.name for f in fields(result)}.isdisjoint({"score", "severity", "probability", "safe", "malicious"})
    assert all(word not in member.value for word in ("beacon", "c2", "malware") for member in Classification)
    with pytest.raises(FrozenInstanceError):
        result.reason = Reason.MINIMUM_INTERVALS  # type: ignore[misc]


@pytest.mark.parametrize("name", ["updater", "telemetry", "sync"])
def test_regular_benign_scheduler_is_low_significance_context(name: str) -> None:
    clock = FakeClock()
    snapshot = connection(process=replace(PROCESS, name=name))
    clock.appearance(snapshot=snapshot)
    for _ in range(5):
        result = clock.appearance(300, snapshot)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.base_interval_seconds == 300
    assert Limitation.BEHAVIORAL_ONLY_LOW_SECURITY_SIGNIFICANCE in result.limitations
    assert Limitation.BENIGN_SCHEDULE_COMPATIBLE in result.limitations


def test_absolute_jitter_gate_and_multiple_normalization() -> None:
    result = evidence((9, 10, 10, 10, 11), poll=1, policy=replace(POLICY, relative_jitter=0))
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.tolerance_seconds == result.maximum_deviation_seconds == 1
    assert evidence((8.999, 10, 10, 10, 11), poll=1).classification is Classification.IRREGULAR
    result = evidence((60, 60, 60, 60, 126))
    assert result.maximum_deviation_seconds == 3
    assert result.normalized_jitter == 0.05
    assert result.classification is Classification.PERIODIC_CANDIDATE


def test_default_hard_interval_cap_and_duplicate_does_not_touch_recency() -> None:
    clock = FakeClock()
    clock.appearance()
    for _ in range(40):
        result = clock.appearance(60)
    assert result.retained_interval_count == 32
    assert Limitation.SEQUENCE_TRUNCATED in result.limitations
    clock = FakeClock(policy=replace(POLICY, maximum_scopes=2))
    event = clock.opened()
    first = clock.round((event,))[0]
    clock.appearance(5, connection(remote=Endpoint("203.0.113.9", 443)))
    clock.advance(5)
    assert clock.round((event,)) == ()
    clock.appearance(5, connection(remote=Endpoint("203.0.113.10", 443)))
    reference = ConnectionRoundObservation(SESSION, UTC_TIME, ObservationQuality.COMPLETE)
    assert clock.service.snapshot(first.scope, round_observation=reference) is None


def test_wall_clock_jumps_do_not_reset_runtime_sequence() -> None:
    clock = FakeClock()
    clock.appearance()
    for index in range(5):
        clock.utc = UTC_TIME + timedelta(days=100 if index % 2 else -100)
        result = clock.appearance(60)
    assert result.classification is Classification.PERIODIC_CANDIDATE
    assert result.base_interval_seconds == 60
    assert result.last_reset is None


@pytest.mark.parametrize("changes", [
    {"intervals": (60,) * 33}, {"intervals": [60] * 5},
    {"polling_interval_seconds": 0}, {"observed_at": datetime(2026, 10, 3)},
    {"session_id": "session"}, {"sequence_truncated": 1}, {"last_reset": "gap"},
])
def test_sequence_contract_rejects_invalid_metadata(changes: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError)):
        replace(sequence((60,) * 5), **changes)


def test_sequence_policy_capacity_and_scope_validations() -> None:
    with pytest.raises(ValueError):
        evaluate_periodicity(sequence((60,) * 6), replace(POLICY, maximum_intervals=5))
    with pytest.raises(ValueError):
        replace(scope(), process_identity=ProcessIdentity(12))
    with pytest.raises(ValueError):
        replace(scope(), behavior=replace(scope().behavior, revision_digest="invalid"))
    with pytest.raises(ValueError):
        replace(scope(), behavior=replace(scope().behavior, network_status=NetworkScopeStatus.UNKNOWN))
