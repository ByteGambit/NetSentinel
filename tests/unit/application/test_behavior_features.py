"""NS-070 deterministic feature and quality contracts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from netsentinel.application.services.application_identity import resolve_application_scope
from netsentinel.application.services.behavior_features import BehaviorCapacity, BehaviorFeatureAccumulator
from netsentinel.application.services.connections import ConnectionTrackingService
from netsentinel.domain.application_identity import ApplicationRevision, ApplicationScope
from netsentinel.domain.connections import (
    ConnectionNetworkScope,
    ConnectionOpened,
    ConnectionRoundObservation,
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    NetworkAttributionMethod,
    NetworkScopeStatus,
    ObservationOrigin,
    ObservationQuality,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.domain.executable_hash import ExecutableHashStatus


UTC_START = datetime(2026, 10, 3, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.tick = 0.0

    def __call__(self) -> float:
        return self.tick


def process(path: str | None = r"C:\Apps\browser.exe", pid: int = 7) -> ProcessInfo:
    return ProcessInfo(
        ProcessInfoStatus.AVAILABLE,
        ProcessIdentity(pid, UTC_START - timedelta(hours=1)),
        "browser.exe",
        executable_path=path,
    )


def scope(fingerprint: str = "a" * 64) -> ConnectionNetworkScope:
    return ConnectionNetworkScope(
        NetworkScopeStatus.RESOLVED, fingerprint, "if-1", 1,
        NetworkAttributionMethod.LOCAL_ADDRESS_MATCH,
    )


def opened(
    session, *, ip: str = "203.0.113.1", port: int = 443,
    application: ProcessInfo | None = None,
    network: ConnectionNetworkScope | None = None,
    origin: ObservationOrigin = ObservationOrigin.OBSERVED,
    remote: bool = True,
    protocol: TransportProtocol = TransportProtocol.TCP,
) -> ConnectionOpened:
    local = "2001:db8::1" if ":" in ip else "192.0.2.1"
    return ConnectionOpened(
        ConnectionSnapshot(
            protocol, Endpoint(local, 50000), Endpoint(ip, port) if remote else None,
            ConnectionState.ESTABLISHED if protocol is TransportProtocol.TCP else ConnectionState.NONE,
            application or process(), UTC_START,
            network or scope(),
        ),
        origin=origin, session_id=session,
    )


def round_at(session, quality: ObservationQuality = ObservationQuality.COMPLETE, utc=UTC_START):
    return ConnectionRoundObservation(session, utc, quality)


def test_initial_update_close_failed_and_gap_do_not_inflate_appearances() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    session = uuid4()
    first = opened(session, origin=ObservationOrigin.INITIAL)
    acc.observe_round(round_at(session), (first,), (first.snapshot,))
    assert acc.snapshot().scopes[0].observed_appearances == 0
    clock.tick = 1
    acc.observe_round(round_at(session), (opened(session),), (first.snapshot,))
    clock.tick = 2
    acc.observe_round(round_at(session), snapshots=(first.snapshot,))
    clock.tick = 3
    acc.observe_round(round_at(session, ObservationQuality.FAILED), (opened(session, ip="203.0.113.2"),))
    clock.tick = 30
    acc.observe_round(round_at(session), snapshots=(first.snapshot,))
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 1
    assert result.monitored_seconds == 2
    assert result.gap_seen
    assert result.destination_diversity == 1


def test_hundred_initial_connections_create_no_feature_counts() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    session = uuid4()
    initial = tuple(
        opened(session, ip=f"203.0.113.{index + 1}", origin=ObservationOrigin.INITIAL)
        for index in range(100)
    )
    acc.observe_round(round_at(session), initial, (event.snapshot for event in initial))
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 0
    assert result.destinations == ()
    assert result.destination_diversity == 0
    assert not result.capacity_loss


def test_reduced_counts_only_real_appearances_without_coverage() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    session = uuid4()
    acc.observe_round(round_at(session), (opened(session),))
    clock.tick = 1
    acc.observe_round(round_at(session, ObservationQuality.REDUCED), (opened(session, ip="2001:db8::2", protocol=TransportProtocol.UDP),))
    clock.tick = 2
    acc.observe_round(round_at(session))
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 2
    assert result.reduced_appearances == 1
    assert result.monitored_seconds == 0
    assert result.gap_seen
    assert result.destination_diversity == 2
    assert result.protocol_diversity == 2


def test_feature_caps_other_and_deterministic_order() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(
        monotonic_clock=clock,
        capacity=BehaviorCapacity(destinations=1, ports=1, protocols=1),
    )
    session = uuid4()
    events = (
        opened(session, ip="203.0.113.1", port=80),
        opened(session, ip="203.0.113.2", port=443, protocol=TransportProtocol.UDP),
    )
    acc.observe_round(round_at(session), events)
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 2
    assert result.destination_diversity == result.port_diversity == result.protocol_diversity == 1
    assert (result.other_destinations, result.other_ports, result.other_protocols) == (1, 1, 1)
    assert result.capacity_loss
    assert result.destinations[0].value == "203.0.113.1"


def test_scope_churn_eviction_and_unknown_network_isolation() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(
        monotonic_clock=clock,
        capacity=BehaviorCapacity(applications=2, networks_per_application=1, scopes=2),
    )
    session = uuid4()
    acc.observe_round(round_at(session), (opened(session, network=ConnectionNetworkScope.unknown()),))
    clock.tick = 1
    acc.observe_round(round_at(session), (opened(session, network=scope()),))
    snapshot = acc.snapshot()
    assert snapshot.evicted_scopes == 1
    assert len(snapshot.scopes) == 1
    assert snapshot.scopes[0].scope.network_status is NetworkScopeStatus.RESOLVED
    assert snapshot.scopes[0].capacity_loss
    clock.tick = 2
    acc.observe_round(round_at(session), (opened(session, application=process(pid=8), network=scope("b" * 64)),))
    assert len(acc.snapshot().scopes) == 1  # same path, network cap


def test_revision_unknown_and_known_hashes_do_not_merge() -> None:
    clock = Clock()
    digest = [None]

    def resolver(info: ProcessInfo) -> ApplicationScope:
        base = resolve_application_scope(info)
        return replace(base, revision=ApplicationRevision(
            digest[0], ExecutableHashStatus.AVAILABLE if digest[0] else None,
        ))

    acc = BehaviorFeatureAccumulator(monotonic_clock=clock, application_scope_resolver=resolver)
    session = uuid4()
    for index, value in enumerate((None, "a" * 64, "a" * 64, "b" * 64)):
        digest[0] = value
        clock.tick = index
        acc.observe_round(round_at(session), (opened(session, ip=f"203.0.113.{index + 1}"),))
    results = acc.snapshot().scopes
    assert len(results) == 3
    assert sorted(item.observed_appearances for item in results) == [1, 1, 2]
    assert results[0].scope.identity_restart_stable


def test_bucket_rotation_sleep_and_wall_clock_changes() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(
        monotonic_clock=clock,
        capacity=BehaviorCapacity(bucket_seconds=2, bucket_count=3),
    )
    session = uuid4()
    first = opened(session)
    acc.observe_round(round_at(session), (first,), (first.snapshot,))
    clock.tick = 1
    acc.observe_round(round_at(session, utc=UTC_START - timedelta(days=1)), snapshots=(first.snapshot,))
    assert acc.snapshot().scopes[0].monitored_seconds == 1
    clock.tick = 10_000
    acc.observe_round(round_at(session, utc=UTC_START + timedelta(days=1)), (opened(session, ip="203.0.113.2"),))
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 1
    assert result.monitored_seconds == 0
    assert result.gap_seen
    assert len(acc._scopes[next(iter(acc._scopes))].buckets) <= 3


def test_monitored_time_does_not_cross_networks() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    session = uuid4()
    home = opened(session, network=scope("a" * 64)).snapshot
    office = opened(session, network=scope("b" * 64)).snapshot
    acc.observe_round(round_at(session), snapshots=(home,))
    clock.tick = 1
    acc.observe_round(round_at(session), snapshots=(home,))
    clock.tick = 2
    acc.observe_round(round_at(session), snapshots=(office,))
    clock.tick = 3
    acc.observe_round(round_at(session), snapshots=(office,))
    results = {item.scope.network_token: item.monitored_seconds for item in acc.snapshot().scopes}
    assert results == {"a" * 64: 1, "b" * 64: 1}


def test_capacity_validation() -> None:
    with pytest.raises(ValueError):
        BehaviorCapacity(scopes=0)


def test_tracker_lifecycle_reappearance_and_long_lived_flow() -> None:
    clock = Clock()
    tracker = ConnectionTrackingService(clock=lambda: UTC_START)
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    first = opened(tracker.session_id).snapshot
    for tick, snapshots in (
        (0, (first,)),
        (1, (replace(first, observed_at=UTC_START + timedelta(seconds=1)),)),
        (2, ()),
        (3, (replace(first, observed_at=UTC_START + timedelta(seconds=3)),)),
        (4, (replace(first, observed_at=UTC_START + timedelta(seconds=4)),)),
        (5, ()),
        (6, (replace(first, observed_at=UTC_START + timedelta(seconds=6)),)),
    ):
        clock.tick = tick
        events = tracker.track(snapshots, observed_at=UTC_START + timedelta(seconds=tick))
        assert tracker.last_round is not None
        acc.observe_round(tracker.last_round, events, snapshots)
    assert acc.snapshot().scopes[0].observed_appearances == 2


def test_identity_and_network_scopes_remain_separate() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(monotonic_clock=clock)
    session = uuid4()
    events = (
        opened(session, application=process(pid=7), network=scope("a" * 64)),
        opened(session, application=process(pid=8), network=scope("a" * 64)),
        opened(session, application=process(r"C:\Apps\other.exe"), network=scope("a" * 64)),
        opened(session, application=process(), network=scope("b" * 64)),
        opened(session, application=process(), network=ConnectionNetworkScope.unknown()),
        opened(session, application=process(), network=ConnectionNetworkScope.ambiguous()),
    )
    acc.observe_round(round_at(session), events)
    snapshots = acc.snapshot().scopes
    assert len(snapshots) == 5
    assert sorted(item.observed_appearances for item in snapshots) == [1, 1, 1, 1, 2]
    assert {item.scope.network_status for item in snapshots} == {
        NetworkScopeStatus.RESOLVED, NetworkScopeStatus.UNKNOWN,
        NetworkScopeStatus.AMBIGUOUS,
    }
    assert all(not item.scope.identity_restart_stable for item in snapshots if item.scope.network_status is not NetworkScopeStatus.RESOLVED)


def test_provisional_instances_unknown_remote_and_burst_bounded() -> None:
    clock = Clock()
    acc = BehaviorFeatureAccumulator(
        monotonic_clock=clock,
        capacity=BehaviorCapacity(applications=2, networks_per_application=2, scopes=2, destinations=3, ports=2),
    )
    session = uuid4()
    events = tuple(
        opened(session, ip=f"203.0.113.{index + 1}", port=100 + index)
        for index in range(50)
    )
    acc.observe_round(round_at(session), events)
    result = acc.snapshot().scopes[0]
    assert result.observed_appearances == 50
    assert result.destination_diversity == 3
    assert result.port_diversity == 2
    assert result.other_destinations == 47
    assert result.other_ports == 48
    clock.tick = 1
    acc.observe_round(round_at(session), (opened(session, remote=False),))
    assert acc.snapshot().scopes[0].unknown_destinations == 1
    for pid in (10, 11, 12):
        clock.tick += 1
        acc.observe_round(round_at(session), (opened(session, application=process(None, pid)),))
    snapshot = acc.snapshot()
    assert len(snapshot.scopes) <= 2
    assert snapshot.evicted_scopes >= 1
    assert all(not item.scope.identity_restart_stable for item in snapshot.scopes if item.scope.application_key.startswith("instance:"))
