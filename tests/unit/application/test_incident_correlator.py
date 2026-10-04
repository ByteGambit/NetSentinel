"""NS-089 identity, time, gap, capacity and concurrent admission acceptance."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import timedelta
from itertools import permutations
from uuid import UUID

import pytest

from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.alert_risk import AlertAssessmentReference
from netsentinel.domain.connections import ConnectionRoundObservation, NetworkScopeStatus, ObservationQuality, ProcessIdentity, TransportProtocol
from netsentinel.domain.incidents import (
    IncidentDestination, IncidentDestinationKind as D,
    IncidentCorrelationStatus as S, IncidentLimitation as L, IncidentPolicy,
    IncidentProcessRef, IncidentRelationReason as R,
)
from netsentinel.domain.risk_evidence import (
    EvidenceLimitation, EvidenceQuality, EvidenceReference, EvidenceReferenceKind,
    EvidenceScope, EvidenceScopeKind,
)
from tests.fixtures.incidents import DESTINATION, NOW, PROCESS, SCOPE, SESSION, evidence_ref, item


def test_seed_lifecycle_update_duplicate_and_stable_runtime_id():
    service = IncidentCorrelator()
    a = item()
    first = service.correlate(a)
    assert first.status is S.NEW_INCIDENT and first.reason is R.FIRST_OBSERVATION
    second = service.correlate(item(2, connection=a.connection, stamp=NOW + timedelta(minutes=1)))
    assert second.status is S.ATTACHED and second.reason is R.SAME_CONNECTION_LIFECYCLE
    assert second.incident.incident_id == first.incident.incident_id
    assert len(second.incident.connections) == 1 and len(second.incident.relations) == 2
    for _ in range(100):
        result = service.correlate(replace(a))
        assert result.status is S.DUPLICATE
    assert service.diagnostics().duplicates == 100
    assert service.snapshot() == (second.incident,)


@pytest.mark.parametrize("reference", [evidence_ref(999),
    EvidenceReference(EvidenceReferenceKind.DNS_EVIDENCE, UUID(int=999)),
    EvidenceReference(EvidenceReferenceKind.LEGACY_ARP_EVENT, "f" * 64)])
def test_exact_evidence_reference_bridges_different_process_destination_scope(reference):
    service = IncidentCorrelator()
    service.correlate(item(evidence=(reference,)))
    result = service.correlate(item(2, evidence=(reference,), process=None,
        scope=EvidenceScope(EvidenceScopeKind.HOST), destination=None, connection=None))
    assert result.status is S.ATTACHED and result.reason is R.SAME_CANONICAL_EVIDENCE
    assert reference in result.incident.evidence


def test_assessment_logical_lineage_retains_revision_pointers_without_new_occurrence():
    service = IncidentCorrelator()
    ref = AlertAssessmentReference("b" * 64, 1, NetworkScopeStatus.RESOLVED)
    service.correlate(item(assessment=ref, process=None, connection=None))
    second = item(2, assessment=replace(ref, revision=2), process=None, connection=None)
    result = service.correlate(second)
    assert result.status is S.ATTACHED and result.reason is R.SAME_ASSESSMENT_LINEAGE
    assert result.incident.assessments == (ref, second.assessment)
    assert result.incident.first_observed_at == result.incident.last_observed_at == NOW
    assert service.correlate(second).status is S.DUPLICATE


def test_exact_alert_record_links_but_distant_observation_is_separate():
    service = IncidentCorrelator()
    service.correlate(item(alert_id=UUID(int=999), process=None, connection=None))
    result = service.correlate(item(2, alert_id=UUID(int=999), process=None, connection=None))
    assert result.reason is R.SAME_ALERT_OBSERVATION
    distant = service.correlate(item(3, stamp=NOW + timedelta(minutes=11), alert_id=UUID(int=999)))
    assert distant.status is S.NEW_INCIDENT


def test_exact_process_destination_resolved_scope_attaches():
    service = IncidentCorrelator()
    service.correlate(item())
    result = service.correlate(item(2, stamp=NOW + timedelta(minutes=1)))
    assert result.status is S.ATTACHED and result.reason is R.SAME_PROCESS_AND_DESTINATION
    assert len(result.incident.connections) == 2
    assert result.incident.relations[-1].matched_key.identity.destination == DESTINATION


@pytest.mark.parametrize("changes", [
    {"process": IncidentProcessRef(SESSION, ProcessIdentity(456, PROCESS.identity.create_time))},
    {"process": IncidentProcessRef(SESSION, ProcessIdentity(123, NOW - timedelta(hours=2)))},
    {"process": IncidentProcessRef(SESSION, ProcessIdentity(123))},
    {"process": IncidentProcessRef(UUID(int=2000), PROCESS.identity), "connection": None},
    {"process": None},
    {"destination": None},
    {"destination": replace(DESTINATION, value="1.1.1.1")},
    {"destination": replace(DESTINATION, port=22)},
    {"destination": replace(DESTINATION, protocol=TransportProtocol.UDP)},
    {"destination": replace(DESTINATION, port=None)},
    {"destination": replace(DESTINATION, protocol=None)},
    {"scope": replace(SCOPE, network_fingerprint="b" * 64)},
    {"scope": EvidenceScope(EvidenceScopeKind.HOST)},
    {"scope": EvidenceScope(EvidenceScopeKind.UNKNOWN, NetworkScopeStatus.UNKNOWN)},
    {"scope": EvidenceScope(EvidenceScopeKind.UNKNOWN, NetworkScopeStatus.AMBIGUOUS)},
    {"quality": EvidenceQuality()},
    {"quality": EvidenceQuality(ObservationQuality.REDUCED)},
    {"quality": EvidenceQuality(ObservationQuality.COMPLETE, (EvidenceLimitation.MONITORING_GAP,))},
])
def test_weak_identity_scope_and_quality_never_attach(changes):
    service = IncidentCorrelator()
    service.correlate(item())
    assert service.correlate(item(2, **changes)).status is S.NEW_INCIDENT


@pytest.mark.parametrize("process", [None, IncidentProcessRef(SESSION, ProcessIdentity(123))])
@pytest.mark.parametrize("destination", [DESTINATION, IncidentDestination(D.DOMAIN, "example.com", 443, TransportProtocol.TCP)])
def test_unknown_pid_only_or_shared_domain_and_ip_never_group(process, destination):
    service = IncidentCorrelator()
    for number in range(1, 31):
        result = service.correlate(item(number, process=process, destination=destination))
        assert result.status is S.NEW_INCIDENT
    assert len(service.snapshot()) == 30


def test_unknown_everything_and_shared_network_time_are_isolated():
    service = IncidentCorrelator()
    for number in range(1, 20):
        assert service.correlate(item(number, process=None, destination=None, connection=None)).status is S.NEW_INCIDENT


@pytest.mark.parametrize("address,kind", [("8.8.8.8", D.IPV4), ("2001:db8::1", D.IPV6), ("example.com", D.DOMAIN)])
def test_typed_destination_families(address, kind):
    destination = IncidentDestination(kind, address, 443, TransportProtocol.TCP)
    service = IncidentCorrelator()
    service.correlate(item(destination=destination))
    assert service.correlate(item(2, destination=destination)).status is S.ATTACHED
    other = IncidentProcessRef(SESSION, ProcessIdentity(456, PROCESS.identity.create_time))
    assert service.correlate(item(3, process=other, destination=destination)).status is S.NEW_INCIDENT


@pytest.mark.parametrize("offset,expected", [(timedelta(minutes=10) - timedelta(microseconds=1), S.ATTACHED),
    (timedelta(minutes=10), S.NEW_INCIDENT), (timedelta(minutes=10, microseconds=1), S.NEW_INCIDENT)])
def test_frozen_window_boundary(offset, expected):
    service = IncidentCorrelator()
    service.correlate(item())
    assert service.correlate(item(2, stamp=NOW + offset)).status is expected


def test_close_observations_on_opposite_cohort_sides_are_conservatively_separate():
    service = IncidentCorrelator()
    service.correlate(item(stamp=NOW + timedelta(minutes=9, seconds=59)))
    assert service.correlate(item(2, stamp=NOW + timedelta(minutes=10))).status is S.NEW_INCIDENT


def test_sliding_chain_bridge_cannot_extend_incident_span():
    service = IncidentCorrelator()
    results = [service.correlate(item(i + 1, stamp=NOW + timedelta(minutes=minutes)))
        for i, minutes in enumerate((0, 9, 18, 27, 36))]
    assert results[0].incident.incident_id == results[1].incident.incident_id
    assert results[1].incident.incident_id != results[2].incident.incident_id
    for incident in service.snapshot():
        assert incident.last_observed_at - incident.first_observed_at <= service.policy.window


def membership(service):
    return {frozenset(relation.observation for relation in incident.relations) for incident in service.snapshot()}


def test_permutations_of_supported_out_of_order_inputs_have_equal_membership():
    # Across two cohorts, including the exact supported lateness boundary.
    inputs = [item(i + 1, stamp=NOW + timedelta(minutes=minutes)) for i, minutes in enumerate((3, 5, 11, 13))]
    expected = None
    for permutation in permutations(inputs):
        service = IncidentCorrelator()
        for value in permutation:
            assert service.correlate(value).status in (S.NEW_INCIDENT, S.ATTACHED)
        current = membership(service)
        assert len(current) == 2
        if expected is None:
            expected = current
        assert current == expected


def test_lateness_equality_extreme_late_and_event_time_expiry():
    service = IncidentCorrelator()
    service.correlate(item(stamp=NOW + timedelta(minutes=5)))
    result = service.correlate(item(2, stamp=NOW + timedelta(minutes=3)))
    assert result.status is S.ATTACHED
    assert result.incident.first_observed_at == NOW + timedelta(minutes=3)
    assert result.incident.last_observed_at == NOW + timedelta(minutes=5)
    assert service.diagnostics().out_of_order == 1
    at_boundary = service.correlate(item(3, stamp=NOW - timedelta(minutes=5)))
    assert at_boundary.status is S.NEW_INCIDENT
    state = service.snapshot()
    assert service.correlate(item(4, stamp=NOW - timedelta(minutes=5, microseconds=1))).status is S.LATE
    assert service.snapshot() == state
    service.correlate(item(5, stamp=NOW + timedelta(hours=1)))
    assert len(service.snapshot()) == 1 and service.diagnostics().expired == 2
    assert service.correlate(item()).status is S.LATE


def test_retention_horizon_equality_then_index_cleanup():
    service = IncidentCorrelator()
    original = service.correlate(item()).incident
    service.correlate(item(2, stamp=NOW + service.policy.retention_horizon))
    assert original in service.snapshot()
    service.correlate(item(3, stamp=NOW + service.policy.retention_horizon + timedelta(microseconds=1)))
    assert original not in service.snapshot()
    assert all(original.incident_id not in ids for ids in service._indexes.values())


def test_known_round_gap_breaks_derived_relation_but_exact_reference_can_bridge():
    service = IncidentCorrelator()
    first = item()
    service.correlate(first)
    assert service.observe_round(ConnectionRoundObservation(SESSION, NOW + timedelta(minutes=1), ObservationQuality.FAILED))
    second = service.correlate(item(2, stamp=NOW + timedelta(minutes=2)))
    assert second.status is S.NEW_INCIDENT
    third = service.correlate(item(3, stamp=NOW + timedelta(minutes=2), connection=first.connection))
    assert third.reason is R.SAME_CONNECTION_LIFECYCLE
    assert L.CANONICAL_GAP_BRIDGE in third.limitations and L.MONITORING_GAP in third.limitations
    assert service.diagnostics().gap_separated >= 1


def test_gap_evidence_exact_link_and_out_of_order_round_marker():
    service = IncidentCorrelator()
    shared = evidence_ref(999)
    service.correlate(item(stamp=NOW + timedelta(minutes=5), evidence=(shared,)))
    service.observe_round(ConnectionRoundObservation(SESSION, NOW + timedelta(minutes=4), ObservationQuality.REDUCED))
    result = service.correlate(item(2, stamp=NOW + timedelta(minutes=3), evidence=(shared,)))
    assert result.reason is R.SAME_CANONICAL_EVIDENCE and L.CANONICAL_GAP_BRIDGE in result.limitations


def test_round_duplicates_complete_round_gap_capacity_and_expiry_are_bounded():
    service = IncidentCorrelator(IncidentPolicy(max_gaps=1))
    gap = ConnectionRoundObservation(SESSION, NOW + timedelta(minutes=1), ObservationQuality.REDUCED)
    service.correlate(item())
    assert service.observe_round(gap) and service.observe_round(gap)
    assert service.observe_round(replace(gap, quality=ObservationQuality.COMPLETE))
    assert not service.observe_round(replace(gap, observed_at=NOW + timedelta(minutes=2)))
    result = service.correlate(item(2, stamp=NOW + timedelta(minutes=3)))
    assert result.status is S.NEW_INCIDENT and L.GAP_CAPACITY in result.limitations
    assert service.diagnostics().gap_markers == 1
    service.correlate(item(3, stamp=NOW + timedelta(hours=1)))
    assert service.diagnostics().gap_markers == 0
    assert not service.observe_round(gap)


def test_known_late_gap_adds_limitation_without_retroactive_union_or_split():
    service = IncidentCorrelator()
    service.correlate(item())
    service.correlate(item(2, stamp=NOW + timedelta(minutes=2)))
    before = membership(service)
    service.observe_round(ConnectionRoundObservation(SESSION, NOW + timedelta(minutes=1), ObservationQuality.FAILED))
    assert membership(service) == before
    assert L.MONITORING_GAP in service.snapshot()[0].limitations


@pytest.mark.parametrize("limit,value", [("max_processes", 1), ("max_connections", 1), ("max_destinations", 1),
    ("max_evidence", 2), ("max_alerts", 1), ("max_assessments", 1), ("max_scopes", 1),
    ("max_relations", 1), ("max_keys_per_incident", 6), ("max_index_entries", 7)])
def test_each_reference_relation_and_index_capacity_is_atomic(limit, value):
    service = IncidentCorrelator(replace(IncidentPolicy(), **{limit: value}))
    shared = evidence_ref(999)
    first = item(evidence=(shared,), assessment=AlertAssessmentReference("b" * 64, 1, NetworkScopeStatus.RESOLVED), alert_id=UUID(int=101))
    assert service.correlate(first).status is S.NEW_INCIDENT
    before = service.snapshot()[0]
    index_entries = service.diagnostics().index_entries
    second = item(2, evidence=(shared,), process=IncidentProcessRef(SESSION, ProcessIdentity(456, PROCESS.identity.create_time)),
        destination=replace(DESTINATION, value="1.1.1.1"), scope=replace(SCOPE, network_fingerprint="c" * 64),
        assessment=replace(first.assessment, revision=2), alert_id=UUID(int=102))
    result = service.correlate(second)
    assert result.status is S.CAPACITY_LIMITED and L.CAPACITY_LIMITED in result.incident.limitations
    assert replace(result.incident, limitations=before.limitations) == before
    assert service.diagnostics().index_entries == index_entries
    assert second.observation not in service._observations
    assert service.correlate(first).status is S.DUPLICATE


def test_new_input_capacity_rejection_does_not_evict_existing_incident():
    service = IncidentCorrelator(IncidentPolicy(max_incidents=1, max_evidence=1))
    service.correlate(item())
    before = service.snapshot()
    result = service.correlate(item(2, evidence=(evidence_ref(999),), process=None))
    assert result.status is S.CAPACITY_LIMITED and result.incident is None
    assert service.snapshot() == before and service.diagnostics().evictions == 0


def test_incident_capacity_oldest_eviction_cleans_all_indexes_and_dedup():
    service = IncidentCorrelator(IncidentPolicy(max_incidents=2))
    first = item(process=None)
    original = service.correlate(first).incident
    service.correlate(item(2, stamp=NOW + timedelta(seconds=1), process=None))
    service.correlate(item(3, stamp=NOW + timedelta(seconds=2), process=None))
    assert original not in service.snapshot() and service.diagnostics().evictions == 1
    assert all(original.incident_id not in ids for ids in service._indexes.values())
    assert first.observation not in service._observations
    assert service.correlate(first).status is S.NEW_INCIDENT
    assert len(service.snapshot()) == 2


def test_eviction_ties_are_deterministic_across_runtime_ids():
    service = IncidentCorrelator(IncidentPolicy(max_incidents=2))
    a = service.correlate(item(process=None)).incident
    b = service.correlate(item(2, process=None)).incident
    service.correlate(item(3, process=None))
    assert a.incident_id not in {s.incident_id for s in service.snapshot()}
    assert b.incident_id in {s.incident_id for s in service.snapshot()}


def test_priority_multimatch_is_explicit_and_does_not_union_incidents():
    service = IncidentCorrelator()
    a = service.correlate(item()).incident
    b = service.correlate(item(2, process=None)).incident
    bridge = item(3, connection=b.connections[0])  # B exact lifecycle, A process+destination
    result = service.correlate(bridge)
    assert result.incident.incident_id == b.incident_id and result.reason is R.SAME_CONNECTION_LIFECYCLE
    assert L.AMBIGUOUS_MATCH in result.limitations
    assert len(service.snapshot()) == 2
    assert next(i for i in service.snapshot() if i.incident_id == a.incident_id) == a


def test_equal_multimatch_tiebreak_is_canonical_observation_and_no_union():
    service = IncidentCorrelator()
    a = service.correlate(item(process=None)).incident
    service.correlate(item(2, process=None))
    result = service.correlate(item(3, process=None, evidence=(evidence_ref(1), evidence_ref(2))))
    assert result.incident.incident_id == a.incident_id
    assert L.AMBIGUOUS_MATCH in result.limitations and len(service.snapshot()) == 2


def test_no_synthesized_process_destination_cross_product_from_aggregate():
    service = IncidentCorrelator()
    shared = evidence_ref(999)
    other_process = IncidentProcessRef(SESSION, ProcessIdentity(456, PROCESS.identity.create_time))
    other_destination = replace(DESTINATION, value="1.1.1.1")
    service.correlate(item(evidence=(shared,)))
    service.correlate(item(2, evidence=(shared,), process=other_process, destination=other_destination))
    assert service.correlate(item(3, destination=other_destination)).status is S.NEW_INCIDENT


def test_concurrent_duplicate_and_distinct_inputs_serialize_and_snapshots_do_not_leak():
    service = IncidentCorrelator()
    first = item()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(service.correlate, [first] * 64))
    assert sum(r.status is S.NEW_INCIDENT for r in results) == 1
    assert sum(r.status is S.DUPLICATE for r in results) == 63
    saved = service.snapshot()[0]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(service.correlate, [item(i) for i in range(2, 17)]))
    assert all(r.status is S.ATTACHED for r in results)
    assert len(service.snapshot()[0].relations) == 16 and len(saved.relations) == 1
    with pytest.raises(FrozenInstanceError):
        saved.last_observed_at = NOW + timedelta(hours=1)
    assert isinstance(service.snapshot(), tuple) and isinstance(saved.evidence, tuple)


def test_diagnostics_are_aggregate_and_restart_has_no_memory_continuity():
    service = IncidentCorrelator()
    service.correlate(item())
    assert all(type(value) is int for value in asdict(service.diagnostics()).values())
    restarted = IncidentCorrelator()
    assert restarted.snapshot() == ()
    assert restarted.correlate(item()).incident.incident_id != service.snapshot()[0].incident_id
