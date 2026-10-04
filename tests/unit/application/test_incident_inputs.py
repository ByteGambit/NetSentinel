"""Existing NS-056/063/076/078 types cross the incident boundary without payloads."""

from dataclasses import fields, replace
from datetime import timedelta
from uuid import UUID

import pytest

from netsentinel.application.services.incident_inputs import (
    incident_input_from_assessment, incident_input_from_connection, incident_input_from_evidence,
)
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.connections import (
    ConnectionClosed, ConnectionNetworkScope, ConnectionOpened, ConnectionSnapshot,
    ConnectionState, ConnectionUpdated, Endpoint, NetworkAttributionMethod, NetworkScopeStatus,
    ObservationOrigin, ProcessInfo, ProcessInfoStatus, TransportProtocol,
)
from netsentinel.domain.dns import DnsEvidenceId
from netsentinel.domain.incidents import IncidentCorrelationStatus as S, IncidentObservationKind as K
from netsentinel.domain.risk_assessment import RiskAssessmentRevision
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind as RK
from tests.fixtures.incidents import NOW, PROCESS, QUALITY, SESSION
from tests.fixtures.risk_assessments import evidence, key, snapshot


def connection_snapshot(stamp=NOW):
    return ConnectionSnapshot(TransportProtocol.TCP, Endpoint("192.0.2.10", 50000),
        Endpoint("8.8.8.8", 443), ConnectionState.ESTABLISHED,
        ProcessInfo(ProcessInfoStatus.AVAILABLE, PROCESS.identity, "browser.exe"), stamp,
        ConnectionNetworkScope(
            # Use the existing attribution contract, not a fake network sentinel.
            NetworkScopeStatus.RESOLVED, "a" * 64, "test-interface", 1,
            NetworkAttributionMethod.LOCAL_ADDRESS_MATCH))


def test_initial_snapshot_observed_update_close_reuses_lifecycle_and_never_infers_creation():
    original = connection_snapshot()
    opened = ConnectionOpened(original, ObservationOrigin.INITIAL, SESSION, UUID(int=1))
    current = replace(original, observed_at=NOW + timedelta(minutes=1), state=ConnectionState.CLOSE_WAIT)
    updated = ConnectionUpdated(original, current, SESSION, UUID(int=1))
    closed = ConnectionClosed(current, NOW + timedelta(minutes=2), session_id=SESSION, lifecycle_id=UUID(int=1))
    values = [incident_input_from_connection(event, QUALITY) for event in (opened, updated, closed)]
    assert [value.observation.kind for value in values] == [K.CONNECTION_OBSERVED, K.CONNECTION_UPDATED, K.CONNECTION_NOT_OBSERVED]
    assert [value.observed_at for value in values] == [NOW, current.observed_at, closed.occurred_at]
    assert all(value.process.identity == PROCESS.identity and value.connection.lifecycle_id == UUID(int=1) for value in values)
    service = IncidentCorrelator()
    assert [service.correlate(value).status for value in values] == [S.NEW_INCIDENT, S.ATTACHED, S.ATTACHED]
    assert service.correlate(incident_input_from_connection(opened, QUALITY)).status is S.DUPLICATE


def test_tuple_reuse_after_restart_or_unknown_instance_has_distinct_lifecycle():
    original = replace(connection_snapshot(), process=ProcessInfo.unavailable())
    first = ConnectionOpened(original, session_id=SESSION, lifecycle_id=UUID(int=1))
    second = ConnectionOpened(original, session_id=SESSION, lifecycle_id=UUID(int=2))
    assert first.key == second.key
    service = IncidentCorrelator()
    assert service.correlate(incident_input_from_connection(first)).status is S.NEW_INCIDENT
    assert service.correlate(incident_input_from_connection(second)).status is S.NEW_INCIDENT
    assert service.snapshot()[0].processes == ()


def test_metadata_changes_are_not_identity_or_causal_keys():
    original = connection_snapshot()
    changed = replace(original, process=replace(original.process, name="renamed.exe"))
    a = incident_input_from_connection(ConnectionOpened(original, session_id=SESSION, lifecycle_id=UUID(int=1)))
    b = incident_input_from_connection(ConnectionOpened(changed, session_id=SESSION, lifecycle_id=UUID(int=1)))
    assert a == b
    assert "name" not in {field.name for field in fields(a.process)}


def test_dns_origin_reference_is_retained_without_domain_or_ip_inference():
    dns = DnsEvidenceId(UUID(int=1234))
    source = evidence(observed_at=NOW, references=(EvidenceReference(RK.DNS_EVIDENCE, dns.value),))
    result = incident_input_from_evidence(source)
    assert EvidenceReference(RK.DNS_EVIDENCE, dns.value) in result.evidence
    assert result.destination.value == source.subject.ip_address
    assert result.destination.port is None and result.destination.protocol is None
    assert result.connection is None and result.process is None
    service = IncidentCorrelator()
    service.correlate(result)
    # New envelope, same origin DNS result: exact reference, not domain/IP equality.
    assert service.correlate(incident_input_from_evidence(replace(source, reason_code="other_context"))).status is S.ATTACHED


def test_generic_evidence_extracts_exact_session_lifecycle_only_when_unambiguous():
    refs = (EvidenceReference(RK.MONITORING_SESSION, SESSION), EvidenceReference(RK.CONNECTION_LIFECYCLE, UUID(int=1)))
    source = evidence(observed_at=NOW, references=refs)
    result = incident_input_from_evidence(source)
    assert result.connection.session_id == SESSION and result.connection.lifecycle_id == UUID(int=1)
    assert not any(ref.kind is RK.MONITORING_SESSION for ref in result.evidence)
    ambiguous = replace(source, references=(*refs, EvidenceReference(RK.CONNECTION_LIFECYCLE, UUID(int=2))))
    assert incident_input_from_evidence(ambiguous).connection is None


def test_same_application_and_ip_different_process_instances_do_not_merge():
    from netsentinel.domain.risk_evidence import EvidenceSubject, EvidenceSubjectKind
    from tests.fixtures.risk_assessments import APP
    service = IncidentCorrelator()
    for index in (1, 2):
        subject = EvidenceSubject(EvidenceSubjectKind.DESTINATION, application=APP,
            process=replace(PROCESS.identity, pid=index), session_id=SESSION, ip_address="8.8.8.8")
        source = evidence(observed_at=NOW, subject=subject)
        assert service.correlate(incident_input_from_evidence(source)).status is S.NEW_INCIDENT
    assert len(service.snapshot()) == 2


def test_assessment_adapter_keeps_original_time_and_revision_reference_only():
    logical = key(original_observed_at=NOW)
    first = RiskAssessmentRevision(logical, 1, NOW, snapshot())
    second = replace(first, revision=2, assessed_at=NOW + timedelta(days=1))
    a, b = [incident_input_from_assessment(revision) for revision in (first, second)]
    assert a.observed_at == b.observed_at == NOW
    assert b.assessment.assessment_id == logical.assessment_id and b.assessment.revision == 2
    assert not hasattr(b, "snapshot") and not hasattr(b, "score")
    service = IncidentCorrelator()
    initial = service.correlate(a)
    revised = service.correlate(b)
    assert revised.status is S.ATTACHED and revised.incident.incident_id == initial.incident.incident_id
    assert revised.incident.last_observed_at == NOW


@pytest.mark.parametrize("adapter", [incident_input_from_connection, incident_input_from_evidence, incident_input_from_assessment])
def test_adapters_reject_arbitrary_objects(adapter):
    with pytest.raises(TypeError):
        adapter({"ip": "8.8.8.8"})
