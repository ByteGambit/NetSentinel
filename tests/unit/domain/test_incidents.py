"""NS-089 portable identities, input limits and observation-only semantics."""

import ast
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from netsentinel.domain.connections import Endpoint, TransportProtocol
from netsentinel.domain.incidents import (
    IncidentConnectionRef, IncidentCorrelationKey, IncidentDestination,
    IncidentDestinationKind as D, IncidentInput, IncidentObservationKind,
    IncidentObservationRef, IncidentPolicy, IncidentProcessRef, IncidentRelation,
    IncidentRelationReason as R,
)
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind
from tests.fixtures.incidents import DESTINATION, NOW, PROCESS, evidence_ref, item


@pytest.mark.parametrize("field", [f.name for f in fields(IncidentPolicy) if f.name.startswith("max_") and f.name != "max_lateness"])
@pytest.mark.parametrize("mode", ["zero", "bool", "too_large"])
def test_policy_hard_capacity_bounds(field, mode):
    default = getattr(IncidentPolicy(), field)
    value = {"zero": 0, "bool": True, "too_large": default + 1}[mode]
    with pytest.raises(ValueError):
        replace(IncidentPolicy(), **{field: value})


@pytest.mark.parametrize("changes", [{"window": timedelta(0)}, {"window": timedelta(minutes=11)},
    {"window": 600}, {"max_lateness": timedelta(seconds=-1)}, {"max_lateness": timedelta(minutes=11)}])
def test_policy_temporal_bounds(changes):
    with pytest.raises(ValueError):
        replace(IncidentPolicy(), **changes)


@pytest.mark.parametrize("stamp", [NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=3)))])
def test_timestamps_require_utc(stamp):
    with pytest.raises(ValueError):
        replace(item().observation, observed_at=stamp)


@pytest.mark.parametrize("kind,value,expected", [(D.IPV4, "8.8.8.8", "8.8.8.8"),
    (D.IPV6, "2001:0db8:0000::1", "2001:db8::1"), (D.DOMAIN, "Example.COM", "example.com.")])
def test_destination_canonical_identity(kind, value, expected):
    result = IncidentDestination(kind, value, 443, TransportProtocol.TCP)
    assert result.value == expected
    assert result.port == 443 and result.protocol is TransportProtocol.TCP
    assert result != replace(result, port=22)
    assert result != replace(result, protocol=TransportProtocol.UDP)


@pytest.mark.parametrize("kind,value", [(D.IPV4, "2001:db8::1"), (D.IPV6, "8.8.8.8"),
    (D.DOMAIN, "https://example.com"), (D.DOMAIN, "a" * 256), (D.IPV6, "fe80::1%eth0")])
def test_invalid_destinations(kind, value):
    with pytest.raises(ValueError):
        IncidentDestination(kind, value)


def test_ip_and_domain_names_are_distinct_and_endpoint_reuses_existing_identity():
    assert IncidentDestination(D.DOMAIN, "8.8.8.8") != IncidentDestination(D.IPV4, "8.8.8.8")
    assert IncidentDestination.from_endpoint(Endpoint("8.8.8.8", 443), TransportProtocol.TCP) == DESTINATION


@pytest.mark.parametrize("port", [-1, 65536, True, "443"])
def test_invalid_ports(port):
    with pytest.raises(ValueError):
        replace(DESTINATION, port=port)


def test_reference_types_sessions_and_input_consistency():
    with pytest.raises(TypeError):
        IncidentConnectionRef("session", UUID(int=1))
    with pytest.raises(TypeError):
        IncidentProcessRef(UUID(int=1), "process")
    with pytest.raises(ValueError):
        replace(item(), connection=IncidentConnectionRef(UUID(int=2), UUID(int=1)))
    with pytest.raises(TypeError):
        IncidentObservationRef(IncidentObservationKind.CONNECTION_OBSERVED, UUID(int=1), NOW)
    with pytest.raises(ValueError):
        IncidentInput(IncidentObservationRef(IncidentObservationKind.CONNECTION_OBSERVED,
            item().connection, NOW), item().scope)


def test_canonical_evidence_types_and_hard_input_bounds():
    with pytest.raises(ValueError):
        replace(item(), evidence=(evidence_ref(1), evidence_ref(1)))
    with pytest.raises(ValueError):
        replace(item(), evidence=tuple(evidence_ref(i) for i in range(65)))
    with pytest.raises(ValueError):
        replace(item(), evidence=())
    with pytest.raises(ValueError):
        replace(item(), evidence=(EvidenceReference(EvidenceReferenceKind.MONITORING_SESSION, UUID(int=1)),))
    with pytest.raises(ValueError):
        replace(item(), evidence=[evidence_ref(1)])


def test_relation_must_explain_typed_matching_key():
    with pytest.raises(TypeError):
        IncidentCorrelationKey(R.SAME_CONNECTION_LIFECYCLE, "connection")
    with pytest.raises(ValueError):
        IncidentCorrelationKey(R.SAME_ASSESSMENT_LINEAGE, "not-a-digest")
    with pytest.raises(ValueError):
        IncidentRelation(item().observation, R.SAME_CONNECTION_LIFECYCLE)
    with pytest.raises(ValueError):
        IncidentRelation(item().observation, R.FIRST_OBSERVATION,
            IncidentCorrelationKey(R.SAME_CANONICAL_EVIDENCE, evidence_ref(1)))


def test_closed_input_contract_has_no_weak_keys_or_created_inference():
    names = {f.name for f in fields(IncidentInput)}
    assert names == {"observation", "scope", "process", "connection", "destination", "evidence", "assessment", "alert_id", "quality"}
    assert all("created" not in kind.value and "started" not in kind.value for kind in IncidentObservationKind)
    assert "same_ip" not in {reason.value for reason in R}
    with pytest.raises(FrozenInstanceError):
        PROCESS.session_id = UUID(int=2)
    with pytest.raises(FrozenInstanceError):
        item().scope = None


def test_domain_and_service_import_boundaries():
    root = Path(__file__).resolve().parents[3] / "src/netsentinel"
    for path in (root / "domain/incidents.py", root / "application/services/incidents.py",
                 root / "application/services/incident_inputs.py"):
        modules = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
        assert not any(m.startswith(("sqlite3", "PyQt6", "psutil", "scapy", "socket", "urllib",
            "netsentinel.infrastructure", "netsentinel.presentation")) for m in modules)
        if path.name == "incidents.py" and path.parent.name == "domain":
            assert not any(m.startswith(("threading", "netsentinel.application")) for m in modules)
