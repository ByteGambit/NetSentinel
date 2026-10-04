"""NS-089 explicit boundary on real existing offline risk/TI reassessment output."""

import pytest

from netsentinel.application.services.incident_inputs import incident_input_from_assessment
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.incidents import IncidentCorrelationStatus as S
from netsentinel.domain.threat_intelligence import ThreatIntelResultStatus
from tests.integration.test_threat_intel_evidence import initial, enrich
from tests.integration.test_risk_alert_pipeline import Harness


@pytest.mark.parametrize("status", list(AlertStatus))
@pytest.mark.parametrize("ti_status", [ThreatIntelResultStatus.HIT, ThreatIntelResultStatus.NO_HIT])
def test_ti_revision_attaches_original_lineage_without_alert_or_observation_mutation(tmp_path, status, ti_status):
    harness = Harness(tmp_path / "existing-risk.sqlite3")
    first = initial(harness)
    harness.alerts.set_status(first.alert.id, status, first.alert.last_seen)
    before = harness.alerts.get(first.alert.id)
    service = IncidentCorrelator()
    original_revision = first.assessment.revision
    original = service.correlate(incident_input_from_assessment(original_revision))
    revised = enrich(harness, status=ti_status).assessment.revision
    assert revised.revision == 2 and revised.format_version == 2
    result = service.correlate(incident_input_from_assessment(revised))
    assert result.status is S.ATTACHED
    assert result.incident.incident_id == original.incident.incident_id
    assert result.incident.first_observed_at == result.incident.last_observed_at == original_revision.key.original_observed_at
    assert len(service.snapshot()) == 1
    assert service.correlate(incident_input_from_assessment(revised)).status is S.DUPLICATE
    after = harness.alerts.get(before.id)
    for field in ("status", "occurrence_count", "first_seen", "last_seen", "fingerprint", "severity", "confidence"):
        assert getattr(before, field) == getattr(after, field)
    assert revised.snapshot.score == original_revision.snapshot.score
    assert not hasattr(result.incident, "threat_intelligence")
