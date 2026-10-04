"""NS-090 persistence of existing assessment/TI output, without live providers."""

import pytest

from netsentinel.application.services.incident_inputs import incident_input_from_assessment
from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.incident_persistence import IncidentStatus
from netsentinel.domain.threat_intelligence import ThreatIntelResultStatus
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from tests.integration.test_risk_alert_pipeline import Harness
from tests.integration.test_threat_intel_evidence import enrich, initial


@pytest.mark.parametrize("alert_state", list(AlertStatus))
@pytest.mark.parametrize("ti_status", [ThreatIntelResultStatus.HIT, ThreatIntelResultStatus.NO_HIT])
def test_real_ti_revision_persists_original_time_and_preserves_alert_state(tmp_path, alert_state, ti_status):
    path = tmp_path / "durable.db"
    harness = Harness(path)
    original = initial(harness)
    harness.alerts.set_status(original.alert.id, alert_state, original.alert.last_seen)
    before = harness.alerts.get(original.alert.id)
    service = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(path)))
    first = incident_input_from_assessment(original.assessment.revision)
    saved = service.observe(first, now=original.assessment.revision.assessed_at)
    assert saved.status is IncidentStatus.CHANGED
    revised = enrich(harness, status=ti_status).assessment.revision
    value = incident_input_from_assessment(revised)
    result = service.append(saved.record.incident_id, value, now=revised.assessed_at)
    assert result.status is IncidentStatus.CHANGED
    assert result.record.snapshot.first_observed_at == result.record.snapshot.last_observed_at == first.observed_at
    assert len(result.record.snapshot.assessments) == 2
    restarted = IncidentPersistenceService(SQLiteIncidentRepository(SQLiteDatabase(path)))
    assert restarted.get(saved.record.incident_id).record == result.record
    assert restarted.append(saved.record.incident_id, value, now=revised.assessed_at).status is IncidentStatus.NO_CHANGE
    after = harness.alerts.get(original.alert.id)
    for field in ("status", "occurrence_count", "first_seen", "last_seen", "fingerprint", "last_notified_at"):
        assert getattr(after, field) == getattr(before, field)
