"""NS-091 bounded offline story with precise polling and lifecycle timestamps."""

from datetime import timedelta
from netsentinel.application.services.incidents import IncidentCorrelator
from netsentinel.application.services.incident_persistence import IncidentPersistenceService
from netsentinel.application.services.incident_timeline import IncidentTimelineQueryService
from netsentinel.domain.incidents import IncidentInput, IncidentObservationRef, IncidentObservationKind, IncidentConnectionRef
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
from tests.fixtures.incidents import NOW, SESSION, PROCESS, DESTINATION, SCOPE
from uuid import UUID


def story(tmp_path, count=3):
    db = SQLiteDatabase(tmp_path / "timeline.db")
    writer = IncidentPersistenceService(SQLiteIncidentRepository(db))
    correlator = IncidentCorrelator()
    connection = IncidentConnectionRef(SESSION, UUID(int=1))
    for i in range(count):
        obs = IncidentObservationRef(IncidentObservationKind.CONNECTION_OBSERVED, connection, NOW + timedelta(microseconds=i))
        result = correlator.correlate(IncidentInput(obs, SCOPE, PROCESS, connection, DESTINATION))
    record = writer.create_or_get(result.incident, now=NOW + timedelta(seconds=1)).record
    repository = SQLiteIncidentTimelineRepository(db)
    query = IncidentTimelineQueryService(repository)
    return db, writer, record, repository, query
