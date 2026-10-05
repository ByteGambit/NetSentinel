"""Shared NS-095 assessment guards for maintenance and write-time eviction."""

import sqlite3


def admit_new(connection: sqlite3.Connection, table: str, quota: int,
              predicate: str, values: tuple[object, ...]) -> None:
    """Called only with code-owned table/predicate constants, inside write transaction."""
    if connection.execute(f"SELECT 1 FROM {table} WHERE {predicate} LIMIT 1", values).fetchone() is None:
        if connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= quota:
            raise ValueError("Local storage capacity is protected; maintenance is required.")

# Uncorrelated reference sets are evaluated once per query, instead of scanning
# every retained alert payload for every assessment. Active lifecycle lookup
# uses the existing unique lifecycle index. Malformed JSON roots fail closed.
_VALID_ALERTS = """NOT EXISTS (SELECT 1 FROM alerts al WHERE
 json_type(CASE WHEN json_valid(al.evidence_json) THEN al.evidence_json ELSE '{}' END) != 'array')"""
_REFERENCE_ID = "json_extract(CASE WHEN e.type = 'object' THEN e.value ELSE '{}' END, '$.assessment.assessment_id')"
_REFERENCE_REVISION = "json_extract(CASE WHEN e.type = 'object' THEN e.value ELSE '{}' END, '$.assessment.revision')"
_REFERENCES = "FROM alerts al, json_each(CASE WHEN json_valid(al.evidence_json) THEN al.evidence_json ELSE '[]' END) e"

ASSESSMENT_UNPROTECTED = _VALID_ALERTS + f"""
 AND risk_assessments.assessment_id NOT IN (
 SELECT {_REFERENCE_ID} {_REFERENCES} WHERE {_REFERENCE_ID} IS NOT NULL)
 AND json_valid(risk_assessments.identity_payload)
 AND NOT EXISTS (SELECT 1 FROM connection_history ch
     WHERE ch.closed_at_utc_us IS NULL AND ch.observation_gap = 0
       AND (ch.lifecycle_id = json_extract(CASE WHEN json_valid(risk_assessments.identity_payload)
           THEN risk_assessments.identity_payload ELSE '{{}}' END, '$.observation_reference.value')
         OR (json_extract(CASE WHEN json_valid(risk_assessments.identity_payload)
           THEN risk_assessments.identity_payload ELSE '{{}}' END, '$.observation_reference.kind') = 'monitoring_session'
          AND ch.monitoring_session_id = json_extract(CASE WHEN json_valid(risk_assessments.identity_payload)
           THEN risk_assessments.identity_payload ELSE '{{}}' END, '$.observation_reference.value'))))
"""

REVISION_UNPROTECTED = _VALID_ALERTS + f"""
 AND (risk_assessment_revisions.assessment_id, risk_assessment_revisions.revision) NOT IN (
 SELECT {_REFERENCE_ID}, {_REFERENCE_REVISION} {_REFERENCES}
 WHERE {_REFERENCE_ID} IS NOT NULL AND {_REFERENCE_REVISION} IS NOT NULL)
"""
