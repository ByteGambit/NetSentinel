CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY CHECK(length(incident_id) = 36),
    state TEXT NOT NULL CHECK(state IN ('open', 'acknowledged', 'resolved')),
    cohort TEXT NOT NULL CHECK(length(cohort) <= 32),
    updated_at TEXT NOT NULL CHECK(length(updated_at) <= 32),
    resolved_at TEXT CHECK(resolved_at IS NULL OR length(resolved_at) <= 32),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    format_version INTEGER NOT NULL CHECK(format_version >= 1),
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= 131072)
);
CREATE INDEX idx_incidents_cohort ON incidents(cohort, incident_id);
CREATE INDEX idx_incidents_state ON incidents(state, incident_id);
CREATE INDEX idx_incidents_cleanup ON incidents(state, resolved_at, incident_id);
CREATE TABLE incident_revisions (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    format_version INTEGER NOT NULL CHECK(format_version >= 1),
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= 2048),
    PRIMARY KEY(incident_id, revision)
);
CREATE TABLE incident_references (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('process', 'connection', 'destination', 'evidence', 'assessment', 'alert', 'scope', 'relation')),
    identity TEXT NOT NULL CHECK(length(identity) = 64),
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= 2048),
    PRIMARY KEY(incident_id, kind, identity)
);
CREATE INDEX idx_incident_references_source ON incident_references(kind, identity, incident_id);
