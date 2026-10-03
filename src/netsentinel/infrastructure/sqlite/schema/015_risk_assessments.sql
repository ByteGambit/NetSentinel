-- Assessment explanation history only. No source FK or alert lifecycle fields.
CREATE INDEX idx_connection_history_monitoring_session ON connection_history
    (monitoring_session_id) WHERE monitoring_session_id IS NOT NULL;
CREATE TABLE risk_assessments (
    assessment_id TEXT PRIMARY KEY NOT NULL CHECK (length(assessment_id) = 64),
    original_observed_at TEXT NOT NULL CHECK (length(original_observed_at) <= 32),
    identity_payload TEXT NOT NULL CHECK (length(CAST(identity_payload AS BLOB)) <= 8192),
    last_revision INTEGER NOT NULL CHECK (last_revision >= 1)
);
CREATE INDEX idx_risk_assessments_retention ON risk_assessments
    (original_observed_at, assessment_id);

CREATE TABLE risk_assessment_revisions (
    assessment_id TEXT NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    format_version INTEGER NOT NULL CHECK (format_version >= 1),
    assessed_at TEXT NOT NULL CHECK (length(assessed_at) <= 32),
    content_fingerprint TEXT NOT NULL CHECK (length(content_fingerprint) = 64),
    snapshot TEXT NOT NULL CHECK (length(CAST(snapshot AS BLOB)) <= 65536),
    PRIMARY KEY (assessment_id, revision),
    UNIQUE (assessment_id, content_fingerprint)
);
