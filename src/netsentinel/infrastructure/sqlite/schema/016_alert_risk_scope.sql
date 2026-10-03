-- NS-079: unresolved risk scopes have no invented network fingerprint.
CREATE TABLE alerts_ns079 (
    id TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE CHECK (length(fingerprint) = 64),
    rule_id TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 64),
    network_fingerprint TEXT CHECK (length(network_fingerprint) = 64),
    entity_id TEXT NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 128),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
    confidence TEXT NOT NULL CHECK (confidence IN ('passive_observation', 'low', 'moderate', 'high')),
    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count >= 1),
    evidence_json TEXT NOT NULL CHECK (length(evidence_json) BETWEEN 2 AND 8192),
    created_at_utc_us INTEGER NOT NULL CHECK (created_at_utc_us >= 0),
    updated_at_utc_us INTEGER NOT NULL CHECK (updated_at_utc_us >= created_at_utc_us),
    last_notified_at_utc_us INTEGER NOT NULL CHECK (last_notified_at_utc_us >= 0)
);

INSERT INTO alerts_ns079 SELECT * FROM alerts;
DROP TABLE alerts;
ALTER TABLE alerts_ns079 RENAME TO alerts;

CREATE INDEX idx_alerts_last_seen ON alerts (last_seen_utc_us DESC, id);
CREATE INDEX idx_alerts_scope_status ON alerts (network_fingerprint, status, last_seen_utc_us DESC);
