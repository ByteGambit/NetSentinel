-- An open observation is not evidence of socket continuity across monitoring sessions.
ALTER TABLE connection_history ADD COLUMN observation_gap INTEGER NOT NULL DEFAULT 0
    CHECK (observation_gap IN (0, 1));
ALTER TABLE connection_history ADD COLUMN monitoring_session_id TEXT
    CHECK (monitoring_session_id IS NULL OR length(monitoring_session_id) = 36);
ALTER TABLE connection_history ADD COLUMN lifecycle_id TEXT
    CHECK (lifecycle_id IS NULL OR length(lifecycle_id) = 36);
CREATE INDEX idx_connection_history_active_observation
    ON connection_history (observation_gap, closed_at_utc_us)
    WHERE closed_at_utc_us IS NULL;
CREATE UNIQUE INDEX idx_connection_history_lifecycle
    ON connection_history (lifecycle_id)
    WHERE lifecycle_id IS NOT NULL;
