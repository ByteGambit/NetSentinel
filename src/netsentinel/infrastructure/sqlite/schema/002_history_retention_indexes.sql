CREATE INDEX idx_connection_history_completed_closed
    ON connection_history (
        closed_at_utc_us ASC,
        first_seen_utc_us ASC,
        id ASC
    )
    WHERE closed_at_utc_us IS NOT NULL;

CREATE INDEX idx_connection_history_completed_oldest
    ON connection_history (
        first_seen_utc_us ASC,
        closed_at_utc_us ASC,
        id ASC
    )
    WHERE closed_at_utc_us IS NOT NULL;
