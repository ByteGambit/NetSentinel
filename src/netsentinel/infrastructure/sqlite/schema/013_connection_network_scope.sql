-- Preserve exact connection scope for historical DNS correlation. Legacy rows
-- remain unknown; no scope is inferred from an endpoint after the fact.
ALTER TABLE connection_history ADD COLUMN network_scope_status TEXT NOT NULL DEFAULT 'unknown'
    CHECK (network_scope_status IN ('resolved', 'unknown', 'ambiguous'));
ALTER TABLE connection_history ADD COLUMN network_fingerprint TEXT;
ALTER TABLE connection_history ADD COLUMN network_interface_id TEXT;
ALTER TABLE connection_history ADD COLUMN network_interface_index INTEGER;
ALTER TABLE connection_history ADD COLUMN network_scope_method TEXT;
ALTER TABLE connection_history ADD COLUMN network_scope_since_utc_us INTEGER;
