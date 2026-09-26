ALTER TABLE vlan_summaries
ADD COLUMN verified_at_utc_us INTEGER
CHECK (verified_at_utc_us IS NULL OR verified_at_utc_us >= 0);
