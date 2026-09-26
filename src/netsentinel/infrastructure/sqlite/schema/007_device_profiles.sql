CREATE TABLE device_profiles (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    network_fingerprint TEXT NOT NULL CHECK (length(network_fingerprint) = 64),
    label TEXT NOT NULL CHECK (length(label) <= 128),
    note TEXT NOT NULL CHECK (length(note) <= 1024),
    trust TEXT NOT NULL CHECK (trust IN ('unknown', 'trusted', 'untrusted')),
    created_at_utc_us INTEGER NOT NULL CHECK (created_at_utc_us >= 0),
    updated_at_utc_us INTEGER NOT NULL CHECK (updated_at_utc_us >= created_at_utc_us),
    trust_changed_at_utc_us INTEGER CHECK (
        trust_changed_at_utc_us IS NULL OR
        (trust_changed_at_utc_us >= created_at_utc_us AND trust_changed_at_utc_us <= updated_at_utc_us)
    ),
    expected_macs_json TEXT NOT NULL CHECK (length(expected_macs_json) <= 700),
    expected_ips_json TEXT NOT NULL CHECK (length(expected_ips_json) <= 600),
    merged_into TEXT REFERENCES device_profiles(id),
    CHECK (merged_into IS NULL OR merged_into <> id)
);

CREATE TABLE device_profile_members (
    device_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id),
    profile_id TEXT NOT NULL REFERENCES device_profiles(id)
);

CREATE INDEX idx_device_profile_members_profile ON device_profile_members (profile_id, device_id);
