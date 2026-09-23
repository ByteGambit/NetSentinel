CREATE TABLE gateway_baselines (
    network_fingerprint TEXT PRIMARY KEY NOT NULL CHECK (length(network_fingerprint) = 64),
    gateway_ip TEXT NOT NULL CHECK (length(gateway_ip) BETWEEN 7 AND 15),
    mac TEXT NOT NULL CHECK (length(mac) = 17),
    status TEXT NOT NULL CHECK (status IN ('learning', 'learned', 'verified')),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    learning_started_utc_us INTEGER NOT NULL CHECK (learning_started_utc_us >= 0),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 1),
    conflicted INTEGER NOT NULL CHECK (conflicted IN (0, 1)),
    verified_at_utc_us INTEGER,
    pending_mac TEXT,
    pending_seen_utc_us INTEGER,
    CHECK ((pending_mac IS NULL) = (pending_seen_utc_us IS NULL)),
    CHECK ((status = 'verified') = (verified_at_utc_us IS NOT NULL))
);

CREATE TABLE gateway_baseline_changes (
    id INTEGER PRIMARY KEY,
    network_fingerprint TEXT NOT NULL REFERENCES gateway_baselines(network_fingerprint),
    gateway_ip TEXT NOT NULL,
    old_mac TEXT,
    new_mac TEXT NOT NULL,
    changed_at_utc_us INTEGER NOT NULL CHECK (changed_at_utc_us >= 0),
    reason TEXT NOT NULL CHECK (reason IN ('first_observation', 'user_confirmation'))
);

CREATE INDEX idx_gateway_baseline_changes_scope_time
    ON gateway_baseline_changes (network_fingerprint, changed_at_utc_us, id);
