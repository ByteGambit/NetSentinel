CREATE TABLE devices (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    network_fingerprint TEXT NOT NULL CHECK (length(network_fingerprint) = 64),
    mac TEXT NOT NULL CHECK (length(mac) = 17),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    UNIQUE (network_fingerprint, mac)
);

CREATE TABLE device_bindings (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    device_id TEXT NOT NULL REFERENCES devices(id),
    ip_address TEXT NOT NULL CHECK (length(ip_address) BETWEEN 7 AND 15),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    UNIQUE (device_id, ip_address)
);

CREATE INDEX idx_device_bindings_device_ip
    ON device_bindings (device_id, ip_address);
