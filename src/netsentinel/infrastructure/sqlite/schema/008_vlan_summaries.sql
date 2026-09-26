CREATE TABLE vlan_summaries (
    network_fingerprint TEXT NOT NULL CHECK (length(network_fingerprint) = 64),
    interface_id TEXT NOT NULL CHECK (length(interface_id) BETWEEN 1 AND 512),
    interface_index INTEGER NOT NULL CHECK (interface_index >= 0),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    learning_started_utc_us INTEGER NOT NULL CHECK (learning_started_utc_us >= 0),
    baseline_state TEXT NOT NULL CHECK (baseline_state IN ('learning', 'learned')),
    untagged_count INTEGER NOT NULL CHECK (untagged_count >= 0),
    tagged_count INTEGER NOT NULL CHECK (tagged_count >= 0),
    priority_tagged_count INTEGER NOT NULL CHECK (priority_tagged_count >= 0),
    reserved_count INTEGER NOT NULL CHECK (reserved_count >= 0),
    stacked_count INTEGER NOT NULL CHECK (stacked_count >= 0),
    overflow_count INTEGER NOT NULL CHECK (overflow_count >= 0),
    PRIMARY KEY (network_fingerprint, interface_id, interface_index)
);

CREATE TABLE vlan_id_summaries (
    network_fingerprint TEXT NOT NULL,
    interface_id TEXT NOT NULL,
    interface_index INTEGER NOT NULL,
    vlan_id INTEGER NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
    count INTEGER NOT NULL CHECK (count >= 1),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= first_seen_utc_us),
    learned INTEGER NOT NULL CHECK (learned IN (0, 1)),
    PRIMARY KEY (network_fingerprint, interface_id, interface_index, vlan_id),
    FOREIGN KEY (network_fingerprint, interface_id, interface_index)
        REFERENCES vlan_summaries (network_fingerprint, interface_id, interface_index)
        ON DELETE CASCADE
);
