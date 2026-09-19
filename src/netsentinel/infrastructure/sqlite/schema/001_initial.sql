CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    applied_at_utc_us INTEGER NOT NULL CHECK (applied_at_utc_us >= 0)
);

CREATE TABLE connection_history (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    local_address TEXT NOT NULL CHECK (length(local_address) BETWEEN 1 AND 45),
    local_port INTEGER NOT NULL CHECK (local_port BETWEEN 0 AND 65535),
    remote_address TEXT CHECK (
        remote_address IS NULL OR length(remote_address) BETWEEN 1 AND 45
    ),
    remote_port INTEGER CHECK (
        remote_port IS NULL OR remote_port BETWEEN 0 AND 65535
    ),
    pid INTEGER CHECK (pid IS NULL OR pid >= 0),
    process_create_time_utc_us INTEGER CHECK (
        process_create_time_utc_us IS NULL OR process_create_time_utc_us >= 0
    ),
    process_name TEXT CHECK (
        process_name IS NULL OR length(trim(process_name)) > 0
    ),
    process_status TEXT NOT NULL CHECK (
        process_status IN ('available', 'access_denied', 'not_found', 'unavailable')
    ),
    connection_state TEXT NOT NULL CHECK (
        connection_state IN (
            'none', 'listen', 'established', 'syn_sent', 'syn_received',
            'fin_wait_1', 'fin_wait_2', 'close_wait', 'closing', 'last_ack',
            'time_wait', 'closed', 'unknown'
        )
    ),
    first_seen_utc_us INTEGER NOT NULL CHECK (first_seen_utc_us >= 0),
    last_seen_utc_us INTEGER NOT NULL CHECK (last_seen_utc_us >= 0),
    closed_at_utc_us INTEGER CHECK (
        closed_at_utc_us IS NULL OR closed_at_utc_us >= 0
    ),
    close_reason TEXT CHECK (
        close_reason IS NULL OR close_reason IN ('not_observed')
    ),
    CHECK ((remote_address IS NULL) = (remote_port IS NULL)),
    CHECK (process_create_time_utc_us IS NULL OR pid IS NOT NULL),
    CHECK (
        (process_status = 'available' AND pid IS NOT NULL AND process_name IS NOT NULL)
        OR (process_status IN ('access_denied', 'not_found') AND pid IS NOT NULL AND process_name IS NULL)
        OR (process_status = 'unavailable' AND process_name IS NULL)
    ),
    CHECK (
        (protocol = 'udp' AND connection_state = 'none')
        OR (protocol = 'tcp' AND connection_state <> 'none')
    ),
    CHECK (connection_state <> 'listen' OR remote_address IS NULL),
    CHECK (last_seen_utc_us >= first_seen_utc_us),
    CHECK ((closed_at_utc_us IS NULL) = (close_reason IS NULL)),
    CHECK (closed_at_utc_us IS NULL OR closed_at_utc_us >= last_seen_utc_us)
);

CREATE INDEX idx_connection_history_first_seen_id
    ON connection_history (first_seen_utc_us DESC, id DESC);

CREATE INDEX idx_connection_history_process_name
    ON connection_history (process_name COLLATE NOCASE, first_seen_utc_us DESC)
    WHERE process_name IS NOT NULL;
