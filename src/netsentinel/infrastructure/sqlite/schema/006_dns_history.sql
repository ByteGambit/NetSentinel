CREATE TABLE dns_history (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    status TEXT NOT NULL CHECK (status IN ('completed', 'timed_out', 'evicted', 'unmatched_response')),
    network_fingerprint TEXT NOT NULL CHECK (length(network_fingerprint) = 64),
    transport TEXT NOT NULL CHECK (transport IN ('udp', 'tcp')),
    client_ip TEXT NOT NULL CHECK (length(client_ip) BETWEEN 1 AND 45),
    client_port INTEGER NOT NULL CHECK (client_port BETWEEN 0 AND 65535),
    server_ip TEXT NOT NULL CHECK (length(server_ip) BETWEEN 1 AND 45),
    server_port INTEGER NOT NULL CHECK (server_port BETWEEN 0 AND 65535),
    transaction_id INTEGER NOT NULL CHECK (transaction_id BETWEEN 0 AND 65535),
    qname TEXT CHECK (qname IS NULL OR length(qname) BETWEEN 1 AND 254),
    questions_json TEXT NOT NULL CHECK (length(questions_json) <= 1200),
    query_at_utc_us INTEGER CHECK (query_at_utc_us IS NULL OR query_at_utc_us >= 0),
    response_at_utc_us INTEGER CHECK (response_at_utc_us IS NULL OR response_at_utc_us >= 0),
    event_at_utc_us INTEGER NOT NULL CHECK (event_at_utc_us >= 0),
    latency_us INTEGER CHECK (latency_us IS NULL OR latency_us >= 0),
    response_code INTEGER CHECK (response_code IS NULL OR response_code BETWEEN 0 AND 15),
    truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
    answers_json TEXT NOT NULL CHECK (length(answers_json) <= 10000),
    retry_count INTEGER NOT NULL CHECK (retry_count BETWEEN 0 AND 65535),
    CHECK ((status = 'unmatched_response' AND query_at_utc_us IS NULL AND response_at_utc_us IS NOT NULL)
        OR (status <> 'unmatched_response' AND query_at_utc_us IS NOT NULL)),
    CHECK (status <> 'completed' OR response_at_utc_us IS NOT NULL)
);

CREATE INDEX idx_dns_history_event_id ON dns_history (event_at_utc_us DESC, id DESC);
CREATE INDEX idx_dns_history_network_event ON dns_history (network_fingerprint, event_at_utc_us DESC, id DESC);
CREATE INDEX idx_dns_history_qname_event ON dns_history (qname, event_at_utc_us DESC, id DESC);
