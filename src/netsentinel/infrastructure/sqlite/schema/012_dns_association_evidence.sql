-- NULL explicitly means a legacy row whose pipeline origin identity is unknown.
ALTER TABLE dns_history ADD COLUMN evidence_id TEXT
    CHECK (evidence_id IS NULL OR length(evidence_id) = 36);
CREATE UNIQUE INDEX idx_dns_history_evidence_id ON dns_history (evidence_id)
    WHERE evidence_id IS NOT NULL;

-- Each source observation has its own association evidence; no foreign key
-- keeps retained history alive or cascades future evidence references.
CREATE TABLE dns_associations (
    evidence_id TEXT NOT NULL CHECK (length(evidence_id) = 36),
    association_index INTEGER NOT NULL CHECK (association_index BETWEEN 0 AND 511),
    domain TEXT NOT NULL CHECK (length(domain) BETWEEN 1 AND 254),
    ip TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 45),
    record_type INTEGER NOT NULL CHECK (record_type IN (1, 28)),
    provenance TEXT NOT NULL CHECK (provenance IN ('direct_answer', 'cname_derived')),
    queried_domain TEXT NOT NULL CHECK (length(queried_domain) BETWEEN 1 AND 254),
    answer_name TEXT NOT NULL CHECK (length(answer_name) BETWEEN 1 AND 254),
    cname_chain_json TEXT NOT NULL CHECK (length(cname_chain_json) <= 2300),
    observed_at_utc_us INTEGER NOT NULL CHECK (observed_at_utc_us >= 0),
    expires_at_utc_us INTEGER NOT NULL CHECK (expires_at_utc_us >= observed_at_utc_us),
    ttl INTEGER NOT NULL CHECK (ttl BETWEEN 0 AND 4294967295),
    answer_ttl INTEGER NOT NULL CHECK (answer_ttl BETWEEN 0 AND 4294967295),
    retention_seconds INTEGER NOT NULL CHECK (retention_seconds BETWEEN 0 AND 3600),
    network_fingerprint TEXT NOT NULL CHECK (length(network_fingerprint) = 64),
    client_ip TEXT NOT NULL CHECK (length(client_ip) BETWEEN 1 AND 45),
    server_ip TEXT NOT NULL CHECK (length(server_ip) BETWEEN 1 AND 45),
    transport TEXT NOT NULL CHECK (transport IN ('udp', 'tcp')),
    transaction_id INTEGER NOT NULL CHECK (transaction_id BETWEEN 0 AND 65535),
    query_at_utc_us INTEGER NOT NULL CHECK (query_at_utc_us >= 0),
    PRIMARY KEY (evidence_id, association_index)
);
CREATE INDEX idx_dns_associations_scope_ip ON dns_associations
    (network_fingerprint, client_ip, ip, expires_at_utc_us DESC);
CREATE INDEX idx_dns_associations_expiry ON dns_associations
    (expires_at_utc_us ASC, evidence_id ASC);
CREATE INDEX idx_dns_associations_observed ON dns_associations
    (observed_at_utc_us ASC, evidence_id ASC);
