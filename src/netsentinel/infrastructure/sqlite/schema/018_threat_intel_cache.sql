-- NS-085: bounded normalized cache, separate from assessment/history stores.
CREATE TABLE threat_intel_cache (
    provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 64),
    data_type TEXT NOT NULL CHECK(data_type IN ('ip_reputation','domain_reputation','hash_reputation')),
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ip','domain','hash')),
    canonical_subject TEXT NOT NULL CHECK(length(canonical_subject) BETWEEN 1 AND 255),
    hash_algorithm TEXT NOT NULL CHECK(hash_algorithm IN ('','sha256')),
    result_version INTEGER NOT NULL CHECK(result_version BETWEEN 1 AND 2147483647),
    format_version INTEGER NOT NULL CHECK(format_version > 0),
    normalized_result TEXT NOT NULL CHECK(length(CAST(normalized_result AS BLOB)) <= 4096),
    received_at_utc_us INTEGER NOT NULL,
    fresh_until_utc_us INTEGER NOT NULL,
    stale_until_utc_us INTEGER NOT NULL,
    CHECK(received_at_utc_us < fresh_until_utc_us AND fresh_until_utc_us <= stale_until_utc_us),
    PRIMARY KEY(provider_id, data_type, subject_kind, canonical_subject, hash_algorithm, result_version)
) WITHOUT ROWID;
CREATE INDEX idx_ti_cache_expiry ON threat_intel_cache(stale_until_utc_us);
CREATE INDEX idx_ti_cache_freshness ON threat_intel_cache(fresh_until_utc_us, received_at_utc_us);
