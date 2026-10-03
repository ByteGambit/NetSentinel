-- NS-071 bounded summaries only. No monotonic buckets or raw event journal.
CREATE TABLE behavior_baselines (
    application_key TEXT NOT NULL CHECK(length(CAST(application_key AS BLOB)) <= 4096),
    revision_digest TEXT NOT NULL CHECK(length(revision_digest) IN (0, 64)),
    network_fingerprint TEXT NOT NULL CHECK(length(network_fingerprint) = 64),
    summary_version INTEGER NOT NULL,
    feature_policy_version INTEGER NOT NULL,
    policy_key TEXT NOT NULL CHECK(length(policy_key) <= 512),
    last_observed_at TEXT NOT NULL CHECK(length(last_observed_at) <= 32),
    persisted_at TEXT NOT NULL CHECK(length(persisted_at) <= 32),
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= 16384),
    PRIMARY KEY (application_key, revision_digest, network_fingerprint)
) WITHOUT ROWID;
CREATE INDEX idx_behavior_baselines_observed ON behavior_baselines(last_observed_at);
CREATE TABLE behavior_baseline_storage (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    capacity_loss INTEGER NOT NULL DEFAULT 0 CHECK(capacity_loss IN (0, 1))
);
INSERT INTO behavior_baseline_storage(singleton, capacity_loss) VALUES (1, 0);
CREATE TRIGGER behavior_baseline_row_quota BEFORE INSERT ON behavior_baselines
WHEN (SELECT COUNT(*) FROM behavior_baselines) >= 512
 AND NOT EXISTS (SELECT 1 FROM behavior_baselines
                 WHERE application_key = NEW.application_key
                   AND revision_digest = NEW.revision_digest
                   AND network_fingerprint = NEW.network_fingerprint)
BEGIN
    SELECT RAISE(ABORT, 'baseline row quota');
END;
