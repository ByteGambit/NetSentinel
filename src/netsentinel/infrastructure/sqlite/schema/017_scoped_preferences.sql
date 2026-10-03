-- Local user policy, separate from device trust and observed evidence.
CREATE TABLE scoped_preferences (
    preference_id TEXT PRIMARY KEY NOT NULL CHECK(length(preference_id) = 36),
    created_at TEXT NOT NULL CHECK(length(created_at) = 32),
    created_origin TEXT NOT NULL CHECK(created_origin = 'manual_user'),
    last_revision INTEGER NOT NULL CHECK(typeof(last_revision) = 'integer' AND last_revision > 0),
    FOREIGN KEY(preference_id, last_revision)
        REFERENCES scoped_preference_revisions(preference_id, revision) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE scoped_preference_revisions (
    preference_id TEXT NOT NULL REFERENCES scoped_preferences(preference_id),
    revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision > 0),
    format_version INTEGER NOT NULL CHECK(typeof(format_version) = 'integer' AND format_version > 0),
    action TEXT NOT NULL CHECK(action IN ('create', 'edit', 'revoke')),
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at) = 32),
    action_origin TEXT NOT NULL CHECK(action_origin = 'manual_user'),
    effect TEXT NOT NULL CHECK(effect = 'notification_suppression'),
    application_key TEXT CHECK(application_key IS NULL OR
        (length(CAST(application_key AS BLOB)) <= 4096 AND application_key LIKE 'winpath:v1:%')),
    application_revision TEXT CHECK(application_revision IS NULL OR
        (application_key IS NOT NULL AND length(application_revision) = 64 AND application_revision NOT GLOB '*[^0-9a-f]*')),
    destination_kind TEXT,
    destination_value TEXT,
    network_fingerprint TEXT CHECK(network_fingerprint IS NULL OR
        (length(network_fingerprint) = 64 AND network_fingerprint NOT GLOB '*[^0-9a-f]*')),
    rule_id TEXT CHECK(rule_id IS NULL OR
        (length(rule_id) BETWEEN 1 AND 64 AND substr(rule_id, 1, 1) GLOB '[a-z]' AND rule_id NOT GLOB '*[^a-z0-9_]*')),
    lifetime_kind TEXT NOT NULL CHECK(lifetime_kind IN ('expires_at', 'permanent')),
    expires_at TEXT,
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
    content_fingerprint TEXT NOT NULL CHECK(length(content_fingerprint) = 64 AND content_fingerprint NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(preference_id, revision),
    CHECK(application_key IS NOT NULL OR destination_kind IS NOT NULL OR network_fingerprint IS NOT NULL OR rule_id IS NOT NULL),
    CHECK((destination_kind IS NULL AND destination_value IS NULL) OR
          (destination_kind IS NOT NULL AND destination_kind IN ('ipv4', 'ipv6') AND
           destination_value IS NOT NULL AND length(destination_value) BETWEEN 1 AND 45)),
    CHECK((lifetime_kind = 'permanent' AND expires_at IS NULL) OR
          (lifetime_kind = 'expires_at' AND expires_at IS NOT NULL AND length(expires_at) = 32)),
    CHECK((revision = 1 AND action = 'create') OR (revision > 1 AND action IN ('edit', 'revoke'))),
    CHECK((action = 'revoke' AND status = 'revoked') OR (action IN ('create', 'edit') AND status = 'active'))
);

-- The composite primary key also supports descending bounded history queries.
CREATE INDEX idx_scoped_preference_status ON scoped_preference_revisions(status, preference_id, revision);
