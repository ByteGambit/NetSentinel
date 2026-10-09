CREATE TABLE response_store (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_id TEXT NOT NULL UNIQUE CHECK (length(store_id) = 36)
);

CREATE TABLE response_operations (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 36),
    rule_id TEXT NOT NULL CHECK (length(rule_id) = 36),
    action TEXT NOT NULL CHECK (action IN ('create', 'remove')),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    request BLOB NOT NULL CHECK (typeof(request) = 'blob' AND length(request) BETWEEN 1 AND 32768),
    manifest BLOB CHECK (manifest IS NULL OR (typeof(manifest) = 'blob' AND length(manifest) BETWEEN 1 AND 16384)),
    witness TEXT UNIQUE CHECK (witness IS NULL OR length(witness) = 64),
    lifetime TEXT NOT NULL CHECK (lifetime = 'until_manually_removed'),
    status TEXT NOT NULL CHECK (length(status) <= 32),
    reconciliation TEXT NOT NULL CHECK (length(reconciliation) <= 32),
    result BLOB CHECK (result IS NULL OR (typeof(result) = 'blob' AND length(result) BETWEEN 1 AND 512)),
    updated_at TEXT NOT NULL CHECK (length(updated_at) <= 40),
    attempt_at TEXT CHECK (attempt_at IS NULL OR length(attempt_at) <= 40),
    reconciled_at TEXT CHECK (reconciled_at IS NULL OR length(reconciled_at) <= 40),
    expires_at TEXT CHECK (expires_at IS NULL OR length(expires_at) <= 40),
    purpose TEXT NOT NULL CHECK (purpose IN ('undo', 'rollback', 'expiry')),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9223372036854775806)
);
CREATE UNIQUE INDEX response_create_identity ON response_operations(rule_id) WHERE action = 'create';
CREATE INDEX response_reconcile_order ON response_operations(operation_id);
CREATE INDEX response_rule_operations ON response_operations(rule_id, action);

CREATE TABLE response_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL REFERENCES response_operations(operation_id),
    rule_id TEXT NOT NULL CHECK (length(rule_id) = 36),
    action TEXT NOT NULL CHECK (action IN ('create', 'remove')),
    at TEXT NOT NULL CHECK (length(at) <= 40),
    event TEXT NOT NULL CHECK (length(event) <= 32),
    status TEXT NOT NULL CHECK (length(status) <= 32),
    reconciliation TEXT NOT NULL CHECK (length(reconciliation) <= 32),
    outcome TEXT CHECK (outcome IS NULL OR length(outcome) <= 32)
);
