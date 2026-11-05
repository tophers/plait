-- Phase 3: administrator sessions, site enrollment, audit, status details,
-- and controller-wide settings.

CREATE TABLE admins (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,               -- argon2id, PHC string format
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE admin_sessions (
    id_hash BLOB PRIMARY KEY,                  -- SHA-256 of the cookie secret
    admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX idx_admin_sessions_admin ON admin_sessions(admin_id);

-- Short-lived, single-use credentials an administrator issues so a gateway
-- can bind its locally generated public key to a site.
CREATE TABLE site_enrollment_tokens (
    id TEXT PRIMARY KEY,                       -- selector, not a secret
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX idx_enrollment_tokens_site ON site_enrollment_tokens(site_id);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'         -- JSON; never contains secrets
);

CREATE INDEX idx_audit_target ON audit_events(target_type, target_id);

-- Agent-reported revision it has accepted (may exceed desired after a
-- controller restore) and its version, alongside the applied revision.
ALTER TABLE site_status ADD COLUMN accepted_revision INTEGER;
ALTER TABLE site_status ADD COLUMN agent_version TEXT;

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
