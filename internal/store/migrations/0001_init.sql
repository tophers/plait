-- Core schema from SPEC.md section 3. Timestamps are UTC ISO-8601 strings
-- ("2026-10-30T14:28:00.000Z"); write queries set updated_at explicitly.

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    assigned_ipv4 TEXT NOT NULL UNIQUE,
    client_mtu INTEGER CHECK (client_mtu BETWEEN 576 AND 1500),
    search_domain TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    retired_at TEXT,
    profile_revision INTEGER NOT NULL DEFAULT 1 CHECK (profile_revision > 0),
    last_exported_revision INTEGER,
    last_exported_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE device_dns_servers (
    device_id TEXT NOT NULL REFERENCES devices(id),
    position INTEGER NOT NULL CHECK (position >= 0),
    address TEXT NOT NULL,
    PRIMARY KEY (device_id, position),
    UNIQUE (device_id, address)
);

CREATE TABLE sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    endpoint_host TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 51111 CHECK (listen_port BETWEEN 1 AND 65535),
    public_key TEXT UNIQUE,                    -- NULL until the gateway enrolls
    egress_interface TEXT NOT NULL,
    mtu INTEGER NOT NULL DEFAULT 1420 CHECK (mtu BETWEEN 576 AND 1500),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    desired_revision INTEGER NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE site_subnets (
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    PRIMARY KEY (site_id, cidr)
);

CREATE TABLE site_device_links (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id),
    preshared_key_ciphertext BLOB NOT NULL,
    encryption_key_id TEXT NOT NULL,
    persistent_keepalive INTEGER NOT NULL DEFAULT 25
        CHECK (persistent_keepalive BETWEEN 0 AND 65535),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    UNIQUE (site_id, device_id)
);

CREATE TABLE agent_credentials (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT,
    revoked_at TEXT
);

CREATE TABLE site_status (
    site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    last_seen_at TEXT,
    applied_revision INTEGER,
    applied_at TEXT,
    last_observed_at TEXT,
    last_error_code TEXT,
    last_error_message TEXT
);

CREATE INDEX idx_links_device ON site_device_links(device_id);
CREATE INDEX idx_credentials_site ON agent_credentials(site_id);
