-- name: CreateAdmin :exec
INSERT INTO admins (id, username, password_hash) VALUES (?, ?, ?);

-- name: GetAdminByUsername :one
SELECT * FROM admins WHERE username = ?;

-- name: CountAdmins :one
SELECT count(*) FROM admins;

-- name: UpdateAdminPassword :exec
UPDATE admins SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: SetAdminTOTPPending :exec
UPDATE admins SET totp_secret = ?, totp_key_id = ?, totp_enabled_at = NULL, totp_last_step = 0,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: EnableAdminTOTP :execrows
UPDATE admins SET totp_enabled_at = ?, totp_last_step = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND totp_secret IS NOT NULL AND totp_enabled_at IS NULL;

-- name: AdvanceAdminTOTPStep :execrows
UPDATE admins SET totp_last_step = sqlc.arg(step) WHERE id = sqlc.arg(id) AND totp_last_step < sqlc.arg(step);

-- name: ClearAdminTOTP :exec
UPDATE admins SET totp_secret = NULL, totp_key_id = NULL, totp_enabled_at = NULL, totp_last_step = 0,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: DeleteOtherAdminSessions :exec
DELETE FROM admin_sessions WHERE admin_id = ? AND id_hash != ?;

-- name: CreateSession :exec
INSERT INTO admin_sessions (id_hash, admin_id, csrf_token, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT s.id_hash, s.admin_id, s.csrf_token, s.expires_at, s.last_seen_at, a.username
FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
WHERE s.id_hash = ?;

-- name: TouchSession :exec
UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ?;

-- name: DeleteSession :exec
DELETE FROM admin_sessions WHERE id_hash = ?;

-- name: DeleteAdminSessions :exec
DELETE FROM admin_sessions WHERE admin_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM admin_sessions WHERE expires_at < ?;

-- name: CreateEnrollmentToken :exec
INSERT INTO site_enrollment_tokens (id, site_id, token_hash, expires_at) VALUES (?, ?, ?, ?);

-- name: GetEnrollmentToken :one
SELECT * FROM site_enrollment_tokens WHERE id = ?;

-- name: ConsumeEnrollmentToken :execrows
UPDATE site_enrollment_tokens SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND consumed_at IS NULL;

-- name: InvalidateSiteEnrollmentTokens :exec
UPDATE site_enrollment_tokens SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE site_id = ? AND consumed_at IS NULL;

-- name: CreateAgentCredential :exec
INSERT INTO agent_credentials (id, site_id, token_hash) VALUES (?, ?, ?);

-- name: GetAgentCredential :one
SELECT * FROM agent_credentials WHERE id = ?;

-- name: ListSiteCredentials :many
SELECT id, site_id, created_at, expires_at, revoked_at FROM agent_credentials
WHERE site_id = ? ORDER BY created_at;

-- name: CountExpiringSiteCredentials :one
SELECT COUNT(*) FROM agent_credentials
WHERE site_id = ? AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at > ?;

-- name: ExpireOtherSiteCredentials :exec
UPDATE agent_credentials SET expires_at = ?
WHERE site_id = ? AND id != ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?);

-- name: RevokeAgentCredential :exec
UPDATE agent_credentials SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeSiteCredentials :exec
UPDATE agent_credentials SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE site_id = ? AND revoked_at IS NULL;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (actor, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?);

-- name: ListAuditEvents :many
SELECT * FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT ?;

-- name: GetSiteStatus :one
SELECT * FROM site_status WHERE site_id = ?;

-- name: ListSiteStatus :many
SELECT * FROM site_status;

-- name: UpsertSiteStatus :exec
INSERT INTO site_status (site_id, last_seen_at, applied_revision, applied_at, last_observed_at,
    last_error_code, last_error_message, accepted_revision, agent_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (site_id) DO UPDATE SET
    last_seen_at = excluded.last_seen_at,
    applied_revision = excluded.applied_revision,
    applied_at = excluded.applied_at,
    last_observed_at = excluded.last_observed_at,
    last_error_code = excluded.last_error_code,
    last_error_message = excluded.last_error_message,
    accepted_revision = excluded.accepted_revision,
    agent_version = excluded.agent_version;

-- name: GetSetting :one
SELECT value FROM settings WHERE key = ?;

-- name: SetSetting :exec
INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: DeleteSetting :exec
DELETE FROM settings WHERE key = ?;
