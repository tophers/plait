-- TOTP second factor (RFC 6238). The secret is sealed with the controller's
-- encryption key, bound to the administrator's ID. A secret with no
-- totp_enabled_at is an unconfirmed setup and is not enforced at login.
-- totp_last_step is the last accepted time step, so a code is accepted once.
ALTER TABLE admins ADD COLUMN totp_secret BLOB;
ALTER TABLE admins ADD COLUMN totp_key_id TEXT;
ALTER TABLE admins ADD COLUMN totp_enabled_at TEXT;
ALTER TABLE admins ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
