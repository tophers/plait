-- name: CreateLink :exec
INSERT INTO site_device_links (id, site_id, device_id, preshared_key_ciphertext, encryption_key_id, persistent_keepalive)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLink :one
SELECT * FROM site_device_links WHERE id = ?;

-- name: GetLinkBySiteDevice :one
SELECT * FROM site_device_links WHERE site_id = ? AND device_id = ?;

-- name: ListLinks :many
SELECT * FROM site_device_links ORDER BY site_id, device_id;

-- name: SetLinkEnabled :exec
UPDATE site_device_links SET enabled = ? WHERE id = ?;

-- name: SetLinkKeepalive :exec
UPDATE site_device_links SET persistent_keepalive = ? WHERE id = ?;

-- name: SetLinkPresharedKey :exec
UPDATE site_device_links SET preshared_key_ciphertext = ?, encryption_key_id = ? WHERE id = ?;
