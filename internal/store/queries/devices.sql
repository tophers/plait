-- name: CreateDevice :exec
INSERT INTO devices (id, name, public_key, assigned_ipv4) VALUES (?, ?, ?, ?);

-- name: GetDevice :one
SELECT * FROM devices WHERE id = ?;

-- name: GetDeviceByName :one
SELECT * FROM devices WHERE name = ?;

-- name: ListDevices :many
SELECT * FROM devices ORDER BY name;

-- Includes retired devices: v1 never reuses their reservations.
-- name: ListAssignedIPv4 :many
SELECT assigned_ipv4 FROM devices;

-- name: RenameDevice :exec
UPDATE devices SET name = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: SetDeviceEnabled :exec
UPDATE devices SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: RetireDevice :exec
UPDATE devices
SET retired_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND retired_at IS NULL;

-- name: ReplaceDeviceKey :exec
UPDATE devices SET public_key = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: SetDeviceClientSettings :exec
UPDATE devices
SET client_mtu = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: BumpDeviceProfileRevision :exec
UPDATE devices
SET profile_revision = profile_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: RecordDeviceExport :exec
UPDATE devices
SET last_exported_revision = ?, last_exported_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: ListDeviceDNSServers :many
SELECT * FROM device_dns_servers ORDER BY device_id, position;

-- name: DeleteDeviceDNSServers :exec
DELETE FROM device_dns_servers WHERE device_id = ?;

-- name: InsertDeviceDNSServer :exec
INSERT INTO device_dns_servers (device_id, position, address) VALUES (?, ?, ?);

-- name: ListDeviceSearchDomains :many
SELECT * FROM device_search_domains ORDER BY device_id, position;

-- name: DeleteDeviceSearchDomains :exec
DELETE FROM device_search_domains WHERE device_id = ?;

-- name: InsertDeviceSearchDomain :exec
INSERT INTO device_search_domains (device_id, position, domain) VALUES (?, ?, ?);

-- name: DeleteDeviceLinks :exec
DELETE FROM site_device_links WHERE device_id = ?;

-- name: DeleteDevice :exec
DELETE FROM devices WHERE id = ?;
