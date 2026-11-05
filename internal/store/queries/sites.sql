-- name: CreateSite :exec
INSERT INTO sites (id, name, endpoint_host, listen_port, public_key, egress_interface, mtu)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSite :one
SELECT * FROM sites WHERE id = ?;

-- name: GetSiteByName :one
SELECT * FROM sites WHERE name = ?;

-- name: ListSites :many
SELECT * FROM sites ORDER BY name;

-- name: UpdateSiteNetwork :exec
UPDATE sites
SET endpoint_host = ?, listen_port = ?, public_key = ?, egress_interface = ?, mtu = ?,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: SetSiteGatewayTCPPorts :exec
UPDATE sites SET gateway_tcp_ports = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: RenameSite :exec
UPDATE sites SET name = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: SetSiteEnabled :exec
UPDATE sites SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: BumpSiteRevision :exec
UPDATE sites
SET desired_revision = desired_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: ListSiteSubnets :many
SELECT * FROM site_subnets ORDER BY site_id, cidr;

-- name: DeleteSiteSubnets :exec
DELETE FROM site_subnets WHERE site_id = ?;

-- name: InsertSiteSubnet :exec
INSERT INTO site_subnets (site_id, cidr) VALUES (?, ?);

-- name: SetSitePublicKey :exec
UPDATE sites SET public_key = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- Recovery: move a site's revision past anything an agent has accepted.
-- name: AdvanceSiteRevision :exec
UPDATE sites
SET desired_revision = sqlc.arg(revision), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = sqlc.arg(id) AND desired_revision < sqlc.arg(revision);
