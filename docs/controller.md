# plaitd

`plaitd` stores intent in SQLite, compiles desired state, and serves the REST
API for agents and administrators. It is outside the packet path: an outage
stops configuration changes, not tunnels.

## Setup

Full walkthrough: [deploy.md](deploy.md). In short, plaitd runs as the static
`plaitd` system user, and `plaitctl` must run as that user too
(`sudo -u plaitd plaitctl ...`) because it opens the same database and key.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin plaitd
install -d -m 0700 -o plaitd -g plaitd /var/lib/plaitd
plaitctl init-key /etc/plait/psk.key          # encryption key for PSKs and TOTP secrets; back up separately
chown plaitd:plaitd /etc/plait/psk.key
cat > /etc/plait/plaitd.json <<'JSON'
{
  "database": "/var/lib/plaitd/plaitd.db",
  "encryption_key_file": "/etc/plait/psk.key",
  "client_pool": "10.0.0.0/24",
  "listen": "0.0.0.0:8443",
  "tls_cert_file": "/etc/plait/tls/cert.pem",
  "tls_key_file": "/etc/plait/tls/key.pem"
}
JSON
sudo -u plaitd plaitctl admin create alice   # prompts for a password (12+ chars)
systemctl enable --now plaitd                 # packaging/plaitd.service
```

TLS: with `tls_cert_file`/`tls_key_file`, plaitd serves those files and
reloads them when they change on disk (checked every 30 s). With neither, a
loopback `listen` serves plaintext for a TLS-terminating reverse proxy, and
any other listener uses a controller-generated CA and server certificate in
`tls/` beside the database. That certificate is renewed and reissued
automatically, and covers the host's names and addresses plus any
`tls_names`. Gateways pin the CA with `-ca-fingerprint` at enrollment, and it
is published at `/ca.pem`. `plaitctl tls status|auto|files` inspects or
switches the mode ([deploy.md](deploy.md#23-tls-certificate)). Agents must reach the
controller independently of the Plait tunnels they manage.

## Authentication

- **Administrators**: `POST /api/v1/admin/login` sets an HttpOnly, Secure,
  SameSite=Strict session cookie (12 h absolute, 2 h idle) and returns a CSRF
  token. Every state-changing admin request must send it as `X-CSRF-Token`;
  cross-origin requests are rejected. Ten failed logins per username or client
  address (IPv6 by /64) within 15 minutes are throttled; attempts still in
  progress count toward the limit. Passwords are 12 to 256 bytes. At most four
  password hashes run at once; a login that waits more than 5 s for one gets
  `503` with `Retry-After`. v1 has one administrator role.
- **Two-factor (TOTP)**: optional per administrator, set up on the UI's
  **Account** page (click your username). Once on, login also needs a
  6-digit code (RFC 6238: SHA-1, 30 s, one step of clock skew); the API takes
  it as `"code"`. Each code is accepted once, wrong codes count as failed
  logins, and the response never says which factor failed. The secret is
  sealed with the encryption key, like PSKs. Setting it up or turning it off
  re-asks for the password (throttled like logins); turning it on ends the
  administrator's other sessions. There are no recovery codes: with a lost
  authenticator, run `plaitctl admin totp-reset <username>` on the controller
  host, which turns it off and ends that administrator's sessions.
- **Agents**: `Authorization: Bearer plaita_<id>_<secret>`. The secret has 256
  bits of randomness; only its SHA-256 is stored. The site is derived from the
  credential, never from the request, so an agent cannot read or report for
  another site. An agent credential is never administrator access.
- **Enrollment**: an administrator issues a single-use token
  (`plaite_...`, default 1 h). The agent exchanges it and its public key for a
  credential; the token is consumed in the same transaction.

## API

All responses are `Cache-Control: no-store`. Request bodies are JSON with
unknown fields rejected.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness, unauthenticated |
| `POST /api/v1/agent/enroll` | token + gateway public key → site ID + credential |
| `GET /api/v1/agent/sync` | complete desired snapshot (503 during recovery) |
| `POST /api/v1/agent/status` | revisions, health, sanitized errors, peer telemetry |
| `POST /api/v1/agent/credential/rotate` | new credential; others expire in 10 min; 429 while an earlier overlap runs |
| `POST /api/v1/admin/login`, `logout`; `GET .../session` | sessions (login takes `"code"` once TOTP is on; TOTP setup is UI-only) |
| `GET/POST /api/v1/admin/sites`, `GET/PUT .../sites/{id}` | sites (no key → pending enrollment) |
| `POST .../sites/{id}/enable`, `disable` | drain/restore a site |
| `POST .../sites/{id}/enrollment-token` | `{"ttl_seconds": N}` optional |
| `GET .../sites/{id}/credentials`, `POST .../credentials/revoke` | agent credentials |
| `GET .../sites/{id}/status` | reachability, applied revision, health, peers |
| `GET/POST /api/v1/admin/devices`, `GET .../devices/{id}` | devices, links, pending revocation; POST takes `name`, `public_key`, and optionally `mtu`, `search_domains`, `dns_servers` |
| `POST .../devices/{id}/rename`, `enable`, `disable`, `retire`, `replace-key` | lifecycle |
| `DELETE .../devices/{id}[?force=true]` | delete a disabled or retired device and free its address; refused while a linked site has not applied its removal, unless forced |
| `PUT .../devices/{id}/settings` | client MTU, DNS servers, search domains (ordered lists) |
| `GET .../devices/{id}/profile-material` | PSK-bearing material for local assembly (audited) |
| `POST .../devices/{id}/exports` | record an export (not proof of installation) |
| `POST /api/v1/admin/links`; `.../links/{id}/enable`, `disable`, `rotate-psk`; `PUT .../keepalive` | links |
| `GET /api/v1/admin/audit?before=&limit=` | audit log |

## Status semantics

Site status reports four facts separately instead of one "online" flag:

- **Reachability** (`unknown` / `reachable` / `stale`): controller receipt time
  of the last authenticated report; stale after 60 s. Unknown after a
  controller restart until the agent reports again.
- **Configuration applied**: the durable acknowledged revision. It only moves
  forward and never past the desired revision; `change_pending` is true while
  `applied < desired`. A device's `revocation_pending` is true while any site
  where it lost access has not acknowledged.
- **Health**: from the latest live report only; unknown when stale.
- **Peer activity**: transient handshake and traffic counters held in memory.
  Silence does not prove a client is offline; a handshake does not prove LAN
  or DNS access.

A disconnected agent keeps enforcing its cached state, including access that
was revoked after it lost contact; there is no bounded revocation time for an
unreachable gateway. Durable status writes are coalesced (on change, or every
5 minutes) so heartbeats do not churn SQLite.

## Audit

Enrollment, authorization changes, revocations, key and credential changes,
profile-material access, exports, logins, two-factor changes (enable,
disable, `totp-reset`), applied-revision transitions, backup, and recovery
are recorded with their actor (`admin:<name>`,
`agent:<site>`, `local:plaitctl`, `enrollment:<token id>`). Details never
contain keys, PSKs, tokens, or profiles. Retention is unbounded in v1.

## Backup and recovery

```sh
plaitctl backup /backups/plaitd-$(date +%F).db   # consistent, includes WAL contents
```

The backup does **not** include `psk.key`. Without that key, stored PSKs
cannot be decrypted and every link needs a new PSK and profile refresh, and
an administrator with TOTP on can't log in until `plaitctl admin totp-reset`
clears it. Keep the key in separate, protected storage.

Restoring an older database could silently re-enable access revoked after the
backup. Restore therefore puts the controller into recovery:

1. Stop plaitd. `plaitctl restore /backups/plaitd-....db` (keeps the previous
   database as `*.pre-restore-<timestamp>`; refuses a backup that fails
   `integrity_check`).
2. Start plaitd. Agents keep their cached state; `sync` returns 503 so nothing
   older is distributed. Agents still report status.
3. `plaitctl recover status` shows sites whose agents accepted revisions beyond
   the restored database. Review `plaitctl audit` from the pre-restore database
   and re-apply every revocation and change made after the backup.
4. `plaitctl recover complete` advances each site's revision beyond what its
   agent accepted and resumes distribution.

Agents independently reject older revisions, so a restored controller cannot
roll back a gateway without the explicit advancement in step 4.
