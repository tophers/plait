# Deploying Plait

This guide installs the controller, enrolls one or more site gateways, and
issues device profiles. For the details behind each step, see
[controller.md](controller.md), [agent.md](agent.md), and [ui.md](ui.md).

## Topology

```
 phones / laptops ──WireGuard UDP──▶ site gateway (plait-agent) ──▶ site LAN
                                          │
                                          │ HTTPS poll every ~15 s
                                          ▼
 admin browser ───────HTTPS──────▶ controller (plaitd + SQLite)
```

- **Controller** (`plaitd`): one host. It doesn't have to be a gateway, and
  it isn't in the packet path. While it is down, nobody can make changes, but
  existing tunnels keep working.
- **Gateways** (`plait-agent`): one Linux host per site, with kernel
  WireGuard, nftables, and a UDP port reachable from the internet.
- **Gateways must reach the controller without going through a Plait
  tunnel.** Use a public address or a separate management path.

| Host | Inbound | Outbound |
|---|---|---|
| Controller | TCP 8443 (or your `listen` port) from gateways and admins | none |
| Gateway | UDP listen port (default 51111) from clients | TCP to the controller; the site LAN |

## 1. Binaries

The repository ships prebuilt static binaries for linux/amd64 and linux/arm64
in `dist/linux-<arch>/`, with `dist/SHA256SUMS`. A plain `git clone` on the
target host is enough, and `install.sh` verifies the checksums before
installing. `plait-agent` reports the source commit it was built from in its
status, shown on the site page.

To build them yourself instead (Go 1.27.3 or later, any OS):

```sh
make dist        # dist/linux-amd64 and dist/linux-arm64, plus SHA256SUMS
```

The builds are reproducible: unchanged source produces identical bytes, and
`make dist-check` fails if the committed binaries don't match the source.
Run `make test` (and `make integration` if Docker is available) before you
deploy a new build.

If you install by hand rather than with the script, the controller needs
`plaitd` and `plaitctl` in `/usr/local/bin/`, and each gateway needs
`plait-agent`.

## Quick path: `packaging/install.sh`

Clone the repository on the host (the prebuilt binaries in `dist/` come
with it), then run as root from the checkout:

```sh
sudo ./packaging/install.sh
```

With no arguments, the script walks you through the setup:
- **What this host runs:** controller, gateway, or both.
- **Controller questions:** the client address pool, the port, and how to
  handle TLS. TLS can be generated automatically, use a Let's Encrypt
  certificate the script found, or use your own files. With the generated
  certificate, it also asks the name gateways will use to reach the
  controller.
- **Confirmation:** a summary of what it will install, before anything
  changes.
- **After installing:** it offers to create the first web UI administrator.
  On a gateway, it asks you to paste the enrollment command from the site
  page, then enrolls the gateway and starts the agent.

Run it again to upgrade. It detects what's installed and keeps your
settings.

For scripts and automation, pass the role and options instead, and nothing
is asked:

```sh
./packaging/install.sh controller --client-pool 10.99.0.0/24 --tls-auto --tls-name plait.example.net
./packaging/install.sh agent      # then: plait-agent enroll ..., and run it again to start the agent
```

The script performs sections 2 and 3.1–3.2 below:
- **Users and directories:** the `plaitd` user and every directory, with the
  ownership and modes described below.
- **Controller files:** generates `psk.key` and writes `plaitd.json`, only
  when they are missing. TLS is set up as described in
  [2.3](#23-tls-certificate). Without a terminal, pass `--client-pool`, and
  optionally a TLS option.
- **Gateway setup:** installs `nftables` and `wireguard-tools`, loads the
  module at boot, and turns on IPv4 forwarding.
- **Binaries, units, docs:** installs the binaries, the systemd units, and
  these docs.

Re-run it with new binaries to upgrade. It never overwrites existing
configuration, keys, or state. On each run it:
- skips any binary that hasn't changed;
- restarts only the services whose binary, unit, or TLS files changed;
- backs up the database before replacing `plaitd`, into
  `/var/backups/plaitd/pre-upgrade-*.db`;
- keeps the previous binaries as `*.prev`;
- runs `plaitd -check` before starting the controller;
- repairs ownership and modes that have drifted, such as root-owned files in
  `/var/lib/plaitd` or a group-readable `psk.key`.

Options: `--bin-dir`, `--listen`, `--no-deps`, and `--no-start`.
`./packaging/install.sh --help` explains each one. To remove Plait, use
`--uninstall` or `--purge` (see [Uninstall](#uninstall)).
`harness/install-test.sh` exercises the script on Debian trixie under systemd.

## 2. Controller

Run every step as root unless it says otherwise.

### 2.1 User and directories

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin plaitd
install -d -m 0755 /etc/plait
install -d -m 0750 -o root -g plaitd /etc/plait/tls
install -m 0644 packaging/plaitd.service /etc/systemd/system/plaitd.service
```

systemd creates `/var/lib/plaitd`, owned by `plaitd` with mode 0700, the
first time the service starts. The local admin commands below need it before
then, so create it now:

```sh
install -d -m 0700 -o plaitd -g plaitd /var/lib/plaitd
```

### 2.2 Encryption key

```sh
plaitctl init-key /etc/plait/psk.key
chown plaitd:plaitd /etc/plait/psk.key        # stays mode 0600
```

This key encrypts every link's preshared key and every administrator's TOTP
secret in the database. **Back it up now, somewhere other than where you
keep database backups.** Without it, a database backup can't decrypt any
PSK, so every device would need a new profile, and two-factor login would
have to be reset with `plaitctl admin totp-reset`. `plaitd` refuses to start if the file is readable by group or
others.

### 2.3 TLS certificate

`plaitd` serves TLS itself, in one of three ways:

| Mode | When | You manage |
|---|---|---|
| **Generated** (default) | no `tls_cert_file`/`tls_key_file` in the config | nothing |
| **Let's Encrypt / your own files** | `tls_cert_file` and `tls_key_file` set | getting the certificate (certbot does it for Let's Encrypt) |
| **Behind a proxy** | `listen` is a loopback address | TLS at the proxy |

**Generated certificate.** On first start, `plaitd` creates its own CA and a
server certificate in `/var/lib/plaitd/tls/`:
- **Names covered:** this host's name and addresses, plus `localhost`. To
  add another name, such as a public DNS name behind NAT, use `tls_names`,
  `install.sh --tls-name`, or the installer's guided setup, which asks for
  it.
- **Renewal:** the server certificate is renewed automatically, and reissued
  if the host's names or addresses change. `plaitd` checks every 12 hours.
- **The CA never changes.** Gateways pin it once, when they enroll: the
  enrollment command on each site page includes
  `-ca-fingerprint sha256:…`, and `plait-agent` checks the controller's CA
  against it, then saves a copy.
- **Browsers:** they warn until you trust the CA. Download it from
  `https://<controller>:8443/ca.pem` and add it to your OS or browser's
  trusted certificates, or accept the warning once.
- **Status:** `plaitctl tls status` shows the fingerprint, the names, and the
  expiry date.

Back up `/var/lib/plaitd/tls/` along with `psk.key`. If it's lost, `plaitd`
generates a new CA, and every gateway must be enrolled again.

**Let's Encrypt.** `install.sh --letsencrypt` lists the certificates in
`/etc/letsencrypt/live/` and asks which one to use (or use
`--letsencrypt=NAME`). It then:
- copies the certificate to `/etc/plait/tls/`;
- installs a certbot deploy hook at
  `/etc/letsencrypt/renewal-hooks/deploy/plait`, which copies each renewal
  for that certificate.

`plaitd` reloads replaced certificate files within a minute, so renewals need
no restart. Gateways need no extra options, because Let's Encrypt is trusted
by the system's certificate store. The certificate must cover the name
gateways and browsers use to reach the controller. For a wildcard
certificate, give that name explicitly; the installer checks the certificate
covers it and remembers it (in `/etc/plait/controller-name`) for upgrades:

```
sudo ./packaging/install.sh controller --letsencrypt=example.net --controller-name wg.example.net
```

**Your own files.** Use `install.sh --tls-cert fullchain.pem --tls-key
privkey.pem`, or `plaitctl tls files -cert … -key …`. Gateways need
`-ca-file` at enrollment only if your CA isn't publicly trusted.

Switch modes at any time with `install.sh --tls-auto`, `--letsencrypt`, or
`--tls-cert`/`--tls-key`, or with `plaitctl tls auto|files` followed by
`systemctl restart plaitd`. Switching away from the generated certificate and
back keeps the same CA, so enrolled gateways keep working.

The unit has no `CAP_NET_BIND_SERVICE`, so use a port above 1023 such as
8443. If you need port 443, see [Reverse proxy](#reverse-proxy-alternative).

### 2.4 Configuration

`/etc/plait/plaitd.json` must be readable by `plaitd` (mode 0644 is fine; it
contains no secrets):

```json
{
  "database": "/var/lib/plaitd/plaitd.db",
  "encryption_key_file": "/etc/plait/psk.key",
  "client_pool": "10.99.0.0/24",
  "listen": "0.0.0.0:8443"
}
```

That's a complete configuration using the generated certificate. Add
`"tls_names": ["plait.example.net"]` to cover more names than the host's
own, or `tls_cert_file` and `tls_key_file` to use certificate files.

- `client_pool`: devices get their tunnel addresses from this range. It must
  not overlap any site LAN, or the networks your users join (home Wi-Fi,
  hotels, carrier NAT). Avoid `10.0.0.0/24`, `192.168.0.0/24`,
  `192.168.1.0/24`, and similar common ranges. You can't easily change it
  once devices exist.
- `pool_exclusions` (optional): addresses inside the pool that must never be
  assigned.
- Unknown keys are rejected, so a typo fails at startup rather than being
  silently ignored.

### 2.5 Running `plaitctl` on the controller

`plaitctl` opens the database and key directly, so **always run it as the
`plaitd` user**. If you run it as root, it can create root-owned database
files that `plaitd` then can't open.

```sh
alias plaitctl='sudo -u plaitd plaitctl'      # add to root's shell profile
# minimal Debian has no sudo; runuser (util-linux) is always present:
alias plaitctl='runuser -u plaitd -- plaitctl'
```

Each example below includes the `sudo -u plaitd` explicitly.

### 2.6 First administrator, check, start

```sh
sudo -u plaitd plaitctl admin create alice    # prompts; 12+ characters
sudo -u plaitd plaitd -check -config /etc/plait/plaitd.json
systemctl daemon-reload
systemctl enable --now plaitd
journalctl -u plaitd -f
```

`-check` validates the configuration, the key, and the stored state, then
exits. Database migrations run automatically whenever `plaitd` or `plaitctl`
opens the database.

Open `https://plait.example.net:8443/` and log in. To require a code from an
authenticator app as well, click your username and choose **Set up
two-factor authentication**.

### Reverse proxy alternative

If `listen` is a loopback address (for example `127.0.0.1:8443`), `plaitd`
runs without TLS and expects a proxy in front of it. The proxy must:

- terminate TLS for the public name;
- pass the original `Host` header through. Origin checks compare it with the
  browser's `Origin`, so without it every UI change fails with
  "cross-origin request rejected";
- set `X-Forwarded-Proto: https`, which `plaitd` uses for the enrollment
  command it displays.

```nginx
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
}
```

With a loopback `listen`, the proxy owns TLS: `plaitd` neither generates nor
loads certificates.

**Caveat:** `plaitd` doesn't read `X-Forwarded-For`. Behind a proxy, every
login appears to come from the proxy's address. After ten failed logins from
anyone, logins are blocked for everyone for 15 minutes. Serving TLS directly
avoids this.

## 3. Site gateways

Repeat this section for each site.

### 3.1 Host prerequisites (one time)

```sh
echo wireguard > /etc/modules-load.d/plait.conf && modprobe wireguard
echo net.ipv4.ip_forward=1 > /etc/sysctl.d/90-plait.conf && sysctl --system
apt install nftables          # or dnf/apk; note the path from `command -v nft`
```

- **UDP port:** forward the site's UDP port (default 51111) from the WAN or
  router to this host.
- **LAN routes:** the gateway's LAN interface must reach every prefix you
  will advertise.
- **Existing firewall:** see [3.5](#35-a-host-firewall-managed-elsewhere).
  Plait's own table can't override a drop in another table, so a ruleset
  that drops by default must explicitly allow Plait's traffic.
- **Reverse-path filtering:** strict `rp_filter` works. The agent reports the
  setting but never changes it ([agent.md](agent.md)).

### 3.2 Install

```sh
install -m 0755 plait-agent /usr/local/bin/plait-agent
install -d -m 0755 /etc/plait
cat > /etc/plait/agent.json <<'JSON'
{
  "state_dir": "/var/lib/plait",
  "nft_path": "/usr/sbin/nft"
}
JSON
install -m 0644 packaging/plait-agent.service /etc/systemd/system/plait-agent.service
install -d -m 0700 /var/lib/plait
```

### 3.3 Create the site on the controller

In the UI, go to **Sites → Add site** and fill in:

| Field | Value |
|---|---|
| Name | e.g. `Home` |
| Public endpoint | DNS name or IP that clients reach; a dynamic DNS name is fine |
| UDP port | the forwarded port (default 51111) |
| Gateway MTU | the default unless the WAN needs less (PPPoE: 1412 or lower) |
| LAN interface | the gateway's LAN-facing interface, e.g. `enp1s0` |
| Advertised LAN prefixes | e.g. `192.168.50.0/24`; must not overlap the client pool or another site |
| Gateway access from the tunnel | empty, or TCP ports on the gateway host itself that devices may reach, e.g. `22` |

Connected devices can reach every host in the advertised prefixes except the
gateway itself: traffic addressed to the gateway, including its LAN address,
is dropped unless its port is listed under **Gateway access**. The gateway's
own firewall must accept those ports too.

Then open the site and click **Issue enrollment token**. The token can be
used once and expires after 1 hour. The page shows the exact command to run.

### 3.4 Enroll and start

On the gateway:

```sh
plait-agent enroll -controller https://plait.example.net:8443 -token plaite_...
#   the site page's command adds -ca-fingerprint sha256:... when plaitd uses its
#   generated certificate; for another private CA use -ca-file ca.pem instead
systemctl daemon-reload
systemctl enable --now plait-agent
plait-agent status
```

Enrollment generates the gateway's key locally, sends only the public key,
and writes `site_id`, `controller_url`, and the credential. Within a few
seconds the site page should show **Agent reachable: reachable** and
**Configuration applied: rN of rN**, with no errors under **Local health**.

### 3.5 A host firewall managed elsewhere

nftables runs every packet through every table attached to a hook, and a drop
in any of them is final. If the gateway already has a ruleset with
`policy drop` on input or forward, managed by your own tooling, it must allow
Plait's traffic:

```
input chain:    udp dport <site port> accept            # the site's WireGuard port
forward chain:  iifname "plait*" accept
                oifname "plait*" accept                 # or rely on ct state established,related
```

You don't need to restrict `plait*` traffic further. Plait's own table limits
devices to the advertised prefixes, blocks client-to-client traffic and
access to the gateway, and masquerades its own traffic, and its drops apply
even when your rules accept.

On each pass the agent reads other tables' input and forward chains that drop
by default. It warns on the site page when it finds no rule that clearly
accepts Plait's UDP port, traffic from `plait0`, or replies to it, and the
warning names the chain and the rule to add. Rules it can't evaluate, such as
jumps or matches on named sets, are assumed to accept, so a warning signals a
likely problem rather than proving one.

**If your configuration runs `flush ruleset` on reload** (common when a tool
regenerates `/etc/nftables.conf`), each reload also deletes Plait's table
until the agent restores it, within about 15 seconds. During that window only
your rules apply to `plait0`. To avoid it, let your configuration include
Plait's table:

1. Run `install.sh agent --nft-include`, or answer yes when the guided setup
   offers it. It does the following:
   - points `nft_include_file` in `agent.json` at
     `/etc/nftables/conf.d/plait.nft`;
   - adds a systemd drop-in that allows the sandboxed agent to write to that
     directory.

   From then on, the agent keeps that file identical to its live table.
2. In your configuration, include the directory with a glob:
   `include "/etc/nftables/conf.d/*.nft"`. A glob that matches nothing is
   fine, so hosts without Plait still load.

A reload then rebuilds your tables and Plait's in the same transaction. The
file starts by deleting any existing `plait` table, so it is also safe in a
configuration that doesn't flush. `plait-agent uninstall` and
`install.sh agent --no-nft-include` remove the file.

## 4. Devices

1. Go to **Devices → Add device**, enter a name, and tick the sites the
   device should reach. The browser generates the device's key.
2. The page shows a QR code and a `.conf` download. Scan it with the
   WireGuard app, or import the file. The private key exists only in that
   browser tab. Click **Clear from this page** when you're done.
3. Each site the device can reach adds to the profile's size. With four or
   more sites, use the file instead of the QR code ([ui.md](ui.md#qr-codes-and-files)).

Profiles don't update themselves. When a device shows **changed since
export**, use **Update profile (new key)** on its device page and import the
new profile on the device (replace the old tunnel). Revocations take effect
without touching the device.

## 5. Verify the deployment

- [ ] A device reaches a LAN host at each linked site, at the same time.
- [ ] If DNS is configured, names resolve with the tunnel up.
- [ ] Disable the device in the UI. Within about 15 s it loses access at
      every site, and **revocation pending** clears.
- [ ] Re-enable it, then restart `plaitd`. Tunnels keep working throughout,
      and sites return to *reachable* within one poll.
- [ ] Stop `plait-agent` on one gateway. After 60 s the site shows *stale*,
      and the other sites are unaffected. Start it again.
- [ ] A large download over the tunnel completes, which confirms MTU and MSS
      are right.

## 6. Operations

### Backups

```sh
install -d -m 0700 -o plaitd -g plaitd /var/backups/plaitd
sudo -u plaitd plaitctl backup /var/backups/plaitd/plaitd-$(date +%F).db
```

Run this from a daily timer or cron job, and copy the results off the host.
The backup is a consistent copy, safe to take while `plaitd` is running. It
contains PSKs and TOTP secrets, which stay encrypted under `psk.key`, but
**not** `psk.key` itself. Keep `psk.key` in a separate protected place, such as a password
manager or an offline copy.

With the generated certificate, also keep a copy of `/var/lib/plaitd/tls/`.
`ca.key` in that directory is the CA's private key, so protect it like
`psk.key`. Without it, a rebuilt controller gets a new CA, and every gateway
must be enrolled again.

Gateways keep their own state in `/var/lib/plait`, which contains
`gateway.key`. Losing it means the gateway must be re-enrolled (a new token)
and every linked device must import a new profile. Back it up only if that
cost matters to you, and protect it like a private key.

### Restore

Restoring an older database could re-enable access you revoked after the
backup was taken, so a restore always enters recovery mode:

```sh
systemctl stop plaitd
sudo -u plaitd plaitctl restore /var/backups/plaitd/plaitd-2026-10-01.db
systemctl start plaitd
sudo -u plaitd plaitctl recover status        # wait for agents to report
# re-apply every revocation/change made since the backup (see the old audit log)
sudo -u plaitd plaitctl recover complete
```

[controller.md](controller.md#backup-and-recovery) explains each step.

### Upgrades

`install.sh` does all of this for you; by hand:

1. Controller:
   1. Take a backup.
   2. `systemctl stop plaitd`
   3. Replace `plaitd` and `plaitctl` together. Both open the database, and
      after a migration an older `plaitctl` may no longer read it.
   4. `sudo -u plaitd plaitd -check -config /etc/plait/plaitd.json`
   5. `systemctl start plaitd`
2. Gateways, one at a time, when a release changes `plait-agent` (an
   unchanged agent keeps working with a newer controller):
   1. Replace `plait-agent`.
   2. `systemctl restart plait-agent`
   3. Confirm the site returns to *reachable* and *applied*.

Migrations only move forward. To roll back, restore a pre-upgrade backup,
which means going through recovery. Peers keep their sessions across agent
restarts, so a restart doesn't drop connected clients.

### Routine tasks

| Task | How |
|---|---|
| Logs | `journalctl -u plaitd`, `journalctl -u plait-agent` |
| Gateway state | `plait-agent status` (no secrets in the output) |
| Rotate a gateway credential | `plait-agent rotate-credential` on the gateway |
| Cut off a gateway's controller access | Site page → **Revoke all credentials** (it keeps enforcing its cached peers) |
| Replace a gateway | Site page → **Issue token to replace gateway key**, enroll the new host, then refresh every linked device's profile |
| Admin password | `sudo -u plaitd plaitctl admin password alice` |
| Two-factor login | UI → your username → **Set up two-factor authentication** |
| Lost authenticator | `sudo -u plaitd plaitctl admin totp-reset alice` (turns two-factor off, ends sessions) |
| Audit | UI → **Audit**, or `sudo -u plaitd plaitctl audit -n 100` |

### Emergency removal at a site

A gateway that can't reach the controller keeps enforcing its cached state
indefinitely, **including access you revoked after it lost contact**. To cut
off a site immediately, run on the gateway:

```sh
systemctl stop plait-agent && plait-agent uninstall
```

This removes `plait0`, its routes, and `table inet plait`. The gateway key is
kept, so later you can run `systemctl start plait-agent`, and it will restore
the state it has cached.

### Uninstall

```sh
sudo ./packaging/install.sh --uninstall [controller|agent]   # keep config, keys, and data
sudo ./packaging/install.sh --purge [controller|agent]       # delete everything
```

With no role, it removes every role it finds on the host. From a terminal it
lists what it will remove and asks first; `PLAIT_NONINTERACTIVE=1` skips the
question.

| | `--uninstall` | `--purge` adds |
|---|---|---|
| Gateway | stops and disables `plait-agent`; removes `plait0`, its routes, `table inet plait`, the nft include file and its unit drop-in, the binary and unit, and `/etc/modules-load.d/plait.conf` and `/etc/sysctl.d/90-plait.conf` | `/etc/plait/agent.json`, `/etc/plait/controller-ca.pem`, and `/var/lib/plait` (gateway key, credential, cached state) |
| Controller | stops and disables `plaitd`; removes the binaries, the unit, and the Let's Encrypt renewal hook | `/etc/plait/plaitd.json`, the PSK key, `/etc/plait/tls`, `/var/lib/plaitd` (database, generated CA), `/var/backups/plaitd`, and the `plaitd` user and group |

After `--uninstall`, running the installer again resumes where it left off:
same database, CA fingerprint, administrators, gateway key and enrollment,
TLS mode (including the renewal hook), and include file. `/usr/share/doc/plait`
and an empty `/etc/plait` go once neither role remains.

**`--purge` is irreversible.** Every device profile and gateway enrollment
depends on the controller's database and PSK key. To keep a copy, take a backup
first and store it with `/etc/plait/psk.key` (see [Backups](#backups)).

Neither option touches:
- **Packages:** `nftables`, `wireguard-tools`, and the rest.
- **IPv4 forwarding:** it keeps its current value until reboot.
- **Your host firewall:** remove the `plait*` rules, Plait's UDP and TCP ports,
  and the include line from `/etc/nftables.conf` or the tool that writes it.
  The installer reminds you when that file mentions Plait. A glob include such
  as `conf.d/*.nft` keeps loading without the file.
- **Devices:** delete the Plait tunnels from phones and laptops.

## 7. Known limitations

- **Partly tested on real devices:** Android QR import, two-site access, and
  internal DNS work in daily use. iOS, file import, DNS failure cases, and
  roaming across a site's address change haven't been checked yet. Record
  results in the [compatibility matrix](ui.md#compatibility-matrix).
- **Revocation needs a connected gateway:** an unreachable gateway has no
  bounded revocation time.
- **Unbounded audit log:** it grows without limit. The login throttle lives
  in memory and resets when `plaitd` restarts.
- **Single administrator role:** there is one administrator role. There is
  no high availability: one controller with SQLite.
- **Unaudited crypto release:** the vendored `@noble/curves` (2.4.0) is one
  release newer than the audited 2.3.0 (see
  [VENDOR.md](../internal/ui/static/vendor/VENDOR.md)).
