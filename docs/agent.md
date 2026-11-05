# plait-agent

`plait-agent` runs on each Linux site gateway. It owns exactly three things:
the `plait0` WireGuard interface, `/32` return routes on `plait0` tagged with
route protocol `77`, and the nftables table `inet plait`. It never edits
`/etc/wireguard`, other interfaces, other routes, or other nftables tables.

## Host prerequisites (one-time setup, outside the service)

| Requirement | How |
|---|---|
| Kernel WireGuard | `echo wireguard > /etc/modules-load.d/plait.conf` (the service cannot load modules) |
| IPv4 forwarding | `echo net.ipv4.ip_forward=1 > /etc/sysctl.d/90-plait.conf && sysctl --system` |
| nftables | install `nft`; set `nft_path` to its absolute path |
| Reachable UDP endpoint | WAN must accept/forward UDP to the site's listen port (default 51111) |
| Routes to advertised LANs | the egress interface must reach every advertised prefix |
| Gateway address in an advertised prefix | the egress interface should hold an address inside one advertised prefix (see below) |
| Controller reachability | must not depend on the Plait tunnel itself |

**Reverse-path filtering.** The agent reports effective `rp_filter`
(`max(all, interface)`) for `plait0` and the egress interface in its status
but never changes it. Strict mode on `plait0` is satisfied by the explicit
`/32` return routes; loose mode can be scoped to one interface, e.g.
`all=1, plait0=2` gives loose on `plait0` only.

**ICMP source address.** `plait0` has no address, so for errors the gateway
itself generates toward a client (Fragmentation Needed, TTL exceeded) Linux
would pick a source from whichever interface it finds first, often a WAN or
management address. The client's WireGuard drops those, silently breaking
path MTU discovery and traceroute. Each return route therefore carries a
preferred source (`ip route ... dev plait0 src 10.15.0.1`): the gateway's
lowest address on the egress interface inside an advertised prefix. If there
is none, the agent warns; access still works.

**Firewall coexistence.** Plait's accepts live in its own table and can't
override a drop in another table. If another input or forward chain has a
drop policy, it must accept the site's UDP port and traffic between `plait0`
and the egress interface. The agent analyzes those chains and warns
specifically about what is missing.
- **Included table:** for a ruleset that runs `flush ruleset` on reload,
  `nft_include_file` keeps a copy of Plait's table for that ruleset to
  `include` ([deploy.md](deploy.md#35-a-host-firewall-managed-elsewhere)).
- **The gateway itself:** tunnel traffic to the gateway is dropped except
  for the site's listed gateway TCP ports.

## Configuration

`/etc/plait/agent.json`:

```json
{
  "state_dir": "/var/lib/plait",
  "nft_path": "/usr/sbin/nft"
}
```

`nft_include_file` (optional, an absolute `*.nft` path) receives a copy of the
table whenever it changes; set it with `plait-agent configure -nft-include
PATH` (`""` disables and removes the file). The service needs write access to
its directory (`install.sh` adds a `ReadWritePaths=` drop-in).

`plait-agent enroll` fills in `site_id`, `controller_url`, and `ca_file` (when
`-ca-file` or `-ca-fingerprint` is used). The CA is written to
`controller-ca.pem` beside the configuration, because the service cannot read
home directories (`ProtectHome=yes`).
- `-ca-file` copies a CA you supply, after checking that it parses.
- `-ca-fingerprint sha256:…` fetches the controller's generated CA from its
  TLS handshake, then requires two things before saving it: its SHA-256 must
  match, and it must have issued the server certificate for the controller's
  host name. Nothing is sent to the controller before this check passes. `credential_file` defaults to
`/var/lib/plait/agent.credential` so the service can rotate it under
`ProtectSystem=strict`. `ca_file` replaces the system roots for verifying the
controller; certificate verification is never disabled.

State directory contents (all mode 0600, directory 0700):

- `gateway.key` — the gateway's private key; generated locally, never sent anywhere.
- `desired.json` — last accepted snapshot with a SHA-256 integrity check. Contains PSKs.
- `applied.json` — last revision verified as fully applied.
- `agent.credential` — the site bearer credential.

## Enrollment

```sh
# controller (or POST /api/v1/admin/sites and .../enrollment-token)
plaitctl site add -name Home -endpoint home.example.net -egress enp1s0 -subnet 10.13.37.0/24
plaitctl site enroll-token Home          # single use, 1h by default
# gateway
plait-agent enroll -controller https://plait.example.net -token plaite_...
systemctl enable --now plait-agent
```

The gateway generates its key locally and sends only the public key. Issuing a
new token for an already enrolled site authorizes a gateway key replacement;
the old gateway's credentials are revoked when the token is used, and linked
devices must refresh their profiles.

`plait-agent rotate-credential` obtains a new credential; the previous one
expires after 10 minutes, and the controller refuses another rotation until
it has. The running agent re-reads the credential file before every request,
so it switches to the new credential without a restart. If the controller
revokes the credential, the agent logs `credential rejected` and keeps
serving its cached state.

`plait-agent apply-file <snapshot.json>` remains available for local or
emergency use (snapshots from `plaitctl site snapshot` contain PSKs).

## Behavior

- On start it loads the cached snapshot and reconciles immediately. With no
  valid cache and no controller it reports not ready and enables nothing.
- Every ~15 s (±20%) it fetches the snapshot, validates it (site ID, gateway
  key, schema, revision, prefixes), caches it atomically, then reconciles.
  Controller failures back off up to 5 minutes; drift repair from the cache
  continues every tick regardless.
- Reconciliation reads actual state and changes only what differs. Peers are
  added, updated in place, or removed by public key; `ReplacePeers` is never
  used, so unchanged peers keep their sessions and learned endpoints.
- Revocations (peer and route removal) are always applied. New or changed
  access is enabled only after the firewall and return routes for it are in
  place. A revision is recorded as applied only after full verification.
- An older revision, or different contents for the same revision, is rejected.
  A newer revision that partially fails is retried; earlier peer sets are never
  restored.
- Revocation timing: a healthy agent enforces a change within about one poll
  interval. A disconnected agent keeps serving its cached state indefinitely
  (no lease expiry in v1); emergency removal requires local action, e.g.
  `plait-agent uninstall`.

## Firewall policy (`table inet plait`)

- input: accept the WireGuard UDP port; accept enabled clients to the site's
  gateway TCP ports, if any; drop everything else arriving on `plait0`.
- forward: clamp TCP MSS (SYN and SYN-ACK, both directions) to `mtu - 40`
  only when larger; accept enabled client `/32`s to advertised LAN prefixes
  via the egress interface; accept established/related replies; drop all
  other traffic to or from `plait0` (including client-to-client).
- postrouting: masquerade only client-pool traffic to advertised prefixes on
  the egress interface.

The table is replaced atomically and only when drift is observed. Drift
detection compares chains, set elements, and the ordered rule comments; it
does not compare rule bodies, so values that must trigger a reapply (such as
the gateway TCP ports) are part of the rule's comment.

## Testing

`make integration` builds Linux binaries and runs three harnesses in a
privileged container, using network namespaces for a LAN host and two roaming
clients (`harness/ui-integration.sh`, the third, imports a browser-assembled
profile; see [ui.md](ui.md)). `harness/agent-integration.sh` drives the agent with snapshot files;
`harness/controller-integration.sh` runs plaitd, enrolls the agent by token,
and exercises polling, revocation, controller outage and restart, credential
rotation and revocation, and secret redaction end to end.

The agent harness covers foreign-interface
refusal, masquerade, gateway-local and unadvertised-destination denial,
modified client profiles, no-op reconciliation, endpoint preservation, route
and firewall drift repair, gateway-generated ICMP errors reaching the client
(and being dropped without the preferred source), uninterrupted flows while adding peers,
client-to-client denial, gateway TCP access, a host ruleset that flushes
and includes Plait's table (and the warnings when it lacks Plait's rules),
revocation, revision regression, cache corruption, site drain, and uninstall.

## Uninstall

`plait-agent uninstall` removes `plait0` (and its routes), `table inet
plait`, and the include file if one is configured. It works on an unenrolled
gateway and never creates a key. It leaves the state directory, including the
gateway key. `install.sh --uninstall agent` runs it and also removes the service,
binary, and host settings; `--purge agent` also deletes the state directory and
configuration (see [deploy.md](deploy.md#uninstall)).
