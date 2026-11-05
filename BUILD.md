# Plait

WireGuard multi-site remote access: one key pair and one stable `/32` per
roaming device, with one `[Peer]` per authorized site. For what Plait is and
how it works, start with [OVERVIEW.md](OVERVIEW.md); the design is in
[SPEC.md](SPEC.md).

To install the controller and gateways, see [docs/deploy.md](docs/deploy.md).
Prebuilt linux/amd64 and linux/arm64 binaries are in `dist/`; after changing
the source, refresh them with `make dist` and commit them separately.

## Status

In use on two sites since 2026-10-31: one Android profile reaches both
sites' LANs, with internal DNS.

| Phase | State |
|---|---|
| 0. Networking proof (Linux namespace harness, real phone) | namespace items done (`make phase0`); two-site access verified on Android; DNS edge cases, DDNS, and iOS pending (SPEC §8) |
| 1. Persistence and configuration compiler | implemented (see below) |
| 2. Agent and Linux integration | implemented; see [docs/agent.md](docs/agent.md) |
| 3. Controller API, auth, enrollment, status, recovery | implemented, including optional TOTP two-factor login; see [docs/controller.md](docs/controller.md) |
| 4. Administration UI and browser export | implemented; see [docs/ui.md](docs/ui.md). Android QR import verified; iOS, file import, and browsers other than Chrome untested |

Phase 1:

- SQLite (`modernc.org/sqlite`, CGO-free) with embedded migrations, sqlc
  queries, WAL, and `busy_timeout`/`foreign_keys` applied on every pooled
  connection via the DSN (verified at open and in tests).
- Write transactions use `BEGIN IMMEDIATE` with bounded whole-transaction
  retry; concurrent enrollment is tested across connections.
- Lowest-free `/32` allocation from the client pool (network, broadcast, and
  first host reserved), pool exhaustion, retired reservations retained until
  the device is deleted, which waits for linked sites to apply its removal.
- PSKs and administrator TOTP secrets encrypted at rest with AES-256-GCM
  (nonce prepended, the owning link or administrator ID as associated data)
  using a key file kept outside SQLite.
- Deterministic compiler for site snapshots and client profile material.
  Every mutation validates the complete resulting state and bumps exactly the
  site/device revisions whose compiled output changed; renames never do.
- Local profile assembly in `plaitctl`: the private key is generated and used
  only on the client side and is verified against the registered public key.

## Layout

```
cmd/plaitd         controller: REST API for agents and administrators
cmd/plaitctl       keys, local administration, profile assembly, backup/recovery
cmd/plait-agent    gateway agent: init, run, apply-file, status, uninstall
internal/model     domain types, pool, validation
internal/compiler  stored intent -> site snapshots / profile material
internal/controller transactional operations, revisions, audit, auth (incl. TOTP), enrollment, status
internal/api       HTTP handlers, session/CSRF and bearer authentication
internal/ui        server-rendered admin UI; browser key generation, QR, profile assembly
web/               pinned JS dependencies, vendoring build, cross-implementation tests
internal/store     SQLite, migrations, sqlc output (internal/store/db)
internal/protocol  JSON documents shared by controller, agent, CLI
internal/profile   wg-quick rendering (full and minified)
internal/secrets   encryption at rest (PSKs, TOTP secrets)
internal/wg        WireGuard key types (crypto/ecdh X25519)
internal/agent     agent cache, validation, reconciler, controller client, loop
internal/network   plait0 link and owned /32 routes (rtnetlink, Linux only)
internal/firewall  nftables rendering, nft execution, JSON drift inspection
harness/           Linux integration test (runs in a privileged container)
packaging/         systemd units
```

## Try it

```sh
make build
bin/plaitctl init-key ./psk.key
cat > plaitd.json <<JSON
{"database":"./plaitd.db","encryption_key_file":"./psk.key","client_pool":"10.0.0.0/24"}
JSON
export PLAIT_CONFIG=$PWD/plaitd.json

bin/plaitctl site add -name Home -endpoint home.example.net \
  -pubkey "$(bin/plaitctl genkey | bin/plaitctl pubkey)" -egress enp1s0 -subnet 10.13.37.0/24
bin/plaitctl device enroll phone -new -private-key-out phone.key
bin/plaitctl link add Home phone
bin/plaitctl profile phone -private-key-file phone.key
```

`make test` runs the Go tests with the race detector; `make test-js` checks
the browser code against the Go renderer and decodes its QR codes;
`make integration` runs the agent, the full controller/agent stack, and a
browser-assembled profile against a real kernel in Docker (three harnesses); `make phase0`
runs the Phase 0 networking proof (two gateways, ICMP, MSS/MTU, rp_filter)
in network namespaces; `make generate`
reruns sqlc. The UI is at `/` on plaitd's listener.
