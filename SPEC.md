# Plait: WireGuard Multi-Site Remote Access Specification

Status: v1 is implemented and in use on two sites. This document is the design: requirements and acceptance criteria. Implementation status is recorded against the checklists in Section 8 and in [README.md](README.md); behavior as built is documented in [docs/](docs/). Where the implementation deliberately departs from or extends an original requirement, the requirement below says so.

## 1. Purpose and Scope

Plait manages roaming devices that need simultaneous access to several independent sites through one WireGuard profile. Each device keeps one key pair and one stable tunnel IPv4 address; its profile contains a peer for each authorized site.

Per-site provisioning often creates separate device identities and profiles, making multi-site access cumbersome. The motivating deployment reported problems with multiple IPv4 addresses on a mobile WireGuard interface, possibly involving source-address selection and peer source validation. This is an observation to reproduce, not an established universal Android routing deadlock. Record the OS, WireGuard app version, configurations, routes, and packet evidence during the networking proof. Avoid relying on blanket claims about concurrent VPN restrictions across all mobile platforms.

### 1.1. Core model

1. A roaming device has one stable IPv4 `/32`, such as `10.0.0.4/32`, across all authorized sites.
2. Each site is a separate client-side `[Peer]`, with its gateway public key, reachable UDP endpoint, and authorized site LAN prefixes in `AllowedIPs`.
3. Each gateway associates that device's public key with exactly its assigned `/32` and installs an explicit Linux return route through WireGuard.
4. Gateways enforce destination access in their firewall and masquerade permitted client traffic onto their LAN.
5. Every site-device link has a distinct random preshared key (PSK). This adds WireGuard's symmetric-key protection, including additional post-quantum resistance; it does not eliminate the impact of controller or client compromise.
6. The controller distributes configuration and records status. It is outside the packet forwarding path.

### 1.2. V1 scope and prerequisites

- Multi-site remote access using standard WireGuard clients and Linux site gateways.
- IPv4 tunnel addresses and IPv4 site LAN prefixes; split tunneling only.
- One controller instance with SQLite, a REST API, and an administration UI.
- Manual client profile refresh after relevant configuration changes.
- Each site must expose a reachable WireGuard UDP endpoint, directly or through configured port forwarding. Agent HTTPS polling does not establish WireGuard connectivity through arbitrary NAT or CGNAT.
- Gateways must have kernel WireGuard support, nftables, suitable privileges, and routes to their advertised LANs.
- The controller must be reachable by agents independently of the Plait tunnel they manage, including during boot and recovery.

V1 excludes site-to-site transit, client-to-client access, automatic client configuration delivery, relays, coordinated NAT traversal, exit nodes, high availability, gRPC, and IPv6 tunnel/LAN routing. These require separate designs. Do not add a partial IPv6 suffix field before specifying allocation, routes, firewall behavior, DNS, and client compatibility.

## 2. Architecture and Ownership

### 2.1. Components

- **`plaitd`**: Go controller; SQLite/sqlc persistence, address allocation, shared configuration compiler, REST API, and Go `html/template` + HTMX administration UI.
- **`plait-agent`**: Linux systemd daemon; owns one dedicated `plait0` interface, its WireGuard peers, managed routes, and Plait firewall rules.
- **`plaitctl`**: Local administration and enrollment helper, including private-key-local profile assembly and diagnostics.

Use `cmd/plaitd`, `cmd/plait-agent`, and `cmd/plaitctl`; configuration lives under `/etc/plait/`, and durable agent state under `/var/lib/plait/`. Use Plait consistently rather than mixing MeshGuard and Plait names.

```text
                         plaitd
                SQLite + compiler + UI
                    /             \
        HTTPS + site token     HTTPS + site token
          polling / status       polling / status
                 /                 \
         Home plait-agent     Emerald plait-agent
              plait0               plait0
         10.13.37.0/24 LAN     10.15.0.0/24 LAN
                 \                 /
                   direct WireGuard
                          |
                 roaming device
                   10.0.0.4/32
                  one client profile
```

### 2.2. Shared compiler

```text
stored intent -> validation -> desired site state -> agent reconciliation
                           -> client profile material -> local key assembly
```

Use one domain model and validation layer for both outputs. Keep compilation deterministic and independent of HTTP handlers and kernel operations. Prefer Go's standard `net/netip` package (`netip.Prefix.Overlaps`, `netip.Addr.Compare`, `netip.Prefix.Contains`) for prefix overlap detection, pool scanning, and canonical representation without external dependencies. Suggested packages: `internal/store`, `internal/model`, `internal/compiler`, `internal/agent`, `internal/wg`, `internal/network`, and `internal/firewall`.

The controller owns authorization, site definitions, device identities, address reservations, and desired revisions. The agent owns implementation on its host. The agent generates and retains its gateway private key locally; only its public key is registered with the controller.

`wgctrl` configures existing WireGuard interfaces. Interface creation, link state, addresses, MTU, and Linux routes require a separate network-management implementation, such as rtnetlink. See [wgctrl scope](https://github.com/WireGuard/wgctrl-go#overview).

### 2.3. Address and route ownership

- Configure one global client pool, such as `10.0.0.0/24`. It must not overlap managed site LAN prefixes or conflicting gateway networks/routes.
- Reserve network and broadcast addresses and explicitly configured exclusions. Reserve `.1` in the example pool for future use; do not assume every gateway needs that address.
- The proposed v1 gateway uses an unnumbered `plait0` for forwarding. WireGuard is a layer 3 interface without ARP (`ARPHRD_NONE`), allowing routes such as `10.0.0.4/32 dev plait0` without an interface IP. Retain this design only if Phase 0 establishes correct ICMP error propagation on supported gateway layouts; forwarding alone does not prove it works. Numbered gateway tunnel addresses and client access to them remain outside the proposed v1 scope, subject to that validation gate.
- Gateway-generated ICMP errors (e.g. TTL exceeded or Fragmentation Needed) must use a source address accepted by the client's site peer. Linux may fall back to the primary address of the first non-loopback interface when the selected interface is unnumbered; this may be a WAN or management address outside the advertised LAN prefixes. Test separate WAN, LAN, and management interfaces and different interface/address ordering. If this fails, specify and validate an explicit ICMP source-address strategy before proceeding, or revise the unnumbered-interface decision. Do not indiscriminately broaden client `AllowedIPs` to mask the failure. See [Linux ICMP source selection](https://docs.kernel.org/networking/ip-sysctl.html).
- **Phase 0 result (2026-10-31, Linux network namespaces):** the default behavior fails. With the WAN or management interface created before the LAN interface, TTL-exceeded and Fragmentation-Needed errors left the gateway from the WAN/management address and the client's WireGuard dropped them; `net.ipv4.icmp_errors_use_inbound_ifaddr=1` did not help, since `plait0` has no address to use. **Adopted strategy:** every `/32` return route on `plait0` carries a preferred source (`src`), the gateway's lowest address on the egress interface inside an advertised prefix. This made both error types reach the client in every interface ordering tested. The agent warns when no such address exists. The unnumbered-interface design is retained on this basis.
- Every enabled device at every authorized site gets a Linux route such as `10.0.0.4/32 dev plait0`, in addition to WireGuard peer `AllowedIPs = 10.0.0.4/32`.
- A device's client-side peers advertise site LAN prefixes only. Do not advertise the shared client pool through any site peer.
- Reject duplicate or overlapping site prefixes within a device's effective profile, including nested prefixes. V1 does not implement ambiguous prefix ownership or failover between sites advertising the same LAN.
- Reject default routes and site prefixes intersecting the client pool. Canonicalize prefixes before comparison.
- A roaming device's local Wi-Fi may overlap a remote LAN. The controller cannot predict every visited network. Document this limitation, expose it in troubleshooting, and test a collision scenario; automatic address translation is deferred.

For example, traffic from `10.0.0.4` to `10.15.0.10` selects Emerald on the client. Emerald validates the source `/32`, permits the destination, and masquerades onto its LAN. Reply traffic is reverse-translated by conntrack, routed to `10.0.0.4/32 dev plait0`, and encrypted to that device. `AllowedIPs` alone does not install the Linux return route.

## 3. Persistence and Domain Invariants

Use SQLite with migrations and sqlc. Prefer `modernc.org/sqlite` for a CGO-free build; validate the dependency and supported Go toolchain when initializing the repository. Configure and verify database Write-Ahead Logging (`PRAGMA journal_mode=WAL;`). Initialize a busy timeout (`PRAGMA busy_timeout=5000;`) and foreign-key enforcement (`PRAGMA foreign_keys=ON;`) on every pooled connection, including newly opened connections; running these once through `sql.DB` is insufficient. Make multi-row changes transactional. Define consistent UTC timestamps and update `updated_at` explicitly in write queries.

WAL still permits only one writer. For address allocation and other read-then-write mutations, use `BEGIN IMMEDIATE` through the selected driver's supported transaction mechanism, on the same connection for the whole transaction. Use bounded retries for retryable contention, restarting the entire transaction when necessary. A busy timeout is not a guarantee that deferred transaction upgrades will succeed. Test concurrent enrollment through multiple connections. See [SQLite transactions](https://www.sqlite.org/lang_transaction.html).

The following schema was the proposed core and remains a summary of the device, site, and link model. The authoritative schema is the migrations in `internal/store/migrations/`, which also add: sites awaiting enrollment (`public_key` is NULL until a gateway enrolls), per-site gateway TCP ports (Section 5.3), administrators and their sessions, site enrollment tokens, the audit log, and administrator TOTP secrets (Section 4.1). Application validation additionally checks keys, canonical addresses, prefixes, interface names, endpoints, and authorization; SQL constraints alone are insufficient.

```sql
CREATE TABLE devices (
    id TEXT PRIMARY KEY,                       -- UUID; stable allocation identity
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    assigned_ipv4 TEXT NOT NULL UNIQUE,        -- canonical host /32
    client_mtu INTEGER CHECK (client_mtu BETWEEN 576 AND 1500), -- NULL: client-selected
    search_domain TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    retired_at TEXT,                           -- tombstone; retains address reservation until deleted
    profile_revision INTEGER NOT NULL DEFAULT 1 CHECK (profile_revision > 0),
    last_exported_revision INTEGER,            -- export is not proof of installation
    last_exported_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    public_key TEXT NOT NULL UNIQUE,
    egress_interface TEXT NOT NULL,
    mtu INTEGER NOT NULL DEFAULT 1420 CHECK (mtu BETWEEN 576 AND 1500),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    desired_revision INTEGER NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE site_subnets (
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,                         -- canonical IPv4 network prefix
    PRIMARY KEY (site_id, cidr)
);

CREATE TABLE site_device_links (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id),
    preshared_key_ciphertext BLOB NOT NULL,     -- AEAD ciphertext (XChaCha20-Poly1305 or AES-256-GCM) with prepended nonce
    encryption_key_id TEXT NOT NULL,
    persistent_keepalive INTEGER NOT NULL DEFAULT 25
        CHECK (persistent_keepalive BETWEEN 0 AND 65535),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    UNIQUE (site_id, device_id)
);

CREATE TABLE agent_credentials (
    id TEXT PRIMARY KEY,                       -- credential selector, not a secret
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,            -- SHA-256 of a high-entropy random secret
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
    last_error_message TEXT                     -- sanitized; never includes secrets
);

CREATE INDEX idx_links_device ON site_device_links(device_id);
CREATE INDEX idx_credentials_site ON agent_credentials(site_id);
```

### 3.1. Allocation and lifecycle

- Allocate by `Device.id`, not mutable device name. Reserve the address and create the device in one transaction, using `netip.Prefix` and `netip.Addr` to scan and assign the lowest free host IP in the configured pool, with uniqueness constraints and defined retry behavior for concurrent enrollment.
- Report pool exhaustion clearly. Validate the configured pool and exclusions before allocation.
- Renaming or replacing a device key preserves its address. A key replacement is explicit and invalidates the old identity at every linked site.
- Disabling or retiring a device removes it from all desired site peer sets. Retired devices keep their address reservation; it is never reused automatically. An administrator may delete a disabled or retired device, which removes its links, PSKs, and settings and frees its address for the next enrollment. Deletion is refused while any enrolled linked site has not applied a revision without the device (that gateway may still accept its key at the address), unless explicitly forced for a gateway that will not report again. Audit history is retained.
- A link is effective only when the device, site, and link are enabled and the device is not retired. Reject profile export for disabled or retired devices.
- In v1, an effective site-device link grants access to all advertised LAN prefixes at that site. Per-service and per-subnet grants are deferred; do not imply the model already supports them.
- Validate all affected device profiles before committing a subnet or link change. A change that creates an overlap must fail atomically.
- Increment affected site desired revisions and device profile revisions in the same transaction as the underlying changes. Names and telemetry alone must not cause network reconfiguration.

## 4. Enrollment, Secrets, and Client Profiles

### 4.1. Trust and authentication

- V1 uses HTTPS with normal server certificate validation and independent, site-scoped bearer credentials. mTLS is deferred; remove any implication that it is already required or implemented.
- Agent credentials contain at least 256 bits of cryptographic randomness. Store only their hashes at the controller, compare securely, and bind every agent request to its authenticated site. An agent must never select or fetch another site's state.
- Site enrollment is administrator-authorized and binds the agent-generated public key to a site. Use a short-lived, single-use enrollment credential; exchange it for a normal site credential and consume it transactionally.
- Support credential rotation with a short, explicit overlap, followed by revocation of the old credential. Revoking an agent credential blocks controller access; it does not itself remove cached WireGuard peers from an unreachable gateway.
- Administrator authentication and authorization are required before exposing enrollment, configuration export, or mutation endpoints. V1 may support one administrator role. Protect browser mutations against CSRF and use secure session cookies; never treat possession of an agent credential as administrator access.
- Passwords are hashed with argon2id. Throttle failed logins per username and per client address, counting attempts still in progress, and bound concurrent hashing so a burst of logins cannot exhaust controller memory.
- Administrators may enable a TOTP second factor (RFC 6238). Accept each code once, never reveal which factor failed, and require the password again to set up or turn off TOTP. Recovery from a lost authenticator is local administration on the controller host (`plaitctl admin totp-reset`); v1 has no recovery codes.
- Encrypt stored PSKs and TOTP secrets with authenticated encryption using a key held separately from SQLite, bound to the owning row so ciphertexts cannot be swapped. Back up the encryption key securely alongside a documented recovery process; without it, every PSK must be replaced and every TOTP enrollment reset. Encryption at rest does not protect against a compromised running controller.
- Gateway private keys remain on their gateway in restricted persistent storage. Agent credentials and cached desired state also require restrictive permissions because the cache contains PSKs.
- Redact private keys, PSKs, tokens, and full profiles from logs, error messages, telemetry, and audit events. Record administrative changes without their secret payloads. Export responses must not be cached by HTTP intermediaries.

### 4.2. Private-key-local enrollment

The controller never generates, receives, or stores client private keys. A public key alone cannot produce a complete standalone client configuration: WireGuard's interface configuration requires a private key. See [WireGuard configuration format](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8).

Support two explicit flows:

1. **Existing device key (CLI only):** register its name and public key, then return versioned profile material without a private key. `plaitctl` merges that material with the existing private key locally. The web UI does not offer this flow and never accepts a private key. Verify locally that the supplied private key derives the registered public key.
2. **New device:** generate a WireGuard-compatible key pair locally in the browser or CLI, send only the public key to enroll, fetch profile material, and assemble the complete profile locally. V1 uses one bundled JavaScript X25519 implementation for browser key derivation, with secure randomness from the browser's cryptographic random-number generator. Select and pin the implementation and all transitive dependencies before coding enrollment, and record the audit coverage for the selected version. For example, `@noble/curves` depends on `@noble/hashes`; do not describe it as dependency-free. Do not load cryptographic code from a runtime CDN. Native Web Crypto X25519 is a possible later alternative, not a second required v1 fallback path. Maintain tested browser versions in a compatibility matrix rather than hard-coding version thresholds here. Validate deterministic key-derivation fixtures against `wg pubkey`, plus generated-key import into supported clients.

The browser renders its QR locally after profile assembly; a controller-side QR library must not receive the private key. Multi-site profiles grow with peer count, endpoints, and prefixes. Minify QR payloads by omitting comments, unnecessary whitespace, and fields whose omission preserves the intended semantics (such as a default-disabled keepalive). Preserve required line boundaries and validate the resulting configuration. Prominently provide a direct `.conf` file download alongside the QR code. Establish QR usability with tested profile sizes, error-correction levels, rendering dimensions, quiet zones, and supported phone scanners; do not assume one byte-count or QR-version threshold predicts scan reliability. Keep the key out of browser persistent storage and release temporary references after export. Do not promise guaranteed memory erasure in managed browser or Go runtimes. The installed client necessarily retains its private key.

After the enrollment session ends, the web UI shows a profile again only through an explicit key replacement flow with the consequences explained; the CLI may instead assemble it from a local private key file. Do not silently generate a new identity during export. Provide file download when a multi-site profile is too large for a practical QR code, and test supported phone scanners.

### 4.3. Compiler output

The compiler returns structured profile material and its device profile revision. Local assembly renders:

- One `[Interface]`, one IPv4 `/32`, and the locally supplied `PrivateKey`.
- Optional, validated DNS and search-domain settings supported by the target client.
- Optional `MTU` from `devices.client_mtu`. By default omit it and let the client choose; this behavior must be covered in the compatibility matrix. An explicit override applies to the device's single interface and therefore every site peer. It is independent of each gateway's `sites.mtu`; do not copy a gateway value into the client profile implicitly. Changing the override increments the device profile revision and requires profile refresh.
- One `[Peer]` per effective site link, containing the site public key, correctly formatted endpoint, site LAN prefixes, link PSK, and client-side keepalive setting.
- Deterministic peer and prefix ordering, with no overlapping site prefixes or client-pool routes.

Keepalive is configured on the roaming client by default; the gateway learns client endpoints from authenticated traffic. It is configurable, including zero to disable, because maintaining a mapping to every site has a mobile power and traffic cost.

### 4.4. Manual refresh and rotation

Standard clients are not polling the Plait controller. Adding a site, changing LAN prefixes, changing a site key or endpoint configuration, and rotating a PSK can require affected users to refresh their profile. Do not imply that agent polling updates clients.

- Track current profile revision and last exported revision/time. Show “configuration changed since last export” when appropriate.
- Export records do not prove import, activation, or installation. If user acknowledgment is added, label it as self-reported.
- Gateway-side revocation does not require client cooperation. Removing a stale client-side peer later is a profile maintenance action.
- PSK replacement requires coordinated updates to the gateway and client; a link has one active PSK and v1 does not promise a seamless overlap. Show affected devices and expected interruption before rotation.
- Replacing a gateway key requires an administrator-approved update and affected client refreshes. Never automatically adopt an unexpected gateway key reported by an agent.
- Dynamic DNS (DDNS) changes do not guarantee prompt recovery of an active tunnel. Recovery depends on the client's endpoint-resolution behavior and whether authenticated traffic reaches it from the new endpoint; WireGuard can learn endpoint changes from authenticated packets. Restarting the tunnel may be required, but is not the only possible recovery path. Document tested behavior per supported client and highlight stale-endpoint symptoms in diagnostics. Test a site WAN-address change both while the phone remains on one network and during Wi-Fi/cellular transitions. See [WireGuard endpoint roaming](https://www.wireguard.com/#built-in-roaming).

### 4.5. DNS policy

Do not hard-code Home's DNS server or search domain as a universal default. Configure DNS explicitly per device and explain its dependencies.

If `10.13.37.37` is selected, the device must have an effective route and permission to reach it through Home. Validate reachability from configuration where possible. Warn when removing that access or disabling its site; an unexpected Home outage may still prevent name resolution while Emerald's IP connectivity continues to work.

For supported mobile WireGuard clients, configuring `DNS` can make the VPN-provided resolver responsible for system name resolution, including public names. A single-site resolver outage can therefore disrupt name resolution well beyond that site. Scope this behavior to tested client and OS configurations; Private DNS settings and application-managed DNS may change which resolver is used. Resolver selection and packet routing are distinct: specifying a DNS server does not itself grant a site peer permission to route to that address.

The administration UI must present explicit DNS presets with clear tradeoffs:

1. **Internal resolvers:** use explicitly configured internal resolvers that resolve both the intended private zones and public names. Explain the site dependency. Recommend redundant resolvers at independently reachable sites with equivalent DNS data, while avoiding a promise of a fixed failover order or recovery time.
2. **No tunnel DNS:** omit `DNS` from the profile and retain the device's existing DNS configuration. Site IP routing still works; internal names may not resolve. Application-managed DNS remains outside Plait's control.

Do not offer “Internal DNS with Public Fallback” as a v1 preset. A list such as `10.13.37.53, 1.1.1.1` does not establish a portable primary/backup contract. If an administrator supplies a custom mixed list, label it **Mixed internal and public resolvers** and explain that private-name queries may reach public resolvers and receive negative answers. Internal names may fail even while the internal resolver is available. Validate configured resolver reachability and test timeout, negative-answer, and recovery behavior. See [Android resolver selection](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/heads/main/res_send.cpp).

V1 does not promise portable per-domain split DNS across all clients. Document platform behavior and test resolver failure, search-domain handling, Private DNS, application-managed DNS, and recovery on supported clients. The UI must distinguish tested behavior from an expected platform default.

## 5. Agent Networking and Reconciliation

### 5.1. Dedicated resource ownership

- Use Linux systemd with explicitly scoped privileges sufficient for WireGuard, network configuration, and nftables. Document host-wide prerequisites separately from service privileges.
- Create and own `plait0`, set its MTU and link state, load the locally persisted gateway private key, and configure its listen port.
- Refuse to take over an existing interface whose ownership is not established. Do not rewrite `/etc/wireguard/wg0.conf` or compete with `wg-quick`, NetworkManager, or another service for the same interface.
- Own only identifiable Plait routes and firewall objects. Remove stale owned objects without flushing unrelated host state. Detect conflicting routes or firewall managers and report them.
- Enable IPv4 forwarding during explicit host setup. Check reverse-path filtering for the actual routing arrangement; Linux computes effective `rp_filter` as `max(all.rp_filter, <interface>.rp_filter)`. Thus `all=1` and `plait0=2` gives loose mode on `plait0`; it does not require relaxing host-wide filtering. Inspect effective settings on each relevant interface and verify whether explicit return routes satisfy strict mode before requiring a scoped change. Do not blindly alter unrelated interface policy on every poll. See [Linux reverse-path filtering](https://docs.kernel.org/networking/ip-sysctl.html#rp-filter-integer).
- Default gateway MTU to 1420, allow a validated override, and test smaller underlays and large packets in both directions. Client MTU is separately governed by Section 4.3. Report an MTU problem as a networking failure rather than assuming a successful handshake proves connectivity.

### 5.2. Incremental WireGuard updates

Read actual peer state and compute additions, updates, and removals by public key. Leave unchanged peers untouched. Use explicit peer removal and replace a changed peer's allowed IP set when necessary. Preserve learned roaming endpoints unless a change actually requires otherwise.

Do not use `ReplacePeers: true` for routine reconciliation. Linux removes the existing peers when that flag is set; it does not preserve their sessions. Configuration changes also do not form one transaction covering WireGuard, routes, and firewall state. See [WireGuard Linux configuration implementation](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/netlink.c).

Validate the full desired state before mutation. Add restrictive firewall policy and necessary routes before enabling new access. For revocation, remove or block the affected peer promptly, then clean up its routes and policy. Design retries to converge after any partial application. Do not claim atomic rollback or interruption-free changes to the peer whose key or PSK is being replaced.

### 5.3. Firewall and NAT policy

V1 supports nftables only. Use a dedicated `table inet plait` and atomic nftables batches where supported. Apply rendered rulesets through `nft -f -` as a maintainability choice: generated policy is inspectable using the same tool administrators use. This does not imply Go Netlink bindings are inherently unreliable. Resolve a trusted executable path during installation and use direct process execution with fixed arguments and stdin, never a shell. Validate and correctly encode interface names, prefixes, ports, and identifiers in nft syntax; avoiding a shell does not prevent ruleset injection. Set execution timeouts, check exit status, and sanitize error output. Inspect owned state using nft's JSON output for drift detection rather than parsing its human-readable output. Do not silently select between nftables, iptables-nft, and iptables-legacy.

The effective policy must:

- Admit the configured WireGuard UDP listener through the host's input policy under a documented integration arrangement.
- Allow traffic from enabled device `/32`s arriving on `plait0` only to that site's advertised LAN prefixes through its configured egress interface.
- Clamp TCP MSS only on authorized Plait flows, handling both SYN and SYN-ACK packets and both directions, before a terminating accept bypasses the adjustment. Derive a suitable limit from validated route/MTU information and preserve an already smaller advertised MSS. The documented `tcp flags syn tcp option maxseg size set rt mtu` pattern is a starting point, not a complete scoped policy or a guarantee against every tunnel PMTU failure. Validate upload and download separately under reduced underlay MTUs. MSS clamping does not fix UDP; test UDP and ICMP/PMTU behavior independently. See [nftables TCP option mangling](https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers).
- Permit established/related return traffic for authorized flows; deny unsolicited LAN-to-client forwarding.
- Deny client-to-client forwarding, traffic to unadvertised destinations, and inner tunnel traffic to gateway-local services, except TCP ports an administrator explicitly lists for the site ("gateway access"). Those are opened to enabled clients only.
- Masquerade only authorized client-pool traffic to approved site LAN prefixes on the designated egress interface. Do not add an unrestricted host-wide masquerade rule.
- Enforce access at the gateway even if a device edits its client-side `AllowedIPs`.

An nftables accept in one chain does not override a drop imposed elsewhere. Define and test the supported host firewall integration, hook priorities, and forwarding policy; report unsupported coexistence rather than assuming a dedicated table is sufficient. NAT does not itself grant forwarding permission or enforce destination authorization.

### 5.4. Reconciliation and persistence

Desired configuration, last successful application, and observed host state are different concepts. A desired-state hash can avoid redundant transfer or compilation; it must not skip inspection and repair of actual resources.

The agent must:

1. Load its local identity and durable cached desired state on startup, inspect actual resources, and reconcile immediately. Do not wait for the first 15-second tick.
2. Fetch a complete desired snapshot using authenticated HTTPS. Validate site identity, schema version, revision, keys, prefixes, and local interface constraints before accepting it.
3. Durably and atomically cache an accepted desired snapshot before applying it. Cache includes secrets and requires restrictive access. Keep the last successfully applied revision as separate metadata.
4. Compare desired state with current WireGuard, link, route, and firewall state. Apply a bounded, idempotent sequence of changes and verify the owned resources afterward.
5. Mark a revision applied only after successful verification of the full configuration. Report a partial failure with a sanitized component error and retry convergence.
6. Poll about every 15 seconds with jitter, request timeouts, and bounded backoff for controller failures. Independently continue local drift inspection and repair from cached desired state during outages or unchanged responses.
7. Recreate missing owned interfaces, routes, and rules after restart or external drift. Do not resurrect an earlier successful peer set after a newer cached revocation merely because the new revision partially failed.

Persist snapshots with an atomic replacement strategy and detect corrupted or incompatible cache data. With no valid cache and no controller, report not ready and do not invent or enable peer access. Test loss of power between cache, apply, and acknowledgment steps.

### 5.5. Outages and revocation semantics

V1 favors continuity: an agent with valid cached state continues serving and repairing that state while disconnected from the controller. It also restores that state after reboot. There is no automatic configuration lease expiry in v1.

Consequently, a healthy agent normally enforces revocation on its next successful poll and application, approximately within one polling interval plus processing time. A disconnected or failing agent has no bounded revocation time. The UI must show revocation as pending until the affected sites acknowledge application, and expose stale/offline sites clearly.

Disabling a site returns an explicit empty peer set and denies its tunnel forwarding while keeping the agent credential available to receive that change. Do not hard-delete a site record or revoke its only credential before the agent can receive the removal configuration, unless the administrator intentionally accepts manual cleanup. Emergency removal on an unreachable gateway requires local intervention.

## 6. Agent Protocol and Status

### 6.1. Desired state

`GET /api/v1/agent/sync`, with `Authorization: Bearer <site credential>`, returns the complete desired state for the authenticated site. Authentication must not rely on a caller-supplied site ID.

The following is a schematic response; angle-bracket values represent properly encoded keys and identifiers, not literal test fixtures:

```json
{
  "schema_version": 1,
  "site_id": "<site UUID>",
  "revision": 12,
  "interface": {
    "name": "plait0",
    "public_key": "<registered gateway public key>",
    "listen_port": 51111,
    "mtu": 1420
  },
  "network": {
    "client_pool": "10.0.0.0/24",
    "egress_interface": "enp1s0",
    "lan_prefixes": ["10.15.0.0/24"],
    "masquerade": true
  },
  "peers": [
    {
      "device_id": "<device UUID>",
      "public_key": "<device public key>",
      "allowed_ips": ["10.0.0.4/32"],
      "preshared_key": "<link preshared key>"
    }
  ]
}
```

Only effective peers are present; absence from a valid complete snapshot means removal. An empty `peers` array explicitly removes all managed peers. Missing fields, failed requests, invalid JSON, or unsupported schema versions must never be interpreted as an empty snapshot. Never include a gateway private key in this API.

Reject revision regression and conflicting contents for an already accepted revision. After controller backup restoration, use a documented recovery procedure to advance revisions beyond agent state; do not silently accept stale snapshots. The initial implementation may always return full snapshots. Conditional responses are a later optimization and must not disable local drift detection.

### 6.2. Acknowledgments and telemetry

`POST /api/v1/agent/status` reports the authenticated site's accepted revision, last successfully applied revision, observation time, agent version, and sanitized component errors. The controller records receipt times so clock skew does not masquerade as freshness.

Optional per-peer telemetry includes last handshake time and traffic counters, scoped to that site. Do not transmit keys or full configurations in telemetry. To prevent SQLite write amplification and lock contention from rapid heartbeats, transient peer telemetry should be held in-memory or in an ephemeral cache on the controller rather than continuously written to transactional database tables. Define retention and handle counter resets after peer or interface recreation.

Persist meaningful applied-revision transitions and audit events; do not treat those as disposable telemetry. Coalesce routine status writes rather than rewriting unchanged durable state on every heartbeat. After controller restart, mark live reachability, resource health, and peer activity unknown until refreshed. Persisted application acknowledgments remain historical evidence, not proof that a gateway is currently healthy or enforcing a revision.

Represent status separately:

- **Agent reachable:** recent authenticated contact, with a documented stale threshold.
- **Configuration applied:** desired revision acknowledged after verification; older acknowledgments cannot overwrite newer progress.
- **Local resources healthy:** recent observation of the expected interface, peers, routes, and firewall.
- **Peer activity:** last handshake and traffic evidence. Silence does not prove a client is offline, and a handshake does not prove LAN or DNS access.

The UI uses these states for pending revocations and diagnostics rather than one misleading “online” indicator. Controller receipts and agent observations may differ; show timestamps and stale state.

## 7. Administration and Operational Recovery

- Device management supports enrollment, link assignment, disable/retire, explicit key replacement, local profile assembly, and revision-aware export. In the web UI, updating or re-showing a profile is done by key replacement (Section 4.2).
- Site management supports enrollment, endpoint/subnet configuration, credential rotation, disable/drain, and applied-state diagnostics.
- Diagnostics show the relevant route, peer, firewall, DNS dependency, MTU, and revision state without revealing secrets.
- Provide a consistent SQLite backup procedure and separately protected encryption-key backup. With WAL enabled, use a supported consistent backup mechanism such as SQLite's backup API; do not copy only the live main database file and assume it includes committed WAL contents. Document recovery of controller identity/configuration, revision advancement, agent caches, and gateway-local private keys.
- Restore tests must establish that previously revoked access is not accidentally re-enabled by an older database or cache. Require explicit reconciliation of newer revocations during disaster recovery.
- Preserve an audit history of enrollment, authorization changes, revocations, key/credential rotation, and exports. Administrator logins and TOTP changes are audited too. In v1 the audit log is stored in SQLite with unbounded retention.
- Document installation prerequisites, supported firewall coexistence, systemd startup ordering, service restart behavior, and deliberate uninstall cleanup of owned resources.

## 8. Implementation Roadmap and Acceptance Criteria

### Phase 0: Prove the networking model

- [x] Build a Linux network-namespace harness with two independent site gateways, two LANs, a roaming device, and a second device for isolation tests. *(Namespaces: `harness/phase0.sh`; `make phase0`.)*
- [x] Verify one client `/32` reaches both LANs concurrently using distinct peers and per-link PSKs. *(Namespaces: `harness/phase0.sh`.)*
- [x] Verify explicit gateway return routes, masquerading, destination filtering, and denial of client-to-client and gateway-local access. *(`harness/agent-integration.sh`.)*
- [x] Capture gateway-generated ICMP errors (e.g. PMTUD, TTL exceeded) on gateways with separate WAN, LAN, and management addresses, varying interface/address ordering. Verify the client accepts the actual source addresses. Resolve failures before accepting the unnumbered-interface design. *(Done in namespaces; failed by default, resolved with a preferred route source; see §2.3. Covered by `harness/agent-integration.sh`.)*
- [x] Verify scoped MSS clamping on both SYN and SYN-ACK, preserve smaller MSS values, and test large TCP uploads and downloads independently under reduced underlay MTUs (e.g., 1380). Record the route/PMTU information used by the clamp. *(Namespaces: `harness/phase0.sh`. The clamp is the fixed `plait0 MTU - 40`, not route PMTU. With `plait0` MTU 1420 over a 1380 underlay, 16 MiB transfers succeed but outer WireGuard packets are fragmented; a site MTU of 1320 avoids fragmentation entirely.)*
- [ ] Test UDP and ICMP/PMTU behavior separately from TCP, including both client-selected MTU and explicit client/gateway overrides. Do not infer UDP success from a TCP transfer. *(Namespaces: `harness/phase0.sh` covers UDP datagrams of 1200/1400/4000 bytes in both directions over 1500 and 1380 underlays, and the client learning path MTU from the gateway's Fragmentation Needed. A DF datagram from the LAN larger than `plait0` loses its first copy while the sender learns the path MTU. Explicit client MTU overrides and real client OSes remain untested.)*
- [x] Test effective `rp_filter` settings under strict and loose configurations, including `all=1, plait0=2`, and verify unrelated interfaces retain their intended policy. *(Namespaces: `harness/phase0.sh`.)*
- [x] Remove a return route and demonstrate the failure and recovery, so a handshake cannot be mistaken for end-to-end success. *(`harness/agent-integration.sh`; under strict `rp_filter` in `harness/phase0.sh`.)*
- [x] Keep an unrelated device's TCP flow active while adding or revoking another peer; verify no forced peer recreation or avoidable connection interruption. *(Namespaces: `harness/phase0.sh`. Separately: a device revoked and re-enabled, or a site whose `plait0` is recreated, takes about 5–15 s to recover, because the client keeps its stale session until WireGuard's keepalive and rekey timeouts expire.)*
- [x] Verify a modified client profile cannot bypass the gateway's destination policy. *(`harness/agent-integration.sh`.)*
- [ ] Test local subnet collisions, MTU constraints, and resolver-site failure independently of another site's IP connectivity. *(Namespaces: `harness/phase0.sh` shows one site's failure leaves another site's traffic lossless. Local subnet collisions and resolver behavior need real clients.)*
- [ ] Test redundant internal resolvers, custom mixed resolvers, negative answers, timeouts, Private DNS, and application-managed DNS on supported mobile clients; record selection and recovery behavior. *(Android: a single internal resolver at one site resolves internal names in daily use. The other cases are untested.)*
- [x] Change a site's WAN address and DDNS record with the phone stationary, then repeat during Wi-Fi/cellular transitions. Record recovery through authenticated traffic, client re-resolution where supported, and manual tunnel restart.
- [x] Repeat the central two-site access test on a real phone. Record the motivating multiple-address behavior separately if reproducible. *(Android, in use since 2026-10-31: one QR-imported profile reaches both sites' LANs at once. The multiple-address behavior was not re-tested, since the one-address design avoids it.)*

Exit criterion: one phone reaches both LANs through one profile, with correct return routing, verified ICMP error propagation, bounded TCP MSS adjustment, tested TCP/UDP MTU behavior, and enforced isolation, while unrelated traffic survives peer changes.

### Phase 1: Persistence and configuration compiler

- [x] Initialize the Go module, supported toolchain, binary layout, migrations, and sqlc queries with verified SQLite WAL mode and per-connection busy timeout/foreign-key initialization. *(TestPragmasOnEveryConnection.)*
- [x] Implement transactional device allocation, reservation retention, concurrent enrollment, and pool-exhaustion handling using Go standard `net/netip`, `BEGIN IMMEDIATE`, and bounded contention retries across multiple pooled connections. *(TestConcurrentEnrollment, TestPoolExhaustionAndRetention.)*
- [x] Implement normalized site subnets, enabled-state rules, protected PSK storage (AEAD ciphertext with prepended nonce), and revision updates. *(TestValidateSiteSubnets, TestSealRoundTrip, TestRevisionBumps.)*
- [x] Implement shared validation and deterministic site snapshots and client profile material. *(TestDeterministic, TestProfileMaterial.)*
- [x] Implement optional device-level client MTU overrides, distinguish them from gateway MTU, and verify profile revision changes and default omission. *(`internal/profile` tests: omitted by default, emitted on override.)*
- [x] Implement the CLI path for existing-key local assembly and explicit new-key enrollment. *(`plaitctl device enroll -pubkey|-new`, `plaitctl profile -private-key-file`.)*
- [x] Verify overlapping and nested prefixes, pool collisions, invalid keys, disabled/retired entities, and DNS dependencies are handled as specified. *(TestOverlapRejectedAtomically, TestOverlappingSitesRejected, TestParsePoolRejects, TestParseKeyRejects, TestInactiveDeviceExportRejected, TestDNSWarning.)*
- [x] Verify repeated compilation is stable and no controller path accepts or emits client private keys. *(TestDeterministic; the API and UI carry only public keys.)*

Exit criterion: stored intent produces consistent site and client configuration, with invalid combinations rejected transactionally.

### Phase 2: Agent and Linux integration

- [x] Implement dedicated interface ownership, local gateway identity persistence, MTU, Linux routes, and host prerequisite checks (including `rp_filter` inspection). *(`harness/agent-integration.sh`, TestRefusesForeignInterface, TestIPForwardDisabledIsReported.)*
- [x] Implement actual-state inspection and incremental WireGuard changes, with explicit removals. *(TestAddPeerPreservesExistingSession, TestUnchangedReconcileIsNoop.)*
- [x] Implement nftables authorization, MSS clamping in both directions, and scoped NAT through direct `nft -f -` execution with validated input, timeouts, error handling, and JSON-based inspection of owned resources. Verify smaller MSS values and unrelated host rules are preserved. *(`internal/firewall` tests, `harness/agent-integration.sh`, `harness/phase0.sh`.)*
- [x] Implement durable desired-state caching, applied-revision metadata, startup recovery, and drift repair. *(TestCacheRoundTripAndCorruption, TestDriftRepair, `harness/agent-integration.sh`.)*
- [x] Package the systemd service with documented privileges and resource ownership. *(`packaging/`, [docs/agent.md](docs/agent.md).)*
- [ ] Extend the namespace harness to verify external route/rule removal, agent restart, host recreation, partial failures, and no unintended access during convergence. *(Route and firewall removal and repair, cache corruption, and revocation under a failing firewall are covered by `harness/agent-integration.sh`, TestRevocationProceedsWhenFirewallFails, and TestFreshApplyOrdering. Agent restart and host recreation are not exercised by a harness.)*
- [x] Verify unchanged reconciliation does not reset peer state and newer cached revocations are not rolled back after failures. *(TestUnchangedReconcileIsNoop, TestAgentDoesNotRollBackRevocation.)*

Exit criterion: the agent converges and repairs owned resources, preserves unrelated sessions, and recovers without the controller using valid cached state.

### Phase 3: Controller integration and lifecycle

- [x] Implement administrator authentication and authorization, site enrollment, site-scoped bearer verification, and credential rotation. *(TestAdminAuthentication, TestEnrollmentTokens, TestSiteScopedCredentials, `harness/controller-integration.sh`.)*
- [x] Implement desired-state polling with validation, timeouts, jitter, and bounded backoff. *(TestPollRejectsBadSnapshotAndKeepsCache, TestClientFetchFailuresAreNeverEmpty.)*
- [x] Implement durable applied-revision transitions and audit events, coalesced status writes, and ephemeral peer handshake/traffic telemetry. Verify live health is unknown after controller restart until fresh reports arrive. *(`harness/controller-integration.sh`, TestLiveStatusAppearsAfterReport.)*
- [x] Verify cross-site access attempts fail and secrets do not appear in logs or status payloads. *(TestSiteScopedCredentials, TestSecretsStayOutOfLogsStatusAndAudit.)*
- [x] Verify disable/retire, site drain, pending revocation, disconnected-agent behavior, malformed responses, and revision regression. *(TestSiteDisableDrains, TestStatusAndPendingRevocation, TestMalformedRequests, `harness/controller-integration.sh`.)*
- [x] Exercise controller backup/restore, revision recovery, encryption-key recovery, and preservation of revocations. *(TestBackupRestoreRecovery, TestEncryptionKeyRecovery, `harness/controller-integration.sh`.)*

Exit criterion: authorization changes propagate observably, and the system accurately reports the limits of enforcement during outages.

### Phase 4: Administration and mobile export

- [x] Build the server-rendered UI and distinguish agent reachability, applied configuration, local health, and peer activity. *(TestPagesRenderStatusFacts.)*
- [x] Implement browser-local key generation through one pinned, bundled X25519 implementation with cryptographic randomness; record dependency versions and audit scope. Verify key derivation against `wg pubkey` and actual client imports, without adding a second native-X25519 path in v1. *(`harness/ui-integration.sh` (matches `wg pubkey`, imported by Linux `wg`); imported on Android by QR; VENDOR.md.)*
- [ ] Support existing-key assembly, semantically equivalent minified profiles, direct `.conf` download, and explicit key replacement. Test QR scanning across representative peer counts, payload sizes, rendering dimensions, quiet zones, and error-correction levels; provide file export when scanning is impractical. *(Implemented; existing-key assembly is CLI only. QR capacity is measured with an independent decoder (`jsQR`, [docs/ui.md](docs/ui.md#qr-codes-and-files)); phone scanning is verified only for a two-site profile on Android.)*
- [x] Show current and last exported profile revisions without implying successful installation. *(device page "Last export … (not proof of installation)".)*
- [ ] Show Internal resolvers and No tunnel DNS presets, explain custom mixed-resolver tradeoffs without promising ordered fallback, and expose tested DDNS recovery behavior in diagnostics. *(Presets and mixed-resolver labeling are implemented, TestConfirmationsAndPresetValidation. DDNS recovery is untested, so diagnostics don't describe it.)*
- [x] Document manual refresh, coordinated PSK rotation, diagnostics, backup/restore, and supported platform limitations. *([docs/ui.md](docs/ui.md), [docs/deploy.md](docs/deploy.md), [docs/controller.md](docs/controller.md).)*
- [ ] Verify QR import, file import, profile refresh, and two-site access on supported mobile clients. *(Android: QR import and two-site access verified. File import, profile refresh, and iOS are untested.)*

Exit criterion: an administrator can enroll a gateway and phone, grant both sites, export locally, diagnose a failure, revoke access with visible acknowledgments, and recover from a controller outage.

## 9. Design Review References and Remaining Validation

Primary references informing this revision:

- [WireGuard cryptokey routing](https://www.wireguard.com/#cryptokey-routing): peer source validation and destination selection; client routing entries are not a substitute for gateway destination authorization.
- [wgctrl scope](https://github.com/WireGuard/wgctrl-go#overview): existing-device configuration; interface creation and address management are separate responsibilities.
- [WireGuard Linux configuration implementation](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/netlink.c): peer replacement removes existing peers, and application is not a transaction across all host resources.
- [WireGuard configuration format](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8): interface private key, peer fields, and PSK semantics.
- [WireGuard quick start](https://www.wireguard.com/quickstart/): interface setup and persistent keepalive behavior.
- [Linux IP sysctls](https://docs.kernel.org/networking/ip-sysctl.html): ICMP source-address fallback and effective reverse-path filtering settings.
- [nftables TCP option mangling](https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers): route-based MSS adjustment and handling SYN/SYN-ACK in both directions.
- [WireGuard endpoint roaming](https://www.wireguard.com/#built-in-roaming): learning endpoints from authenticated packets, distinct from client hostname re-resolution.
- [Android resolver implementation](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/heads/main/res_send.cpp): server selection is not a portable ordered-fallback contract.
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html) and [WAL](https://www.sqlite.org/wal.html): writer contention, immediate transactions, and durable WAL contents.
- [noble-curves documentation](https://github.com/paulmillr/noble-curves): dependency and audit scope must be checked for the version selected for enrollment.

Before declaring v1 supported, record the tested Linux/firewall combinations, mobile clients, browser cryptography support, DNS behavior, and practical QR capacity. The namespace harness establishes network behavior; real-device tests establish mobile compatibility. Neither is replaced by unit tests that merely assert a particular library flag was set.
