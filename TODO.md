# TODO

Deferred work to pick up later.

## Device page

- [x] **Make Replace key the main way to update an outdated profile.** Done:
  the device page's Profile card ("Update profile (new key)") replaces the
  export panel and the Lifecycle Replace key; no page accepts a private key,
  and the new-device page always generates the key. Original notes: When a
  device's profile changes (DNS, search domain, MTU, links), the "configuration
  changed since last export" warning appears in the export panel
  (`internal/ui/templates/device.html`, `export-panel`). That panel asks for the
  existing private key so it can rebuild the profile. The better path, Replace
  key, is a red button lower down under Lifecycle (`data-replace-key`,
  `internal/ui/static/js/export.js`).
  - Show an "Update profile (new key)" action in the export panel when the
    profile is outdated. It should replace the key and export in one step.
  - Remove the rebuild-with-existing-key export from the web UI (the
    `data-private-key` paste field and its code in `export.js`). Decided:
    getting a phone's private key into a browser means moving it through the
    clipboard, files, or sync, which defeats keeping keys on the device. Keep
    `plaitctl profile -private-key-file` for hosts whose key already lives in
    a local file.
  - Keep the "keep this tab open until scanned" behavior: after a replace, the
    new private key exists only in page memory.
  - Why: the tunnel is re-imported either way. A new key keeps the device, its
    address, links, PSKs, and settings, and the private key never leaves the
    phone. The cost is that the old tunnel stops once agents apply the new
    key, which is acceptable with out-of-tunnel (sshd) access to the
    controller.

- [x] **Align the Remove access buttons (cosmetic).** Done: `td.actions` was
  a flex box (taking the cell out of table layout) and the access form had a
  top margin; the buttons now share a width. In the device page's site
  access table, the per-site Remove access / Restore access buttons are not
  aligned with each other (`internal/ui/templates/device.html`, the link rows
  around the `Remove access` button).

## Overview page

- [ ] **"Revocation pending" is site-wide, not per device (low priority).**
  `revocationPending` (`internal/ui/pages.go`) flags a device when it has a
  non-effective link to a site whose agent hasn't applied the site's latest
  revision, so an unrelated pending change at that site, or a stuck agent,
  shows a false "revocation pending". (The original "doesn't clear" report
  was a misread of the empty-state text, since reworded.)
  - Fix: in `mutate` (`internal/controller/service.go`), when a site's
    revision is bumped, record on each link that just stopped being effective
    the new revision (`removed_revision` column, backfilled with each site's
    current desired revision). Pending then means the site's applied revision
    is below that link's `removed_revision`. The site page's copy of the check
    needs the same change.
  - Not agent peer telemetry: the agent reports only peers in the snapshot it
    accepted, so a removal accepted but not applied would look done.

## Gateway firewall

- [ ] **Scope `input` chain rules to LAN addresses and non-tunnel ingress
  (possible fix).** In `Policy.rules` (`internal/firewall/firewall.go`),
  `gateway-access` (`iifname "plait0" ip saddr @clients tcp dport { ... }
  accept`) does not restrict `ip daddr`. Under Linux's weak host model, a
  client that widens its local `AllowedIPs` can reach those TCP ports on any
  IPv4 address owned by the gateway host itself (such as an out-of-band
  management NIC, non-Plait VLAN IP, or container bridge), even if a service is
  bound only to that non-LAN address. Other hosts on those networks remain
  blocked by `forward`.
  - Consider adding `ip daddr @lans` (and a companion `ct state
    established,related` rule for client ICMP/PMTUD on `GatewayTCPPorts` flows)
    to `gateway-access`, and `iifname != "plait0"` to `wg-listen`.

## Controller authentication & UI

- [x] **Bound concurrent Argon2id allocations, password length, and UI `POST`
  body sizes.** Done: 4 hashing slots (`ErrBusy` → 503 after 5 s), 256-byte
  password cap, 64 KiB UI bodies, IPv6 keyed by /64 in `LoginKeys` (logs keep
  the full address), and `LoginLimiter.Attempt`/`Withdraw` replace
  `Blocked`/`Fail` so in-flight attempts count toward the limit. (The JSON API
  cap is actually 1 MiB, not 64 KiB.) Original notes: Each `Login` attempt (`internal/controller/auth.go`) allocates
  64 MiB in `argon2.IDKey`, including unknown usernames via `dummyHash`.
  `LoginLimiter.Blocked` (`internal/api/server.go`, `internal/api/admin.go`,
  `internal/ui/session.go`) only checks completed failures recorded after
  `Login` returns, so a burst of simultaneous unauthenticated login requests
  from a single IP passes `Blocked()` at once and can OOM-kill `plaitd` (and
  IPv6 rate-limit keys use `/128` rather than `/64`). Separately, UI `POST`
  handlers call `r.PostFormValue` without `http.MaxBytesReader` (defaulting to
  10 MiB per form) and enforce no maximum password length.
  - Recommended fix:
    1. Guard `argon2.IDKey` calls in `internal/controller/auth.go` with a small
       concurrency semaphore (e.g. `make(chan struct{}, 4)`), respecting
       `ctx.Done()` or returning `429 Too Many Requests` when full.
    2. Enforce a maximum password length (e.g. `256` bytes) in
       `validatePassword` and `verifyPassword` before hashing.
    3. Wrap UI `POST` request bodies with `http.MaxBytesReader(w, r.Body,
       64<<10)` in `internal/ui/ui.go` to match the JSON API's 64 KiB cap.
    4. Bucket IPv6 addresses by `/64` prefix in `LoginKeys` / `ClientIP` for
       rate limiting.

- [x] **TOTP (authenticator app) second factor for administrator login.**
  Done: opt-in per administrator on the Account page; the secret is sealed
  with the existing encryption key (bound to the admin ID); codes are
  single-use (last accepted step stored) with one step of skew; both login
  paths take the code; setup and disable re-check the password under the
  login limiter. No recovery codes (decided): `plaitctl admin totp-reset`
  over SSH is the recovery path.
