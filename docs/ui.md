# Administration UI

plaitd serves a server-rendered UI (Go `html/template`, a little htmx) at
`/`, on the same listener and session as the API. Log in with an
administrator created by `plaitctl admin create`, plus an authentication
code if you turned on two-factor authentication on the **Account** page
(click your username).

## What each page shows

- **Overview**: per-site status, and devices needing attention (changed since
  last export, or revocation pending).
- **Site**: four separate facts that are never combined into one "online"
  flag: agent reachability (controller receipt time; stale after 60 s),
  configuration applied (durable acknowledgments: desired vs applied
  revision), local health (latest live report: errors and warnings), and peer
  activity (handshake and traffic per device). Also: configuration, gateway
  enrollment and credentials, linked devices, the TCP MSS clamp, and which
  devices' DNS depends on this site. The status block refreshes every 10 s.
- **Device**: identity, profile revision vs last export, per-site access with
  that site's status and this device's last handshake there, the *Profile*
  card (update or re-show the profile with a new key), DNS presets, MTU
  override, and lifecycle actions: disable, retire, and delete. Delete is
  offered once the device is disabled or retired; it frees the address and
  waits until linked sites have applied the removal, with an explicit
  override for a gateway that will not report again.
- **Add device**: name, site access with a keepalive for the granted sites,
  and the same DNS and MTU settings as the device page, so the first profile
  shown is complete.
- **Audit**: every recorded change, with its actor.
- **Account** (click your username): turn two-factor authentication (TOTP)
  on or off. Setup re-asks for your password, shows a QR code and key once,
  and takes effect only after you enter a valid code.

Live facts are unknown after a controller restart until agents report again.
A handshake shows a tunnel formed, not that LAN or DNS access works.

## Device keys stay in the browser

- **New device**: the page generates the key with `crypto.getRandomValues`
  (clamped like `wg genkey`), derives the public key with the vendored X25519
  code, and sends only the public key. It then fetches profile material,
  assembles the profile, and shows the QR code and file download, all in the
  page.
- **Update or show again**: the device page's *Profile* card offers *Update
  profile (new key)*, highlighted when the configuration changed since the
  last export. It generates a new key in the browser, invalidates the old one
  at every linked site once they apply the change, and shows the new profile.
  The device keeps its address, site access, PSKs, and settings. It needs an
  explicit confirmation and never happens silently during export.
- **No pasted keys**: no page accepts a private key. Moving a phone's key
  into a browser means passing it through the clipboard, files, or sync.
  Devices that make their own keys are enrolled with `plaitctl device enroll
  -pubkey`, and `plaitctl profile -private-key-file` assembles their profile
  where the key file lives.

The private key is never sent to plaitd, written to browser storage, or put
in the DOM. *Clear from this page* (and leaving the page) zeroes the key
bytes and drops the profile. A managed runtime may still hold copies; there
is no guarantee of memory erasure. The installed client keeps its key.

All scripts load from plaitd itself under a CSP of `script-src 'self'`; no
CDN is used. Vendored versions, checksums, and audit coverage are in
[`internal/ui/static/vendor/VENDOR.md`](../internal/ui/static/vendor/VENDOR.md).

## QR codes and files

The QR payload is the minified profile: no comments or optional whitespace,
and no `PersistentKeepalive` line when it is 0. The `.conf` download is the
full, readable profile; both are semantically identical. The code uses error
correction M while it stays at version 20 or below, otherwise L. The page
shows the byte count and version, recommends the file for dense codes, and
offers only the file when no QR version can hold the profile.

Measured with the test fixtures (two prefixes and a long hostname per site),
decoded by an independent decoder (`jsQR`). On a phone, only a two-site
profile has been scanned (WireGuard for Android):

| Peers | Minified bytes | QR |
|---|---|---|
| 0 | 88 | version 6, M |
| 1 | 298 | version 13, M |
| 2 | 577 | version 19, M |
| 4 | 998 | version 22, L (file recommended) |
| 8 | 1863 | version 32, L (file recommended) |
| 16 | 3576 | none, file only |

Phone scanning reliability depends on screen, rendering size, and camera, and
must be measured on supported phones before these thresholds are trusted.

## Profiles do not update themselves

WireGuard clients do not poll plaitd. Adding or removing a site, changing
prefixes, a gateway key or endpoint, client DNS or MTU, keepalive, or a PSK
changes the device's profile revision. The device then shows *configuration
changed since last export*; use *Update profile (new key)* and import the new
profile on the device. An
export record is not proof the profile was imported.

Removing access never needs the device: gateways enforce revocations on
their next successful poll. A stale peer left in the client profile is
harmless and is cleaned up at the next refresh.

## Coordinated PSK rotation

Each site link has one PSK. Rotating it breaks that link until **both** the
gateway applies the new PSK and the device imports a refreshed profile; there
is no overlap period. The UI requires acknowledging this. Other sites in the
same profile are unaffected until the device re-imports.

## DNS presets

- **No tunnel DNS**: the device keeps its own resolver. Site routing works;
  internal names may not resolve.
- **Internal resolvers**: private addresses inside a linked site's prefixes,
  answering both internal and public names. On mobile clients they typically
  handle *all* lookups, so if their site is unavailable, name resolution
  fails everywhere. Prefer redundant resolvers at independently reachable
  sites with equivalent data. No failover order or recovery time is promised.
- **Custom**: any list. A list mixing internal and public resolvers is
  labeled as such. It is not a primary/backup arrangement, and private-name
  queries may get negative answers from the public resolver.

Selecting a resolver does not grant routing to it. The device page warns
when a private resolver is not inside any linked site. The site page lists
the devices whose DNS would fail if that site is disabled. Per-domain split
DNS is not offered.

## Diagnostics

| Symptom | Where to look |
|---|---|
| No handshake at a site | Site reachability and health; endpoint/port forwarding; site applied revision; profile changed since export |
| Handshake but no LAN access | Site health errors (routes, firewall), whether the link is effective, local subnet collision warning |
| Names fail but IPs work | DNS preset; site hosting the resolver; Private DNS or app-managed DNS on the device |
| Revocation not enforced | Site reachability (stale agents enforce nothing new) and *revocation pending* |
| Large transfers stall | Gateway MTU/MSS on the site page; client MTU override |

## Compatibility matrix

Android results come from the deployment in daily use since 2026-10-31
(two sites, internal DNS). The browser key generation path is also verified
in Node and against `wg pubkey`, and a browser-assembled profile is imported
by Linux `wg setconf` (`harness/ui-integration.sh`).

| Client / browser | Profile import | QR scan | DNS behavior | Client-selected MTU |
|---|---|---|---|---|
| WireGuard for Android | verified by QR; file import not yet tested | verified (two-site profile) | internal resolver works; failure cases not yet tested | not yet tested |
| WireGuard for iOS | not yet tested | not yet tested | not yet tested | not yet tested |
| Linux `wg`/`wg-quick` | verified (`wg setconf`) | n/a | not yet tested | not yet tested |
| Chrome (admin UI) | enrollment, profile update, and TOTP setup exercised on macOS | n/a | n/a | n/a |
| Firefox, Safari (admin UI) | not yet tested | n/a | n/a | n/a |

## Updating vendored code

1. Change the pinned version in `web/package.json` and run
   `npm install --ignore-scripts` in `web/`.
2. `make vendor-js`, then update the checksums, integrity hashes, and audit
   notes in `VENDOR.md` (the Go tests fail until the checksums match).
3. `make test-js` and `make integration`.
