# Vendored browser code

These files are embedded in plaitd and served from its own origin. Nothing is
loaded from a CDN at runtime. They are produced by `web/build.mjs` from the
exact versions pinned in `web/package.json` / `web/package-lock.json`
(installed with `npm install --ignore-scripts`). `internal/ui` tests fail if
an embedded file's SHA-256 no longer matches this table.

| File | Source | Version | License |
|---|---|---|---|
| `x25519.js` | `@noble/curves` (`ed25519.js` → `x25519`), bundled with its dependency `@noble/hashes` by esbuild 0.28.2, unminified | curves 2.4.0, hashes 2.4.0 | MIT |
| `qrcode.js` | `qrcode-generator` `dist/qrcode.js`, unmodified | 2.0.4 | MIT |
| `htmx.min.js` | `htmx.org` `dist/htmx.min.js`, unmodified | 2.0.11 | 0BSD |

## Checksums

<!-- sha256 of the embedded files; keep in sync with web/build.mjs output -->
```
e30252afb536375657e70dfc4dd300c7d72325387283387d2085b27af5488b56  x25519.js
79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c  qrcode.js
d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717  htmx.min.js
```

npm tarball integrity (from the registry):

```
@noble/curves@2.4.0     sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==
@noble/hashes@2.4.0     sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==
qrcode-generator@2.0.4  sha512-mZSiP6RnbHl4xL2Ap5HfkjLnmxfKcPWpWe/c+5XxCuetEenqmNFf1FH/ftXPCtFG5/TDobjsjz6sSNL0Sr8Z9g==
htmx.org@2.0.11         sha512-Thx/WtpeOQqSrqBCw/A1cwGJGg4UrVa3+sW0GmrM3p4gJgO89ecH4qtbnyzDDWFvBTqjnIMCgELTNt636dtamA==
```

## Cryptographic code and audit coverage

Only `x25519.js` performs cryptography: X25519 public-key derivation for
browser-generated device keys. Private keys come from
`crypto.getRandomValues` and are clamped as `wg genkey` does. Native Web
Crypto X25519 is a possible later alternative; v1 has no second path.

Audit status, as stated in the `@noble/curves` 2.4.0 README:

- **2.3.0**, Aug 2026, Trail of Bits (with OpenAI, "Patch the Planet"), scope: everything.
- 1.6.0, Sep 2024, Cure53, scope includes ed25519/montgomery.
- 1.2.0, Sep 2023, Kudelski Security (scure-starknet scope).

**The pinned 2.4.0 is one release after the most recent audited version
(2.3.0); the 2.3.0 → 2.4.0 diff has not been independently audited.** Review
that diff (or pin 2.3.0) before declaring v1 supported. `@noble/hashes` is
bundled because `ed25519.js` imports it; X25519 derivation itself uses only
field arithmetic.

`qrcode-generator` and `htmx` handle no secrets cryptographically, but the QR
encoder does receive the complete profile, including the private key, in
memory in the browser. It runs locally and makes no network requests.

Correctness checks (`make test-js`, `make integration`): derivation matches
the RFC 7748 vector and Go/`wg pubkey` fixtures; browser-assembled profiles
are byte-identical to `plaitctl`'s; QR payloads decode back to the profile;
a browser-assembled profile is imported into a real WireGuard client.
