// Cross-implementation tests for the browser code embedded in plaitd. The
// scripts are loaded exactly as a browser would (classic scripts on the
// global object), from internal/ui/static.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import jsQR from 'jsqr';

const staticDir = new URL('../../internal/ui/static/', import.meta.url);
for (const f of ['vendor/x25519.js', 'vendor/qrcode.js', 'js/profile.js', 'js/qr.js']) {
  vm.runInThisContext(readFileSync(new URL(f, staticDir), 'utf8'), { filename: f });
}
const { PlaitProfile: P, PlaitQR: Q } = globalThis;
const fixtures = JSON.parse(readFileSync(new URL('fixtures.json', import.meta.url), 'utf8'));

test('X25519 derivation matches Go (crypto/ecdh) and the RFC 7748 vector', () => {
  assert.equal(fixtures.keys[0].public, 'hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=');
  for (const k of fixtures.keys) {
    assert.equal(P.encodeKey(P.publicKeyFor(P.decodeKey(k.private))), k.public);
  }
});

test('generated keys are clamped like wg genkey and derive a public key', () => {
  const seen = new Set();
  for (let i = 0; i < 64; i++) {
    const k = P.generatePrivateKey();
    assert.equal(k[0] & 7, 0);
    assert.equal(k[31] & 128, 0);
    assert.equal(k[31] & 64, 64);
    assert.equal(P.publicKeyFor(k).length, 32);
    seen.add(P.encodeKey(k));
  }
  assert.equal(seen.size, 64);
});

test('decodeKey rejects malformed keys', () => {
  for (const bad of ['', 'short', btoa('x'.repeat(31)), 'not base64!!', btoa('x'.repeat(33))]) {
    assert.throws(() => P.decodeKey(bad));
  }
});

test('wipe zeroes key material', () => {
  const k = P.generatePrivateKey();
  P.wipe(k);
  assert.ok(k.every((b) => b === 0));
});

test('rendered profiles are byte-identical to the Go renderer', () => {
  for (const f of fixtures.profiles) {
    const priv = P.decodeKey(f.private);
    assert.equal(P.render(f.material, priv, {}), f.full, `${f.name} full`);
    assert.equal(P.render(f.material, priv, { minify: true }), f.minified, `${f.name} minified`);
  }
});

test('render refuses a private key that does not match the device', () => {
  const f = fixtures.profiles[1];
  assert.throws(() => P.render(f.material, P.generatePrivateKey(), {}), /does not match/);
  assert.throws(() => P.render({ ...f.material, schema_version: 1 }, P.decodeKey(f.private), {}), /schema/);
});

test('render refuses values that could start a new line', () => {
  const f = fixtures.profiles.find((p) => p.material.peers.length > 0);
  const priv = P.decodeKey(f.private);
  const peer = f.material.peers[0];
  const cases = {
    'dns zone': { dns_servers: ['fe80::1%eth0\nPreUp = id'] },
    'search domain': { dns_servers: ['10.0.0.53'], search_domains: ['lan\rPostUp = id'] },
    endpoint: { peers: [{ ...peer, endpoint: '[fe80::1%x\nPostUp = id]:51111' }] },
    'device name': { device_name: 'phone\nPreUp = id' },
    'site name': { peers: [{ ...peer, site_name: 'Home\u2028PreUp = id' }] },
  };
  for (const [name, patch] of Object.entries(cases)) {
    assert.throws(() => P.render({ ...f.material, ...patch }, priv, {}), /control character/, name);
  }
  assert.throws(() => P.render({ ...f.material, ...cases.endpoint }, priv, { minify: true }), /control character/);
});

// rasterize turns a QR matrix into RGBA pixels for an independent decoder.
function rasterize(rows, cell) {
  const n = rows.length * cell;
  const data = new Uint8ClampedArray(n * n * 4);
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      const v = rows[Math.floor(y / cell)][Math.floor(x / cell)] ? 0 : 255;
      const i = (y * n + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
  }
  return { data, n };
}

test('QR payloads decode back to the exact minified profile', () => {
  const report = [];
  for (const f of fixtures.profiles) {
    const p = Q.plan(f.minified);
    if (!p) {
      report.push(`${f.name}: ${f.minified.length} bytes -> no QR (file download only)`);
      continue;
    }
    // jsQR's version 23 table has alignment centres 6, 30, 54, 74, 102; the
    // standard (and qrcode-generator) uses 78, so jsQR cannot read any v23
    // code. Phone scanners do not share the bug.
    if (p.version === 23) {
      report.push(`${f.name}: ${p.bytes} bytes -> version 23, level ${p.level} (not decodable by jsQR; skipped)`);
      continue;
    }
    const { data, n } = rasterize(Q.matrix(p), 4);
    const decoded = jsQR(data, n, n);
    assert.ok(decoded, `${f.name}: decoder found no code (version ${p.version})`);
    assert.equal(decoded.data, f.minified, `${f.name}: decoded payload differs`);
    report.push(`${f.name}: ${p.bytes} bytes -> version ${p.version} (${p.modules} modules), level ${p.level}${p.comfortable ? '' : ', recommend file'}`);
  }
  console.log('QR capacity (synthetic decode, not a phone scan):\n  ' + report.join('\n  '));
});

test('payloads beyond QR capacity are reported, not truncated', () => {
  assert.equal(Q.plan('x'.repeat(4000)), null);
});
