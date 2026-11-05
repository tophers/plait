// Runs plaitd's embedded browser code (the same files the UI serves) under
// Node to enroll a device the way the "Add device" page does: generate the
// key locally, send only the public key, fetch profile material, and
// assemble the profile. Usage:
//   node browser-assemble.mjs <static dir> <api base> <csrf> <cookie> <site id> <device name> <out.conf> <out.key>
import { readFileSync, writeFileSync } from 'node:fs';
import vm from 'node:vm';

const [staticDir, api, csrf, cookie, siteId, name, outConf, outKey] = process.argv.slice(2);
for (const f of ['vendor/x25519.js', 'js/profile.js']) {
  vm.runInThisContext(readFileSync(`${staticDir}/${f}`, 'utf8'), { filename: f });
}
const P = globalThis.PlaitProfile;

async function call(method, path, body) {
  const headers = { 'X-CSRF-Token': csrf, Cookie: cookie, Accept: 'application/json' };
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(api + path, { method, headers, body: body && JSON.stringify(body) });
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${data && data.error}`);
  return data;
}

const priv = P.generatePrivateKey();
const pub = P.encodeKey(P.publicKeyFor(priv));
const dev = await call('POST', '/api/v1/admin/devices', { name, public_key: pub });
await call('POST', '/api/v1/admin/links', { site_id: siteId, device_id: dev.id });
const m = await call('GET', `/api/v1/admin/devices/${dev.id}/profile-material`);
writeFileSync(outConf, P.render(m, priv, { minify: true }), { mode: 0o600 });
// The key is written only so the harness can cross-check it with `wg pubkey`.
writeFileSync(outKey, P.encodeKey(priv) + '\n', { mode: 0o600 });
console.log(pub);
