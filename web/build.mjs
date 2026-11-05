// Produces the vendored browser files embedded in plaitd. Run after changing
// a pinned version in package.json, then update VENDOR.md with the printed
// checksums. Output is unminified so it can be reviewed.
import { build } from 'esbuild';
import { copyFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const out = new URL('../internal/ui/static/vendor/', import.meta.url).pathname;

await build({
  entryPoints: ['src/x25519-entry.js'],
  bundle: true,
  format: 'iife',
  globalName: 'PlaitX25519',
  target: 'es2020',
  legalComments: 'inline',
  outfile: out + 'x25519.js',
});
copyFileSync('node_modules/qrcode-generator/dist/qrcode.js', out + 'qrcode.js');
copyFileSync('node_modules/htmx.org/dist/htmx.min.js', out + 'htmx.min.js');

for (const f of ['x25519.js', 'qrcode.js', 'htmx.min.js']) {
  const sum = createHash('sha256').update(readFileSync(out + f)).digest('hex');
  console.log(`${sum}  ${f}`);
}
