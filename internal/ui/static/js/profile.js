// Browser-local key handling and profile assembly. Mirrors
// internal/profile.Render exactly; web/test checks the two byte for byte.
// Private keys exist only in this page's memory: they are never sent to the
// controller or written to browser storage.
(function (root) {
  'use strict';

  var KEY_LEN = 32;
  var SCHEMA_VERSION = 2;

  function encodeKey(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function decodeKey(b64) {
    var s;
    try {
      s = atob(String(b64).trim());
    } catch (e) {
      throw new Error('invalid WireGuard key');
    }
    if (s.length !== KEY_LEN) throw new Error('invalid WireGuard key');
    var out = new Uint8Array(KEY_LEN);
    for (var i = 0; i < KEY_LEN; i++) out[i] = s.charCodeAt(i);
    if (encodeKey(out) !== String(b64).trim()) throw new Error('invalid WireGuard key');
    return out;
  }

  // generatePrivateKey matches `wg genkey`: 32 random bytes, clamped.
  function generatePrivateKey() {
    var k = new Uint8Array(KEY_LEN);
    root.crypto.getRandomValues(k);
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    return k;
  }

  // publicKeyFor matches `wg pubkey`.
  function publicKeyFor(priv) {
    if (!(priv instanceof Uint8Array) || priv.length !== KEY_LEN) throw new Error('invalid private key');
    return root.PlaitX25519.x25519.getPublicKey(priv);
  }

  // wipe overwrites key material. Managed runtimes may retain copies, so this
  // reduces exposure but cannot guarantee erasure.
  function wipe(bytes) {
    if (bytes && bytes.fill) bytes.fill(0);
  }

  function render(m, priv, opts) {
    opts = opts || {};
    if (!m || m.schema_version !== SCHEMA_VERSION) {
      throw new Error('unsupported profile schema version ' + (m && m.schema_version));
    }
    var pub = encodeKey(publicKeyFor(priv));
    if (pub !== m.public_key) {
      throw new Error('private key does not match the registered device public key');
    }
    var minify = !!opts.minify;
    var sep = minify ? '=' : ' = ';
    var listSep = minify ? ',' : ', ';
    var out = '';
    var bad = null;
    // wg-quick runs some keys (PostUp and friends) as shell commands, so a
    // value that could start a new line must never be written, even if the
    // controller let one through. Same rule as internal/profile.
    function line(s) {
      if (bad === null && UNSAFE.test(s)) bad = s;
      out += s + '\n';
    }
    function field(k, v) { line(k + sep + v); }

    if (!minify) line('# Plait profile for ' + m.device_name + ', revision ' + m.revision);
    line('[Interface]');
    field('PrivateKey', encodeKey(priv));
    field('Address', m.address);
    var dns = (m.dns_servers || []).slice();
    if (dns.length > 0) dns = dns.concat(m.search_domains || []);
    if (dns.length > 0) field('DNS', dns.join(listSep));
    if (m.mtu > 0) field('MTU', String(m.mtu));
    (m.peers || []).forEach(function (p) {
      if (!minify) { line(''); line('# Site: ' + p.site_name); }
      line('[Peer]');
      field('PublicKey', p.public_key);
      field('PresharedKey', p.preshared_key);
      field('Endpoint', p.endpoint);
      if (p.allowed_ips && p.allowed_ips.length > 0) field('AllowedIPs', p.allowed_ips.join(listSep));
      if (p.persistent_keepalive > 0 || !minify) field('PersistentKeepalive', String(p.persistent_keepalive));
    });
    if (bad !== null) throw new Error('profile material contains a control character: ' + JSON.stringify(bad));
    return out;
  }

  // Control characters (including CR and LF) and the Unicode line and
  // paragraph separators.
  var UNSAFE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

  root.PlaitProfile = {
    encodeKey: encodeKey,
    decodeKey: decodeKey,
    generatePrivateKey: generatePrivateKey,
    publicKeyFor: publicKeyFor,
    render: render,
    wipe: wipe,
  };
})(typeof window !== 'undefined' ? window : globalThis);
