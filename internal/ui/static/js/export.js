// Device enrollment, key replacement, and profile export. Private keys are
// generated here and used only in this page: requests to the controller
// carry public keys and fetch profile material, never a private key. Nothing
// is written to browser storage, and no page accepts a pasted private key.
(function () {
  'use strict';
  var P = window.PlaitProfile;
  var Q = window.PlaitQR;

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  }

  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', cache: 'no-store',
      headers: { 'X-CSRF-Token': csrfToken(), Accept: 'application/json' } };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* not JSON */ }
        if (!r.ok) throw new Error((data && data.error) || 'request failed (HTTP ' + r.status + ')');
        return data;
      });
    });
  }

  function show(el, on) { if (el) el.hidden = !on; }

  function showError(el, err) {
    if (!el) return;
    el.textContent = err ? (err.message || String(err)) : '';
    show(el, !!err);
  }

  // WireGuard apps derive the tunnel name from the file name; Android limits
  // it to 15 characters from a small set.
  function tunnelFileName(name) {
    var s = String(name || 'plait').replace(/[^A-Za-z0-9_=+.-]/g, '-').slice(0, 15);
    return (s || 'plait') + '.conf';
  }

  // ExportPanel drives one [data-export] section for a key generated in this
  // page.
  function ExportPanel(el, priv) {
    this.el = el;
    this.deviceId = el.getAttribute('data-device-id');
    this.publicKey = el.getAttribute('data-public-key');
    this.priv = priv;
    this.full = null;
    this.name = 'plait';
    this.err = el.querySelector('[data-error]');
    var self = this;
    el.querySelector('[data-download]').addEventListener('click', function () { self.download(); });
    el.querySelector('[data-clear]').addEventListener('click', function () { self.clear(); });
    window.addEventListener('pagehide', function () { self.clear(); });
  }

  ExportPanel.prototype.assemble = function () {
    var self = this;
    showError(this.err, null);
    if (!this.priv) {
      showError(this.err, new Error('The private key was cleared from this page. Issue a new profile instead.'));
      return Promise.resolve();
    }
    if (P.encodeKey(P.publicKeyFor(this.priv)) !== this.publicKey) {
      showError(this.err, new Error('Internal error: the generated key does not match this device.'));
      return Promise.resolve();
    }
    return api('GET', '/api/v1/admin/devices/' + encodeURIComponent(this.deviceId) + '/profile-material')
      .then(function (m) {
        self.name = m.device_name;
        self.full = P.render(m, self.priv, {});
        var minified = P.render(m, self.priv, { minify: true });
        self.drawQR(minified);
        minified = null;
        show(self.el.querySelector('[data-step="result"]'), true);
        return api('POST', '/api/v1/admin/devices/' + encodeURIComponent(self.deviceId) + '/exports', { revision: m.revision });
      })
      .then(function () {
        document.querySelectorAll('[data-export-stale]').forEach(function (b) { show(b, false); });
      })
      .catch(function (e) { showError(self.err, e); });
  };

  ExportPanel.prototype.drawQR = function (text) {
    var canvas = this.el.querySelector('[data-qr]');
    var info = this.el.querySelector('[data-qr-info]');
    var plan = Q.plan(text);
    if (!plan) {
      canvas.width = canvas.height = 0;
      show(canvas, false);
      info.textContent = 'This profile is too large for a QR code (' + text.length + ' bytes). Use the .conf file.';
      return;
    }
    show(canvas, true);
    Q.draw(canvas, plan, 400);
    info.textContent = text.length + ' bytes · QR version ' + plan.version + ', error correction ' + plan.level +
      (plan.comfortable ? '' : ' · Dense code: if your phone cannot scan it, use the .conf file.');
  };

  ExportPanel.prototype.download = function () {
    if (!this.full) return;
    var url = URL.createObjectURL(new Blob([this.full], { type: 'application/octet-stream' }));
    var a = document.createElement('a');
    a.href = url;
    a.download = tunnelFileName(this.name);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };

  ExportPanel.prototype.clear = function () {
    if (this.priv) P.wipe(this.priv);
    this.priv = null;
    this.full = null;
    var canvas = this.el.querySelector('[data-qr]');
    if (canvas) canvas.width = canvas.height = 0;
    var info = this.el.querySelector('[data-qr-info]');
    if (info) info.textContent = '';
    show(this.el.querySelector('[data-step="result"]'), false);
  };

  // newPanel clones the server-rendered panel template for a device.
  function newPanel(container, deviceId, publicKey) {
    var tpl = document.querySelector('template[data-export-template]');
    var node = tpl.content.firstElementChild.cloneNode(true);
    node.setAttribute('data-device-id', deviceId);
    node.setAttribute('data-public-key', publicKey);
    container.textContent = '';
    container.appendChild(node);
    show(container, true);
    return node;
  }

  // isPrivateAddr mirrors Go's netip.Addr.IsPrivate for the Internal
  // resolvers choice; the controller validates the addresses themselves.
  function isPrivateAddr(a) {
    var v4 = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(a);
    if (v4) {
      var o1 = +v4[1], o2 = +v4[2];
      return o1 === 10 || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 192 && o2 === 168);
    }
    return /^f[cd][0-9a-f]{0,2}:/i.test(a);
  }

  // clientSettings reads the shared DNS and MTU fields into the enrollment
  // request, applying the same rules as the device page's settings form.
  function clientSettings(form) {
    var cs = { search_domains: form.search_domains.value.split(/[\s,]+/).filter(Boolean), dns_servers: [] };
    var mtu = form.mtu.value.trim();
    if (mtu !== '') {
      if (!/^\d+$/.test(mtu)) throw new Error('MTU must be a number');
      cs.mtu = parseInt(mtu, 10);
    }
    var mode = form.querySelector('input[name="dns_mode"]:checked');
    mode = mode ? mode.value : 'none';
    if (mode !== 'none') {
      cs.dns_servers = form.dns_servers.value.split(/[\s,]+/).filter(Boolean);
      if (!cs.dns_servers.length) throw new Error('enter at least one resolver, or choose No tunnel DNS');
      if (mode === 'internal' && !cs.dns_servers.every(isPrivateAddr)) {
        throw new Error('Internal resolvers must be private addresses; choose Custom for public or mixed resolvers');
      }
    }
    return cs;
  }

  // --- new device ---
  var enroll = document.querySelector('[data-enroll]');
  if (enroll) {
    var form = enroll.querySelector('[data-enroll-form]');
    var enrollErr = enroll.querySelector('[data-enroll-error]');
    var result = document.querySelector('[data-enroll-result]');
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      showError(enrollErr, null);
      var req, keepalive;
      try {
        req = clientSettings(form);
        if (form.keepalive) {
          var k = form.keepalive.value.trim();
          if (!/^\d+$/.test(k)) throw new Error('keepalive must be a number');
          keepalive = parseInt(k, 10);
        }
      } catch (e) {
        showError(enrollErr, e);
        return;
      }
      req.name = form.name.value.trim();
      var priv = P.generatePrivateKey();
      var pub = P.encodeKey(P.publicKeyFor(priv));
      req.public_key = pub;
      var sites = Array.prototype.map.call(form.querySelectorAll('input[name="site"]:checked'), function (c) { return c.value; });
      var button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      var device;
      api('POST', '/api/v1/admin/devices', req)
        .then(function (d) {
          device = d;
          return sites.reduce(function (p, siteId) {
            return p.then(function () { return api('POST', '/api/v1/admin/links', { site_id: siteId, device_id: d.id, persistent_keepalive: keepalive }); });
          }, Promise.resolve());
        })
        .catch(function (e) {
          showError(enrollErr, device ? new Error('Device created, but granting site access failed: ' + e.message + '. Adjust access on the device page.') : e);
        })
        .then(function () {
          if (!device) { button.disabled = false; P.wipe(priv); return; }
          form.querySelectorAll('input, textarea, button').forEach(function (i) { i.disabled = true; });
          var link = document.createElement('p');
          var a = document.createElement('a');
          a.href = '/devices/' + encodeURIComponent(device.id);
          a.textContent = 'Open ' + device.name + ' (' + device.address + ')';
          link.appendChild(a);
          var panel = new ExportPanel(newPanel(result, device.id, pub), priv);
          result.insertBefore(link, result.firstChild);
          panel.assemble();
        });
    });
  }

  // --- key replacement (device page) ---
  var replace = document.querySelector('[data-replace-key]');
  if (replace) {
    var confirmBox = replace.querySelector('[data-replace-confirm]');
    var replaceErr = replace.querySelector('[data-replace-error]');
    var replaceResult = document.querySelector('[data-replace-result]');
    var deviceId = replace.getAttribute('data-device-id');
    replace.querySelector('[data-replace-generate]').addEventListener('click', function (ev) {
      showError(replaceErr, null);
      if (!confirmBox.checked) {
        showError(replaceErr, new Error('Confirm that the current key will be invalidated.'));
        return;
      }
      var btn = ev.currentTarget;
      btn.disabled = true;
      var priv = P.generatePrivateKey();
      var pub = P.encodeKey(P.publicKeyFor(priv));
      api('POST', '/api/v1/admin/devices/' + encodeURIComponent(deviceId) + '/replace-key', { public_key: pub })
        .then(function () {
          var panel = new ExportPanel(newPanel(replaceResult, deviceId, pub), priv);
          return panel.assemble();
        })
        .catch(function (e) {
          P.wipe(priv);
          btn.disabled = false;
          showError(replaceErr, e);
        });
    });
  }
})();
