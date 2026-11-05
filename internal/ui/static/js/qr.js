// QR rendering for locally assembled profiles. The payload contains the
// private key, so encoding and drawing happen only in this page.
(function (root) {
  'use strict';

  // Above this QR version, codes get dense enough that phone scanning is
  // unreliable at typical screen sizes; the page then recommends the file.
  var COMFORTABLE_VERSION = 20;
  var QUIET_ZONE = 4;

  function encode(text, level) {
    try {
      var qr = root.qrcode(0, level);
      qr.addData(text, 'Byte');
      qr.make();
      var count = qr.getModuleCount();
      var version = (count - 17) / 4;
      return { qr: qr, level: level, version: version, modules: count, bytes: text.length,
        comfortable: version <= COMFORTABLE_VERSION };
    } catch (e) {
      return null; // payload too large at this level
    }
  }

  // plan prefers error-correction level M while the code stays comfortably
  // scannable, and otherwise uses L for a smaller, less dense code. It
  // returns null when no QR version can hold the payload; callers must offer
  // the .conf file instead.
  function plan(text) {
    var m = encode(text, 'M');
    if (m && m.comfortable) return m;
    return encode(text, 'L') || m;
  }

  // matrix returns rows of booleans including the quiet zone.
  function matrix(p) {
    var n = p.modules + 2 * QUIET_ZONE;
    var rows = [];
    for (var y = 0; y < n; y++) {
      var row = [];
      for (var x = 0; x < n; x++) {
        var mx = x - QUIET_ZONE, my = y - QUIET_ZONE;
        row.push(mx >= 0 && my >= 0 && mx < p.modules && my < p.modules && p.qr.isDark(my, mx));
      }
      rows.push(row);
    }
    return rows;
  }

  // draw paints the code onto a canvas with whole-pixel modules.
  function draw(canvas, p, maxPixels) {
    var m = matrix(p);
    var cell = Math.max(2, Math.floor((maxPixels || 360) / m.length));
    canvas.width = canvas.height = cell * m.length;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000';
    for (var y = 0; y < m.length; y++) {
      for (var x = 0; x < m.length; x++) {
        if (m[y][x]) ctx.fillRect(x * cell, y * cell, cell, cell);
      }
    }
  }

  root.PlaitQR = { plan: plan, matrix: matrix, draw: draw, COMFORTABLE_VERSION: COMFORTABLE_VERSION };
})(typeof window !== 'undefined' ? window : globalThis);
