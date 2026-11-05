// Draws the authenticator setup QR code. The otpauth URI is already in the
// page as text for manual entry; this only renders it.
(function () {
  'use strict';
  var canvas = document.querySelector('canvas[data-otpauth]');
  if (!canvas) return;
  var plan = window.PlaitQR.plan(canvas.getAttribute('data-otpauth'));
  if (plan) window.PlaitQR.draw(canvas, plan, 240);
})();
