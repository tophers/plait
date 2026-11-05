// Adds the session's CSRF token to htmx requests.
(function () {
  'use strict';
  document.addEventListener('htmx:configRequest', function (e) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) e.detail.headers['X-CSRF-Token'] = meta.content;
  });
})();
