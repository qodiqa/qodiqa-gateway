'use strict';

/**
 * Tenant portal page —.
 *
 * Fetches ONLY from this codebase's existing authenticated API surface
 * (/tenant-portal/api/me, /keys, /consent) — no business logic is
 * duplicated here, this is purely a rendering layer over server-computed
 * data (see src/api/routes/tenantPortal.js). Every value is rendered via
 * QodiqaCommon.esc()/textContent, never innerHTML with unescaped input —
 * the same XSS-safety convention public/js/policy-management.js already
 * establishes for this codebase's other admin UIs.
 *
 * TOKEN HANDLING: on first load after the OIDC callback redirect, the
 * session token arrives in the URL FRAGMENT (never sent to the server, not
 * logged) — this script moves it into sessionStorage (cleared when the tab
 * closes; NOT localStorage — see src/api/routes/tenantPortal.js's callback
 * handler comment) and strips it from the URL via history.replaceState()
 * so it never lingers in browser history.
 */
(function () {
  var esc = window.QodiqaCommon.esc;
  var STORAGE_KEY = 'qodiqa_portal_token';

  function getToken() {
    var fromFragment = null;
    if (window.location.hash && window.location.hash.indexOf('token=') !== -1) {
      var params = new URLSearchParams(window.location.hash.slice(1));
      fromFragment = params.get('token');
    }
    if (fromFragment) {
      try {
        window.sessionStorage.setItem(STORAGE_KEY, fromFragment);
      } catch (e) { /* sessionStorage unavailable — proceed with the in-memory value for this page load only */ }
      // Never leave the token sitting in the URL/history.
      history.replaceState(null, '', window.location.pathname);
      return fromFragment;
    }
    try {
      return window.sessionStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function clearToken() {
    try { window.sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
  }

  var token = getToken();
  if (!token) {
    window.location.replace('/tenant-login.html');
    return;
  }

  function showFatalError(message) {
    var banner = document.getElementById('error-banner');
    banner.textContent = message;
    banner.hidden = false;
  }

  function api(path) {
    return fetch(path, { headers: { Authorization: 'Bearer ' + token } }).then(function (res) {
      if (res.status === 401) {
        clearToken();
        window.location.replace('/tenant-login.html?error=authentication_failed');
        throw new Error('unauthenticated');
      }
      return res.json().then(function (body) {
        if (!res.ok || body.status !== 'success') {
          var code = (body.error && body.error.code) || 'ERROR';
          throw new Error(code);
        }
        return body.data;
      });
    });
  }

  function badgeClass(state) {
    var s = String(state || '').toLowerCase();
    return 'badge badge-' + (s || 'unknown');
  }

  // ── Identity ────────────────────────────────────────────────────────────

  api('/tenant-portal/api/me').then(function (me) {
    var el = document.getElementById('identity-section');
    el.innerHTML =
      '<h2>Identity</h2>' +
      '<div class="row"><span class="k">Signed in as</span><span class="v">' + esc(me.email) + '</span></div>' +
      '<div class="row"><span class="k">Tenant</span><span class="v">' + esc(me.tenantName || me.tenantId) + '</span></div>' +
      '<div class="row"><span class="k">Tenant ID</span><span class="v">' + esc(me.tenantId) + '</span></div>' +
      '<div class="row"><span class="k">Role</span><span class="v">' + esc(me.role) + '</span></div>';
  }).catch(function (err) {
    if (err.message !== 'unauthenticated') {
      document.getElementById('identity-section').innerHTML = '<h2>Identity</h2><div class="empty">Unable to load identity information.</div>';
      showFatalError('Some sections could not be loaded. Please refresh the page.');
    }
  });

  // ── Keys ────────────────────────────────────────────────────────────────

  api('/tenant-portal/api/keys').then(function (status) {
    var el = document.getElementById('keys-section');
    var html = '<h2>Signing keys</h2>';
    html += '<div class="row"><span class="k">Status</span><span class="v"><span class="' + badgeClass(status.status) + '">' + esc(status.status) + '</span></span></div>';
    html += '<div class="row"><span class="k">Active keys</span><span class="v">' + esc(status.activeKeyCount) + ' of ' + esc(status.keyCount) + '</span></div>';
    if (status.activeKey) {
      html += '<div class="row"><span class="k">Active key ID</span><span class="v">' + esc(status.activeKey.keyId) + '</span></div>';
      html += '<div class="row"><span class="k">Created</span><span class="v">' + esc(status.activeKey.createdAt) + '</span></div>';
      html += '<div class="row"><span class="k">Rotation deadline</span><span class="v">' + esc(status.activeKey.rotationDeadline) + ' (' + esc(status.activeKey.daysUntilRotation) + 'd)</span></div>';
      html += '<div class="row"><span class="k">Expires</span><span class="v">' + esc(status.activeKey.expiresAt) + ' (' + esc(status.activeKey.daysUntilExpiry) + 'd)</span></div>';
    } else {
      html += '<div class="empty">No active signing key.</div>';
    }
    if (status.issues && status.issues.length > 0) {
      html += '<div class="row"><span class="k">Issues</span><span class="v">' + esc(status.issues.join(', ')) + '</span></div>';
    }
    el.innerHTML = html;
  }).catch(function (err) {
    if (err.message !== 'unauthenticated') {
      document.getElementById('keys-section').innerHTML = '<h2>Signing keys</h2><div class="empty">Unable to load key information.</div>';
      showFatalError('Some sections could not be loaded. Please refresh the page.');
    }
  });

  // ── Consent ─────────────────────────────────────────────────────────────

  api('/tenant-portal/api/consent').then(function (result) {
    var el = document.getElementById('consent-section');
    if (!result.records || result.records.length === 0) {
      el.innerHTML = '<h2>Consent</h2><div class="empty">No consent records found for this tenant.</div>';
      return;
    }
    var rows = result.records.map(function (r) {
      return '<tr>' +
        '<td>' + esc(r.actorId) + '</td>' +
        '<td>' + esc(r.action) + '</td>' +
        '<td><span class="' + badgeClass(r.state) + '">' + esc(r.state) + '</span></td>' +
        '<td>' + esc(r.grantedAt) + '</td>' +
        '</tr>';
    }).join('');
    el.innerHTML =
      '<h2>Consent</h2>' +
      '<table><thead><tr><th>Actor</th><th>Action</th><th>State</th><th>Granted</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }).catch(function (err) {
    if (err.message !== 'unauthenticated') {
      document.getElementById('consent-section').innerHTML = '<h2>Consent</h2><div class="empty">Unable to load consent information.</div>';
      showFatalError('Some sections could not be loaded. Please refresh the page.');
    }
  });

  // ── Logout ──────────────────────────────────────────────────────────────

  document.getElementById('logout-btn').addEventListener('click', function () {
    fetch('/tenant-portal/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })
      .catch(function () { /* best-effort — the client-side clear below is what actually ends the session */ })
      .then(function () {
        clearToken();
        window.location.replace('/tenant-login.html');
      });
  });
})();
