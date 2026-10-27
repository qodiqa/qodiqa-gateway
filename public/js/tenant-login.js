'use strict';

/**
 * Tenant portal login page —.
 *
 * Shows the ?error= query param safely: mapped through a fixed allowlist
 * of known error codes to a generic, pre-written message. The raw query
 * value itself is NEVER rendered into the page — only used as a lookup key
 * — so this cannot be an XSS vector regardless of what a crafted URL
 * contains, and never exposes internal exception text (see
 * src/api/routes/tenantPortal.js's error-handling notes: the server itself
 * only ever redirects with one of these exact codes).
 */
(function () {
  var MESSAGES = {
    login_unavailable:      'Sign-in is temporarily unavailable. Please try again shortly.',
    invalid_request:        'Your sign-in request could not be verified. Please try signing in again.',
    authentication_failed:  'Authentication failed. Please try signing in again.',
    tenant_not_provisioned: 'Your organization is not yet provisioned for QODIQA. Contact your administrator.',
    account_disabled:       'This account has been disabled. Contact your administrator.',
  };

  function showError(code) {
    var box = document.getElementById('error-box');
    var message = Object.prototype.hasOwnProperty.call(MESSAGES, code)
      ? MESSAGES[code]
      : 'Something went wrong during sign-in. Please try again.';
    box.textContent = message; // textContent, never innerHTML — no HTML interpretation of any value here
    box.hidden = false;
  }

  var params = new URLSearchParams(window.location.search);
  var errorCode = params.get('error');
  if (errorCode) {
    showError(errorCode);
  }

  // If a stale session token is still present, clear it — arriving back at
  // the login page means the previous session ended (logout, expiry, or a
  // failed re-auth attempt).
  try {
    window.sessionStorage.removeItem('qodiqa_portal_token');
  } catch (e) {
    // sessionStorage may be unavailable (private browsing, blocked site
    // data) — non-fatal, the login flow itself does not depend on it.
  }
})();
