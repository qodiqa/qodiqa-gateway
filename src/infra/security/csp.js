'use strict';

/**
 * Content Security Policy (CSP) —
 *
 * Two policies are maintained:
 *
 *   API_CSP    — Applied when the response body is application/json.
 *                Prevents any script/style/resource execution on JSON
 *                responses.  frame-ancestors 'none' is belt-and-suspenders
 *                alongside X-Frame-Options: DENY.
 *
 *   PORTAL_CSP — Applied when serving HTML responses (portal, audit viewer,
 *                dashboard, demo pages in public/).
 *
 *                The portal HTML requires:
 *                  • Google Fonts  (fonts.googleapis.com, fonts.gstatic.com)
 *                  • Inline <style> blocks   → style-src 'unsafe-inline'
 *                  • Same-origin script      → script-src 'self'
 *                  • Same-origin fetch()     → connect-src 'self'
 *                  • data: URIs in img-src   → img-src data:
 *
 * remediation (see WEB-2-REMEDIATION-REPORT.md): every
 *                inline <script> block and inline event-handler attribute
 *                (onclick, onchange, oninput, …) that used to live in
 *                public/*.html has been moved into external files under
 *                public/js/*.js, referenced via <script src="…" defer>.  With
 *                no inline script remaining, script-src no longer needs
 *                'unsafe-inline' — 'self' alone is sufficient and a future
 *                inline-script regression will be blocked by the browser
 *                instead of silently executing.
 *
 *                style-src keeps 'unsafe-inline' — the portal pages still use
 *                inline <style> blocks, which is a separate, lower-severity
 *                finding (style injection cannot achieve script execution)
 * and is out of scope for.
 *
 * Middleware strategy:
 *   createCspMiddleware() installs a per-request hook on res.json() so that
 *   any Express route calling res.json() receives API_CSP (strict), while HTML
 *   served by express.static() receives PORTAL_CSP (from Helmet's global CSP).
 *   The hook fires before headers are sent, allowing a clean override.
 */

const API_CSP = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'none'",
  "img-src 'none'",
  "connect-src 'none'",
  "font-src 'none'",
  "object-src 'none'",
  "media-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

const PORTAL_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'none'",
  "object-src 'none'",
  "media-src 'none'",
  "manifest-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ');

/**
 * Returns Express middleware that overrides the CSP header to API_CSP
 * whenever a route calls res.json().
 *
 * Helmet sets PORTAL_CSP globally (see headers.js).  This middleware narrows
 * it to the strict API_CSP for all JSON responses, which represents the
 * large majority of this server's traffic.
 *
 * Must be registered BEFORE route handlers so the hook is in place when
 * any route calls res.json().
 */
function createCspMiddleware() {
  return function cspMiddleware(req, res, next) {
    const _origJson = res.json.bind(res);

    res.json = function strictCspJson(body) {
      res.set('Content-Security-Policy', API_CSP);
      return _origJson(body);
    };

    next();
  };
}

module.exports = { createCspMiddleware, API_CSP, PORTAL_CSP };
