'use strict';

const helmet = require('helmet');
const { PORTAL_CSP } = require('./csp');

/**
 * Permissions-Policy value —
 *
 * Denies all browser features not required by this server.  QODIQA is an AI
 * enforcement gateway with no browser-feature dependencies.  Disabling
 * everything reduces the attack surface available to any injected content.
 *
 * Each feature is set to the empty allowlist () which means no origin
 * (including the document origin) may use the feature.
 */
const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'ambient-light-sensor=()',
  'autoplay=()',
  'battery=()',
  'camera=()',
  'cross-origin-isolated=()',
  'display-capture=()',
  'document-domain=()',
  'encrypted-media=()',
  'execution-while-not-rendered=()',
  'execution-while-out-of-viewport=()',
  'fullscreen=()',
  'geolocation=()',
  'gyroscope=()',
  'keyboard-map=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'navigation-override=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'sync-xhr=()',
  'usb=()',
  'wake-lock=()',
  'web-share=()',
  'xr-spatial-tracking=()',
].join(', ');

/**
 * Returns Express middleware that sets all required HTTP security headers.
 *
 * Headers applied:
 *   Content-Security-Policy     — PORTAL_CSP global default; overridden to
 *                                  API_CSP for JSON responses by csp.js
 *   Cross-Origin-Opener-Policy  — same-origin (Helmet default)
 *   Origin-Agent-Cluster        — ?1 (Helmet default)
 *   Permissions-Policy          — all features denied (custom, added here)
 *   Referrer-Policy             — strict-origin-when-cross-origin
 *   Strict-Transport-Security   — 1-year HSTS + includeSubDomains (production)
 *   X-Content-Type-Options      — nosniff
 *   X-DNS-Prefetch-Control      — off
 *   X-Download-Options          — noopen
 *   X-Frame-Options             — DENY
 *   X-Permitted-Cross-Domain-Policies — none
 *   X-Powered-By                — removed
 *   X-XSS-Protection            — 0 (disabled — legacy header, can mislead)
 *
 * @param {string} [env] - Deployment environment. Defaults to NODE_ENV.
 *                         Pass explicitly for testing.
 */
function createSecurityHeaders(env) {
  const resolvedEnv = env ?? process.env.NODE_ENV;
  const isProduction = resolvedEnv === 'production';

  const helmetMiddleware = helmet({
    // ── X-Frame-Options: DENY ────────────────────────────────────────────────
    frameguard: { action: 'deny' },

    // ── Referrer-Policy: strict-origin-when-cross-origin ─────────────────────
    // Full URL on same-origin; only origin on cross-origin HTTPS; nothing on
    // cross-origin HTTP downgrade.  Balanced for enterprise APIs and portal.
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

    // ── Strict-Transport-Security ─────────────────────────────────────────────
    // Production only — plain HTTP in development.
    // max-age=31536000 (1 year), includeSubDomains enabled.
    // preload NOT set: irreversible list submission requires separate process.
    hsts: isProduction
      ? { maxAge: 31536000, includeSubDomains: true }
      : false,

    // ── Content-Security-Policy — PORTAL_CSP ─────────────────────────────────
    // PORTAL_CSP is the global default: it permits what the enforcement portal,
    // audit viewer, dashboard, and demo pages require.  The csp.js middleware
    // overrides this to the strict API_CSP for every res.json() call, ensuring
    // all JSON API responses carry the tightest possible policy.
    //
    // See src/infra/security/csp.js for full policy rationale.
    contentSecurityPolicy: {
      directives: {
        defaultSrc:      ["'none'"],
        // no inline script remains in public/*.html (all moved to
        // public/js/*.js) — 'self' alone is sufficient. See
        // src/infra/security/csp.js and WEB-2-REMEDIATION-REPORT.md.
        scriptSrc:       ["'self'"],
        styleSrc:        ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc:         ["'self'", 'https://fonts.gstatic.com'],
        imgSrc:          ["'self'", 'data:'],
        connectSrc:      ["'self'"],
        workerSrc:       ["'none'"],
        objectSrc:       ["'none'"],
        mediaSrc:        ["'none'"],
        manifestSrc:     ["'none'"],
        frameAncestors:  ["'none'"],
        baseUri:         ["'self'"],
        formAction:      ["'none'"],
      },
    },

    // ── Cross-Origin-Resource-Policy: DISABLED ────────────────────────────────
    // cors() middleware manages cross-origin access.  CORP same-origin would
    // block cross-origin API consumers fetching from a different origin.
    crossOriginResourcePolicy: false,

    // ── Remaining helmet v8 defaults (all enabled) ────────────────────────────
    // X-Content-Type-Options: nosniff           (noSniff: true)
    // X-DNS-Prefetch-Control: off               (dnsPrefetchControl)
    // X-Download-Options: noopen                (ieNoOpen)
    // X-Permitted-Cross-Domain-Policies: none   (permittedCrossDomainPolicies)
    // X-Powered-By: removed                     (hidePoweredBy)
    // Origin-Agent-Cluster: ?1                  (originAgentCluster)
    // Cross-Origin-Opener-Policy: same-origin   (crossOriginOpenerPolicy)
    // X-XSS-Protection: 0                       (xssFilter — disables legacy)
  });

  // Wrap Helmet to inject Permissions-Policy after Helmet's header pass.
  // Helmet v8 does not include a Permissions-Policy helper; we add it here
  // so all security headers are managed from a single location.
  return function securityHeaders(req, res, next) {
    helmetMiddleware(req, res, (err) => {
      if (err) return next(err);
      res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
      next();
    });
  };
}

module.exports = { createSecurityHeaders, PERMISSIONS_POLICY, PORTAL_CSP };
