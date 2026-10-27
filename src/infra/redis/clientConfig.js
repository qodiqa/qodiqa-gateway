'use strict';

/**
 * Redis client configuration builder — auth + TLS.
 *
 * Centralises credential and transport configuration so nonceStore and
 * anomalyStore share identical precedence rules and redaction behaviour.
 *
 * Credential precedence (highest → lowest):
 *   1. REDIS_USERNAME / REDIS_PASSWORD env vars
 *   2. Credentials embedded in REDIS_URL (user:pass@host)
 *
 * TLS is enabled when either condition holds:
 *   • REDIS_URL scheme is rediss://
 *   • REDIS_TLS=true
 *
 * Credentials are NEVER written to stdout/stderr.  All URL logging uses
 * _redactUrl() which replaces the userinfo component with [REDACTED].
 *
 * Env vars:
 *   REDIS_URL                        connection string (default: redis://localhost:6379)
 *   REDIS_USERNAME                   ACL username (overrides URL-embedded)
 *   REDIS_PASSWORD                   auth password (overrides URL-embedded)
 *   REDIS_TLS                        'true' to force TLS regardless of URL scheme
 *   REDIS_TLS_CA                     filesystem path to PEM CA certificate
 *   REDIS_TLS_CERT                   filesystem path to PEM client certificate
 *   REDIS_TLS_KEY                    filesystem path to PEM client private key
 *   REDIS_TLS_REJECT_UNAUTHORIZED    'false' to disable certificate verification
 *                                    (unsafe — only for development/testing)
 */

const fs = require('fs');

// ── Auth / TLS error pattern matching ─────────────────────────────────────────
//
// Used by stores to classify Redis error events without re-implementing the
// pattern logic in two places.

const _AUTH_ERR_RE = /WRONGPASS|NOAUTH|ERR invalid password|AUTHFAILED/i;
const _TLS_ERR_RE  = /SSL|certificate|handshake|TLS/i;

// ── Internal helpers ──────────────────────────────────────────────────────────

function _hasUrlCredentials(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return !!(u.username || u.password);
  } catch { return false; }
}

function _redactUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (u.username) u.username = '[REDACTED]';
    if (u.password) u.password = '[REDACTED]';
    return u.toString();
  } catch { return '[INVALID_URL]'; }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Return a config summary derived solely from env vars (no file I/O).
 * Safe to call at module load time or in test environments.
 *
 * @returns {{ authConfigured: boolean, tlsEnabled: boolean, tlsVerified: boolean, urlRedacted: string }}
 */
function getConfigSummary() {
  const rawUrl         = process.env.REDIS_URL || 'redis://localhost:6379';
  const tlsEnabled     = rawUrl.startsWith('rediss://') || process.env.REDIS_TLS === 'true';
  const authConfigured = !!(
    process.env.REDIS_USERNAME ||
    process.env.REDIS_PASSWORD ||
    _hasUrlCredentials(rawUrl)
  );
  const tlsVerified = tlsEnabled && process.env.REDIS_TLS_REJECT_UNAUTHORIZED !== 'false';

  return {
    authConfigured,
    tlsEnabled,
    tlsVerified,
    urlRedacted: _redactUrl(rawUrl),
  };
}

/**
 * Build the full createClient() options object.
 * May perform synchronous file reads for TLS cert/key/CA paths.
 *
 * @param {{ reconnectStrategy: Function, connectTimeout: number }} hooks
 * @returns {import('redis').RedisClientOptions}
 */
function buildClientOptions({ reconnectStrategy, connectTimeout }) {
  const rawUrl     = process.env.REDIS_URL || 'redis://localhost:6379';
  const tlsEnabled = rawUrl.startsWith('rediss://') || process.env.REDIS_TLS === 'true';

  // finding: @redis/client's parseOptions() requires `socket.tls` to be
  // exactly `true` (or undefined) when the URL scheme is rediss:// — it
  // throws "tls socket option is set to [object Object] which is mismatch
  // with protocol..." for anything else (node_modules/@redis/client/dist/lib/client/index.js,
  // parseOptions()). CA/cert/key must instead be flat sibling properties on
  // `socket` itself: #createSocketFactory() only takes the TLS branch when
  // `options.tls === true`, then spreads the *whole* socket options object
  // into `tls.connect()` (node_modules/@redis/client/dist/lib/client/socket.js).
  // Nesting them under `socket.tls` (the previous shape here) made every
  // mTLS-configured connection — REDIS_TLS_CA/CERT/KEY, exactly the
  // production-recommended posture in docs/deployment/redis-tls.md — throw at
  // createClient() time, discovered only via an actual container boot since
  // no existing test exercised this against the real redis client's own
  // validation (clientConfig.test.js only asserts `toBeTruthy()`).
  const tlsOpts = {};
  if (tlsEnabled) {
    if (process.env.REDIS_TLS_REJECT_UNAUTHORIZED === 'false') {
      tlsOpts.rejectUnauthorized = false;
    }
    if (process.env.REDIS_TLS_CA)   tlsOpts.ca   = fs.readFileSync(process.env.REDIS_TLS_CA);
    if (process.env.REDIS_TLS_CERT) tlsOpts.cert = fs.readFileSync(process.env.REDIS_TLS_CERT);
    if (process.env.REDIS_TLS_KEY)  tlsOpts.key  = fs.readFileSync(process.env.REDIS_TLS_KEY);
  }

  const opts = {
    url: rawUrl,
    socket: {
      reconnectStrategy,
      connectTimeout,
      ...(tlsEnabled ? { tls: true, ...tlsOpts } : {}),
    },
  };

  // Explicit env vars take precedence over URL-embedded credentials
  if (process.env.REDIS_USERNAME) opts.username = process.env.REDIS_USERNAME;
  if (process.env.REDIS_PASSWORD) opts.password = process.env.REDIS_PASSWORD;

  return opts;
}

/**
 * Returns true if err looks like a Redis authentication rejection.
 * @param {Error} err
 * @returns {boolean}
 */
function isAuthError(err) {
  return _AUTH_ERR_RE.test(err?.message || '');
}

/**
 * Returns true if err looks like a TLS / certificate failure.
 * @param {Error} err
 * @returns {boolean}
 */
function isTlsError(err) {
  return _TLS_ERR_RE.test(err?.message || '');
}

module.exports = { getConfigSummary, buildClientOptions, isAuthError, isTlsError };
