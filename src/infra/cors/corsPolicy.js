'use strict';

const cors   = require('cors');
const { emit } = require('../../../services/logger');

// ── CORS policy constants ─────────────────────────────────────────────────────

// Methods needed by browser clients against QODIQA public and protected routes.
// PUT/PATCH/DELETE are excluded — no browser-facing route uses them.
const ALLOWED_METHODS = ['GET', 'HEAD', 'POST', 'OPTIONS'];

// Non-simple request headers that browser clients may include.
// Explicitly listed to prevent implicit header reflection.
const ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Ops-Token',
  'X-Request-ID',
  'X-Qodiqa-Artifact',
];

// Response headers that browser JavaScript is permitted to read.
const EXPOSED_HEADERS = ['X-Request-ID', 'Content-Disposition'];

// Default origins for local development when QODIQA_ALLOWED_ORIGINS is not set.
// Never used in production.
const DEV_DEFAULTS = [
  'http://localhost:3000',
  'http://localhost:4200',
  'http://localhost:5173',
  'http://localhost:8080',
];

// ── Origin validation ─────────────────────────────────────────────────────────

/**
 * Returns true if `str` is a well-formed, non-wildcard origin.
 * An origin is exactly: scheme + host + optional port — no path, query, or fragment.
 */
function _isValidOrigin(str) {
  if (!str || str === '*' || str === 'null') return false;
  try {
    const u = new URL(str);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (u.origin === 'null') return false;
    // The input must exactly match its own computed origin (strips trailing slash too).
    return str === u.origin || str.replace(/\/$/, '') === u.origin;
  } catch {
    return false;
  }
}

/**
 * Parses a comma-separated list of allowed origins.
 * Validates each entry, deduplicates, and normalises (strips trailing slash).
 *
 * @param {string} raw - Raw value of QODIQA_ALLOWED_ORIGINS.
 * @returns {{ origins: string[], errors: string[] }}
 */
function parseCorsOrigins(raw) {
  if (!raw || typeof raw !== 'string') {
    return { origins: [], errors: [] };
  }

  const tokens = raw.split(',').map(s => s.trim()).filter(Boolean);
  const origins = [];
  const errors  = [];
  const seen    = new Set();

  for (const token of tokens) {
    if (!_isValidOrigin(token)) {
      errors.push(
        `invalid origin "${token}": must be a fully-qualified scheme://host[:port] ` +
        `with no path, query, or fragment; wildcards ("*") are not permitted`,
      );
      continue;
    }
    const normalized = token.replace(/\/$/, '');
    if (seen.has(normalized)) continue; // deduplicate silently
    seen.add(normalized);
    origins.push(normalized);
  }

  return { origins, errors };
}

// ── Startup validation ────────────────────────────────────────────────────────

/**
 * Validates the CORS configuration at startup.
 *
 * - Malformed origins in QODIQA_ALLOWED_ORIGINS → fatal (always blocks startup).
 * - QODIQA_ALLOWED_ORIGINS unset in production → non-fatal advisory
 *   (fail-closed: all cross-origin requests will be denied).
 * - QODIQA_ALLOWED_ORIGINS unset in non-production → no findings (dev defaults used).
 *
 * @returns {{ findings: string[], fatal: boolean, origins?: string[] }}
 */
function validateCorsConfiguration() {
  const raw          = process.env.QODIQA_ALLOWED_ORIGINS;
  const isProduction = process.env.NODE_ENV === 'production';

  if (!raw) {
    if (isProduction) {
      return {
        findings: [
          'QODIQA_ALLOWED_ORIGINS is not set — all cross-origin browser requests will be ' +
          'denied in production (fail-closed). Set this to the comma-separated list of ' +
          'browser-facing origins that require API access (e.g. https://portal.example.com).',
        ],
        fatal: false,
      };
    }
    // Non-production: dev defaults will be used — no warning needed.
    return { findings: [], fatal: false };
  }

  const { origins, errors } = parseCorsOrigins(raw);

  if (errors.length > 0) {
    return { findings: errors, fatal: true };
  }

  if (origins.length === 0) {
    return {
      findings: ['QODIQA_ALLOWED_ORIGINS is set but contains no valid origins after parsing'],
      fatal: true,
    };
  }

  return { findings: [], fatal: false, origins };
}

/**
 * Runs CORS startup validation and emits structured log events.
 * Malformed-origin findings cause process.exit(1).
 */
function runCorsValidation() {
  const result = validateCorsConfiguration();

  if (result.findings.length === 0) {
    emit('INFO', 'CORS_VALIDATION_OK', {
      originsConfigured: !!(process.env.QODIQA_ALLOWED_ORIGINS),
    });
    return;
  }

  if (result.fatal) {
    emit('FATAL', 'CORS_VALIDATION_FATAL', {
      findingCount: result.findings.length,
      findings:     result.findings,
      message:      'CORS configuration is invalid — startup aborted',
    });
    process.exit(1);
  }

  emit('WARN', 'CORS_VALIDATION_WARN', {
    findingCount: result.findings.length,
    findings:     result.findings,
  });
}

// ── Middleware factory ────────────────────────────────────────────────────────

/**
 * Creates the CORS middleware with an explicit, deterministic origin allowlist.
 *
 * Origin resolution (in priority order):
 *   1. QODIQA_ALLOWED_ORIGINS env var — all environments
 *   2. DEV_DEFAULTS — non-production only, when env var is not set
 *   3. Empty list — production with no env var configured (fail-closed: deny all)
 *
 * Fail-closed: origins not in the allowlist receive no CORS headers.
 * The browser enforces the block. No wildcard ("*") is ever returned.
 * No arbitrary Origin header is reflected.
 *
 * Credentials:
 *   Disabled — QODIQA uses bearer tokens in the Authorization header, not
 *   session cookies. Enabling credentials would require reflecting the specific
 *   origin and expose unnecessary attack surface.
 *
 * @param {string} [env] - Override NODE_ENV. Used in tests only.
 * @returns {import('express').RequestHandler}
 */
function createCorsMiddleware(env) {
  const resolvedEnv = env ?? process.env.NODE_ENV;
  const raw         = process.env.QODIQA_ALLOWED_ORIGINS;

  let allowedOrigins;

  if (raw) {
    const { origins, errors } = parseCorsOrigins(raw);
    if (errors.length > 0) {
      // Should have been caught by runCorsValidation() at startup; throw defensively.
      throw new Error(`CORS configuration error: ${errors.join('; ')}`);
    }
    allowedOrigins = origins;
  } else if (resolvedEnv !== 'production') {
    allowedOrigins = DEV_DEFAULTS.slice();
  } else {
    allowedOrigins = []; // production without config → deny all (fail-closed)
  }

  const allowedSet = new Set(allowedOrigins);

  return cors({
    origin(requestOrigin, callback) {
      if (!requestOrigin) {
        // No Origin header → server-to-server request. Pass through without CORS headers.
        return callback(null, false);
      }
      if (allowedSet.has(requestOrigin)) {
        // Reflect the exact allowed origin. Never use '*'.
        return callback(null, requestOrigin);
      }
      // Unknown or disallowed origin → no CORS headers → browser blocks. Fail-closed.
      return callback(null, false);
    },
    methods:        ALLOWED_METHODS,
    allowedHeaders: ALLOWED_HEADERS,
    exposedHeaders: EXPOSED_HEADERS,
    credentials:    false,  // bearer-token-only model; session cookies not used
    maxAge:         86400,  // browsers cache preflight for 24 hours
  });
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  createCorsMiddleware,
  parseCorsOrigins,
  validateCorsConfiguration,
  runCorsValidation,
  DEV_DEFAULTS,
  ALLOWED_METHODS,
  ALLOWED_HEADERS,
  EXPOSED_HEADERS,
};
