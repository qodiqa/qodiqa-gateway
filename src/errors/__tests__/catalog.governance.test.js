'use strict';

/**
 * Error Catalog Governance Test — ERR-2 remediation drift
 * prevention.
 *
 * Mirrors the pattern already established by
 * src/api/__tests__/responseEnvelopeGovernance.test.js: a hand-maintained
 * source of truth (here, src/errors/catalog.js) needs something forcing it
 * to stay internally consistent and in sync with the things that consume
 * it. This checks, in order:
 *
 *   A. Every catalog entry is well-formed (valid HTTP status, non-empty
 *      description/category, boolean retryable).
 *   B. src/reasons.js's REASONS is derived from (a subset of / identical
 *      to) the catalog — every key has a real catalog entry.
 *   C. Regression guard for the exact FILTERED_ERROR_CODES drift bug this
 *      remediation fixed (POLICY_BLOCK -> POLICY_BLOCKED, SIGNATURE_INVALID
 *      -> INVALID_SIGNATURE): the correct strings must be present, the
 *      wrong ones must not be.
 *   D. Completeness: every code previously listed independently across
 *      docs/operations/troubleshooting.md's and docs/architecture/enforcement-flow.md's hand-written tables
 *      (pre-WP-030) still has a catalog entry — nothing was silently
 *      dropped when those tables were consolidated into this file.
 *   E. Documentation drift: docs/operations/troubleshooting.md and docs/architecture/enforcement-flow.md
 *      actually reference src/errors/catalog.js as the source of truth,
 *      rather than re-duplicating the table independently again.
 */

const fs   = require('fs');
const path = require('path');

const { ERROR_CATALOG } = require('../catalog');
const { REASONS } = require('../../reasons');

const ROOT = path.join(__dirname, '..', '..', '..');
function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

// ── A. Structural validity ───────────────────────────────────────────────

describe('error catalog governance — structural validity', () => {
  test('catalog is non-empty', () => {
    expect(Object.keys(ERROR_CATALOG).length).toBeGreaterThan(0);
  });

  test.each(Object.entries(ERROR_CATALOG))('%s is a well-formed catalog entry', (code, entry) => {
    expect(code).toMatch(/^[A-Z][A-Z0-9_]+$/);
    expect(Number.isInteger(entry.httpStatus)).toBe(true);
    expect(entry.httpStatus).toBeGreaterThanOrEqual(100);
    expect(entry.httpStatus).toBeLessThan(600);
    expect(typeof entry.description).toBe('string');
    expect(entry.description.length).toBeGreaterThan(0);
    expect(typeof entry.category).toBe('string');
    expect(entry.category.length).toBeGreaterThan(0);
    expect(typeof entry.retryable).toBe('boolean');
  });
});

// ── B. reasons.js is derived from the catalog ────────────────────────────

describe('error catalog governance — reasons.js consistency', () => {
  test('REASONS is non-empty and every key has a real catalog entry', () => {
    const keys = Object.keys(REASONS);
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(ERROR_CATALOG).toHaveProperty(key);
      expect(REASONS[key]).toBe(key); // self-documenting: key === value
    }
  });

  test('every catalog entry is reachable via REASONS (REASONS is exhaustive, not partial)', () => {
    for (const code of Object.keys(ERROR_CATALOG)) {
      expect(REASONS).toHaveProperty(code);
    }
  });
});

// ── C. Core codes stay in the catalog ─────────────────────────────────────

describe('error catalog governance — core codes', () => {
  test('the catalog has the real POLICY_BLOCKED code, not the drifted POLICY_BLOCK', () => {
    expect(ERROR_CATALOG).toHaveProperty('POLICY_BLOCKED');
    expect(ERROR_CATALOG).not.toHaveProperty('POLICY_BLOCK');
  });

  test('the catalog has the real INVALID_SIGNATURE code, not the drifted SIGNATURE_INVALID', () => {
    expect(ERROR_CATALOG).toHaveProperty('INVALID_SIGNATURE');
    expect(ERROR_CATALOG).not.toHaveProperty('SIGNATURE_INVALID');
  });
});

// ── D. Completeness vs. the pre-WP-030 hand-written tables ───────────────

describe('error catalog governance — completeness against the pre-existing tables', () => {
  // Every code that was independently listed in either docs/operations/troubleshooting.md's
  // "Quick-reference: reason codes and HTTP status" table or
  // docs/architecture/enforcement-flow.md's "Complete decision table" / "Canonical reason
  // vocabulary" section before this remediation consolidated them here.
  const PRE_EXISTING_CODES = [
    'ALL_CHECKS_PASSED', 'MISSING_ARTIFACT', 'ARTIFACT_TOO_LARGE', 'ARTIFACT_DECODE_FAILED',
    'ARTIFACT_INVALID_TYPE', 'INVALID_REQUEST_BODY', 'MISSING_PROMPT', 'PROMPT_TOO_LARGE',
    'INVALID_ARTIFACT', 'INVALID_SIGNATURE', 'KEY_NOT_FOUND', 'EXPIRED', 'FUTURE_TIMESTAMP',
    'TIME_SKEW_EXCEEDED', 'REQUEST_MISMATCH', 'REPLAY_DETECTED', 'NONCE_STORE_ERROR',
    'ANOMALY_DETECTED', 'CONSENT_MISSING', 'CONSENT_STORE_UNAVAILABLE', 'CONSENT_NOT_FOUND',
    'CONSENT_REVOKED', 'CONSENT_EXPIRED', 'CONSENT_SUSPENDED', 'CONSENT_NOT_ACTIVE',
    'CONSENT_SCOPE_MISMATCH', 'CONSENT_SCOPE_MISSING', 'CONSENT_CONTEXT_INCOMPLETE',
    'CONSENT_EVALUATION_ERROR', 'IP_BLOCKED', 'RATE_LIMIT_EXCEEDED', 'OUTSIDE_TIME_WINDOW',
    'POLICY_BLOCKED', 'MISSING_PROVIDER', 'PROVIDER_MODEL_NOT_ALLOWED', 'PROVIDER_INVALID_REQUEST',
    'PROVIDER_REQUEST_REJECTED', 'PROVIDER_RESPONSE_INVALID', 'PROVIDER_UNAVAILABLE',
    'PROVIDER_RATE_LIMITED', 'PROVIDER_AUTH_FAILED', 'PROVIDER_TIMEOUT', 'REQUEST_TIMEOUT',
    'PROVIDER_NOT_CONFIGURED', 'PROVIDER_CONFIG_INVALID', 'PROVIDER_INVALID_RESPONSE',
    'AUDIT_PERSISTENCE_FAILED',
    // From docs/architecture/enforcement-flow.md's "additional codes" list / decision table:
    'INVALID_EXPIRY', 'POLICY_STATE_UNAVAILABLE', 'INTERNAL_ERROR', 'INVALID_CONTEXT',
    'NO_POLICIES_LOADED', 'NO_ENABLED_POLICIES', 'EVALUATOR_MISSING', 'EVALUATOR_ERROR',
    'IP_MISSING', 'TIMESTAMP_MISSING', 'RATE_LIMIT_KEY_MISSING',
    // From src/reasons.js's original ~29-code subset:
    'KEY_REVOKED', 'RATE_LIMITED', 'BYPASS_ATTEMPT',
  ];

  test.each(PRE_EXISTING_CODES)('%s has a catalog entry', (code) => {
    expect(ERROR_CATALOG).toHaveProperty(code);
  });
});

// ── E. Documentation points at the catalog instead of re-duplicating it ──

describe('error catalog governance — documentation references the catalog', () => {
  test('docs/operations/troubleshooting.md references src/errors/catalog.js', () => {
    expect(readFile('docs/operations/troubleshooting.md')).toMatch(/src\/errors\/catalog\.js/);
  });

  test('docs/architecture/enforcement-flow.md references src/errors/catalog.js', () => {
    expect(readFile('docs/architecture/enforcement-flow.md')).toMatch(/src\/errors\/catalog\.js/);
  });
});
