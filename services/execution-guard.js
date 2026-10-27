'use strict';

/**
 * GLOBAL EXECUTION INVARIANT GUARD
 *
 * Enforces: "No valid artifact → no execution"
 *
 * Every call that reaches the provider layer must carry a verified execution
 * context produced by the /ai/chat enforcement pipeline. This module is the
 * single authority for that assertion. It tracks every attempt — verified
 * and violating — so any bypass surfaces in metrics and logs even if the
 * throw is caught upstream.
 *
 * structural shape alone is no longer sufficient. Before this
 * remediation, any caller able to construct an object of the right shape
 * (verified:true, a syntactically valid requestHash, etc.) passed the
 * invariant — security depended entirely on there being only one legitimate
 * call path in the codebase. assertExecutionInvariant() now also requires a
 * valid HMAC-SHA256 signature (services/executionInvariantToken.js) binding
 * requestHash+policyHash+issuedAt, verified in constant time, within a
 * bounded lifetime. A forged-but-correctly-shaped context is cryptographically
 * rejected: the signature check does not depend on any comparison an
 * attacker without the signing secret can satisfy.
 *
 * Design properties:
 *   - Stateful counters survive the lifetime of the process (module singleton)
 *   - Violations are written to stderr BEFORE the throw — they appear in logs
 *     even if an outer catch swallows the error
 *   - Throws are synchronous and untyped (plain Error) so Promise chains cannot
 *     silently absorb them without handling
 *   - getStats() / resetStats() are exported for test introspection only;
 *     production callers have no need to call either
 *   - Every failure mode (missing field, wrong format, forged signature,
 *     expired signature, future timestamp) fails closed identically — there
 *     is no code path that logs a violation and still returns normally
 */

const { emit } = require('./logger');
const { verifyExecutionToken } = require('./executionInvariantToken');

const HASH_RE = /^[a-f0-9]{64}$/;

// ── Invariant state (module-level singleton) ──────────────────────────────────

let _totalAttempts  = 0;
let _verifiedCalls  = 0;
let _violationCount = 0;

// ── Internal helpers ──────────────────────────────────────────────────────────

function _collectViolations(ctx) {
  const v = [];
  if (ctx === null || typeof ctx !== 'object' || Array.isArray(ctx)) {
    v.push('CTX_NOT_OBJECT');
    return v;   // further field checks are meaningless
  }
  if (ctx.verified !== true)
    v.push('VERIFIED_NOT_TRUE');
  if (typeof ctx.requestHash !== 'string' || !HASH_RE.test(ctx.requestHash))
    v.push('REQUEST_HASH_INVALID');
  if (typeof ctx.policyHash !== 'string' || !HASH_RE.test(ctx.policyHash))
    v.push('POLICY_HASH_INVALID');
  if (typeof ctx.artifactId !== 'string' || !ctx.artifactId)
    v.push('ARTIFACT_ID_MISSING');
  if (typeof ctx.tenantId !== 'string' || !ctx.tenantId)
    v.push('TENANT_ID_MISSING');

  // cryptographic binding check — runs regardless of the structural
  // outcomes above (multiple violations may co-occur; each one is reported).
  // verifyExecutionToken() is fail-closed on every possible defect: missing/
  // malformed/corrupted/random signature, wrong signing secret, modified
  // requestHash/policyHash/issuedAt, expired token, and future-dated
  // issuedAt all return false — never throw — so this always resolves to a
  // single, specific violation code rather than an uncaught exception.
  if (!verifyExecutionToken(ctx))
    v.push('EXECUTION_TOKEN_INVALID');

  return v;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Assert the execution invariant before any provider call.
 *
 * On violation:
 *   1. Increments the violation counter (visible in getStats())
 *   2. Writes a CRITICAL log line to stderr synchronously
 *   3. Throws Error('UNVERIFIED_EXECUTION_ATTEMPT')
 *
 * On success:
 *   1. Increments verifiedCalls
 *   2. Returns void
 *
 * @param {unknown} ctx        - The verifiedCtx object passed to executeProviderCall.
 *   Expected shape: { verified: true, requestHash: <64-hex>, policyHash: <64-hex>,
 *   artifactId: <string>, tenantId: <string>, issuedAt: <number>, signature: <64-hex> }
 *   — issuedAt/signature are minted by services/executionInvariantToken.js's
 *   mintExecutionToken() and re-verified here; shape alone is never sufficient.
 * @param {string}  [callSite] - Optional label identifying the call site (for logs)
 */
function assertExecutionInvariant(ctx, callSite) {
  _totalAttempts++;

  const violations = _collectViolations(ctx);

  if (violations.length > 0) {
    _violationCount++;

    // Write the violation record to stderr BEFORE throwing so it is never lost
    // if the caller catches the error.
    emit('CRITICAL', 'EXECUTION_INVARIANT_VIOLATED', {
      callSite:   callSite || 'unknown',
      violations,
      stats: {
        totalAttempts:  _totalAttempts,
        verifiedCalls:  _verifiedCalls,
        violationCount: _violationCount,
      },
    });

    throw new Error('UNVERIFIED_EXECUTION_ATTEMPT');
  }

  _verifiedCalls++;
}

/**
 * Return a snapshot of invariant enforcement statistics.
 * totalAttempts = verifiedCalls + violationCount (identity invariant).
 *
 * @returns {{ totalAttempts: number, verifiedCalls: number, violationCount: number }}
 */
function getStats() {
  return {
    totalAttempts:  _totalAttempts,
    verifiedCalls:  _verifiedCalls,
    violationCount: _violationCount,
  };
}

/**
 * Reset counters.  Test use only — do not call in production code.
 */
function resetStats() {
  _totalAttempts  = 0;
  _verifiedCalls  = 0;
  _violationCount = 0;
}

module.exports = { assertExecutionInvariant, getStats, resetStats };
