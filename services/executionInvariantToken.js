'use strict';

/**
 * Execution invariant token —.
 *
 * Cryptographically binds the `verifiedCtx` object produced by the /ai/chat
 * enforcement pipeline (src/api/routes/aiChat.js) to the specific requestHash
 * and policyHash that pipeline run actually verified, so that
 * services/execution-guard.js's assertExecutionInvariant() no longer trusts
 * verifiedCtx on shape alone — it re-derives the expected HMAC and rejects
 * any context whose signature does not match, was signed with a different
 * key, has been tampered with, or has expired.
 *
 * Design:
 *   - HMAC-SHA256 over a domain-separated canonical message
 *     (ARTIFACT_DOMAINS.EXECUTION_INVARIANT | requestHash | policyHash | issuedAt)
 *   - Secret is a dedicated, purpose-isolated 256-bit key
 *     (QODIQA_EXECUTION_INVARIANT_SECRET, via services/secrets/secretsProvider.js)
 *     — never the KEK, never derived from any other secret or from
 *     request-controlled data.
 *   - issuedAt is always server-generated (the process-local monotonic clock
 * _monoNowMs() at mint time — not Date.now()). Callers
 *     never supply it and verification never trusts a client-controlled
 *     timestamp — the only clock consulted is this process's own, so there is
 *     no cross-host clock-skew surface to exploit.
 *   - Constant-time comparison (crypto.timingSafeEqual) — no early-exit
 *     string/Buffer equality anywhere in the verification path.
 *   - Bounded lifetime (QODIQA_EXECUTION_INVARIANT_TTL_MS, default 60s) — a
 *     captured, still-correctly-signed token cannot be replayed indefinitely.
 *
 * mintExecutionToken() is called exactly once per request, by
 * src/api/routes/aiChat.js._executeAI(), immediately after the enforcement
 * pipeline (validation + policy + semantic checks) has passed and
 * immediately before the provider dispatch that verifyExecutionToken() (via
 * assertExecutionInvariant()) gates.
 */

const crypto = require('crypto');
const { getExecutionInvariantSecret } = require('./secrets/secretsProvider');
const { ARTIFACT_DOMAINS } = require('../src/infra/crypto/hashing');

const HASH_RE      = /^[a-f0-9]{64}$/;
const SIGNATURE_RE = /^[a-f0-9]{64}$/; // HMAC-SHA256 digest, hex-encoded

// the token's clock. It is MONOTONIC within this process — an epoch-anchored high-resolution clock
// (performance.timeOrigin, fixed at process start, + performance.now(), which never goes backwards), floored to
// whole ms. Date.now() is NOT used: on Windows V8 re-syncs it to the system time every 60 s of uptime and can step it
// back 1 ms, which made a mint just before the re-sync and a verify just after it fail as "future-dated" (reproduced:
// 8 in 105.65M pairs). The token is minted and verified in the same
// process (it never leaves it), so a process-local monotonic clock is exact for both the zero-tolerance future check
// and the TTL; its value only approximates wall time and is never compared with it.
const { monoNowMs: _monoNowMs } = require('../src/infra/time/monotonicClock');

const DEFAULT_TTL_MS = 60_000; // 60s — comfortably exceeds normal mint→verify latency

function _resolveTtlMs() {
  const v = parseInt(process.env.QODIQA_EXECUTION_INVARIANT_TTL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_TTL_MS;
}

// Canonical, domain-separated message. Pipe-joined with a domain prefix —
// mirrors the same domain-separation discipline as domainSeparatedHash()
// (src/infra/crypto/hashing.js), applied here to a keyed HMAC rather than a
// plain hash so the message can never be confused with, or replayed against,
// any other artifact class's signature.
function _canonicalMessage(requestHash, policyHash, issuedAt) {
  return `${ARTIFACT_DOMAINS.EXECUTION_INVARIANT}|${requestHash}|${policyHash}|${issuedAt}`;
}

function _hmac(message) {
  const secret = getExecutionInvariantSecret();
  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest();
}

/**
 * Mint a fresh execution-invariant token for the given requestHash/policyHash.
 * Called once, by the enforcement pipeline, after every check has passed.
 *
 * @param {{ requestHash: string, policyHash: string }} fields
 * @returns {{ issuedAt: number, signature: string }}
 * @throws {TypeError} if requestHash/policyHash are not 64-char lowercase hex
 */
function mintExecutionToken({ requestHash, policyHash }) {
  if (typeof requestHash !== 'string' || !HASH_RE.test(requestHash)) {
    throw new TypeError('mintExecutionToken: requestHash must be a 64-character lowercase hex string');
  }
  if (typeof policyHash !== 'string' || !HASH_RE.test(policyHash)) {
    throw new TypeError('mintExecutionToken: policyHash must be a 64-character lowercase hex string');
  }

  const issuedAt   = _monoNowMs();
  const signature  = _hmac(_canonicalMessage(requestHash, policyHash, issuedAt)).toString('hex');

  return { issuedAt, signature };
}

/**
 * Verify an execution-invariant token. Fail-closed: any structural defect,
 * signature mismatch, or expiry returns false — never throws, so callers
 * (assertExecutionInvariant) can treat every failure mode identically.
 *
 * @param {{ requestHash: unknown, policyHash: unknown, issuedAt: unknown, signature: unknown }} ctx
 * @param {{ _now?: number, _ttlMs?: number }} [opts] — injectable for tests only
 * @returns {boolean}
 */
function verifyExecutionToken(ctx, opts = {}) {
  if (ctx === null || typeof ctx !== 'object') return false;

  const { requestHash, policyHash, issuedAt, signature } = ctx;

  if (typeof requestHash !== 'string' || !HASH_RE.test(requestHash)) return false;
  if (typeof policyHash  !== 'string' || !HASH_RE.test(policyHash))  return false;
  if (typeof signature   !== 'string' || !SIGNATURE_RE.test(signature)) return false;
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt) || issuedAt <= 0) return false;

  const now = typeof opts._now === 'number' ? opts._now : _monoNowMs();

  // No client/caller clock is ever consulted — issuedAt was minted by this
  // same process's monotonic clock (_monoNowMs). A future-dated issuedAt is therefore never
  // legitimate skew, it is tampering — reject unconditionally rather than
  // granting any allowance.
  if (issuedAt > now) return false;

  const ttlMs = typeof opts._ttlMs === 'number' ? opts._ttlMs : _resolveTtlMs();
  if (now - issuedAt > ttlMs) return false;

  let expected;
  try {
    expected = _hmac(_canonicalMessage(requestHash, policyHash, issuedAt));
  } catch {
    // Secret unavailable/misconfigured — fail closed, never fall back to an
    // unsigned or default-keyed comparison.
    return false;
  }

  const provided = Buffer.from(signature, 'hex');
  if (provided.length !== expected.length) return false;

  return crypto.timingSafeEqual(provided, expected);
}

module.exports = {
  mintExecutionToken,
  verifyExecutionToken,
  // Exported for targeted unit testing only.
  _resolveTtlMs,
  _monoNowMs,
  DEFAULT_TTL_MS,
};
