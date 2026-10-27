'use strict';

/**
 * QODIQA Request Binding Verifier
 *
 * Verifies that a validated artifact is bound to the exact HTTP request being
 * executed and carries a well-formed unique execution identity.
 *
 * MUST be called AFTER validateArtifact() returns { decision: 'ALLOW' }.
 *
 * Verification order:
 *   1. artifact and artifact.payload must be plain objects
 *   2. artifact.payload.requestId must be a valid UUID v4 (present + format)
 *   3. artifact.payload.requestHash must be a 64-char lowercase hex string
 *   4. request must be a plain object with { method, path, body }
 *   5. Recompute requestHash over actual request
 *   6. Timing-safe compare stored requestHash vs recomputed requestHash
 *
 * Any failure → { bound: false, reason: 'REQUEST_MISMATCH' } — no fallback.
 *
 * Note on requestId uniqueness:
 *   This verifier confirms requestId is present and well-formed.  Replay
 *   detection (asserting each requestId is used at most once) requires a
 *   persistent seen-nonce store and is enforced by the replay-guard layer,
 *   which must be invoked separately after this function returns bound: true.
 */

const crypto                  = require('crypto');
const { computeRequestHash }  = require('./requestHash');
const { isValidRequestId }    = require('./requestId');
const { isPlainObject }       = require('./canonicalize');

const HEX_RE     = /^[0-9a-f]{64}$/;
const HASH_BYTES = 32;

/**
 * Verify request binding and requestId integrity for a validated artifact.
 *
 * @param {object} artifact  A validated QODIQA artifact (validateArtifact → ALLOW).
 * @param {{ method: string, path: string, body: object }} request
 *   The actual HTTP request being executed.
 *
 * @returns {{ bound: true,  requestId: string } |
 *           { bound: false, reason: 'REQUEST_MISMATCH', details: object }}
 */
function verifyRequestBinding(artifact, request) {
  // ── 1. Structural guard ───────────────────────────────────────────────────────
  if (!isPlainObject(artifact) || !isPlainObject(artifact.payload)) {
    return block('artifact or payload is not a plain object');
  }

  // ── 2. requestId: present and valid UUID v4 ───────────────────────────────────
  // Checked before requestHash so callers get a specific diagnostic on the
  // field that represents execution identity — the more critical of the two.
  const storedId = artifact.payload.requestId;
  if (!isValidRequestId(storedId)) {
    return block('missing or malformed requestId in artifact payload — must be a UUID v4');
  }

  // ── 3. requestHash: present and 64-char lowercase hex ────────────────────────
  const storedHash = artifact.payload.requestHash;
  if (typeof storedHash !== 'string' || !HEX_RE.test(storedHash)) {
    return block('missing or malformed requestHash in artifact payload');
  }

  // ── 4. Request must be a plain object ────────────────────────────────────────
  if (!isPlainObject(request)) {
    return block('request must be a plain object');
  }

  const { method, path: reqPath, body } = request;

  // ── 5. Recompute requestHash — fail-closed on any error ──────────────────────
  let recomputedHash;
  try {
    recomputedHash = computeRequestHash(method, reqPath, body);
  } catch (err) {
    // `issue` reaches the client in the REQUEST_MISMATCH BLOCK body — a stable
    // text goes out (as validateArtifact.js's 'envelope canonicalization failed' already does); the canonicalizer's
    // own message stays in the server log.
    try {
      require('../../services/logger').emit('WARN', 'REQUEST_CANONICALIZATION_FAILED', { error: err?.message ?? String(err) });
    } catch { /* logging must never change the fail-closed result */ }
    return block('request canonicalization failed');
  }

  // ── 6. Timing-safe comparison of requestHash ──────────────────────────────────
  const storedBuf     = Buffer.from(storedHash,     'hex');
  const recomputedBuf = Buffer.from(recomputedHash, 'hex');

  if (storedBuf.length !== HASH_BYTES || recomputedBuf.length !== HASH_BYTES) {
    return block('hash buffer length mismatch — possible encoding corruption');
  }

  if (!crypto.timingSafeEqual(storedBuf, recomputedBuf)) {
    return block('requestHash does not match actual request');
  }

  // Return requestId so the replay-guard layer can record it without having
  // to re-read artifact.payload — single extraction point.
  return Object.freeze({ bound: true, requestId: storedId });
}

function block(issue) {
  return Object.freeze({
    bound:   false,
    reason:  'REQUEST_MISMATCH',
    details: Object.freeze({ issue }),
  });
}

module.exports = { verifyRequestBinding };
