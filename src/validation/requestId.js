'use strict';

/**
 * QODIQA Request Identity — cryptographically random per-execution nonce.
 *
 * Every artifact must carry a requestId that is:
 *   - cryptographically random (128 bits via crypto.randomUUID)
 *   - unique per signing invocation (never reused by construction)
 *   - part of the signed payload envelope (covered by Ed25519 signature)
 *   - validated at verification time for format before any further checks
 *
 * Format: UUID v4 — canonical lowercase with hyphens.
 *   xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 *   where x is a hex digit and y is one of [89ab].
 *
 * UUID v4 is chosen because:
 *   - 122 bits of cryptographic entropy from crypto.randomUUID()
 *   - universally recognised format with unambiguous validation regex
 *   - zero collision risk at any realistic request volume
 */

const { randomUUID } = require('crypto');

// UUID v4 canonical form — lowercase, hyphenated.
// Version nibble must be 4; variant nibble must be 8, 9, a, or b.
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Generate a cryptographically random UUID v4 requestId.
 *
 * @returns {string}  Lowercase UUID v4 string.
 */
function generateRequestId() {
  return randomUUID(); // Node ≥14.17 — always lowercase UUID v4
}

/**
 * Return true iff id is a valid UUID v4 in canonical lowercase form.
 *
 * Rejects:
 *   - non-strings
 *   - empty strings
 *   - wrong length
 *   - wrong version nibble (not 4)
 *   - wrong variant nibble (not 8/9/a/b)
 *   - uppercase hex — canonical form is lowercase only
 *
 * @param {unknown} id
 * @returns {boolean}
 */
function isValidRequestId(id) {
  return typeof id === 'string' && UUID_V4_RE.test(id);
}

module.exports = { generateRequestId, isValidRequestId, UUID_V4_RE };
