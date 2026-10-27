'use strict';

const { getPublicKey } = require('../../services/artifact/keyStore');

/**
 * Deterministically resolve a publicKeyId to its public key material.
 *
 * Behaviour:
 *   - Missing / non-string / empty publicKeyId  → KEY_NOT_FOUND (no fallback)
 *   - Revoked key                                → KEY_NOT_FOUND
 *   - Unknown key                                → KEY_NOT_FOUND
 *   - Any error from the key store              → KEY_NOT_FOUND (fail-closed)
 *
 * Never throws.  Any failure path returns `{ found: false }`.
 *
 * @param {unknown} publicKeyId
 * @returns {{ found: true,  pubDer: Buffer, status: string, clientId: string, timeline?: any } |
 *           { found: false, reason: 'KEY_NOT_FOUND', details: object }}
 *   clientId (CRYPTO-6) is the key store's own authoritative resolution —
 *   correct even for a legacy (colon-less) publicKeyId, unlike re-parsing
 *   publicKeyId as a string.
 */
function resolveKey(publicKeyId) {
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) {
    return { found: false, reason: 'KEY_NOT_FOUND', details: { publicKeyId, issue: 'must be a non-empty string' } };
  }

  try {
    const { pubDer, status, clientId, timeline } = getPublicKey(publicKeyId);
    return { found: true, pubDer, status, clientId, timeline };
  } catch (err) {
    return { found: false, reason: 'KEY_NOT_FOUND', details: { publicKeyId, error: err.message } };
  }
}

module.exports = { resolveKey };
