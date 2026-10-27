'use strict';

/**
 * Typed parser for the canonical "${tenantId}:key_v${version}" key ID format
 * (Register #106). Single authoritative decoder — every call site that needs
 * a tenantId or keyVersion out of a key ID goes through parseKeyId() instead
 * of hand-rolling `.split(':')`, so a malformed ID fails at the point of
 * first parse with an attributable, typed error rather than surfacing as an
 * unrelated failure several layers downstream.
 *
 * Legacy key IDs (bare client ID, no ":key_v${n}" suffix — see
 * LEGACY_KEY_ID_RE in keyStore.js) are not in this format and always fail to
 * parse here; callers that must tolerate legacy IDs decide how to handle
 * that themselves (see validateBoundRequest.js).
 */

const KEY_ID_PATTERN = /^([A-Za-z0-9_-]{1,64}):key_v(\d+)$/;

class InvalidKeyIdError extends Error {
  /**
   * @param {unknown} keyId
   * @param {'NOT_A_STRING'|'MALFORMED'|'VERSION_OVERFLOW'} reason
   */
  constructor(keyId, reason) {
    super(`Invalid key ID (${reason}): ${JSON.stringify(keyId)}`);
    this.name    = 'InvalidKeyIdError';
    this.code    = 'INVALID_KEY_ID';
    this.keyId   = keyId;
    this.reason  = reason;
  }
}

/**
 * Decode a "${tenantId}:key_v${version}" key ID.
 *
 * @param {unknown} keyId
 * @returns {Readonly<{ tenantId: string, keyVersion: number }>}
 * @throws {InvalidKeyIdError}
 */
function parseKeyId(keyId) {
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new InvalidKeyIdError(keyId, 'NOT_A_STRING');
  }

  const match = KEY_ID_PATTERN.exec(keyId);
  if (!match) {
    throw new InvalidKeyIdError(keyId, 'MALFORMED');
  }

  const tenantId   = match[1];
  const keyVersion = Number(match[2]);
  if (!Number.isSafeInteger(keyVersion)) {
    throw new InvalidKeyIdError(keyId, 'VERSION_OVERFLOW');
  }

  return Object.freeze({ tenantId, keyVersion });
}

module.exports = { parseKeyId, InvalidKeyIdError, KEY_ID_PATTERN };
