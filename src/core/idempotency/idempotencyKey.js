'use strict';

/**
 * QODIQA Idempotency-Key — header validation (API-2).
 *
 * Validates the client-supplied `Idempotency-Key` header before it is ever
 * used to address the idempotency store. Two independent limits are
 * enforced, deliberately kept separate:
 *
 *   1. IDEMPOTENCY_HEADER_MAX_BYTES — a cheap, first-line guard against an
 *      oversized header value (checked by byte length, before any charset
 *      scan). Node's HTTP server already caps total header size, but this
 *      is an explicit, documented, application-level limit independent of
 *      that transport-level default.
 *   2. IDEMPOTENCY_KEY_MAX_LENGTH — the documented maximum length of the
 *      actual key value once accepted as a candidate key.
 *
 * Accepted characters: printable, non-whitespace ASCII (0x21–0x7E) —
 * excludes spaces and all control characters, so a key can never be used to
 * inject header/log content or carry ambiguous whitespace. This mirrors the
 * "opaque token" convention used by comparable idempotency-key
 * implementations elsewhere in the industry (e.g. UUIDs, ULIDs, hex/base64
 * digests all satisfy this charset).
 *
 * The header NAME is already case-insensitive by construction — Node's HTTP
 * parser lower-cases every incoming header name, so `req.headers['idempotency-key']`
 * matches regardless of how the client cased it on the wire. Only the VALUE
 * is subject to validation here, and the accepted value is returned
 * unmodified (never trimmed/re-cased) — the original value is what gets
 * echoed back and used to address the store.
 */

const IDEMPOTENCY_KEY_MAX_LENGTH = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_KEY_MAX_LENGTH, 10);
  return Number.isFinite(v) && v > 0 ? v : 255;
})();

const IDEMPOTENCY_HEADER_MAX_BYTES = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_HEADER_MAX_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 1024;
})();

// Printable ASCII, no whitespace/control characters — see module header.
const KEY_CHARSET_RE = /^[\x21-\x7E]+$/;

/**
 * @param {unknown} rawValue  the raw `req.headers['idempotency-key']` value
 * @returns {{ valid: true, key: string } | { valid: false, reason: string }}
 */
function validateIdempotencyKey(rawValue) {
  // Express/Node give an array only for a repeated header; treat that as
  // malformed rather than silently picking one value — ambiguous intent.
  if (Array.isArray(rawValue)) {
    return { valid: false, reason: 'IDEMPOTENCY_KEY_INVALID' };
  }
  if (typeof rawValue !== 'string' || rawValue.length === 0) {
    return { valid: false, reason: 'IDEMPOTENCY_KEY_INVALID' };
  }
  if (Buffer.byteLength(rawValue, 'utf8') > IDEMPOTENCY_HEADER_MAX_BYTES) {
    return { valid: false, reason: 'IDEMPOTENCY_KEY_TOO_LARGE' };
  }
  if (rawValue.length > IDEMPOTENCY_KEY_MAX_LENGTH) {
    return { valid: false, reason: 'IDEMPOTENCY_KEY_TOO_LARGE' };
  }
  if (!KEY_CHARSET_RE.test(rawValue)) {
    return { valid: false, reason: 'IDEMPOTENCY_KEY_INVALID' };
  }
  return { valid: true, key: rawValue };
}

module.exports = {
  validateIdempotencyKey,
  IDEMPOTENCY_KEY_MAX_LENGTH,
  IDEMPOTENCY_HEADER_MAX_BYTES,
};
