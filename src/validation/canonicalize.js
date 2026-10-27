'use strict';

const stableStringify = require('../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../infra/crypto/hashing');

// ── Full-envelope signing domain ──────────────────────────────────────────────
// All new artifacts MUST be signed/verified with this domain.
// Changing this string invalidates every existing V2 signature.
const ENVELOPE_DOMAIN = ARTIFACT_DOMAINS.ARTIFACT;

// The four fields that are included in the signed envelope, sorted lexicographically.
// This list is the authoritative definition of what is cryptographically bound.
const SIGNED_ENVELOPE_KEYS = Object.freeze(['expiry', 'payload', 'publicKeyId', 'timestamp']);

// ── Structural guards ─────────────────────────────────────────────────────────

/**
 * Return true iff value is a strict plain object.
 *
 * Accepts objects whose prototype is Object.prototype or null.
 * Rejects null, arrays, Date, RegExp, Map, Set, and all other exotic objects.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Return true iff value contains an `undefined` at any depth.
 *
 * Traverses own enumerable properties only (consistent with stableStringify).
 * Handles circular references safely.
 *
 * Motivation: stableStringify silently maps undefined → "null", creating a
 * canonical collision between {field: null} and {field: undefined}.  This
 * function enforces explicit rejection before canonicalization occurs.
 *
 * @param {unknown} value
 * @param {Set}     [seen]   Internal cycle guard — callers must not pass this.
 * @returns {boolean}
 */
function hasUndefined(value, seen = new Set()) {
  if (value === undefined) return true;
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (hasUndefined(value[i], seen)) return true;
    }
  } else {
    for (const k of Object.keys(value)) {
      if (hasUndefined(value[k], seen)) return true;
    }
  }
  return false;
}

// ── Canonical serialization — full envelope ───────────────────────────────────

/**
 * Produce the canonical JSON string for the four signed envelope fields.
 *
 * Exactly SIGNED_ENVELOPE_KEYS are included — no extras, no inheritance.
 * stableStringify sorts keys lexicographically, so the output is stable
 * regardless of the insertion order of the input object.
 *
 * @param {{ expiry: number, payload: object, publicKeyId: string, timestamp: number }} envelope
 * @returns {string}  Deterministic JSON string.
 */
function canonicalizeEnvelope({ expiry, payload, publicKeyId, timestamp }) {
  return stableStringify({ expiry, payload, publicKeyId, timestamp });
}

/**
 * Compute the 32-byte domain-separated hash over the full artifact envelope.
 *
 * SHA-256("QODIQA::ARTIFACT::V1" || stableStringify({expiry, payload, publicKeyId, timestamp}))
 *
 * Cryptographically binds all four envelope fields: changing any one of them
 * (payload, timestamp, expiry, or publicKeyId) produces a different hash and
 * therefore invalidates the signature.
 *
 * @param {{ expiry: number, payload: object, publicKeyId: string, timestamp: number }} envelope
 * @returns {Buffer}  32-byte raw hash buffer.
 */
function envelopeHash({ expiry, payload, publicKeyId, timestamp }) {
  const canonical = canonicalizeEnvelope({ expiry, payload, publicKeyId, timestamp });
  return domainSeparatedHash(ENVELOPE_DOMAIN, canonical);
}

module.exports = {
  ENVELOPE_DOMAIN,
  SIGNED_ENVELOPE_KEYS,
  isPlainObject,
  hasUndefined,
  canonicalizeEnvelope,
  envelopeHash,
};
