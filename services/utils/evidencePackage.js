'use strict';

/**
 * Canonical evidence package utilities — SINGLE SOURCE OF TRUTH for CF-02.
 *
 * All evidence package generation, hashing, and verification across the
 * platform (generator.js, portal.js, attestor.js) MUST call these three
 * functions.  Duplicating the serialisation or hash logic elsewhere is
 * forbidden.
 *
 * canonicalSerialize  — deterministic JSON, key-sorted at every depth
 * canonicalHash       — SHA-256 of canonicalSerialize output
 * canonicalVerify     — strip non-content fields, recompute hash, compare
 */

const { createHash } = require('crypto');
const stableStringify = require('./stableStringify');

/**
 * Deterministic serialisation of any value.
 * Object keys are sorted lexicographically at every nesting level.
 * Delegates to stableStringify — see stableStringify.js for edge-case spec.
 *
 * @param {*} obj
 * @returns {string}
 */
function canonicalSerialize(obj) {
  return stableStringify(obj);
}

/**
 * SHA-256 hex digest of the canonical serialisation of obj.
 * Identical for any two objects that are deeply equal regardless of key
 * insertion order.
 *
 * @param {*} obj
 * @returns {string}  64-character lowercase hex
 */
function canonicalHash(obj) {
  return createHash('sha256').update(stableStringify(obj), 'utf8').digest('hex');
}

/**
 * Verify the integrity of an evidence package by recomputing its hash.
 *
 * Non-content fields (packageId, generatedAt, packageHash) are excluded from
 * the hash computation because they are not part of the evidential content:
 *   - packageId    is a derived identifier, not content
 *   - generatedAt  is a post-seal timestamp
 *   - packageHash  is the hash itself (cannot include itself)
 *
 * Works for any package type that follows this convention:
 *   QODIQA::PORTAL_EVIDENCE::V1  (portal.js, attestor.js)
 *
 * @param {object} pkg  — complete evidence package with packageHash field
 * @returns {{ match: boolean, computedHash: string|null, providedHash: string|null, algorithm: string }}
 */
function canonicalVerify(pkg) {
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    return {
      match:        false,
      computedHash: null,
      providedHash: null,
      algorithm:    'SHA-256/stableStringify',
    };
  }

  const { packageId: _pid, generatedAt: _gat, packageHash, ...content } = pkg;
  const computedHash = canonicalHash(content);
  const match = computedHash === (packageHash ?? '');

  return {
    match,
    computedHash,
    providedHash: packageHash ?? null,
    algorithm:    'SHA-256/stableStringify',
  };
}

module.exports = { canonicalSerialize, canonicalHash, canonicalVerify };
