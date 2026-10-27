'use strict';

/**
 * QODIQA Request Binding — V1
 *
 * Computes a deterministic, domain-separated SHA-256 hash that uniquely
 * identifies an HTTP request triple (method, path, body).  The hash is
 * embedded in the artifact payload before signing so that the Ed25519
 * signature cryptographically covers the request context.
 *
 * Hash formula:
 *   SHA-256("QODIQA::REQUEST::V1" || stableStringify({ body, method, path }))
 *
 * Canonicalization rules:
 *   method — uppercased; "post" and "POST" produce the same hash
 *   path   — exact bytes; NO normalization, NO query-string stripping,
 *             NO trailing-slash removal, NO percent-decoding — INSIDE this
 * function. the CALLER decides
 *             which bytes are "the path". The /ai/chat route binds
 *             `req.originalUrl.split('?')[0]` (src/api/routes/aiChat.js), i.e.
 *             the query string is stripped BEFORE this function is called, so
 *             the query string of an /ai/chat request is NOT covered by the
 *             binding (the route has no query-string semantics); the SDKs sign
 *             the bare path '/ai/chat'. Any other caller passing a path with a
 *             query string gets it bound byte-for-byte, as stated above.
 *   body   — stableStringify: sorted keys, no whitespace, arrays preserved,
 *             undefined values rejected before serialization
 */

const stableStringify        = require('../utils/stableStringify');
const { domainSeparatedHash,
        ARTIFACT_DOMAINS }   = require('../infra/crypto/hashing');
const { isPlainObject,
        hasUndefined }       = require('./canonicalize');

const REQUEST_DOMAIN = ARTIFACT_DOMAINS.REQUEST; // 'QODIQA::REQUEST::V1'

/**
 * Compute the request binding hash.
 *
 * @param {string} method  HTTP method (any case; uppercased before hashing)
 * @param {string} path    Exact request path (non-empty; bound byte-for-byte)
 * @param {object} body    Plain object, no undefined values; {} for empty body
 * @returns {string}       64-char lowercase hex SHA-256 digest
 * @throws {TypeError}     On any invalid input — fail-closed, never falls back
 */
function computeRequestHash(method, path, body) {
  if (typeof method !== 'string' || !method.trim()) {
    throw new TypeError('computeRequestHash: method must be a non-empty string');
  }
  if (typeof path !== 'string' || !path) {
    throw new TypeError('computeRequestHash: path must be a non-empty string');
  }
  if (!isPlainObject(body)) {
    throw new TypeError('computeRequestHash: body must be a plain object (Object.prototype or null prototype)');
  }
  if (hasUndefined(body)) {
    throw new TypeError('computeRequestHash: body must not contain undefined values — use null for absent fields');
  }

  // Canonical structure — stableStringify sorts keys, so { body, method, path }
  // and { method, path, body } produce identical output.
  const canonical = stableStringify({
    body,
    method: method.toUpperCase(),
    path,
  });

  return domainSeparatedHash(REQUEST_DOMAIN, canonical).toString('hex');
}

module.exports = { computeRequestHash, REQUEST_DOMAIN };
