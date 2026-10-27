'use strict';

/**
 * QODIQA Idempotency Request Fingerprint (API-2).
 *
 * Binds an Idempotency-Key to the specific request it was issued for, so
 * the key alone can never be replayed against a different request. The
 * fingerprint is a deterministic, domain-separated SHA-256 hash over the
 * fields that determine WHAT gets executed:
 *
 *   tenantId        — authenticated tenant (resolved from the verified
 *                      artifact's publicKeyId — see validateBoundRequest.js).
 *   organizationId   — authenticated tenant's organization boundary.
 *   publicKeyId      — authenticated signing identity.
 * callerId — authenticated caller identity,
 *                       when present.
 *   provider         — the AI provider the artifact designates.
 *   requestHash      — QODIQA's existing request-binding hash
 *                       (src/validation/requestHash.js), itself a
 *                       deterministic SHA-256 over { method, path, body }.
 *                       Because /ai/chat's body schema is `.passthrough()`
 *                       (src/validation/schemas/aiChat.schema.js), this
 *                       transitively covers every execution-affecting field
 *                       in the request body — prompt, model, stream, and
 *                       any additional fields a client sends (messages,
 *                       system prompt, tool configuration, temperature,
 *                       top_p, ...) — without this module needing to
 *                       enumerate them by name, and it stays correct as
 *                       that body schema evolves.
 *
 * Deliberately EXCLUDED (per the finding's own requirement): timestamps,
 * request IDs, audit IDs, trace IDs, or any other per-attempt generated
 * metadata. artifact.timestamp/expiry/requestId change on every signed
 * retry by design (fresh nonce per attempt) and are never part of this
 * hash — only requestHash (body+method+path) and the authenticated-identity
 * fields above are. Two distinct signed artifacts for the *same logical
 * request* (a retry) therefore always produce the *same* fingerprint;
 * two artifacts for genuinely different requests virtually never collide.
 *
 * Consent context is intentionally not a separate input here: in this
 * pipeline, consent is *resolved* from tenantId during policy evaluation —
 * it is not a client-supplied input distinct from tenantId — so it is
 * already covered transitively.
 */

const stableStringify                      = require('../../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');

const IDEMPOTENCY_DOMAIN = ARTIFACT_DOMAINS.IDEMPOTENCY;

/**
 * @param {{
 *   tenantId?:        string|null,
 *   organizationId?:  string|null,
 *   publicKeyId:      string,
 *   callerId?:        string|null,
 *   provider?:        string|null,
 *   requestHash:      string,
 * }} input
 * @returns {string}  64-char lowercase hex SHA-256 digest
 * @throws {TypeError} if publicKeyId or requestHash is missing — both are
 *   always present by the time this is called (post-validateBoundRequest).
 */
function computeFingerprint({ tenantId, organizationId, publicKeyId, callerId, provider, requestHash }) {
  if (typeof publicKeyId !== 'string' || !publicKeyId) {
    throw new TypeError('computeFingerprint: publicKeyId is required');
  }
  if (typeof requestHash !== 'string' || !requestHash) {
    throw new TypeError('computeFingerprint: requestHash is required');
  }

  const canonical = stableStringify({
    callerId:       callerId       ?? null,
    organizationId: organizationId ?? null,
    provider:       provider       ?? null,
    publicKeyId,
    requestHash,
    tenantId:       tenantId       ?? null,
  });

  return domainSeparatedHash(IDEMPOTENCY_DOMAIN, canonical).toString('hex');
}

module.exports = { computeFingerprint, IDEMPOTENCY_DOMAIN };
