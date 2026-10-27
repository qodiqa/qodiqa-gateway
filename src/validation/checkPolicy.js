'use strict';

/**
 * Single shared policy enforcement helper.
 *
 * Used by BOTH the runtime (/ai/chat) and the verification endpoint (/verify/v2).
 * Calling the same function from both paths guarantees identical policy decisions
 * for identical inputs — no separate implementations, no drift.
 *
 * Register #167: calls the pure services/policy/evaluatePolicyDecision() core
 * directly with its own already-explicit parameters — no synthetic Express
 * req/res is constructed. This is a thin adapter over the same pure core
 * the real /ai/chat and /verify route path uses, just shaping the result
 * into checkPolicy's own external { allowed, ... } contract instead of a
 * 403 response.
 *
 * @param {function(): ReadonlyArray} getPolicies  returns the current policy array
 * @param {object}  policyStore    { getCount, increment } — pass a dry-run wrapper for /verify
 * @param {string}  requestId      from validateBoundRequest result
 * @param {object}  artifact       the validated artifact envelope
 * @param {boolean} artifactValid must be the caller's own genuine
 *   `validateBoundRequest(...).allowed === true` result — never default this
 *   to true. checkPolicy has no way to independently re-verify the artifact's
 *   signature/binding/nonce/anomaly checks itself; this parameter exists
 *   specifically so a caller cannot get an implicit ALLOW-eligible evaluation
 *   for free by skipping validateBoundRequest. Both current call sites
 *   (aiChat.js, verify.js) only ever call checkPolicy() after their own
 *   validateBoundRequest() already returned allowed:true.
 * @param {string}  publicKeyId    from validateBoundRequest result — key attribution (legacy actor identity)
 * @param {string|null} clientIp   sanitised client IP (req.clientIp)
 * @param {string|null} [tenantId] from validateBoundRequest result — for consent tenant scope
 * @param {object|null} [attributes] supplied attributes for ABAC rules (services/policy/abac/requestAttributes.js); the same for /ai/chat and /verify/v2
 * @returns {Promise<
 *   { allowed: true, policyHash: string|null, policyId: string|null, policyVersion: number|null,
 *     engineVersion: string|null, evaluatedAt: string|null, evaluationPath: object[],
 *     consentProvenance: object|null } |
 *   { allowed: false, reason: string, details: object, code: number }
 * >}
 *   (TRACE-2) On ALLOW, policyId/policyVersion/engineVersion/evaluatedAt/evaluationPath/
 *   consentProvenance are read off the pure core's result — see
 *   services/policy/evaluatePolicyDecision.js. On BLOCK the same fields are
 *   available under `details`, in the same shape the former enforcePolicy 403 body
 *   would have carried them.
 */

const { evaluatePolicyDecision } = require('../../services/policy/evaluatePolicyDecision');

async function checkPolicy(getPolicies, policyStore, requestId, artifact, artifactValid, publicKeyId, clientIp, tenantId = null, attributes = null) {
  if (typeof artifactValid !== 'boolean') {
    throw new TypeError(
      'checkPolicy: artifactValid must be explicitly passed as a boolean (true only after the ' +
      'caller\'s own validateBoundRequest(...).allowed === true) — there is no implicit default. ' +
      'This closes a latent bypass: without this, an artifact that was never actually validated ' +
      'could reach REQUIRE_CONSENT/requireValidArtifact policy evaluation as if it had been.',
    );
  }

  // the authenticated caller identity bound into the artifact at
  // /sign time (src/api/routes/sign.js's callerContext) — present because the
  // signature verification upstream of this call already proved payload
  // wasn't modified since signing. null only for a pre-remediation artifact
  // (see requireConsent.js for the legacy fallback this enables).
  const callerContext = (artifact?.payload?.callerContext && typeof artifact.payload.callerContext === 'object')
    ? artifact.payload.callerContext
    : null;
  const callerId = (typeof callerContext?.callerId === 'string' && callerContext.callerId) ? callerContext.callerId : null;

  const result = await evaluatePolicyDecision({
    getPolicies,
    policyStore,
    requestId,
    artifactId:    requestId,
    artifactValid,
    userId:        publicKeyId ?? null,
    // publicKeyId is the cryptographically-verified signer identity — proves
    // KEY attribution. callerId proves CALLER attribution — the
    // canonical actor_id for consent registry lookups going forward; see
    // requireConsent.js for how the two are reconciled.
    callerId,
    action:    artifact?.payload?.provider ?? null,
    tenantId:  tenantId ?? null,
    ip:        clientIp ?? null,
    // checkPolicy has no HTTP request to read an x-qodiqa-timestamp override
    // from — always the current time, matching the policy-evaluation default.
    timestamp: Math.floor(Date.now() / 1000),
    keyId:     publicKeyId ?? 'unknown',
    attributes,                         // request attributes for ABAC rules (null = none)
  });

  if (result.decision === 'EXECUTE') {
    return {
      allowed:    true,
      policyHash: result.policyHash,
      // TRACE-2: rule-level + consent provenance, threaded from
      // evaluatePolicyDecision through to callers (aiChat.js, verify.js) so
      // the mandatory audit write can carry it.
      policyId:          result.policyId,
      policyVersion:     result.policyVersion,
      policyRuleHash:    result.policyRuleHash,
      engineVersion:     result.engineVersion,
      evaluatedAt:       result.evaluatedAt,
      evaluationPath:    result.evaluationPath,
      consentProvenance: result.consentProvenance,
    };
  }

  if (result.decision === 'ENFORCEMENT_ERROR') {
    // Matches the bare { error: 'ENFORCEMENT_BLOCKED' } body the former enforcePolicy's
    // HTTP path sends for a getPolicies()/evaluate() failure — no reason/
    // policyId/etc are available for this class of failure.
    return {
      allowed: false,
      reason:  'POLICY_BLOCKED',
      details: { error: 'ENFORCEMENT_BLOCKED' },
      code:    403,
    };
  }

  return {
    allowed: false,
    reason:  result.reason || 'POLICY_BLOCKED',
    details: {
      error:    'ENFORCEMENT_BLOCKED',
      reason:   result.reason,
      policyId: result.policyId,
      policyVersion:     result.policyVersion,
      policyRuleHash:    result.policyRuleHash,
      engineVersion:     result.engineVersion,
      evaluatedAt:       result.evaluatedAt,
      evaluationPath:    result.evaluationPath,
      consentProvenance: result.consentProvenance,
    },
    code: 403,
  };
}

module.exports = { checkPolicy };
