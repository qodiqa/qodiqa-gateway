'use strict';

/**
 * requireConsent evaluator — enforcement-pipeline integration for the
 * Runtime Consent Registry.
 *
 * Fail-closed at every layer:
 *   - artifact absent or invalid     → BLOCK CONSENT_MISSING
 *   - actor_id (userId) missing      → BLOCK CONSENT_CONTEXT_INCOMPLETE
 *   - action missing                 → BLOCK CONSENT_CONTEXT_INCOMPLETE
 *   - consent store unavailable      → BLOCK CONSENT_STORE_UNAVAILABLE
 *   - no consent record found        → BLOCK CONSENT_NOT_FOUND
 *   - record not in ACTIVE state     → BLOCK CONSENT_{STATE}
 *   - scope mismatch                 → BLOCK CONSENT_SCOPE_MISMATCH
 *   - any unexpected exception       → BLOCK CONSENT_EVALUATION_ERROR
 *
 * Context fields consumed (all set by checkPolicy (src/validation/checkPolicy.js)):
 * context.callerId — authenticated caller identity bound into the
 *                        artifact at /sign time; the actor_id used for consent
 *                        lookups whenever present. A consent grant issued to one
 *                        caller never authorizes a different caller sharing the
 *                        same tenant signing key — see evaluate() below.
 *   context.userId    — publicKeyId of the verified artifact signer (key
 *                        attribution only). Used as actor_id ONLY when
 *                        callerId is absent — an artifact signed before the
 * remediation shipped (self-expires within
 *                        the existing max TTL).
 *   context.action    — artifact.payload.provider (the capability being requested)
 *   context.tenantId  — extracted from publicKeyId format "tenantId:key_vN"
 *   context.requestId — artifact requestId (nonce-registered UUID, for audit correlation)
 *
 * config shape (from policy definition):
 *   {
 *     requireValidArtifact: true,        // MUST be true — validated at load time
 *     requiredScope:        string|null  // optional scope enforcement override
 *   }
 *
 * The evaluator is async (returns a Promise). The policy engine wraps all
 * evaluator calls in await Promise.resolve(...) for backward compatibility
 * with synchronous evaluators.
 */

const { logError } = require('../log');
const _ST = require('../../../src/observability/stageTimer'); // bench stage timer (no-op when off)

// Lazy require — avoids opening DB/cache connections at module load time
// and avoids circular dependencies.
function _registry() {
  return require('../../../src/core/consent');
}

function validate(config) {
  if (config.requireValidArtifact !== true) {
    throw new Error('config.requireValidArtifact must be true — false is not a permitted value');
  }
}

function preprocess(config) {
  return config;
}

/**
 * @param {object} context       — validated, frozen execution context
 * @param {object} config        — policy.config (already validated/preprocessed)
 * @param {object} _stateSnapshot— rate-limit state snapshot (not used here)
 * @returns {Promise<{ pass: boolean, reason: string, provenance?: { consent: object|null } }>}
 *   provenance.consent (TRACE-2) — immutable consent record snapshot from
 *   ConsentVerifier, hoisted by the policy engine into the decision's
 *   top-level consentProvenance field for the audit/evidence chains. null
 *   whenever no consent record was found to attach provenance to.
 */
async function evaluate(context, config, _stateSnapshot) {
  // Artifact must be present and cryptographically valid — this is verified upstream
  // by verifyArtifactMiddleware before the policy engine is reached.
  if (!context.artifact || context.artifact.valid !== true) {
    return { pass: false, reason: 'CONSENT_MISSING' };
  }

  // actor_id: prefers context.callerId — the authenticated caller
  // identity bound into the artifact at /sign time (checkPolicy.js reads it
  // out of the signature-verified artifact.payload.callerContext). This is
  // what prevents caller substitution: a consent grant is looked up against
  // the specific caller, not the tenant's shared signing key, so a different
  // caller holding the same key gets CONSENT_NOT_FOUND rather than silently
  // riding on someone else's grant.
  //
  // Falls back to context.userId (publicKeyId — key attribution only) ONLY
  // when callerId is entirely absent, which is structurally only possible
  // for an artifact signed before this remediation shipped — every artifact
  // /sign produces now carries callerContext, and old artifacts self-expire
  // within the existing max TTL. This fallback preserves exactly today's
  // (pre-remediation) consent behavior for those in-flight artifacts; it
  // never grants anything a legacy artifact couldn't already reach.
  const actor_id       = context.callerId || context.userId || null;
  const action         = context.action    ?? null;
  const tenant_id      = context.tenantId  ?? null;
  const request_id     = context.requestId ?? null;
  const required_scope = config.requiredScope ?? null;

  if (!actor_id || !action) {
    return { pass: false, reason: 'CONSENT_CONTEXT_INCOMPLETE' };
  }

  let result;
  try {
    const _tC = _ST.ON ? _ST.start() : 0;
    try {
      result = await _registry().verify({ actor_id, action, tenant_id, required_scope, request_id });
    } finally {
      if (_ST.ON) _ST.end('S24a', _tC); // consent, nested inside S24 policy_engine
    }
  } catch (err) {
    logError('CONSENT_EVALUATION_ERROR', { requestId: request_id, error: err.message });
    return { pass: false, reason: 'CONSENT_EVALUATION_ERROR' };
  }

  const provenance = { consent: result.consentProvenance ?? null };

  if (!result.pass) {
    return { pass: false, reason: result.reason, provenance };
  }

  return { pass: true, reason: 'CONSENT_VERIFIED', provenance };
}

module.exports = { validate, preprocess, evaluate };
