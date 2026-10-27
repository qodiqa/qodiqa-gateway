'use strict';

/**
 * Pure policy evaluation core (Register #167).
 *
 * Takes only explicit inputs — no Express req/res, no mock construction.
 * src/validation/checkPolicy.js (the /ai/chat + /verify/v2 shared helper,
 * called by src/api/routes/aiChat.js and verify.js) calls this directly and
 * shapes its result into its own external response format; no synthetic
 * request/response object is built. (middleware/enforcePolicy.js, the former
 * second caller, was removed in 4bae6188.)
 *
 * Owns: invoking the policy engine, computing/logging the enforced policy
 * hash, and the DENY/error-path audit logging (blocked()/logError()/the
 * ANOMALY_POLICY_DENIAL emit) — all of that is evaluation-outcome behavior,
 * not an HTTP concern. Genuinely HTTP-specific work (reading the
 * x-qodiqa-timestamp header, translating the result into a 403 response or
 * next()) stays in the callers (checkPolicy.js and the routes).
 */

const { evaluate }                   = require('./engine');
const { blocked, emit }              = require('../logger');
const { computePolicyHash }          = require('../policyHash');
const { logHashBound, logError }     = require('./log');

// Strip the ::ffff: prefix from IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 → 127.0.0.1)
// so IPv4 policy rules apply correctly to dual-stack sockets. A pure string
// transform — not Express-specific — so it lives with the evaluation core
// rather than the HTTP adapter.
function _normalizeIp(raw) {
  if (!raw) return '0.0.0.0';
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(raw);
  return mapped ? mapped[1] : raw;
}

function _errorResult(reason) {
  return Object.freeze({
    decision: 'ENFORCEMENT_ERROR',
    reason,
    policyId: null,
    policyHash: null,
    policyVersion: null,
    policyRuleHash: null,
    engineVersion: null,
    evaluatedAt: null,
    evaluationPath: [],
    consentProvenance: null,
  });
}

/**
 * @param {object} params
 * @param {function(): ReadonlyArray} params.getPolicies  returns the current policy array
 * @param {object}  params.policyStore  { getCount, increment } — pass a dry-run wrapper for /verify
 * @param {string}  params.requestId
 * @param {string|null} [params.artifactId]  for audit logging (blocked()/logError()) — defaults to requestId
 * @param {boolean} params.artifactValid
 * @param {string|null} params.userId        key-attribution identity (publicKeyId)
 * @param {string|null} params.callerId authenticated caller identity
 * @param {string|null} params.action
 * @param {string|null} params.tenantId
 * @param {string|null} params.ip            raw client IP — normalized internally
 * @param {number}  params.timestamp         unix seconds
 * @param {string}  [params.keyId]           for the ANOMALY_POLICY_DENIAL log source — defaults to 'unknown'
 * @param {object|null} [params.attributes] request attributes for ABAC rules
 * @returns {Promise<{
 *   decision: string, reason: string|null, policyId: string|null, policyHash: string|null,
 *   policyVersion: number|null, engineVersion: string|null, evaluatedAt: string|null,
 *   evaluationPath: object[], consentProvenance: object|null, policyRuleHash?: string|null,
 * }>}
 *   decision === 'EXECUTE' on ALLOW. decision === 'ENFORCEMENT_ERROR' on a
 *   getPolicies()/evaluate() failure (policyHash/policyId etc all null — the
 *   caller never reaches a real policy decision). Any other value is the
 *   policy engine's own BLOCK/DENY reason.
 */
async function evaluatePolicyDecision({
  getPolicies, policyStore, requestId, artifactId = null,
  artifactValid, userId, callerId, action, tenantId, ip, timestamp,
  keyId = 'unknown', attributes = null,
}) {
  const resolvedArtifactId = artifactId ?? requestId ?? null;

  const context = Object.freeze({
    artifact:  { valid: artifactValid === true },
    userId:    userId || null,
    callerId:  callerId || null,
    action:    action || null,
    tenantId:  tenantId || null,
    requestId: requestId || null,
    ip:        _normalizeIp(ip ?? '0.0.0.0'),
    timestamp,
    ...(attributes ? { attributes } : {}),            // supplied attributes for ABAC rules (validated by the context validator)
  });

  let policies;
  try {
    policies = getPolicies();
  } catch (err) {
    logError('POLICY_LOAD_ERROR', { requestId, error: err.message });
    /** @type {any} */ (blocked)(requestId, resolvedArtifactId, 'POLICY_LOAD_ERROR', null);
    return _errorResult('POLICY_LOAD_ERROR');
  }

  let decision;
  try {
    decision = await evaluate(context, policies, policyStore, { requestId });
  } catch (err) {
    logError('POLICY_ENGINE_ERROR', { requestId, error: err.message });
    /** @type {any} */ (blocked)(requestId, resolvedArtifactId, 'POLICY_ENGINE_ERROR', null);
    return _errorResult('POLICY_ENGINE_ERROR');
  }

  if (decision.decision !== 'EXECUTE') {
    emit('WARN', 'ANOMALY_POLICY_DENIAL', { source: keyId, reason: 'POLICY_BLOCKED' });
    /** @type {any} */ (blocked)(requestId, resolvedArtifactId, decision.reason, null);
    return Object.freeze({
      decision:          decision.decision,
      reason:            decision.reason,
      policyId:          decision.policyId,
      policyHash:        null,
      policyVersion:     decision.policyVersion     ?? null,
      policyRuleHash:    decision.policyRuleHash     ?? null,
      engineVersion:     decision.engineVersion      ?? null,
      evaluatedAt:       decision.evaluatedAt         ?? null,
      evaluationPath:    decision.evaluationPath     ?? [],
      consentProvenance: decision.consentProvenance   ?? null,
    });
  }

  // Compute and log the hash of the CURRENT live policy set that permitted
  // this request. This is the hash of what was enforced RIGHT NOW — it is
  // NOT compared to artifact.payload.policyHash (which records what was
  // active at signing time). policyHash is informational: the runtime
  // always uses the current live policy set regardless of what the artifact
  // claims. If the two hashes differ, it means policies changed between
  // signing and execution; that is auditable but does not block execution.
  const policyHash = computePolicyHash(policies);
  logHashBound(policyHash, { requestId });

  return Object.freeze({
    decision:          decision.decision,
    reason:            decision.reason,
    policyId:          decision.policyId,
    policyHash,
    policyVersion:     decision.policyVersion     ?? null,
    policyRuleHash:    decision.policyRuleHash     ?? null,
    engineVersion:     decision.engineVersion      ?? null,
    evaluatedAt:       decision.evaluatedAt         ?? null,
    evaluationPath:    decision.evaluationPath     ?? [],
    consentProvenance: decision.consentProvenance   ?? null,
  });
}

module.exports = { evaluatePolicyDecision };
