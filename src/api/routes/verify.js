'use strict';

const { Router }               = require('express');
const { validateBoundRequest } = require('../../validation/validateBoundRequest');
const { normalizeReason }      = require('../../validation/reasonAliases');
const { makeDryRunNonceStore,
        makeDryRunAnomalyStore,
        makeDryRunPolicyStore } = require('../../validation/dryRunStores');
const { checkPolicy }          = require('../../validation/checkPolicy');
const { DEFAULT_THRESHOLDS }   = require('../../validation/checkAnomaly');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { policyHashesEqual }    = require('../../../services/policyHash');
const { emit }                 = require('../../../services/logger');
// same tenant-effective config /ai/chat consults ('s tenant
// policy sets +'s floor, both baked into getEffectivePoliciesForTenant)
// — never the raw global getter alone, mirroring aiChat.js's own
// _authenticateAndPolicy() exactly.
const { getEffectivePoliciesForTenant } = require('../../core/tenancy/tenantPolicyRegistry');
// the same REQUEST-side semantic pipeline /ai/chat runs (same
// classifier engine, same tenant semantic overlay via tenantId) — see
// requestSemanticCheck.js's header for why this is side-effect-free by
// construction and shared, not a copy.
const { evaluateRequestSemantic } = require('../../core/semantic/requestSemanticCheck');   //
const enforceContentType       = require('../../../middleware/enforceContentType');
const { verifyBodySchema,
        verifyArtifactPresentSchema } = require('../../validation/schemas/verify.schema');
const { firstQodiqaReason }    = require('../../validation/helpers');
const { raceTimeout }          = require('../../utils/raceTimeout');

// ── Configurable limits (read at startup for rate-limit configuration) ────────

const VERIFY_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.VERIFY_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 5_000;
})();

function _withTimeout(promise) {
  return raceTimeout(promise, VERIFY_TIMEOUT_MS, () => new Error('TIMEOUT')); // timer always cleared
}

// ── Canonical verification handler ───────────────────────────────────────────
//
// Single handler used by BOTH /verify/v2 and /verify (public).
// Runs the full 6-step pipeline on every call:
//   Steps 1–4: validateBoundRequest (signature, binding, nonce dry-run, anomaly dry-run)
//   Step  5:   checkPolicy (policy enforcement, dry-run store — no side effects), against
//              the SAME tenant-effective policy set /ai/chat would use (tenant sets +
// floor via getEffectivePoliciesForTenant — never the raw global set alone)
//   Step 6: Semantic Policy Engine — the SAME evaluateRequestSemantic() pipeline
//              /ai/chat's _runSemanticCheck() calls (same classifier engine, same embedding
//              gate, same tenant semantic overlay via tenantId), side-effect-free by
//              construction: it is a pure classification, and this handler never writes the
//              audit BLOCK entry aiChat.js writes when the SAME verdict blocks a real request
//              — see requestSemanticCheck.js's header.
//              Only runs when incomingRequest.body.prompt is a non-empty string — /verify's
//              bound request can target ANY endpoint, not just /ai/chat (aiChat.schema.js
//              itself 400-rejects a request with no prompt before it ever reaches the
//              semantic stage, so there is no /ai/chat verdict to predict otherwise, and the
//              real embedding backend has no defined behaviour for non-string input).
//
// Rate limiting is applied at mount time for both routes.
//
// Response semantics:
//   • Input validation errors     → HTTP 400, { decision: 'BLOCK', reason, details: {} }
//   • Pipeline BLOCK (steps 1–5)  → HTTP 200, { decision: 'BLOCK', reason, details: {} }
//   • Semantic BLOCK (step 6)     → HTTP 200, { decision: 'BLOCK', reason, details: { semantic: evidence } }
//                                   — the identical envelope shape aiChat.js's _enforceAndExecute()
//                                   returns for the same semantic verdict.
//   • Pipeline EXECUTE            → HTTP 200, { decision: 'EXECUTE', reason, artifactId, keyId }
//   • Internal/timeout errors     → HTTP 200, { decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {} }

function _makeVerifyHandler(dryRunNonce, dryRunAnomaly, thresholds, getPolicies, dryRunPolicyStore) {
  return async function handleVerify(req, res) {
    res.set('Content-Type', 'application/json');
    const reqId = req.requestId ?? null;

    // ── Presence and type checks (produces specific reason codes) ────
    // verifyArtifactPresentSchema validates body is a strict object with exactly
    // {artifact, request} keys and that each is present and is a non-array object.
    const _presenceParsed = verifyArtifactPresentSchema.safeParse(req.body);
    if (!_presenceParsed.success) {
      const hasUnknownKeys = _presenceParsed.error.issues.some(i => i.code === 'unrecognized_keys');
      const reason = hasUnknownKeys
        ? 'UNEXPECTED_FIELDS'
        : firstQodiqaReason(_presenceParsed.error, 'INVALID_REQUEST_BODY');
      return res.status(400).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    }

    // ── Size and depth checks ───────────────────────────────────────
    // verifyBodySchema adds size and depth refinements; both objects are already
    // confirmed non-null plain objects.
    const _sizeParsed = verifyBodySchema.safeParse(req.body);
    if (!_sizeParsed.success) {
      const reason = firstQodiqaReason(_sizeParsed.error, 'INVALID_ARTIFACT');
      return res.status(400).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    }

    const { artifact, request: incomingRequest } = _sizeParsed.data;

    // ── Steps 1–4: signature, binding, nonce (dry-run), anomaly (dry-run) ──────
    let result;
    try {
      result = await _withTimeout(
        validateBoundRequest(artifact, incomingRequest, {
          _store:        dryRunNonce,
          _anomalyStore: dryRunAnomaly,
          _thresholds:   thresholds,
        }),
      );
    } catch {
      return res.status(200).json({ decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {}, requestId: reqId });
    }

    if (!result.allowed) {
      return res.status(200).json({
        decision:  'BLOCK',
        reason:    normalizeReason(result.reason),
        details:   result.details || {},
        requestId: reqId,
      });
    }

    // ── Step 5: Policy enforcement (dry-run) ──────────────────────────────────
    if (!getPolicies || !dryRunPolicyStore) {
      return res.status(200).json({ decision: 'BLOCK', reason: 'POLICY_STATE_UNAVAILABLE', details: {}, requestId: reqId });
    }

    // tenant-effective policy set —
    // mirrors aiChat.js's _authenticateAndPolicy() exactly. Falls back to
    // the raw global getter for a tenant with no stored set (unchanged
    // GLOBAL_FALLBACK semantics).
    const _tenantPolicies    = getEffectivePoliciesForTenant(result.tenantId);
    const _effectivePolicies = _tenantPolicies ? (() => _tenantPolicies) : getPolicies;

    let policyResult;
    try {
      // artifactValid=true is safe here — this line is only
      // reached when validateBoundRequest() above already returned
      // allowed:true (line 92 returns BLOCK for every other case).
      policyResult = await checkPolicy(
        _effectivePolicies, dryRunPolicyStore,
        result.requestId, artifact, true, result.publicKeyId,
        req.clientIp ?? null, result.tenantId,
        require('../../../services/policy/abac/requestAttributes').buildFor(incomingRequest && incomingRequest.body, _effectivePolicies, artifact?.payload?.provider ?? null),
      );
    } catch {
      return res.status(200).json({ decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {}, requestId: reqId });
    }

    if (!policyResult.allowed) {
      return res.status(200).json({
        decision:  'BLOCK',
        reason:    normalizeReason(policyResult.reason),
        details:   policyResult.details || {},
        requestId: reqId,
      });
    }

    // Policy drift detection — informational only, never blocks verification.
    const _artifactPolicyHash = artifact?.payload?.policyHash ?? null;
    const _livePolicyHash     = policyResult.policyHash ?? null;
    if (typeof _artifactPolicyHash === 'string' && typeof _livePolicyHash === 'string') {
      if (!policyHashesEqual(_artifactPolicyHash, _livePolicyHash)) {
        emit('WARN', 'POLICY_DRIFT_DETECTED', {
          requestId:           result.requestId,
          policyDriftDetected: true,
          policyHashExpected:  _livePolicyHash,
          policyHashReceived:  _artifactPolicyHash,
        });
      }
    }

    // ── Step 6: Semantic Policy Engine — parity with /ai/chat ──────────
    // Side-effect-free by construction (see requestSemanticCheck.js's header):
    // no audit append, no transparency entry, no consent consumption, no
    // provider call, no rate-limit consumption.
    //
    // /verify's `request` is bound to whatever endpoint the caller intends to
    // hit next — /ai/chat is one possibility among many (AT-063's own fixture
    // binds to /orders/create). aiChat.schema.js REQUIRES a non-empty string
    // `prompt` before a real /ai/chat request ever reaches its semantic
    // stage — a request missing one is 400-rejected before that point, so
    // the semantic engine never runs, and there is no /ai/chat verdict for
    // /verify to predict. Mirror that gate exactly (never run the classifier
    // on a non-string/absent prompt): the real embedding backend has no
    // defined behaviour for non-string input, unlike the pure keyword engine.
    const _promptForSemantics = incomingRequest?.body?.prompt;
    const _conv = require('../../validation/conversation');
    const _isConversation = _conv.enabled() && _conv.hasConversationFields(incomingRequest?.body) && !_conv.validateConversation(incomingRequest.body);   // same gate, same screening as /ai/chat
    if (_isConversation || (typeof _promptForSemantics === 'string' && _promptForSemantics.length > 0)) {
      let semanticResult;
      try {
        semanticResult = await _withTimeout((_isConversation ? (p) => require('../../core/semantic/requestSemanticCheck').evaluateConversationSemantic({ ...p, body: incomingRequest.body }) : evaluateRequestSemantic)({
          prompt:    _promptForSemantics,
          provider:  artifact?.payload?.provider || null,
          tenantId:  result.tenantId,
          requestId: result.requestId,
        }));
      } catch {
        return res.status(200).json({ decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {}, requestId: reqId });
      }

      if (semanticResult.blocks) {
        return res.status(200).json({
          decision:  'BLOCK',
          reason:    semanticResult.reason,
          details:   { semantic: semanticResult.evidence },
          requestId: reqId,
        });
      }
    }

    return res.status(200).json({
      decision:   'EXECUTE',
      reason:     'ALL_CHECKS_PASSED',
      artifactId: result.requestId   || null,
      keyId:      result.publicKeyId || null,
      // authenticated caller identity, distinct from keyId — null
      // only for an artifact signed before this remediation shipped.
      callerId:   result.callerId    || null,
      tenantId:   result.tenantId    || null,
      requestId:  reqId,
    });
  };
}

module.exports = function createVerifyRouter(getPolicies, opts) {
  const options = (getPolicies && typeof getPolicies === 'object') ? getPolicies : (opts || {});
  const {
    _dryRunNonceStore,
    _dryRunAnomalyStore,
    _thresholds,
    _getPolicies,
    _policyStore,
  } = options;

  const router = Router();
  // admission control for /verify and /verify/v2 - before content type, rate limit, artifact decode and signature verification (src/api/admission.js)
  router.use(require('../admission').get('verify').middleware);

  const dryRunNonce       = makeDryRunNonceStore(_dryRunNonceStore);
  const dryRunAnomaly     = makeDryRunAnomalyStore(_dryRunAnomalyStore);
  const dryRunPolicyStore = makeDryRunPolicyStore(_policyStore);
  const thresholds        = _thresholds || DEFAULT_THRESHOLDS;

  const verifyHandler = _makeVerifyHandler(dryRunNonce, dryRunAnomaly, thresholds, _getPolicies, dryRunPolicyStore);

  // /verify/v2 — rate limited (configurable) + content-type enforcement
  const v2RateLimit = createRateLimitMiddleware('verify_v2', { envelope: 'decision' });
  router.post('/v2', enforceContentType, v2RateLimit, verifyHandler);

  // /verify (public) — tighter rate limit + content-type enforcement
  const publicRateLimit = createRateLimitMiddleware('verify_public', { envelope: 'decision' });
  router.post('/', enforceContentType, publicRateLimit, verifyHandler);

  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));

  return router;
};
