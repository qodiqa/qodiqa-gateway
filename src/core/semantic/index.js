'use strict';

/**
 * Semantic Policy Engine — public entry point.
 *
 * Runs after Consent Verification and the (non-semantic) Policy Engine, and
 * before Execution Invariant / Provider Routing — see the integration in
 * src/api/routes/aiChat.js's _enforceAndExecute() / _enforceAndStream(). It
 * evaluates the *semantic intent* of the request text itself, which the
 * rest of the pipeline (signature, binding, replay, consent, IP/rate/time
 * policy) never inspects — those controls verify WHO is asking and WHETHER
 * they are authorized to ask at all; this engine evaluates WHAT is being
 * asked, independent of whether the caller is legitimately authenticated.
 *
 * Hard architectural invariant — deterministic, non-LLM decision authority:
 *   Every classifier is a pure, synchronous function of the request text
 *   (see classifier/baseClassifier.js and textSignals.js). No classifier
 *   bundled here calls an external model, and the engine's own decision
 *   logic (scoring/scoreAggregator.js) is pure arithmetic over classifier
 *   outputs. This is intentional and permanent: an LLM could in principle
 *   be added later as one more classifier contributing a signal (see
 *   registry/classifierRegistry.js's registerClassifier()), but it may
 *   never become the sole or final authority over ALLOW/WARN/REVIEW/DENY —
 *   QODIQA's own deterministic scoring always makes that call, so the
 *   decision remains reproducible and does not depend on a third party's
 *   availability or non-deterministic output.
 *
 * Provider independence: this function receives only the prompt text and
 * request metadata — never a provider handle or provider-specific request
 * shape — so the exact same evaluation and decision occur regardless of
 * which provider (openai, anthropic, gemini, mistral, llama, local, or any
 * future one) the artifact names. See services/providers/router.js, which
 * is never imported here and never will be.
 *
 * output-side reuse: this function classifies whatever text it is
 * given; it has no notion of "request" vs. "response". src/api/routes/
 * aiChat.js and src/streaming/streamEnforcer.js both call it a second time
 * per request, passing the provider's output as `context.prompt` instead of
 * the caller's prompt. The optional `context.surface` field (default
 * 'REQUEST') exists purely so the resulting evidence can self-describe
 * which side produced it ('REQUEST' | 'RESPONSE' | 'RESPONSE_STREAM') —
 * it does not change classification, scoring, or enforcement in any way.
 * There is deliberately no second engine, no duplicate classifier registry,
 * and no separate confidence/aggregation path for output text.
 *
 * remediation — fail closed when inspection cannot complete:
 *   Semantic inspection is a mandatory enforcement stage, not a best-effort
 *   one. A classifier registry that fails to load, is empty, or whose every
 *   classifier fails/times out/returns invalid output means inspection never
 *   happened — that is NOT equivalent to "inspection happened and found
 *   nothing," and must never resolve to ALLOW. Every branch below that
 *   cannot establish a trustworthy decision returns a deterministic DENY
 *   (see reasons.js's SEMANTIC_ENGINE_UNAVAILABLE_REASON) instead of falling
 *   through to the scoring path. This file is wrapped in an outermost
 *   try/catch specifically so that no internal failure — expected or
 *   not — can ever escape as an uncaught exception and be interpreted by a
 *   caller as anything other than an explicit denial.
 *
 * D3 — no calls outside the local machine on the decision path (SEM-F):
 *   Governing invariant, first stated in the item-20 decision record for
 *   SEM-C's embedding-similarity classifier: localhost (Ollama/ONNX)
 *   permitted, cloud not. This applies to the WHOLE semantic decision
 *   path this file is the entry point for, not just the embedding layer —
 *   the bundled keyword classifiers (pure, synchronous, no I/O at all, per
 *   the hard architectural invariant above) already satisfy it trivially;
 *   embeddingGate.js/embeddingSimilarity/ is the one piece that actually
 *   makes a call (in-process ONNX inference, no network once weights are
 *   cached — see embeddingSimilarity/index.js).
 *   This is a NAMED, CHECKED invariant, not an implicit property of
 *   today's implementation choices (SEM-F, item 6) — two independent,
 *   deliberately non-overlapping layers of assurance:
 
 *       + src/streaming/__tests__/networkInvariant.streaming.test.js
 *       (test:unit, Jest-hosted, mocked embedding backend): proves the
 *       WIRING/GLUE code around the classifiers — this file, aiChat.js,
 *       embeddingGate.js, outputSemanticWindow.js, streamEnforcer.js —
 *       never makes an outbound call across the request check, the
 *       non-streaming response check, and streaming (both the periodic
 *       evaluate() check and the mandatory evaluateFinal() recheck).
 
 *       (npm run test:embeddingSimilarity, CI-gated as a required check —
 *       .github/workflows/test.yml's embedding-similarity-gate job):
 *       proves the REAL ONNX model, with cached weights, itself makes zero
 *       calls. Cannot run inside Jest (native ONNX binding vs. Jest's
 *       sandboxed VM test context — see that script's header).
 *   Neither layer subsumes the other. Both consume the same interceptor,
 *   test/helpers/networkInvariant.js (patches http.request/http.get,
 *   https.request/https.get, and global.fetch; allowlists 127.0.0.1/::1/
 *   localhost; throws NetworkInvariantViolation naming the attempted host
 *   otherwise) — one implementation, two consumers, not two parallel
 *   reimplementations that could silently drift apart.
 */

const { getClassifiersWithStatus, registerClassifier } = require('./registry/classifierRegistry');
const { executeClassifiers } = require('./classifierExecution');
const { aggregate } = require('./scoring/scoreAggregator');
const { resolveAction } = require('./policies/semanticActions');
const { loadSemanticPolicy } = require('./policies/semanticPolicy');
const { normalize, normalizeCased, analyzeNormalization } = require('./textSignals');
const { buildSemanticEvidence, buildFailureEvidence } = require('./evidence/semanticEvidence');
const {
  DECISION, SEVERITY, SEMANTIC_REASONS, ENGINE_STATUS, ENGINE_FAILURE_REASONS, SEMANTIC_ENGINE_UNAVAILABLE_REASON,
} = require('./reasons');
const { emit } = require('../../../services/logger');
const metrics = require('../../observability/metrics');

function _surfaceOf(context) {
  return context.surface === 'RESPONSE' || context.surface === 'RESPONSE_STREAM'
    ? context.surface
    : 'REQUEST';
}

function _allowResult(context) {
  const aggregateResult = { decision: DECISION.ALLOW, reason: null, score: 0, matched: [], topClassifier: null, allResults: [] };
  return {
    blocks: false,
    decision: DECISION.ALLOW,
    reason: null,
    evidence: buildSemanticEvidence({
      aggregateResult, requestId: context.requestId, tenantId: context.tenantId, provider: context.provider,
      surface: _surfaceOf(context),
    }),
  };
}

/**
 * Builds the deterministic, always-audited fail-closed response. Every call
 * site that cannot establish a trustworthy semantic decision routes through
 * here — never returns ALLOW, never lets the caller distinguish "denied
 * because of an attack" from "denied because inspection failed" via the
 * top-level `reason` alone (that distinction lives in evidence.failureReason
 * for audit/observability, per remediation requirement #3), and always
 * produces a structured log + metrics increment so the failure is visible
 * to operators, not just to the denied caller.
 */
function _denyEngineFailure(ctx, failureReason, health) {
  let evidence;
  try {
    evidence = buildFailureEvidence({
      failureReason,
      requestId: ctx.requestId,
      tenantId: ctx.tenantId,
      provider: ctx.provider,
      surface: _surfaceOf(ctx),
      ...health,
    });
  } catch {
    // buildFailureEvidence() is pure object construction and should never
    // throw, but this is the last line of defense in the engine — even here,
    // a failure to build evidence must not become an ALLOW or an uncaught
    // exception. A minimal, hardcoded evidence object guarantees the audit
    // trail always receives *something* structured.
    evidence = Object.freeze({
      engineVersion: '1.0.0',
      timestamp: new Date().toISOString(),
      requestId: ctx.requestId || null,
      tenantId: ctx.tenantId || null,
      provider: ctx.provider || null,
      surface: _surfaceOf(ctx),
      decision: 'DENY',
      reason: SEMANTIC_ENGINE_UNAVAILABLE_REASON,
      confidence: 0,
      score: 0,
      matchedPolicies: [],
      engineStatus: ENGINE_STATUS.UNAVAILABLE,
      registryStatus: 'UNKNOWN',
      failureReason,
    });
  }

  metrics.semanticEngineFailuresTotal.inc({ reason: failureReason });
  metrics.semanticFailClosedTotal.inc({ reason: failureReason });

  emit('CRITICAL', 'SEMANTIC_ENGINE_FAIL_CLOSED', {
    requestId: ctx.requestId || null,
    tenantId: ctx.tenantId || null,
    failureReason,
    engineStatus: health && health.engineStatus,
    registryStatus: health && health.registryStatus,
    classifiersExecuted: health && health.classifiersExecuted,
    classifiersSucceeded: health && health.classifiersSucceeded,
    classifiersFailed: health && health.classifiersFailed,
    classifiersTimedOut: health && health.classifiersTimedOut,
    classifiersInvalidOutput: health && health.classifiersInvalidOutput,
  });

  return {
    blocks: true,
    decision: DECISION.DENY,
    reason: SEMANTIC_ENGINE_UNAVAILABLE_REASON,
    evidence,
  };
}

/**
 * @param {object} context
 * @param {string} context.prompt        — the request text to evaluate
 * @param {string} [context.provider]    — artifact.payload.provider (metadata only, never routing logic)
 * @param {string} [context.tenantId]
 * @param {string} [context.requestId]
 * @returns {{ blocks:boolean, decision:string, reason:string|null, evidence:object }}
 */
function runSemanticPolicyEngine(context) {
  const ctx = context || {};

  try {
    let policy;
    try {
      policy = loadSemanticPolicy();
    } catch (err) {
      emit('ERROR', 'SEMANTIC_POLICY_LOAD_ERROR', { requestId: ctx.requestId, error: err.message });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.POLICY_LOAD_FAILED, {
        engineStatus: ENGINE_STATUS.UNAVAILABLE, registryStatus: 'UNKNOWN',
      });
    }

    if (!policy.enabled) return _allowResult(ctx);

    // ── tenant tighten-only overlay ────────────────────────────────────
    // A tenant WITH a stored semantic config gets the pinned defaults merged
    // with its (validated + clamped, tighten-only) values: tier thresholds
    // only lower, WARN_BLOCKS only enabled, REVIEW_BLOCKS untouchable — see
    // tenantSemanticRegistry.js. A tenant WITHOUT one gets `null` here and
    // the unmodified `policy` object: byte-for-byte the pre-M-03 path. The
    // engine kill switch above is deliberately global-only (a tenant cannot
    // reach it in either direction).
    try {
      const overlay = require('../tenancy/tenantSemanticRegistry')
        .getEffectivePolicyOverlay(ctx.tenantId, policy);
      if (overlay) policy = overlay;
    } catch (err) {
      // Registry failure must not fail the request in either direction:
      // fall back to the pinned defaults (the tighter-or-equal baseline is
      // `policy` itself) and log — never a loosened state, never a crash.
      emit('ERROR', 'TENANT_SEMANTIC_OVERLAY_ERROR', { requestId: ctx.requestId, tenantId: ctx.tenantId, error: err && err.message });
    }

    const { classifiers, registryStatus, error: registryError } = getClassifiersWithStatus(policy);

    if (registryStatus === 'LOAD_FAILED') {
      metrics.semanticRegistryLoadFailuresTotal.inc();
      emit('ERROR', 'SEMANTIC_REGISTRY_LOAD_FAILED', { requestId: ctx.requestId, error: registryError });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.REGISTRY_LOAD_FAILED, {
        engineStatus: ENGINE_STATUS.UNAVAILABLE,
        registryStatus,
        classifiersExecuted: 0, classifiersSucceeded: 0, classifiersFailed: 0, classifiersTimedOut: 0, classifiersInvalidOutput: 0,
      });
    }

    if (classifiers.length === 0) {
      // An empty registry must never be interpreted as "no attack" — see
      // remediation requirement #6. This is a semantic-engine failure,
      // not a benign result, regardless of whether it's because zero
      // classifier files exist or every classifier was disabled via policy.
      metrics.semanticEmptyRegistryTotal.inc();
      emit('ERROR', 'SEMANTIC_REGISTRY_EMPTY', { requestId: ctx.requestId });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.EMPTY_CLASSIFIER_REGISTRY, {
        engineStatus: ENGINE_STATUS.UNAVAILABLE,
        registryStatus: 'EMPTY',
        classifiersExecuted: 0, classifiersSucceeded: 0, classifiersFailed: 0, classifiersTimedOut: 0, classifiersInvalidOutput: 0,
      });
    }

    // follow-up remediation requirement #5/#7: compute normalization
    // exactly once per request here, rather than once per classifier inside
    // each classify() call — a single pipeline stage that runs before every
    // classifier, not N re-derivations of the same text. Both the
    // normalized text and the (audit-safe, metadata-only — never raw/decoded
    // prompt content, consistent with buildSemanticEvidence()'s existing
    // privacy model) analysis are computed together and threaded through
    // ctx so every classifier — declarative ones built via defineClassifier
    // and any future custom one registered via registerClassifier() — sees
    // the identical normalized text for this request.
    let normalizedCtx;
    let normalizationMeta;
    try {
      // casePreservedPrompt is computed here alongside
      // normalizedPrompt, once per request, for the same reason
      // normalizedPrompt is — one pipeline stage before every classifier,
      // not N re-derivations. Classifiers that do not opt in are entirely
      // unaffected: they keep reading normalizedPrompt, whose value is
      // unchanged.
      normalizedCtx = {
        ...ctx,
        normalizedPrompt: normalize(ctx.prompt),
        casePreservedPrompt: normalizeCased(ctx.prompt),
      };
      normalizationMeta = analyzeNormalization(ctx.prompt);
    } catch (err) {
      emit('ERROR', 'SEMANTIC_NORMALIZATION_ERROR', { requestId: ctx.requestId, error: err && err.message });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.NORMALIZATION_FAILED, {
        engineStatus: ENGINE_STATUS.UNAVAILABLE,
        registryStatus: 'OK',
        classifiersExecuted: 0, classifiersSucceeded: 0, classifiersFailed: 0, classifiersTimedOut: 0, classifiersInvalidOutput: 0,
      });
    }

    const outcome = executeClassifiers(classifiers, normalizedCtx, policy);

    for (const f of outcome.failures) {
      if (f.category === 'TIMEOUT') {
        metrics.semanticClassifierTimeoutsTotal.inc({ classifierId: f.classifierId });
        emit('ERROR', 'SEMANTIC_CLASSIFIER_TIMEOUT', { classifierId: f.classifierId, requestId: ctx.requestId, detail: f.message });
      } else if (f.category === 'INVALID_OUTPUT') {
        metrics.semanticInvalidOutputTotal.inc({ classifierId: f.classifierId });
        emit('ERROR', 'SEMANTIC_CLASSIFIER_INVALID_OUTPUT', { classifierId: f.classifierId, requestId: ctx.requestId });
      } else {
        // A single misbehaving classifier must never crash the request or
        // silently disable semantic evaluation for the rest — isolate and log.
        metrics.semanticClassifierFailuresTotal.inc({ classifierId: f.classifierId });
        emit('ERROR', 'SEMANTIC_CLASSIFIER_ERROR', { classifierId: f.classifierId, error: f.message });
      }
    }

    if (outcome.succeeded === 0) {
      // Every classifier failed, timed out, or returned invalid output —
      // inspection was attempted but produced zero trustworthy evidence.
      // This is indistinguishable in effect from having no classifiers at
      // all, and must fail closed identically.
      metrics.semanticFailClosedTotal.inc({ reason: ENGINE_FAILURE_REASONS.ALL_CLASSIFIERS_FAILED });
      emit('CRITICAL', 'SEMANTIC_ALL_CLASSIFIERS_FAILED', {
        requestId: ctx.requestId, classifiersExecuted: outcome.executed,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.ALL_CLASSIFIERS_FAILED, {
        engineStatus: ENGINE_STATUS.FAILED,
        registryStatus: 'OK',
        classifiersExecuted: outcome.executed, classifiersSucceeded: 0,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
    }

    const partialFailureCount = outcome.failed + outcome.timedOut + outcome.invalidOutput;
    const isDegraded = partialFailureCount > 0;
    if (isDegraded) {
      metrics.semanticPartialFailureTotal.inc();
      emit('WARN', 'SEMANTIC_PARTIAL_CLASSIFIER_FAILURE', {
        requestId: ctx.requestId, classifiersExecuted: outcome.executed, classifiersSucceeded: outcome.succeeded,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
    }

    let aggregateResult;
    try {
      aggregateResult = aggregate(outcome.results, policy);
    } catch (err) {
      emit('ERROR', 'SEMANTIC_AGGREGATION_ERROR', { requestId: ctx.requestId, error: err.message });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.AGGREGATION_FAILED, {
        engineStatus: ENGINE_STATUS.FAILED,
        registryStatus: 'OK',
        classifiersExecuted: outcome.executed, classifiersSucceeded: outcome.succeeded,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
    }

    let action;
    try {
      action = resolveAction(aggregateResult, policy);
    } catch (err) {
      emit('ERROR', 'SEMANTIC_POLICY_RESOLUTION_ERROR', { requestId: ctx.requestId, error: err.message });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.POLICY_RESOLUTION_FAILED, {
        engineStatus: ENGINE_STATUS.FAILED,
        registryStatus: 'OK',
        classifiersExecuted: outcome.executed, classifiersSucceeded: outcome.succeeded,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
    }

    let evidence;
    try {
      const base = buildSemanticEvidence({
        aggregateResult, requestId: ctx.requestId, tenantId: ctx.tenantId, provider: ctx.provider,
        surface: _surfaceOf(ctx),
        normalizationMeta,
      });
      evidence = Object.freeze({
        ...base,
        engineStatus: isDegraded ? ENGINE_STATUS.DEGRADED : ENGINE_STATUS.READY,
        registryStatus: 'OK',
        classifiersExecuted: outcome.executed,
        classifiersSucceeded: outcome.succeeded,
        classifiersFailed: outcome.failed,
        classifiersTimedOut: outcome.timedOut,
        classifiersInvalidOutput: outcome.invalidOutput,
        // evidence tagging: present IFF a tenant overlay was active for
        // this decision — the effective config hash ties the decision to the
        // exact config that produced it. Absence means the pinned defaults
        // (deliberate: default-tenant evidence stays byte-identical).
        ...(policy.tenantConfig ? { semanticConfig: policy.tenantConfig } : {}),
      });
    } catch (err) {
      emit('ERROR', 'SEMANTIC_EVIDENCE_GENERATION_ERROR', { requestId: ctx.requestId, error: err.message });
      return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.EVIDENCE_GENERATION_FAILED, {
        engineStatus: ENGINE_STATUS.FAILED,
        registryStatus: 'OK',
        classifiersExecuted: outcome.executed, classifiersSucceeded: outcome.succeeded,
        classifiersFailed: outcome.failed, classifiersTimedOut: outcome.timedOut, classifiersInvalidOutput: outcome.invalidOutput,
      });
    }

    if (aggregateResult.decision !== DECISION.ALLOW) {
      emit('WARN', 'SEMANTIC_POLICY_MATCH', {
        requestId: ctx.requestId,
        decision: aggregateResult.decision,
        reason: aggregateResult.reason,
        score: aggregateResult.score,
        classifiers: aggregateResult.matched.map((m) => m.id),
      });
    }

    return { blocks: action.blocks, decision: action.decision, reason: action.reason, evidence };
  } catch (err) {
    // Absolute last resort: any unexpected internal error anywhere above —
    // never allowed to escape as an uncaught exception or be mistaken for
    // ALLOW by a caller.
    emit('CRITICAL', 'SEMANTIC_ENGINE_INTERNAL_ERROR', { requestId: ctx.requestId, error: err && err.message });
    return _denyEngineFailure(ctx, ENGINE_FAILURE_REASONS.INTERNAL_ENGINE_ERROR, {
      engineStatus: ENGINE_STATUS.UNAVAILABLE, registryStatus: 'UNKNOWN',
    });
  }
}

module.exports = {
  runSemanticPolicyEngine,
  registerClassifier,
  DECISION,
  SEVERITY,
  SEMANTIC_REASONS,
  ENGINE_STATUS,
  ENGINE_FAILURE_REASONS,
  SEMANTIC_ENGINE_UNAVAILABLE_REASON,
};
