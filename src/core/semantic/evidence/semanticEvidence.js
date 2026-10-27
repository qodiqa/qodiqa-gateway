'use strict';

const { ENGINE_STATUS, SEMANTIC_ENGINE_UNAVAILABLE_REASON } = require('../reasons');

const ENGINE_VERSION = '1.0.0';

/**
 * Builds the semantic-analysis evidence record attached to the execution's
 * audit trail (executionContext.semantic in src/api/routes/aiChat.js) —
 * extends QODIQA's existing evidence model rather than introducing a
 * parallel one. Present for every request the engine evaluates, not only
 * denied ones, so ALLOW/WARN/REVIEW/DENY outcomes remain fully auditable too.
 *
 * The engineStatus/registryStatus/classifiers* fields
 * are additive: every existing consumer that reads decision/reason/
 * confidence/score/matchedPolicies is unaffected, and callers that don't
 * pass health info get the "everything is fine" defaults (READY/OK), which
 * is always true when this function is reached at all — a failed inspection
 * never reaches this builder, see buildFailureEvidence() and index.js.
 */
function buildSemanticEvidence({
  aggregateResult, requestId, tenantId, provider,
  surface = 'REQUEST',
  engineStatus = ENGINE_STATUS.READY,
  registryStatus = 'OK',
  classifiersExecuted = null,
  classifiersSucceeded = null,
  classifiersFailed = 0,
  classifiersTimedOut = 0,
  classifiersInvalidOutput = 0,
  normalizationMeta = null,
}) {
  return Object.freeze({
    engineVersion: ENGINE_VERSION,
    timestamp: new Date().toISOString(),
    requestId: requestId || null,
    tenantId: tenantId || null,
    provider: provider || null,
    // which side of the request/response pair produced this
    // evidence — 'REQUEST' (default, unchanged for every existing caller),
    // 'RESPONSE' (non-streaming output classification), or
    // 'RESPONSE_STREAM' (streaming sliding-window classification). Purely
    // descriptive metadata; never affects decision/scoring.
    surface,
    decision: aggregateResult.decision,
    reason: aggregateResult.reason,
    confidence: aggregateResult.topClassifier ? aggregateResult.topClassifier.confidence : 0,
    score: Number((aggregateResult.score || 0).toFixed(4)),
    matchedPolicies: (aggregateResult.matched || []).map((m) => ({
      classifierId: m.id,
      reason: m.reason,
      severity: m.severity,
      confidence: m.confidence,
      weightedScore: Number(m.weightedScore.toFixed(4)),
    })),
    engineStatus,
    registryStatus,
    classifiersExecuted,
    classifiersSucceeded,
    classifiersFailed,
    classifiersTimedOut,
    classifiersInvalidOutput,
    // follow-up remediation requirement #4: structured evidence of
    // which normalization steps fired for this request, present only when
    // normalization actually changed something (keeps evidence small for
    // the common plain-ASCII case). Metadata-only by design — booleans/
    // counts of which transformation categories fired, never the raw or
    // decoded prompt text itself, matching this engine's existing evidence
    // privacy boundary (see classifier/baseClassifier.js: "semantic evidence
    // never carries verbatim prompt content into the audit trail").
    ...(normalizationMeta && normalizationMeta.changed ? { normalization: normalizationMeta } : {}),
  });
}

/**
 * Builds the evidence record for a fail-closed semantic-engine denial (
 * remediation) — used whenever inspection could not be completed, as
 * distinct from inspection completing and finding nothing (ALLOW, built by
 * buildSemanticEvidence() above). Deliberately does not reuse
 * buildSemanticEvidence() or take an aggregateResult: there may be no valid
 * aggregate result at all (e.g. the registry never loaded), and this builder
 * must remain trivially safe to call from every failure branch in index.js,
 * including the outermost catch-all.
 *
 * Never includes stack traces or raw prompt content — only structured,
 * client/audit-safe failure metadata (remediation requirement #10).
 */
function buildFailureEvidence({
  failureReason, engineStatus, registryStatus,
  classifiersExecuted = 0,
  classifiersSucceeded = 0,
  classifiersFailed = 0,
  classifiersTimedOut = 0,
  classifiersInvalidOutput = 0,
  requestId, tenantId, provider,
  surface = 'REQUEST',
}) {
  return Object.freeze({
    engineVersion: ENGINE_VERSION,
    timestamp: new Date().toISOString(),
    requestId: requestId || null,
    tenantId: tenantId || null,
    provider: provider || null,
    // see buildSemanticEvidence()'s matching field for the meaning.
    surface,
    decision: 'DENY',
    reason: SEMANTIC_ENGINE_UNAVAILABLE_REASON,
    confidence: 0,
    score: 0,
    matchedPolicies: [],
    engineStatus,
    registryStatus,
    failureReason,
    classifiersExecuted,
    classifiersSucceeded,
    classifiersFailed,
    classifiersTimedOut,
    classifiersInvalidOutput,
  });
}

module.exports = { buildSemanticEvidence, buildFailureEvidence, ENGINE_VERSION };
