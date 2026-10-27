'use strict';

/**
 * Embedding-similarity gate — SEM-C session 3, integration Option B.
 *
 * A separate, additive check alongside the existing classifier-registry
 * engine (./index.js), not merged into it: classifierExecution.js's
 * classifier loop is synchronous and untouched (ONNX inference is
 * unavoidably async — see embeddingSimilarity/index.js's own header
 * comment), and cosine similarity has no calibrated mapping onto
 * scoreAggregator.js's confidence x severity weighting yet (the threshold
 * itself is still provisional pending SEM-D's >=2,000-item validation).
 * Owner-chosen option, see the SEM-C session 3 decision record.
 *
 * Reuses the exact evidence builders index.js's own engine uses
 * and the same DECISION /
 * SEMANTIC_ENGINE_UNAVAILABLE_REASON vocabulary, so every audit consumer
 * sees one consistent evidence schema regardless of which layer produced a
 * denial — this gate does not invent a parallel format.
 *
 * Call sites (all await this — see each file for exactly where):
 *   - src/api/routes/aiChat.js's _runSemanticCheck() / _runOutputSemanticCheck()
 *   - src/streaming/outputSemanticWindow.js's evaluate() / evaluateFinal()
 *
 * Every call site follows the same rule: run the existing keyword engine
 * first; only call this gate if the keyword engine did NOT already block.
 * That ordering is what makes "no change to existing classifier behavior on
 * inputs the embedding layer doesn't flag" literally true — this module is
 * never even invoked on a request the existing engine already denies, and
 * its own ALLOW result never overwrites the keyword engine's ALLOW result
 * at the call site (each caller only substitutes this gate's result in when
 * IT blocks).
 */

const embeddingClassifier = require('./embeddingSimilarity');
const { buildSemanticEvidence, buildFailureEvidence } = require('./evidence/semanticEvidence');
const {
  DECISION, SEVERITY, SEMANTIC_REASONS, ENGINE_STATUS, SEMANTIC_ENGINE_UNAVAILABLE_REASON,
} = require('./reasons');
const { emit } = require('../../../services/logger');
const metrics = require('../../observability/metrics');
const embeddingConfig = require('./embeddingSimilarity/config'); // static, not inside the request path (same teardown hazard as transparencySigner's metrics)

/**
 * FT-2 OBSERVABILITY LIVES HERE, NOT IN embeddingSimilarity/index.js, and that
 * is a deliberate reversal of nothing — it is the resolution of an objection
 * that module recorded against itself. Its header says it emits no logs because
 * "this module has no request context (requestId/tenantId) of its own to
 * attach". True, and still true. THIS gate is handed a ctx by every call site,
 * so it is the first layer that can attach one. The classifier stays a pure
 * function of text; the gate does the telling.
 *
 * ALERT RULE — the invocation rate, and the tolerance is derived, not guessed.
 *
 * width is taken from the SPREAD OF THE MEASURED POPULATIONS THEMSELVES
 * ~8pp) rather than from any run-to-run timing variance, because the invocation
 * rate is a property of the traffic mix and not of the machine. Rounding 8pp up
 * to 10pp leaves room for a legitimate corpus this system has not seen without
 * someone for.
 *
 * MIN_SAMPLE exists so a cold process does not alert on its first few requests.
 */
const FT2_RATE_EXPECTED = 0.24;
const FT2_RATE_TOLERANCE = 0.10;
const FT2_RATE_MIN_SAMPLE = 200;
const FT2_RATE_REPORT_EVERY = 200;

let _ft2Eligible = 0;
let _ft2Consulted = 0;
let _ft2LastReportAt = 0;

/**
 * Emits the periodic invocation-rate observation, and a WARN when the rate has
 * left the measured band in EITHER direction. A collapse toward zero matters as
 * much as a spike: it is what a silently-broken band looks like, and it would
 * otherwise present as "everything is fine and cheaper than expected".
 */
function _observeFt2Rate() {
  // with the gate disabled (the shipped default, and the ONLY allowed state in
  // production — bootValidator) `ft2Consulted` never appears, so the rate is a constant 0 and this would emit a false
  // SEM_FT2_RATE_OUT_OF_BAND WARN every 200 requests. The band is meaningful only while FT-2 is actually enabled.
  if (embeddingConfig.FT2_ENABLED !== true) return;
  if (_ft2Eligible < FT2_RATE_MIN_SAMPLE) return;
  if (_ft2Eligible - _ft2LastReportAt < FT2_RATE_REPORT_EVERY) return;
  _ft2LastReportAt = _ft2Eligible;
  const rate = _ft2Consulted / _ft2Eligible;
  const low = FT2_RATE_EXPECTED - FT2_RATE_TOLERANCE;
  const high = FT2_RATE_EXPECTED + FT2_RATE_TOLERANCE;
  const outOfBand = rate < low || rate > high;
  emit(outOfBand ? 'WARN' : 'INFO', outOfBand ? 'SEM_FT2_RATE_OUT_OF_BAND' : 'SEM_FT2_RATE', {
    rate: Number(rate.toFixed(4)),
    consulted: _ft2Consulted,
    eligible: _ft2Eligible,
    expected: FT2_RATE_EXPECTED,
    band: [Number(low.toFixed(2)), Number(high.toFixed(2))],
    direction: outOfBand ? (rate > high ? 'ABOVE' : 'BELOW') : null,
  });
}

/** Test-only: the rate window is process-lifetime state. */
function _resetFt2RateForTests() { _ft2Eligible = 0; _ft2Consulted = 0; _ft2LastReportAt = 0; }

// ── FT-3 invocation rate ──────────────────────────────────
//
// DUAL-TRACKED, not re-pointed. FT-2 remains wired behind its flag (default
// OFF after the swap) so the configuration is reversible without a deploy —
// its counters therefore stay live and keep meaning exactly what they meant.
//
// THE BAND IS FT-2's, REUSED ON MEASURED EVIDENCE RATHER THAN RE-DERIVED.
// Both gates test the same `result.score` against the same 0.2977 grey band,
// and in the swap configuration FT-3 occupies the position FT-2 held: the
// first fine-tuned gate, consulted whenever the four cheap gates did not DENY.
// The consultation populations are therefore identical by construction, and
// measured identical over the recorded sets — ext88 14 and 234
// consultations in BOTH configurations. Inventing a second, uncalibrated band
// for FT-3 would have been a fresh number with no derivation behind it.
const FT3_RATE_EXPECTED = FT2_RATE_EXPECTED;
const FT3_RATE_TOLERANCE = FT2_RATE_TOLERANCE;
const FT3_RATE_MIN_SAMPLE = FT2_RATE_MIN_SAMPLE;
const FT3_RATE_REPORT_EVERY = FT2_RATE_REPORT_EVERY;

let _ft3Eligible = 0;
let _ft3Consulted = 0;
let _ft3LastReportAt = 0;

/** Exact FT-3 analogue of _observeFt2Rate, including the both-directions WARN:
 *  a collapse toward zero is what a silently-broken band looks like. */
function _observeFt3Rate() {
  if (_ft3Eligible < FT3_RATE_MIN_SAMPLE) return;
  if (_ft3Eligible - _ft3LastReportAt < FT3_RATE_REPORT_EVERY) return;
  _ft3LastReportAt = _ft3Eligible;
  const rate = _ft3Consulted / _ft3Eligible;
  const low = FT3_RATE_EXPECTED - FT3_RATE_TOLERANCE;
  const high = FT3_RATE_EXPECTED + FT3_RATE_TOLERANCE;
  const outOfBand = rate < low || rate > high;
  emit(outOfBand ? 'WARN' : 'INFO', outOfBand ? 'SEM_FT3_RATE_OUT_OF_BAND' : 'SEM_FT3_RATE', {
    rate: Number(rate.toFixed(4)),
    consulted: _ft3Consulted,
    eligible: _ft3Eligible,
    expected: FT3_RATE_EXPECTED,
    band: [Number(low.toFixed(2)), Number(high.toFixed(2))],
    direction: outOfBand ? (rate > high ? 'ABOVE' : 'BELOW') : null,
  });
}

/** Test-only: the rate window is process-lifetime state. */
function _resetFt3RateForTests() { _ft3Eligible = 0; _ft3Consulted = 0; _ft3LastReportAt = 0; }

const GATE_CLASSIFIER_ID = 'embeddingSimilarity';

function _allowResult({ requestId, tenantId, provider, surface }) {
  return {
    blocks: false,
    decision: DECISION.ALLOW,
    reason: null,
    evidence: buildSemanticEvidence({
      aggregateResult: { decision: DECISION.ALLOW, reason: null, score: 0, matched: [], topClassifier: null },
      requestId, tenantId, provider, surface,
    }),
  };
}

function _denyInfraFailure(failureReason, { requestId, tenantId, provider, surface }) {
  return {
    blocks: true,
    decision: DECISION.DENY,
    reason: SEMANTIC_ENGINE_UNAVAILABLE_REASON,
    evidence: buildFailureEvidence({
      failureReason,
      engineStatus: ENGINE_STATUS.UNAVAILABLE,
      registryStatus: 'OK',
      requestId, tenantId, provider, surface,
    }),
  };
}

function _denyMatch(result, { requestId, tenantId, provider, surface }) {
  // · B-3, extended by B-2 (a'): report the score of the gate that
  // actually decided. Whenever the anchor rule fired this is `result.score`
  // exactly as before, so no pre-existing denial's evidence changes. When it
  // did NOT — a decision the anchor rule could not have produced at all — the
  // anchor cosine is low by definition, and publishing it as the confidence
  // would describe a strong model match as a weak anchor match in the audit
  // record. In that case the highest firing model score decides.
  const anchorFired = typeof result.matchedBy === 'string' && result.matchedBy.includes('anchor');
  const modelScores = [];
  if (result.headFired) modelScores.push(result.headScore);
  if (result.v9Fired) modelScores.push(result.v9Score);
  if (result.v5Fired) modelScores.push(result.v5Score);
  const decidingScore = (anchorFired || modelScores.length === 0)
    ? result.score
    : Math.max(...modelScores);
  const syntheticAggregate = {
    decision: DECISION.DENY,
    reason: SEMANTIC_REASONS.EMBEDDING_SIMILARITY_MATCH,
    score: decidingScore,
    topClassifier: { confidence: decidingScore },
    matched: [{
      id: GATE_CLASSIFIER_ID,
      reason: SEMANTIC_REASONS.EMBEDDING_SIMILARITY_MATCH,
      severity: SEVERITY.HIGH,
      confidence: decidingScore,
      weightedScore: decidingScore,
    }],
  };
  return {
    blocks: true,
    decision: DECISION.DENY,
    reason: SEMANTIC_REASONS.EMBEDDING_SIMILARITY_MATCH,
    evidence: buildSemanticEvidence({
      aggregateResult: syntheticAggregate, requestId, tenantId, provider, surface,
      engineStatus: ENGINE_STATUS.READY, registryStatus: 'OK', classifiersExecuted: 1, classifiersSucceeded: 1,
    }),
  };
}

/**
 * @param {string} text
 * @param {{requestId?, tenantId?, provider?, surface?}} ctx
 * @returns {Promise<{blocks:boolean, decision:string, reason:string|null, evidence:object}>}
 */
async function checkText(text, ctx = {}) {
  const { requestId = null, tenantId = null, provider = null, surface = 'REQUEST' } = ctx;
  const evidenceCtx = { requestId, tenantId, provider, surface };

  // The embedding layer is switched off (QODIQA_SEM_EMBEDDING_ENABLED=false): it never blocks; the rule engine already ran.
  if (embeddingConfig.EMBEDDING_ENABLED === false) return _allowResult(evidenceCtx);

  let result;
  try {
    result = await embeddingClassifier.classify(text);
  } catch {
    // Defense in depth: embeddingSimilarity.classify() is documented to
    // never throw (every failure path inside it already resolves to a
    // DENY-shaped return value) — but this gate must not trust that
    // blindly. An unexpected rejection here must still resolve to DENY,
    // never propagate as an uncaught exception up into the request path.
    return _denyInfraFailure('EMBEDDING_GATE_UNEXPECTED_ERROR', evidenceCtx);
  }

  if (result.engineStatus !== ENGINE_STATUS.READY) {
    const reason = result.failureReason || 'EMBEDDING_LAYER_UNKNOWN_FAILURE';
    // FT-2 is fail-closed, so a model or runtime fault does not degrade the
    // system quietly — it converts every eligible request into a DENY. That is
    // the correct safety behaviour and the WORST possible silent failure, so it
    // gets its own CRITICAL event and its own counter rather than being folded
    // into the generic infra-failure path. An operator seeing this is watching a
    // denial storm build.
    if (reason === 'FT2_SCORING_FAILED' || reason === 'FT2_SCORING_PRODUCED_NON_FINITE_RESULT') {
      metrics.semanticFt2FailuresTotal.inc({ reason });
      emit('CRITICAL', 'SEM_FT2_SCORING_FAILED', {
        requestId, tenantId, provider, surface, reason,
        impact: 'FAIL_CLOSED_DENY — every request reaching the FT-2 gate is being denied',
      });
    }
    // FT-3's own fail-closed surface. Same argument verbatim: this is the
    // WORST possible silent failure, so it gets its own CRITICAL event and its
    // own counter rather than folding into the generic infra-failure path.
    // Separate from FT-2's because in the swap configuration FT-3 is the gate
    // actually in the path — an operator must be able to tell which model is
    // producing the denial storm.
    if (reason === 'FT3_SCORING_FAILED' || reason === 'FT3_SCORING_PRODUCED_NON_FINITE_RESULT') {
      metrics.semanticFt3FailuresTotal.inc({ reason });
      emit('CRITICAL', 'SEM_FT3_SCORING_FAILED', {
        requestId, tenantId, provider, surface, reason,
        impact: 'FAIL_CLOSED_DENY — every request reaching the FT-3 gate is being denied',
      });
    }
    return _denyInfraFailure(reason, evidenceCtx);
  }

  // ── FT-2 observability ────────────────────────────────────────────────────
  // `ft2Consulted` is present only when the gate actually ran. Absent means the
  // band skipped it or the flag is off — neither is logged, so the band's whole
  // point (most traffic never touches the second model) is also its own noise
  // control.
  _ft2Eligible += 1;
  metrics.semanticFt2EligibleTotal.inc();
  if (result.ft2Consulted === true) {
    _ft2Consulted += 1;
    metrics.semanticFt2ConsultedTotal.inc({ fired: String(result.ft2Fired === true) });
    emit('INFO', 'SEM_FT2_CONSULTED', {
      requestId, tenantId, provider, surface,
      anchorScore: result.score,
      ft2Score: result.ft2Score,
      ft2Family: result.ft2Family || null,
      fired: result.ft2Fired === true,
      verdict: result.ft2Fired === true ? DECISION.DENY : DECISION.ALLOW,
    });
  }
  _observeFt2Rate();

  // ── FT-3 observability ────────────────────────────────────────────────────
  // Identical shape and identical noise control to FT-2's block above:
  // `ft3Consulted` is present only when the gate actually ran, so the band's
  // whole point (most traffic never touches the fine-tuned model) is also its
  // own log-volume control. Tracked independently of FT-2 so either gate can
  // be enabled, disabled or swapped without the other's counters going quiet.
  _ft3Eligible += 1;
  metrics.semanticFt3EligibleTotal.inc();
  if (result.ft3Consulted === true) {
    _ft3Consulted += 1;
    metrics.semanticFt3ConsultedTotal.inc({ fired: String(result.ft3Fired === true) });
    emit('INFO', 'SEM_FT3_CONSULTED', {
      requestId, tenantId, provider, surface,
      anchorScore: result.score,
      ft3Score: result.ft3Score,
      ft3Family: result.ft3Family || null,
      fired: result.ft3Fired === true,
      verdict: result.ft3Fired === true ? DECISION.DENY : DECISION.ALLOW,
    });
  }
  _observeFt3Rate();

  if (result.decision === DECISION.DENY) {
    return _denyMatch(result, evidenceCtx);
  }

  // ── tenant tighten-only embedding bar ────────────────────────────────
  // A tenant with a stored embedding.scoreThreshold (validated + clamped to
  // (0, SIMILARITY_THRESHOLD] — tenantSemanticRegistry.js) gets ONE
  // additional check on the anchor score classify() already computed: an
  // ALLOW whose score reaches the tenant's tighter bar becomes a DENY.
  // classify() itself — thresholds, families, gate set, FT flags — is
  // untouched, and a tenant without a config takes the unmodified return
  // below: byte-for-byte the pre-M-03 path. Registry failures fall through
  // to the default ALLOW (the measured baseline), never to a crash.
  try {
    const tenantSemanticRegistry = require('../tenancy/tenantSemanticRegistry');
    const tenantBar = tenantSemanticRegistry.getEmbeddingScoreThreshold(tenantId);
    if (tenantBar !== null && typeof result.score === 'number' && result.score >= tenantBar) {
      const entry = tenantSemanticRegistry.getConfig(tenantId);
      metrics.semanticTenantTightenedDenialsTotal.inc();
      emit('INFO', 'SEM_TENANT_TIGHTENED_DENY', {
        requestId, tenantId, provider, surface,
        anchorScore: result.score,
        tenantScoreThreshold: tenantBar,
        semanticConfigHash: entry?.hash ?? null,
      });
      const denied = _denyMatch({ ...result, matchedBy: 'tenant-tightened-anchor' }, evidenceCtx);
      return {
        ...denied,
        evidence: Object.freeze({
          ...denied.evidence,
          // evidence tagging — ties this denial to the exact tenant
          // config that produced it.
          semanticConfig: entry
            ? Object.freeze({ hash: entry.hash, version: entry.version, source: 'TENANT' })
            : null,
          tenantTightened: true,
          tenantScoreThreshold: tenantBar,
        }),
      };
    }
  } catch (err) {
    emit('ERROR', 'TENANT_EMBEDDING_OVERLAY_ERROR', { requestId, tenantId, surface, error: err && err.message });
  }

  const allow = _allowResult(evidenceCtx);
  // an ALLOW that exists only because the intent gate OVERRODE an ensemble DENY must be
  // distinguishable from an ALLOW the ensemble produced on its own — in the log, in the metrics, and in the audit entry's
  // semantic evidence (which aiChat.js writes into every ALLOW decision).
  if (result.intentGate === true) {
    metrics.semanticIntentGateOverridesTotal.inc({ frame: String(result.intentFrame || 'unknown') });
    emit('INFO', 'SEM_INTENT_GATE_OVERRIDE', {
      requestId, tenantId, provider, surface,
      intentFrame: result.intentFrame || null,
      originalMatchedBy: result.originalMatchedBy || null,
      anchorScore: result.score,
    });
    return {
      ...allow,
      evidence: Object.freeze({
        ...allow.evidence,
        intentGate: Object.freeze({
          overridden: true,
          frame: result.intentFrame || null,
          originalMatchedBy: result.originalMatchedBy || null,
          anchorScore: typeof result.score === 'number' ? Number(result.score.toFixed(4)) : null,
        }),
      }),
    };
  }
  return allow;
}

module.exports = { checkText, _resetFt2RateForTests, _resetFt3RateForTests };
