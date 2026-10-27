'use strict';

const { weightedScore, decisionForScore } = require('./confidence');
const { DECISION } = require('../reasons');

/**
 * Aggregate independent classifier results into one final semantic decision.
 *
 * Multiple classifiers may fire simultaneously on the same prompt (e.g. a
 * jailbreak attempt that also contains a credential-extraction request).
 * The engine's decision is driven by the single highest weighted score —
 * the worst finding wins, so one high-confidence CRITICAL match is never
 * diluted by averaging it against several unrelated low-confidence
 * classifiers that also happened to fire. Every classifier that met at
 * least the WARN threshold is retained in `matched` for the evidence trail,
 * so the full signal picture — not just the winner — is auditable.
 *
 * @param {Array<{id,confidence,severity,reason,evidence}>} results
 * @param {{thresholds:{WARN:number,REVIEW:number,DENY:number}}} policy
 */
function aggregate(results, policy) {
  const scored = results
    .filter(Boolean)
    .map((r) => ({ ...r, weightedScore: weightedScore(r.confidence, r.severity) }))
    .sort((a, b) => b.weightedScore - a.weightedScore);

  if (!scored.length) {
    return {
      decision: DECISION.ALLOW,
      score: 0,
      reason: null,
      matched: [],
      topClassifier: null,
      allResults: [],
    };
  }

  const top = scored[0];
  const decision = decisionForScore(top.weightedScore, policy.thresholds);

  return {
    decision,
    score: top.weightedScore,
    reason: decision === DECISION.ALLOW ? null : top.reason,
    matched: scored.filter((r) => r.weightedScore >= policy.thresholds.WARN),
    topClassifier: top,
    allResults: scored,
  };
}

module.exports = { aggregate };
