'use strict';

const { SEVERITY, DECISION } = require('../reasons');

/**
 * How much a classifier's declared severity discounts (or trusts) its raw
 * confidence when computing the score that decisions are actually made on.
 * A CRITICAL classifier's confidence passes through almost unchanged; a LOW
 * classifier's confidence is discounted, since by definition it is a weaker
 * signal even when it fires strongly.
 */
const SEVERITY_WEIGHT = Object.freeze({
  [SEVERITY.LOW]: 0.35,
  [SEVERITY.MEDIUM]: 0.6,
  [SEVERITY.HIGH]: 0.85,
  [SEVERITY.CRITICAL]: 1.0,
});

function weightedScore(confidence, severity) {
  const weight = SEVERITY_WEIGHT[severity] ?? SEVERITY_WEIGHT[SEVERITY.MEDIUM];
  return Math.min(1, Math.max(0, confidence) * weight);
}

/**
 * @param {number} score
 * @param {{WARN:number, REVIEW:number, DENY:number}} thresholds
 * @returns {string} one of DECISION.*
 */
function decisionForScore(score, thresholds) {
  if (score >= thresholds.DENY) return DECISION.DENY;
  if (score >= thresholds.REVIEW) return DECISION.REVIEW;
  if (score >= thresholds.WARN) return DECISION.WARN;
  return DECISION.ALLOW;
}

module.exports = { SEVERITY_WEIGHT, weightedScore, decisionForScore };
