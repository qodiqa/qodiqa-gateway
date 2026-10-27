'use strict';

/**
 * QODIQA Risk Scorer
 *
 * Computes a composite 0–100 risk score for each alert from:
 *   - Base severity weight
 *   - Subtype amplifiers (known-dangerous patterns get bonus points)
 *   - Confidence modifier (low-confidence detections are discounted)
 *   - Context amplifiers (cross-tenant, repeated offender, cluster member)
 *   - Temporal factors (occurred during low-traffic period = higher risk)
 *
 * Score → Severity mapping is defined in constants.js RISK_SCORE.THRESHOLDS.
 */

const { SEVERITY, ALERT_TYPE, REPLAY_SUBTYPE, SIGNATURE_SUBTYPE,
        POLICY_SUBTYPE, RISK_SCORE } = require('../constants');

// ── Base scores by severity ───────────────────────────────────────────────────

const BASE_SCORE = {
  [SEVERITY.INFO]:     10,
  [SEVERITY.LOW]:      25,
  [SEVERITY.MEDIUM]:   45,
  [SEVERITY.HIGH]:     65,
  [SEVERITY.CRITICAL]: 85,
};

// ── Subtype amplifiers — added to base score ──────────────────────────────────

const SUBTYPE_AMPLIFIER = {
  // Replay — cross-tenant is especially dangerous
  [REPLAY_SUBTYPE.CROSS_TENANT_REPLAY]:       20,
  [REPLAY_SUBTYPE.NONCE_REUSE]:               10,
  [REPLAY_SUBTYPE.DUPLICATE_ARTIFACT]:         8,
  [REPLAY_SUBTYPE.EXCESSIVE_RETRY]:            5,
  [REPLAY_SUBTYPE.EXPIRED_ARTIFACT]:           5,
  [REPLAY_SUBTYPE.REQUEST_BINDING_MISMATCH]:  12,

  // Signature — revoked key usage is an active attack indicator
  [SIGNATURE_SUBTYPE.REVOKED_KEY]:            15,
  [SIGNATURE_SUBTYPE.INVALID_SIGNATURE]:      10,
  [SIGNATURE_SUBTYPE.CORRUPTED_SIGNATURE]:    12,
  [SIGNATURE_SUBTYPE.UNKNOWN_KEY]:            10,
  [SIGNATURE_SUBTYPE.KEY_MISMATCH]:            8,
  [SIGNATURE_SUBTYPE.MULTIPLE_ACTIVE_KEYS]:    8,

  // Policy — invariant violations indicate active bypass
  [POLICY_SUBTYPE.INVARIANT_VIOLATED]:        20,
  [POLICY_SUBTYPE.BYPASS_ATTEMPT]:            18,
  [POLICY_SUBTYPE.FAIL_OPEN_DETECTED]:        15,
  [POLICY_SUBTYPE.DRIFT_DETECTED]:            10,
  [POLICY_SUBTYPE.LOAD_FAILURE]:              12,
};

// ── Context amplifiers (boolean flags in alert context) ───────────────────────

const CONTEXT_AMPLIFIERS = [
  { flag: 'crossTenant',       bonus: 15 },
  { flag: 'repeatedOffender',  bonus: 10 },
  { flag: 'clusterMember',     bonus:  8 },
  { flag: 'duringLowTraffic',  bonus:  5 },
  { flag: 'affectsMultipleKeys', bonus: 8 },
  { flag: 'privilegedActor',   bonus: 10 },
  { flag: 'knownBadIP',        bonus: 12 },
];

/**
 * Compute risk score and derive severity from it.
 *
 * @param {object} params
 * @param {string} params.severity      — Initial severity classification
 * @param {string} params.subtype       — Alert subtype
 * @param {number} [params.confidence]  — Detection confidence 0-100 (default 100)
 * @param {object} [params.context]     — Enriched context flags
 * @returns {{ riskScore: number, derivedSeverity: string, factors: object }}
 */
function computeRiskScore({ severity, subtype, confidence = 100, context = {} }) {
  let score = BASE_SCORE[severity] ?? BASE_SCORE[SEVERITY.MEDIUM];

  // Subtype amplifier
  const subtypeBonus = SUBTYPE_AMPLIFIER[subtype] ?? 0;
  score += subtypeBonus;

  // Context amplifiers
  const contextBonuses = {};
  for (const { flag, bonus } of CONTEXT_AMPLIFIERS) {
    if (context[flag]) {
      score += bonus;
      contextBonuses[flag] = bonus;
    }
  }

  // Confidence discount — low-confidence detections get penalized
  // confidence=100 → no penalty; confidence=50 → -10 points; confidence=0 → -20
  const confidenceDiscount = Math.round((1 - confidence / 100) * 20);
  score -= confidenceDiscount;

  // Clamp to [0, 100]
  score = Math.max(RISK_SCORE.MIN, Math.min(RISK_SCORE.MAX, Math.round(score)));

  return {
    riskScore: score,
    derivedSeverity: _scoreToSeverity(score),
    factors: {
      base: BASE_SCORE[severity] ?? 0,
      subtypeBonus,
      contextBonuses,
      confidenceDiscount: -confidenceDiscount,
      finalScore: score,
    },
  };
}

/**
 * Map numeric risk score back to a severity label.
 * Used to upgrade severity when context amplifiers push the score higher.
 */
function _scoreToSeverity(score) {
  const thresholds = RISK_SCORE.THRESHOLDS;
  if (score >= thresholds.CRITICAL.min) return SEVERITY.CRITICAL;
  if (score >= thresholds.HIGH.min)     return SEVERITY.HIGH;
  if (score >= thresholds.MEDIUM.min)   return SEVERITY.MEDIUM;
  if (score >= thresholds.LOW.min)      return SEVERITY.LOW;
  return SEVERITY.INFO;
}

/**
 * Compare two severity levels.
 * Returns positive if a > b, 0 if equal, negative if a < b.
 */
function compareSeverity(a, b) {
  const weights = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
  return (weights[a] ?? 0) - (weights[b] ?? 0);
}

/**
 * Returns the higher of two severity values.
 */
function maxSeverity(a, b) {
  return compareSeverity(a, b) >= 0 ? a : b;
}

module.exports = { computeRiskScore, compareSeverity, maxSeverity, BASE_SCORE };
