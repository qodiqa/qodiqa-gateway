'use strict';

/**
 * Statistics Generator — Component #41
 *
 * Generates a comprehensive statistical summary of a QODIQA policy including:
 *   rule count, condition count, capability/resource/action inventories,
 *   operator usage, complexity score, risk level, and structural flags.
 *
 * Pure function — no state, no I/O.
 */

const { RISK_LEVELS, HIGH_RISK_ACTIONS, WILDCARD_VALUES } = require('./constants');

// ── Internal helpers ──────────────────────────────────────────────────────────

function _isWildcard(value) {
  if (typeof value === 'string' && WILDCARD_VALUES.has(value)) return true;
  if (Array.isArray(value) && value.some(v => WILDCARD_VALUES.has(String(v)))) return true;
  return false;
}

/**
 * Count conditions in a single rule (including nested group conditions).
 */
function _conditionsInRule(rule) {
  if (!rule || typeof rule !== 'object') return 0;
  if (rule.group && Array.isArray(rule.group.conditions)) {
    return rule.group.conditions.length;
  }
  return 1;
}

/**
 * Compute a numeric complexity score.
 *
 * Scoring rationale:
 *   - Each rule contributes 10 points (non-linear beyond 10 rules).
 *   - Nested condition groups: +5 per nested condition.
 *   - Wildcard values: +15 each (broad/risky).
 *   - Large in/notIn arrays: +2 per 3 values.
 *   - deny effect: +20 (inverted logic is harder to reason about).
 *   - Each parent policy (inheritance): +8 (additional evaluation path).
 *   - Rule count > 10: +20 flat bonus.
 *   - Rule count > 20: +30 additional flat bonus.
 */
function _computeComplexity(policy, ruleList) {
  let score = ruleList.length * 10;

  for (const rule of ruleList) {
    if (!rule) continue;
    if (rule.group && Array.isArray(rule.group.conditions)) {
      score += rule.group.conditions.length * 5;
    }
    if (_isWildcard(rule.value)) score += 15;
    if ((rule.operator === 'in' || rule.operator === 'notIn') && Array.isArray(rule.value)) {
      score += Math.floor(rule.value.length / 3) * 2;
    }
  }

  if (policy.effect === 'deny') score += 20;

  const parents = Array.isArray(policy.inherits) ? policy.inherits.length : 0;
  score += parents * 8;

  if (ruleList.length > 10) score += 20;
  if (ruleList.length > 20) score += 30;

  return score;
}

/**
 * Determine the aggregate risk level for a policy from its statistics.
 */
function _deriveRiskLevel(policy, stats) {
  if (policy.riskLevel === RISK_LEVELS.CRITICAL) return RISK_LEVELS.CRITICAL;
  if (policy.deprecated && policy.effect === 'allow') return RISK_LEVELS.CRITICAL;

  if (policy.expiresAt) {
    try {
      if (new Date(policy.expiresAt) < new Date()) return RISK_LEVELS.HIGH;
    } catch { /* ignore */ }
  }

  if (stats.wildcardCount   > 0) return RISK_LEVELS.HIGH;
  if (stats.highRiskActionCount > 0) return RISK_LEVELS.HIGH;
  if (stats.complexityScore > 120) return RISK_LEVELS.MEDIUM;
  if (stats.complexityScore > 60)  return RISK_LEVELS.MEDIUM;

  return policy.riskLevel || RISK_LEVELS.LOW;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a statistics object for a single policy.
 *
 * @param {object} policy
 * @returns {Readonly<object>}  — all fields are enumerated below
 */
function generateStatistics(policy) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new TypeError('generateStatistics: policy must be a plain object');
  }
  if (typeof policy.policyId !== 'string' || policy.policyId.trim() === '') {
    throw new TypeError('generateStatistics: policy.policyId must be a non-empty string');
  }

  const ruleList = Array.isArray(policy.rules) ? policy.rules : [];

  let conditionCount      = 0;
  let wildcardCount       = 0;
  let highRiskActionCount = 0;

  const capabilitiesSet = new Set(Array.isArray(policy.capabilities) ? policy.capabilities : []);
  const resourcesSet    = new Set(Array.isArray(policy.resources)    ? policy.resources    : []);
  const actionsSet      = new Set();
  const fieldsSet       = new Set();
  const operatorsSet    = new Set();

  for (const rule of ruleList) {
    if (!rule || typeof rule !== 'object') continue;

    conditionCount += _conditionsInRule(rule);

    if (rule.capability) capabilitiesSet.add(rule.capability);
    if (rule.resource)   resourcesSet.add(rule.resource);
    if (rule.action)     actionsSet.add(rule.action);
    if (rule.field)      fieldsSet.add(rule.field);
    if (rule.operator)   operatorsSet.add(rule.operator);

    if (_isWildcard(rule.value)) wildcardCount++;

    if (typeof rule.action === 'string' && HIGH_RISK_ACTIONS.has(rule.action.toLowerCase())) {
      highRiskActionCount++;
    }
    if (typeof rule.value === 'string' && HIGH_RISK_ACTIONS.has(rule.value.toLowerCase())) {
      highRiskActionCount++;
    }

    // Process nested group conditions
    if (rule.group && Array.isArray(rule.group.conditions)) {
      for (const cond of rule.group.conditions) {
        if (!cond || typeof cond !== 'object') continue;
        if (cond.field)    fieldsSet.add(cond.field);
        if (cond.operator) operatorsSet.add(cond.operator);
        if (_isWildcard(cond.value)) wildcardCount++;
      }
    }
  }

  const complexityScore = _computeComplexity(policy, ruleList);

  const partialStats = {
    wildcardCount,
    highRiskActionCount,
    complexityScore,
  };

  const riskLevel = _deriveRiskLevel(policy, partialStats);

  return Object.freeze({
    policyId:           policy.policyId,
    version:            policy.version   || 1,
    effect:             policy.effect    || 'allow',
    ruleCount:          ruleList.length,
    conditionCount,
    capabilityCount:    capabilitiesSet.size,
    resourceCount:      resourcesSet.size,
    actionCount:        actionsSet.size,
    fieldCount:         fieldsSet.size,
    operatorCount:      operatorsSet.size,
    wildcardCount,
    highRiskActionCount,
    complexityScore,
    riskLevel,
    deprecated:         !!policy.deprecated,
    expired:            policy.expiresAt
      ? (() => { try { return new Date(policy.expiresAt) < new Date(); } catch { return false; } })()
      : false,
    inheritanceDepth:   Array.isArray(policy.inherits) ? policy.inherits.length : 0,
    capabilities:       [...capabilitiesSet],
    resources:          [...resourcesSet],
    actions:            [...actionsSet],
    fields:             [...fieldsSet],
    operators:          [...operatorsSet],
  });
}

module.exports = { generateStatistics };
