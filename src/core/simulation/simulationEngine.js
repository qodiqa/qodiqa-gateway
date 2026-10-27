'use strict';

/**
 * QODIQA — Policy Simulation Engine (Component #40).
 *
 * Evaluates policy decisions deterministically without any execution side effects.
 * Reuses the production policy engine (services/policy/engine.js) — there is only
 * one source of truth for authorization logic.
 *
 * What simulation NEVER does:
 *   ✗  provider execution               ✗  nonce registration
 *   ✗  webhook delivery                 ✗  audit record writes
 *   ✗  streaming / SSE connections      ✗  rate-limit counter increments
 *   ✗  artifact commitment              ✗  external network calls
 *
 * What simulation ALWAYS does:
 *   ✓  reads the same policy set as the live enforcement path
 *   ✓  passes context through the same engine.evaluate() call
 *   ✓  uses a dry-run policy store (reads only, never increments)
 *   ✓  respects organization and tenant boundaries
 *   ✓  returns a deterministic, structured simulation report
 */

const crypto  = require('crypto');
const { evaluate }           = require('../../../services/policy/engine');
const { validateAndPrepare } = require('../../../services/policy/loader');
const { computePolicyHash }  = require('../../../services/policyHash');
const { makeDryRunPolicyStore } = require('../../validation/dryRunStores');
const { assertActiveOrganization } = require('../organizations/organizationRegistry');
const { emit } = require('../../../services/logger');

// ── Risk classification ───────────────────────────────────────────────────────

const _RISK_MAP = Object.freeze({
  ALL_CHECKS_PASSED:          'LOW',
  CONSENT_STORE_UNAVAILABLE:  'MEDIUM',
  CONSENT_REQUIRED:           'MEDIUM',
  CONSENT_NOT_FOUND:          'MEDIUM',
  CONSENT_MISSING:            'MEDIUM',
  CONSENT_CONTEXT_INCOMPLETE: 'MEDIUM',
  CONSENT_EVALUATION_ERROR:   'MEDIUM',
  RATE_LIMITED:               'MEDIUM',
  TIME_WINDOW_DENIED:         'MEDIUM',
  POLICY_BLOCKED:             'MEDIUM',
  IP_BLOCKED:                 'HIGH',
  ANOMALY_DETECTED:           'HIGH',
  EVALUATOR_MISSING:          'HIGH',
  EVALUATOR_ERROR:            'HIGH',
  INVALID_CONTEXT:            'HIGH',
  NO_POLICIES_LOADED:         'HIGH',
  NO_ENABLED_POLICIES:        'HIGH',
  INVALID_POLICY_SET:         'HIGH',
  POLICY_STATE_UNAVAILABLE:   'HIGH',
  ORG_SUSPENDED:              'HIGH',
  ORG_DISABLED:               'HIGH',
});

function _classifyRisk(decision, reason) {
  if (decision === 'EXECUTE') return 'LOW';
  return _RISK_MAP[reason] || 'MEDIUM';
}

// ── Evaluation trace ──────────────────────────────────────────────────────────

/**
 * Build a deterministic evaluation trace from the engine result and enabled policy array.
 *
 * The engine evaluates policies in priority order and stops at the first DENY.
 * From the single-pass result we derive:
 *   - EXECUTE: all enabled policies → PASSED
 *   - BLOCK with known policyId: policies before it → PASSED, it → BLOCKED, after → SKIPPED
 *   - BLOCK with policyId='SYSTEM': no policy-level evaluation (system guard fired)
 *
 * @param {{ decision: string, reason: string, policyId: string }} result
 * @param {ReadonlyArray} enabledPolicies — priority-sorted, enabled policies
 * @returns {Array<TraceEntry>}
 */
function _buildTrace(result, enabledPolicies) {
  // EXECUTE: all enabled policies were evaluated and passed
  if (result.decision === 'EXECUTE') {
    return enabledPolicies.map(p => ({
      policyId: p.id, type: p.type, priority: p.priority,
      outcome: 'PASSED', skipped: false,
    }));
  }

  // System-level block (NO_POLICIES_LOADED, NO_ENABLED_POLICIES, INVALID_CONTEXT):
  // no individual policy was reached — return empty trace
  if (result.policyId === 'SYSTEM') {
    return [];
  }

  // Policy-level block: identify the blocking policy position in the sorted array
  const blockIdx = enabledPolicies.findIndex(p => p.id === result.policyId);
  if (blockIdx === -1) {
    // Defensive: policyId not found in enabled array (shouldn't happen)
    return enabledPolicies.map(p => ({
      policyId: p.id, type: p.type, priority: p.priority,
      outcome: 'UNKNOWN', skipped: false,
    }));
  }

  return enabledPolicies.map((p, i) => {
    if (i < blockIdx) {
      return { policyId: p.id, type: p.type, priority: p.priority, outcome: 'PASSED',  skipped: false };
    }
    if (i === blockIdx) {
      return { policyId: p.id, type: p.type, priority: p.priority, outcome: 'BLOCKED', skipped: false, reason: result.reason };
    }
    return { policyId: p.id, type: p.type, priority: p.priority, outcome: 'SKIPPED', skipped: true };
  });
}

function _buildExplanation(result, enabledPolicies) {
  if (result.decision === 'EXECUTE') {
    return `All ${enabledPolicies.length} enabled policy rule(s) passed. Execution would be permitted.`;
  }
  if (result.policyId === 'SYSTEM') {
    return `System-level block: ${result.reason}. No individual policy evaluation occurred.`;
  }
  const p = enabledPolicies.find(pol => pol.id === result.policyId);
  if (p) {
    return `Blocked by policy "${result.policyId}" (type: ${p.type}, priority: ${p.priority}). Reason: ${result.reason}.`;
  }
  return `Blocked by policy "${result.policyId}". Reason: ${result.reason}.`;
}

// ── Shared policy resolution ──────────────────────────────────────────────────

function _resolvePolicies(rawPolicies, getLivePolicies) {
  if (rawPolicies !== undefined) {
    if (!Array.isArray(rawPolicies)) {
      throw Object.assign(new Error('policies must be an array'), { code: 'INVALID_POLICY_SET' });
    }
    // Validate draft/proposed policies with the same loader used in production
    let prepared;
    try {
      prepared = validateAndPrepare({ policies: rawPolicies });
    } catch (err) {
      throw Object.assign(new Error(err.message), { code: 'INVALID_POLICY_SET' });
    }
    return { policies: prepared, policyVersion: 'provided' };
  }

  // Use live policy set
  const policies = getLivePolicies();
  return { policies, policyVersion: 'current' };
}

// ── Org + tenant boundary check ───────────────────────────────────────────────

function _checkOrgBoundary(tenantId) {
  if (!tenantId) return { valid: true, organizationId: null };
  return assertActiveOrganization(tenantId);
}

// ── Core simulation ───────────────────────────────────────────────────────────

/**
 * Run a single policy simulation.
 *
 * @param {{
 *   context?:      { userId?, action?, tenantId?, requestId?, ip?, timestamp? }
 *   policies?:     Array        — draft/proposed; omit to use live policy set
 *   scenario?:     string       — human-readable label for the simulation
 *   _policyStore?: object       — dry-run store override (tests only)
 * }} opts
 * @param {function(): ReadonlyArray} getLivePolicies
 * @param {object} livePolicyStore  — { checkAndIncrement, getCount }
 * @returns {Promise<SimulationResult>}
 */
async function runSimulation(opts, getLivePolicies, livePolicyStore) {
  const startMs      = Date.now();
  const simulationId = crypto.randomUUID();
  const { context: rawCtx = {}, policies: rawPolicies, scenario, _policyStore } = opts || {};

  // ── Resolve policy set ──────────────────────────────────────────────────────
  let policies, policyVersion, policyHash;
  try {
    ({ policies, policyVersion } = _resolvePolicies(rawPolicies, getLivePolicies));
    policyHash = computePolicyHash(policies);
  } catch (err) {
    return _errorResult(simulationId, startMs, err.code || 'INVALID_POLICY_SET', err.message, scenario);
  }

  // ── Org boundary check ──────────────────────────────────────────────────────
  const tenantId = (typeof rawCtx.tenantId === 'string' && rawCtx.tenantId) ? rawCtx.tenantId : null;
  let organizationId = null;

  if (tenantId) {
    const orgResult = _checkOrgBoundary(tenantId);
    if (!orgResult.valid) {
      return _orgBlockResult(simulationId, startMs, orgResult.reason, tenantId, policyVersion, policyHash, scenario);
    }
    organizationId = orgResult.organizationId;
  }

  // ── Build policy context ────────────────────────────────────────────────────
  // artifact.valid is true: simulation assumes the artifact layer is valid.
  // It tests policy logic, not signature verification (that is /verify/v2's job).
  const policyCtx = {
    artifact:  { valid: true },
    userId:    (typeof rawCtx.userId    === 'string' && rawCtx.userId)    ? rawCtx.userId    : null,
    action:    (typeof rawCtx.action    === 'string' && rawCtx.action)    ? rawCtx.action    : null,
    tenantId:  tenantId,
    requestId: (typeof rawCtx.requestId === 'string' && rawCtx.requestId) ? rawCtx.requestId : simulationId,
    ip:        (typeof rawCtx.ip        === 'string' && rawCtx.ip)        ? rawCtx.ip        : null,
    timestamp: (typeof rawCtx.timestamp === 'number')                     ? rawCtx.timestamp : undefined,
  };

  // ── Dry-run policy store ────────────────────────────────────────────────────
  // Reads rate-limit counters but NEVER increments them.
  const dryStore = _policyStore !== undefined
    ? _policyStore
    : makeDryRunPolicyStore(livePolicyStore);

  // ── Policy evaluation ───────────────────────────────────────────────────────
  let engineResult;
  try {
    engineResult = await evaluate(policyCtx, policies, dryStore, { requestId: simulationId });
  } catch (err) {
    return _errorResult(simulationId, startMs, 'SIMULATION_ERROR', err.message, scenario);
  }

  // ── Build trace and report ──────────────────────────────────────────────────
  const enabledPolicies = policies.filter(p => p.enabled === true);
  const trace           = _buildTrace(engineResult, enabledPolicies);
  const matchedRules    = trace.filter(t => t.outcome === 'PASSED').map(({ policyId, type, priority }) => ({ policyId, type, priority }));
  const failedRules     = trace.filter(t => t.outcome === 'BLOCKED').map(({ policyId, type, priority, reason }) => ({ policyId, type, priority, reason }));
  const durationMs      = Date.now() - startMs;

  emit('INFO', 'SIMULATION_COMPLETED', {
    simulationId,
    decision:      engineResult.decision,
    reason:        engineResult.reason,
    policyId:      engineResult.policyId,
    policyVersion,
    tenantId,
    organizationId,
    durationMs,
  });

  return Object.freeze({
    simulationId,
    decision:          engineResult.decision,
    reason:            engineResult.reason,
    policyId:          engineResult.policyId,
    policyVersion,
    policyHash,
    tenantId,
    organizationId,
    riskLevel:         _classifyRisk(engineResult.decision, engineResult.reason),
    matchedRules,
    failedRules,
    evaluationTrace:   trace,
    explanation:       _buildExplanation(engineResult, enabledPolicies),
    executionPrevented: true,
    durationMs,
    scenario:          scenario || null,
  });
}

// ── Policy comparison ─────────────────────────────────────────────────────────

/**
 * Compare two policy sets against the same context and report what changed.
 *
 * currentPolicies is optional — if omitted, the live policy set is used.
 * proposedPolicies is required.
 *
 * @param {{
 *   context?:          object
 *   currentPolicies?:  Array   — omit to use live
 *   proposedPolicies:  Array   — required
 *   scenario?:         string
 *   _policyStore?:     object
 * }} opts
 * @param {function(): ReadonlyArray} getLivePolicies
 * @param {object} livePolicyStore
 * @returns {Promise<PolicyComparisonResult>}
 */
async function runComparison(opts, getLivePolicies, livePolicyStore) {
  const { context, currentPolicies, proposedPolicies, scenario, _policyStore } = opts || {};

  if (!Array.isArray(proposedPolicies)) {
    throw Object.assign(new Error('proposedPolicies is required and must be an array'), { code: 'COMPARISON_REQUIRES_PROPOSED_POLICIES' });
  }

  const [oldResult, newResult] = await Promise.all([
    runSimulation({ context, policies: currentPolicies, scenario: scenario ? `${scenario}:current`  : 'current',  _policyStore }, getLivePolicies, livePolicyStore),
    runSimulation({ context, policies: proposedPolicies, scenario: scenario ? `${scenario}:proposed` : 'proposed', _policyStore }, getLivePolicies, livePolicyStore),
  ]);

  const changedRules  = _diffPolicyTraces(oldResult.evaluationTrace, newResult.evaluationTrace);
  const decisionChanged = oldResult.decision !== newResult.decision;

  return Object.freeze({
    comparison:    true,
    scenario:      scenario || null,
    decisionChanged,
    old: Object.freeze({
      decision:    oldResult.decision,
      reason:      oldResult.reason,
      policyId:    oldResult.policyId,
      policyHash:  oldResult.policyHash,
      riskLevel:   oldResult.riskLevel,
      explanation: oldResult.explanation,
    }),
    proposed: Object.freeze({
      decision:    newResult.decision,
      reason:      newResult.reason,
      policyId:    newResult.policyId,
      policyHash:  newResult.policyHash,
      riskLevel:   newResult.riskLevel,
      explanation: newResult.explanation,
    }),
    changedRules,
    tenantId:          oldResult.tenantId,
    organizationId:    oldResult.organizationId,
    executionPrevented: true,
  });
}

/**
 * Compute which policy outcomes differ between two evaluation traces.
 *
 * @param {Array} oldTrace
 * @param {Array} newTrace
 * @returns {Array<{ policyId, change, oldOutcome, newOutcome }>}
 */
function _diffPolicyTraces(oldTrace, newTrace) {
  const oldMap = new Map(oldTrace.map(t => [t.policyId, t]));
  const newMap = new Map(newTrace.map(t => [t.policyId, t]));
  const allIds = new Set([...oldMap.keys(), ...newMap.keys()]);
  const changes = [];

  for (const id of allIds) {
    const o = oldMap.get(id);
    const n = newMap.get(id);
    if (!o) {
      changes.push({ policyId: id, change: 'ADDED',           oldOutcome: null,       newOutcome: n.outcome });
    } else if (!n) {
      changes.push({ policyId: id, change: 'REMOVED',         oldOutcome: o.outcome,  newOutcome: null });
    } else if (o.outcome !== n.outcome) {
      changes.push({ policyId: id, change: 'OUTCOME_CHANGED', oldOutcome: o.outcome,  newOutcome: n.outcome });
    }
  }
  return changes;
}

// ── Batch simulation ──────────────────────────────────────────────────────────

const MAX_BATCH_SIZE = 100;

/**
 * Run up to 100 simulations concurrently.
 * Each simulation is fully isolated — results are independent.
 *
 * @param {{
 *   simulations: Array<{ context?, policies?, scenario? }>
 *   policies?:   Array   — shared policy set (overridden per-item if item.policies is set)
 *   _policyStore?: object
 * }} opts
 * @param {function(): ReadonlyArray} getLivePolicies
 * @param {object} livePolicyStore
 * @returns {Promise<BatchSimulationResult>}
 */
async function runBatch(opts, getLivePolicies, livePolicyStore) {
  const { simulations, policies: sharedPolicies, _policyStore } = opts || {};

  if (!Array.isArray(simulations) || simulations.length === 0) {
    throw Object.assign(new Error('simulations must be a non-empty array'), { code: 'BATCH_REQUIRES_SIMULATIONS' });
  }
  if (simulations.length > MAX_BATCH_SIZE) {
    throw Object.assign(new Error(`batch size ${simulations.length} exceeds maximum of ${MAX_BATCH_SIZE}`), { code: 'BATCH_EXCEEDS_MAX' });
  }

  const batchId = crypto.randomUUID();
  const startMs = Date.now();

  const results = await Promise.all(
    simulations.map(sim => runSimulation(
      {
        context:    sim.context  || {},
        policies:   sim.policies !== undefined ? sim.policies : sharedPolicies,
        scenario:   sim.scenario || null,
        _policyStore,
      },
      getLivePolicies,
      livePolicyStore,
    ))
  );

  const totalDurationMs = Date.now() - startMs;
  const allowCount      = results.filter(r => r.decision === 'EXECUTE').length;
  const blockCount      = results.filter(r => r.decision === 'BLOCK').length;

  return Object.freeze({
    batchId,
    total:          results.length,
    allowed:        allowCount,
    blocked:        blockCount,
    totalDurationMs,
    results,
    executionPrevented: true,
  });
}

// ── Private helpers ───────────────────────────────────────────────────────────

function _errorResult(simulationId, startMs, reason, message, scenario) {
  emit('WARN', 'SIMULATION_FAILED', { simulationId, reason, message });
  return Object.freeze({
    simulationId,
    decision:          'BLOCK',
    reason,
    policyId:          'SYSTEM',
    policyVersion:     'unknown',
    policyHash:        null,
    tenantId:          null,
    organizationId:    null,
    riskLevel:         'HIGH',
    matchedRules:      [],
    failedRules:       [{ policyId: 'SYSTEM', reason, message: message || reason }],
    evaluationTrace:   [],
    explanation:       message || reason,
    executionPrevented: true,
    durationMs:        Date.now() - startMs,
    scenario:          scenario || null,
  });
}

function _orgBlockResult(simulationId, startMs, reason, tenantId, policyVersion, policyHash, scenario) {
  emit('WARN', 'SIMULATION_ORG_BLOCKED', { simulationId, reason, tenantId });
  return Object.freeze({
    simulationId,
    decision:          'BLOCK',
    reason,
    policyId:          'SYSTEM',
    policyVersion,
    policyHash,
    tenantId,
    organizationId:    null,
    riskLevel:         'HIGH',
    matchedRules:      [],
    failedRules:       [{ policyId: 'SYSTEM', reason }],
    evaluationTrace:   [],
    explanation:       `Organization check failed before policy evaluation: ${reason}.`,
    executionPrevented: true,
    durationMs:        Date.now() - startMs,
    scenario:          scenario || null,
  });
}

module.exports = {
  runSimulation,
  runComparison,
  runBatch,
  // Exported for tests
  _buildTrace,
  _diffPolicyTraces,
  MAX_BATCH_SIZE,
};
