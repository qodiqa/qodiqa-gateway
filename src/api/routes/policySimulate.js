'use strict';

/**
 * Policy Simulation API — Component #40.
 *
 * All routes require ops-level authentication (mounted behind _opsIpAllow +
 * _opsAuth + _opsGate in server.js).
 *
 * Routes:
 *   POST /v1/policy/simulate        — single simulation
 *   POST /v1/policy/compare         — compare current vs proposed policy set
 *   POST /v1/policy/simulate/batch  — batch simulation (up to 100 items)
 *
 * All routes are read-only: no nonce, anomaly, audit, or rate-limit state is
 * mutated.  executionPrevented: true is always present in every response.
 */

const { Router } = require('express');
const {
  runSimulation,
  runComparison,
  runBatch,
  MAX_BATCH_SIZE,
} = require('../../core/simulation/simulationEngine');
const {
  simulationsTotal,
  simulationDurationMs,
  simulationFailuresTotal,
  policyComparisonsTotal,
  batchSimulationsTotal,
} = require('../../observability/metrics');
const { emit } = require('../../../services/logger');
const { success, failure, internalError } = require('../response');

// ── Router factory ────────────────────────────────────────────────────────────

/**
 * @param {function(): ReadonlyArray} getLivePolicies
 * @param {object} livePolicyStore  — { checkAndIncrement, getCount }
 * @returns {Router}
 */
function createPolicySimulateRouter(getLivePolicies, livePolicyStore) {
  const router = Router();

  // ── POST /v1/policy/simulate ───────────────────────────────────────────────
  router.post('/simulate', async (req, res) => {
    const reqId   = req.requestId ?? null;
    const startMs = Date.now();
    const { context, policies, scenario } = req.body || {};

    // Input guard: context must be an object if provided
    if (context !== undefined && (typeof context !== 'object' || context === null || Array.isArray(context))) {
      return failure(res, 'INVALID_CONTEXT', 'context must be a plain object', 400);
    }

    let result;
    try {
      result = await runSimulation({ context, policies, scenario }, getLivePolicies, livePolicyStore);
    } catch (err) {
      simulationFailuresTotal.inc({ reason: 'INTERNAL_ERROR' });
      return internalError(res, req, err, { label: 'SIMULATION_ROUTE_ERROR', code: 'INTERNAL_ERROR' });
    }

    simulationsTotal.inc({ decision: result.decision });
    simulationDurationMs.observe({}, Date.now() - startMs);
    if (result.decision === 'BLOCK') {
      simulationFailuresTotal.inc({ reason: result.reason });
    }

    return success(res, result, 200);
  });

  // ── POST /v1/policy/compare ───────────────────────────────────────────────
  router.post('/compare', async (req, res) => {
    const reqId = req.requestId ?? null;
    const { context, currentPolicies, proposedPolicies, scenario } = req.body || {};

    if (!Array.isArray(proposedPolicies)) {
      return failure(res, 'MISSING_PROPOSED_POLICIES', 'proposedPolicies is required and must be an array', 400);
    }
    if (context !== undefined && (typeof context !== 'object' || context === null || Array.isArray(context))) {
      return failure(res, 'INVALID_CONTEXT', 'context must be a plain object', 400);
    }

    let result;
    try {
      result = await runComparison({ context, currentPolicies, proposedPolicies, scenario }, getLivePolicies, livePolicyStore);
    } catch (err) {
      simulationFailuresTotal.inc({ reason: 'COMPARISON_ERROR' });
      if (err.code === 'COMPARISON_REQUIRES_PROPOSED_POLICIES') {
        emit('ERROR', 'COMPARISON_ROUTE_ERROR', { requestId: reqId, error: err.message });
        return failure(res, err.code, err.message, 400);
      }
      return internalError(res, req, err, { label: 'COMPARISON_ROUTE_ERROR', code: 'INTERNAL_ERROR' });
    }

    policyComparisonsTotal.inc({});
    simulationDurationMs.observe({}, 0);

    return success(res, result, 200);
  });

  // ── POST /v1/policy/simulate/batch ────────────────────────────────────────
  router.post('/simulate/batch', async (req, res) => {
    const reqId = req.requestId ?? null;
    const { simulations, policies } = req.body || {};

    if (!Array.isArray(simulations)) {
      return failure(res, 'MISSING_SIMULATIONS', 'simulations must be an array', 400);
    }
    if (simulations.length === 0) {
      return failure(res, 'EMPTY_BATCH', 'simulations array must not be empty', 400);
    }
    if (simulations.length > MAX_BATCH_SIZE) {
      return failure(res, 'BATCH_TOO_LARGE', `batch size ${simulations.length} exceeds maximum of ${MAX_BATCH_SIZE}`, 400);
    }

    const startMs = Date.now();
    let result;
    try {
      result = await runBatch({ simulations, policies }, getLivePolicies, livePolicyStore);
    } catch (err) {
      simulationFailuresTotal.inc({ reason: 'BATCH_ERROR' });
      if (err.code === 'BATCH_EXCEEDS_MAX' || err.code === 'BATCH_REQUIRES_SIMULATIONS') {
        emit('ERROR', 'BATCH_SIMULATION_ROUTE_ERROR', { requestId: reqId, error: err.message });
        return failure(res, err.code, err.message, 400);
      }
      return internalError(res, req, err, { label: 'BATCH_SIMULATION_ROUTE_ERROR', code: 'INTERNAL_ERROR' });
    }

    batchSimulationsTotal.inc({});
    simulationDurationMs.observe({}, Date.now() - startMs);

    return success(res, result, 200);
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createPolicySimulateRouter };
