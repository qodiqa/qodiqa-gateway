'use strict';

const REGISTRY                          = require('./evaluators/index');
const { validateContext, PolicyContextError } = require('./context');
const { logDecision, logError }         = require('./log');
const { computeRuleHash }               = require('../policyHash');
const decisionCache                     = require('./decisionCache');   //

// TRACE-2 remediation: engine version is now stamped on every decision so
// the audit/evidence chains can record exactly which engine build produced
// a decision — mirrors the pattern already used by src/core/semantic/'s
// `engineVersion: '1.0.0'`.
const ENGINE_VERSION = '1.0.0';

// Builds a frozen decision object. `policyId`/`decision`/`reason` keep their
// existing meaning and values unchanged (including the 'SYSTEM' sentinel for
// guard-clause and full-ALLOW decisions) — everything else is additive
// (TRACE-2): policyVersion of the specific rule that decided (null when no
// single rule decided, e.g. full ALLOW or a pre-evaluation guard),
// engineVersion, a per-decision evaluatedAt timestamp, the ordered
// evaluationPath of every policy actually evaluated, and any consent
// provenance surfaced by a REQUIRE_CONSENT evaluator along the way.
function _decision(decision, reason, policyId, extra = {}) {
  return Object.freeze({
    decision,
    reason,
    policyId,
    policyVersion:     extra.policyVersion     ?? null,
    // TRACE-4: hash of the specific rule that decided (BLOCK only — see
    // evaluate() below for why ALLOW/'SYSTEM' has no single deciding rule).
    policyRuleHash:    extra.policyRuleHash    ?? null,
    engineVersion:     ENGINE_VERSION,
    evaluatedAt:       new Date().toISOString(),
    evaluationPath:    extra.evaluationPath    ?? [],
    consentProvenance: extra.consentProvenance ?? null,
  });
}

// TRACE-4: best-effort — a rule whose content can't be canonicalized (e.g.
// a poisoned/malformed config that slipped past the loader) must not crash
// evaluation just to compute an auxiliary companion hash. Falls back to
// null, matching policyRuleHash's existing "null when not determinable"
// contract for ALLOW/SYSTEM decisions.
function _safeRuleHash(policy) {
  try { return computeRuleHash(policy); } catch { return null; }
}

/**
 * Evaluate a request context against a pre-loaded policy set.
 *
 * Fail-closed at every layer:
 *   - invalid/missing context          → DENY INVALID_CONTEXT
 *   - null or empty policy array       → DENY NO_POLICIES_LOADED
 *   - all policies disabled            → DENY NO_ENABLED_POLICIES
 *   - missing evaluator for type       → DENY EVALUATOR_MISSING
 *   - evaluator throws                 → DENY EVALUATOR_ERROR
 *   - evaluator returns non-pass       → BLOCK <reason from evaluator>
 *   - RATE_LIMIT store op throws       → treated as over limit (blocked);
 *                                         see evaluators/rateLimit.js
 *
 * RATE_LIMIT policies are admitted atomically: the evaluator calls
 * store.checkAndIncrement() directly inside this loop, which reads the
 * counter, decides admission, and increments in one atomic Redis operation.
 * There is no pre-evaluation snapshot read and no post-evaluation commit
 * phase — the admission decision *is* the store write, so concurrent
 * requests can never observe and act on the same stale count.
 *
 * @param {unknown}       rawContext  - unsanitised input from the caller
 * @param {ReadonlyArray} policies    - output of policyLoader.loadPolicies()
 * @param {object}        [store]     - { checkAndIncrement } (sync or async)
 * @param {object}        [meta]      - { requestId } for structured logging
 * @returns {Promise<{ decision: 'EXECUTE'|'BLOCK', reason: string, policyId: string,
 *   policyVersion: number|null, policyRuleHash: string|null, engineVersion: string,
 *   evaluatedAt: string, evaluationPath: object[], consentProvenance: object|null }>}
 *   (TRACE-2) evaluationPath records every policy actually evaluated, in
 *   order — the complete path on ALLOW (every enabled policy had to pass),
 *   truncated at the blocking rule on BLOCK (later rules never ran).
 *   consentProvenance is hoisted from any REQUIRE_CONSENT evaluator's result
 *   — the last one encountered wins if more than one fires in a single
 *   evaluation (uncommon but not prevented by policy config).
 *   (TRACE-4) each evaluationPath entry also carries `ruleHash` — a
 *   deterministic, independently-recomputable hash of that specific rule's
 *   canonical content (see services/policyHash.js computeRuleHash) — and
 *   the top-level `policyRuleHash` mirrors the deciding rule's hash on
 *   BLOCK. null on ALLOW/'SYSTEM': every enabled rule had to pass, so there
 *   is no single "deciding" rule to hash, the same reasoning already
 *   applied to `policyVersion: null` for that case.
 */
async function evaluate(rawContext, policies, store, meta = {}) {
  // ── 1. Validate context ───────────────────────────────────────────────────
  let context;
  try {
    context = validateContext(rawContext);
  } catch (err) {
    const d = _decision('BLOCK', 'INVALID_CONTEXT', 'SYSTEM');
    logError('INVALID_CONTEXT', meta);
    logDecision(d, meta);
    return d;
  }

  // ── 2. Guard: policy array ────────────────────────────────────────────────
  if (!Array.isArray(policies) || policies.length === 0) {
    const d = _decision('BLOCK', 'NO_POLICIES_LOADED', 'SYSTEM');
    logDecision(d, meta);
    return d;
  }

  const enabled = policies.filter(p => p && p.enabled === true);
  if (enabled.length === 0) {
    const d = _decision('BLOCK', 'NO_ENABLED_POLICIES', 'SYSTEM');
    logDecision(d, meta);
    return d;
  }

  // ── 3. Evaluation loop — first DENY wins ──────────────────────────────────
  decisionCache.observeSet(policies);   // a changed policy set drops every cached rule result
  const evaluationPath = [];
  let consentProvenance = null;

  let idx = 0;
  while (idx < enabled.length) {
    const policy = enabled[idx];

    // Batch path (item 16): collapse a run of >=2 consecutive enabled
    // RATE_LIMIT policies into one store round trip via evaluateBatch().
    // Only triggers when the registry evaluator exposes evaluateBatch AND
    // the store exposes checkAndIncrementBatch — every other policy type,
    // and any lone RATE_LIMIT policy, takes the unchanged single-evaluator
    // path below. See evaluators/rateLimit.js#evaluateBatch for why this
    // reproduces the sequential loop's short-circuit semantics exactly.
    if (policy.type === 'RATE_LIMIT') {
      let end = idx + 1;
      while (end < enabled.length && enabled[end].type === 'RATE_LIMIT') end++;
      const batchEvaluator = REGISTRY.RATE_LIMIT;
      if (end - idx >= 2
          && typeof batchEvaluator?.evaluateBatch === 'function'
          && typeof store?.checkAndIncrementBatch === 'function') {
        const run = enabled.slice(idx, end);
        let results;
        try {
          results = await batchEvaluator.evaluateBatch(context, run.map(p => p.config), store);
        } catch (err) {
          logError('EVALUATOR_ERROR', { requestId: meta.requestId, policyId: run[0].id, error: err.message });
          const rh0 = _safeRuleHash(run[0]);
          evaluationPath.push({ policyId: run[0].id, policyVersion: run[0].currentVersion ?? null, type: 'RATE_LIMIT', result: 'BLOCK', reason: 'EVALUATOR_ERROR', ruleHash: rh0 });
          const d = _decision('BLOCK', 'EVALUATOR_ERROR', run[0].id, { policyVersion: run[0].currentVersion ?? null, policyRuleHash: rh0, evaluationPath, consentProvenance });
          logDecision(d, { ...meta, userId: context.userId });
          return d;
        }

        for (let k = 0; k < results.length; k++) {
          const p            = run[k];
          const policyVersion = p.currentVersion ?? null;
          const ruleHash      = _safeRuleHash(p);
          const r             = results[k];

          if (!r || r.pass !== true) {
            const reason = (typeof r?.reason === 'string' && r.reason) ? r.reason : 'POLICY_BLOCKED';
            evaluationPath.push({ policyId: p.id, policyVersion, type: 'RATE_LIMIT', result: 'BLOCK', reason, ruleHash });
            const d = _decision('BLOCK', reason, p.id, { policyVersion, policyRuleHash: ruleHash, evaluationPath, consentProvenance });
            logDecision(d, { ...meta, userId: context.userId });
            return d;
          }
          evaluationPath.push({ policyId: p.id, policyVersion, type: 'RATE_LIMIT', result: 'PASS', reason: r.reason ?? null, ruleHash });
        }

        idx = end;
        continue;
      }
    }

    // ── Single-evaluator path (unchanged) ─────────────────────────────────
    const evaluator     = REGISTRY[policy.type];
    const policyVersion = policy.currentVersion ?? null;

    const ruleHash = _safeRuleHash(policy);

    if (!evaluator || typeof evaluator.evaluate !== 'function') {
      evaluationPath.push({ policyId: policy.id, policyVersion, type: policy.type, result: 'BLOCK', reason: 'EVALUATOR_MISSING', ruleHash });
      const d = _decision('BLOCK', 'EVALUATOR_MISSING', policy.id, { policyVersion, policyRuleHash: ruleHash, evaluationPath, consentProvenance });
      logDecision(d, { ...meta, userId: context.userId });
      return d;
    }

    let result;
    try {
      result = await Promise.resolve(decisionCache.run(policy, ruleHash, evaluator, context, store));   // pure rule types only
    } catch (err) {
      logError('EVALUATOR_ERROR', { requestId: meta.requestId, policyId: policy.id, error: err.message });
      evaluationPath.push({ policyId: policy.id, policyVersion, type: policy.type, result: 'BLOCK', reason: 'EVALUATOR_ERROR', ruleHash });
      const d = _decision('BLOCK', 'EVALUATOR_ERROR', policy.id, { policyVersion, policyRuleHash: ruleHash, evaluationPath, consentProvenance });
      logDecision(d, { ...meta, userId: context.userId });
      return d;
    }

    if (result?.provenance?.consent) consentProvenance = result.provenance.consent;

    if (!result || result.pass !== true) {
      const reason = (typeof result?.reason === 'string' && result.reason) ? result.reason : 'POLICY_BLOCKED';
      evaluationPath.push({ policyId: policy.id, policyVersion, type: policy.type, result: 'BLOCK', reason, ruleHash });
      const d = _decision('BLOCK', reason, policy.id, { policyVersion, policyRuleHash: ruleHash, evaluationPath, consentProvenance });
      logDecision(d, { ...meta, userId: context.userId });
      return d;
    }

    evaluationPath.push({ policyId: policy.id, policyVersion, type: policy.type, result: 'PASS', reason: result.reason ?? null, ruleHash });
    idx++;
  }

  // ── 4. All passed ──────────────────────────────────────────────────────────
  const d = _decision('EXECUTE', 'ALL_CHECKS_PASSED', 'SYSTEM', { evaluationPath, consentProvenance });
  logDecision(d, meta);
  return d;
}

module.exports = { evaluate };
