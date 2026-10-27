'use strict';

/**
 * Safe cache for policy rule results.
 *
 * What is cached: the PASS/BLOCK result of a rule whose evaluator is a pure function of the evaluation context - BLOCK_IP, TIME_WINDOW and ABAC (the latter also reads the
 * deployment's operational mode, which is part of the key). Everything else is NEVER cached and always runs: REQUIRE_CONSENT (consent can be revoked at any moment), RATE_LIMIT
 * and every other stateful or unknown type. A thrown error is never cached.
 *
 * Why it cannot serve a stale answer:
 *   - the key starts with the rule's own content hash (computeRuleHash), so a rule that changes in any way, or is replaced, has a new key and can never hit an old entry;
 *   - the key carries every context field a rule can read (ip, timestamp to the second, user, caller, tenant, action, attributes) and the operational mode;
 *   - the whole cache is also dropped the moment the hash of the enabled policy set changes (policyHash), so retired rules do not linger.
 * The engine still evaluates the rules in the same order and builds the same evaluationPath; only the evaluator call is skipped on a hit.
 *
 * Opt-in: QODIQA_POLICY_DECISION_CACHE=true (default off, see enabled()). Bounded: 5,000 entries, least recently used out first.
 */

const crypto = require('crypto');
const { computePolicyHash } = require('../policyHash');

const PURE = new Set(['BLOCK_IP', 'TIME_WINDOW', 'ABAC']);
const MAX_ENTRIES = 5000;

const entries = new Map();            // key -> { pass, reason }
let currentSetHash = null;
const setHashes = new WeakMap();      // policy array -> hash (the loader hands out immutable arrays)
const counters = { hits: 0, misses: 0, bypass: 0, invalidations: 0 };

// F8V-11: OFF by default - measured, the cache is not faster than evaluating these cheap rules (182 vs 136 microseconds per evaluation) and gets no hits when tenants with different
// policy sets alternate. It stays available (and tested equal to the uncached engine) for deployments whose rules or contexts make evaluation costly.
const enabled = () => process.env.QODIQA_POLICY_DECISION_CACHE === 'true';

function opsMode() { try { return require('./abac/attributes').opsMode(); } catch { return 'normal'; } }

function setHashOf(policies) {
  if (!Array.isArray(policies)) return null;
  let h = setHashes.get(policies);
  if (h === undefined) { try { h = computePolicyHash(policies.filter((p) => p && p.enabled === true)); } catch { h = null; } setHashes.set(policies, h); }
  return h;
}

/** Called by the engine once per evaluation: drops every entry when the enabled policy set is not the one the entries were made under. */
function observeSet(policies) {
  const h = setHashOf(policies);
  if (h === null) { if (entries.size) { entries.clear(); counters.invalidations++; } currentSetHash = null; return; }
  if (currentSetHash !== null && h !== currentSetHash) { entries.clear(); counters.invalidations++; }
  currentSetHash = h;
}

function contextKey(context, mode) {
  const c = context;
  return crypto.createHash('sha256').update(JSON.stringify([c.ip, c.timestamp, c.userId, c.callerId, c.tenantId, c.action, c.artifact && c.artifact.valid, c.attributes || null, mode])).digest('hex');
}

/**
 * Run `evaluator` for `policy` through the cache. `ruleHash` is the rule's content hash computed by the engine (null disables caching for this call).
 * Returns exactly what evaluator.evaluate returns (possibly a promise).
 */
function run(policy, ruleHash, evaluator, context, store) {
  if (!enabled() || !PURE.has(policy.type) || typeof ruleHash !== 'string') { counters.bypass++; return evaluator.evaluate(context, policy.config, store); }
  const key = `${ruleHash}:${contextKey(context, policy.type === 'ABAC' ? opsMode() : '')}`;
  const hit = entries.get(key);
  if (hit) { entries.delete(key); entries.set(key, hit); counters.hits++; return { pass: hit.pass, reason: hit.reason }; }
  counters.misses++;
  return Promise.resolve(evaluator.evaluate(context, policy.config, store)).then((r) => {
    if (r && typeof r.pass === 'boolean' && !r.provenance) {
      entries.set(key, { pass: r.pass, reason: typeof r.reason === 'string' ? r.reason : null });
      if (entries.size > MAX_ENTRIES) entries.delete(entries.keys().next().value);
    }
    return r;
  });
}

const stats = () => ({ ...counters, size: entries.size, enabled: enabled() });
function _reset() { entries.clear(); currentSetHash = null; for (const k of Object.keys(counters)) counters[k] = 0; }

module.exports = { run, observeSet, stats, PURE, MAX_ENTRIES, _reset };
