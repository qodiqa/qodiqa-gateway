'use strict';

/**
 * Tenant configuration hydrator —
 *.
 *
 * Loads every tenant's policy set and semantic config from PostgreSQL (the
 * persistence authority, migration 051) into the in-memory registries at
 * boot, and keeps other replicas convergent via a periodic refresh — the
 * same convergence model the keys.json periodic reload established. The
 * publishing instance is updated synchronously by publish() itself; the
 * refresh exists for every OTHER instance.
 *
 * Fail-safe, never fail-open in the dangerous direction:
 *  - PG disabled → no-op (registries stay empty; every tenant falls back to
 *    the global policies.json + pinned semantic defaults — dev behaviour).
 *  - A malformed policy-set row → that tenant is SKIPPED (falls back to the
 *    global set) with an ERROR event; a malformed/loosening semantic row →
 *    clamped field-by-field to the pinned defaults with a
 *    TENANT_SEMANTIC_CONFIG_CLAMPED WARN (tenantSemanticRegistry.clampToDefaults).
 *  - A failed refresh keeps the last-good cache (WARN) — it never clears.
 */

const pool = require('../../infra/postgres/pool');
const tenantConfigStore = require('./tenantConfigStore');
const tenantPolicyRegistry = require('./tenantPolicyRegistry');
const tenantSemanticRegistry = require('./tenantSemanticRegistry');
const tenantPolicyFloor = require('./tenantPolicyFloor');
const { emit } = require('../../../services/logger');

const REFRESH_MS = (() => {
  const v = parseInt(process.env.QODIQA_TENANT_CONFIG_REFRESH_MS, 10);
  return Number.isInteger(v) && v >= 0 ? v : 30000;
})();

let _timer = null;

function _applyPolicySets(rows) {
  let applied = 0;
  for (const row of rows) {
    if (!Array.isArray(row.policies)) {
      emit('ERROR', 'TENANT_POLICY_SET_INVALID', {
        tenantId: row.tenantId,
        message: 'Stored tenant policy set is not an array — tenant falls back to the global policy set.',
      });
      continue;
    }
    // belt-and-braces load-time clamp — restores, in place, any
    // stored entry that collides with a floor policy id but is
    // non-compliant (a tampered/hand-edited PG row; draft/publish already
    // reject this at write time). Never adds a floor id the row simply
    // never mentioned — that is not a stored violation (see
    // tenantPolicyFloor.js header); the read-side union closes that case.
    const { policies, changes } = tenantPolicyFloor.clampEntries(row.policies);
    if (changes.length) {
      emit('WARN', 'TENANT_POLICY_FLOOR_RESTORED', {
        tenantId: row.tenantId,
        changes,
        message: 'Stored tenant policy set contained a disabled, retyped, or loosened floor policy — restored to the floor definition. The stored row was NOT modified; fix it through the governed change-request flow.',
      });
    }
    // PostgreSQL only ever holds RAW config (see tenantPolicyFloor.js
    // module header), so every hydration — boot and every periodic refresh
    // — re-preprocesses before populating the registry. Idempotent: a row
    // written by a post-fix publish (already preprocessed once, but never
    // persisted preprocessed) and a row that predates the fix entirely are
    // handled identically here.
    tenantPolicyRegistry.setPolicies(row.tenantId, policies.map(tenantPolicyFloor.preprocessEntry));
    applied += 1;
  }
  return applied;
}

function _applySemanticConfigs(rows) {
  let applied = 0;
  for (const row of rows) {
    const { config, changes } = tenantSemanticRegistry.clampToDefaults(row.config);
    if (changes.length) {
      emit('WARN', 'TENANT_SEMANTIC_CONFIG_CLAMPED', {
        tenantId: row.tenantId,
        changes,
        message: 'Stored tenant semantic config contained values outside the tighten-only envelope — clamped to the pinned defaults field-by-field. The stored row was NOT modified; fix it through the governed change-request flow.',
      });
    }
    tenantSemanticRegistry.setConfig(row.tenantId, config, { version: row.version });
    applied += 1;
  }
  return applied;
}

/**
 * Boot hydration. No-op when PG is disabled. Throws only on a PG read
 * failure at BOOT (caller decides; startup treats it as it treats other
 * PG-dependent boot steps) — per-row problems never throw.
 */
async function hydrate() {
  if (!pool.isEnabled()) return { hydrated: false, reason: 'PG_DISABLED' };
  const [policySets, semanticConfigs] = await Promise.all([
    tenantConfigStore.loadAllPolicySets(),
    tenantConfigStore.loadAllSemanticConfigs(),
  ]);
  const policiesApplied = _applyPolicySets(policySets);
  const semanticApplied = _applySemanticConfigs(semanticConfigs);
  emit('INFO', 'TENANT_CONFIG_HYDRATED', {
    tenantPolicySets: policiesApplied,
    tenantSemanticConfigs: semanticApplied,
  });
  return { hydrated: true, policiesApplied, semanticApplied };
}

/** Periodic refresh (unref'd — never keeps the process alive). */
function startRefresh() {
  if (!pool.isEnabled() || REFRESH_MS === 0 || _timer) return false;
  _timer = setInterval(async () => {
    try {
      await hydrate();
    } catch (err) {
      emit('WARN', 'TENANT_CONFIG_REFRESH_FAILED', {
        error: err.message,
        message: 'Periodic tenant-config refresh failed — keeping the last-good in-memory cache.',
      });
    }
  }, REFRESH_MS);
  if (typeof _timer.unref === 'function') _timer.unref();
  return true;
}

function stopRefresh() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}

module.exports = { hydrate, startRefresh, stopRefresh, REFRESH_MS };
