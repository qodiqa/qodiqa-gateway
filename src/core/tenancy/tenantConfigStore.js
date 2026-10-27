'use strict';

/**
 * Tenant configuration store — PostgreSQL persistence for per-tenant policy
 * sets and per-tenant semantic configs (/ migration 051;
 *).
 *
 * PostgreSQL is the persistence AUTHORITY for tenant configuration; the
 * in-memory registries (tenantPolicyRegistry / tenantSemanticRegistry) are
 * caches hydrated from here. Writers are exclusively the governed
 * publish step (PolicyGovernanceService.publish()) — there is deliberately
 * no other write path.
 *
 * Writes run in a transaction with the tenant context set transaction-
 * locally (tenantContext.setLocal — the exact persistEntry() idiom), which
 * is what satisfies migration 051's strict RLS policies. Platform-wide
 * hydration reads go through the two SECURITY DEFINER full-read functions
 * (051) because the hydrating process deliberately has no tenant context.
 */

const crypto = require('crypto');
const pool = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // boot hydration runs as qodiqa_system
const { setLocal } = require('../../infra/postgres/tenantContext');
const stableStringify = require('../../utils/stableStringify');

function policiesHash(policies) {
  return crypto.createHash('sha256').update(stableStringify(policies)).digest('hex');
}

/** @returns {Promise<{tenantId, policies, hash, version}>} */
async function upsertPolicySet({ tenantId, policies, changeRequestId = null, updatedBy = null }) {
  const hash = policiesHash(policies);
  return pool.withTransaction(async (tx) => {
    await setLocal(tx, tenantId);
    const res = await tx.query(`
      INSERT INTO tenant_policy_sets (tenant_id, policies, policies_hash, version, change_request_id, updated_by)
      VALUES ($1, $2::jsonb, $3, 1, $4, $5)
      ON CONFLICT (tenant_id) DO UPDATE SET
        policies          = EXCLUDED.policies,
        policies_hash     = EXCLUDED.policies_hash,
        version           = tenant_policy_sets.version + 1,
        change_request_id = EXCLUDED.change_request_id,
        updated_by        = EXCLUDED.updated_by,
        updated_at        = now()
      RETURNING version
    `, [tenantId, JSON.stringify(policies), hash, changeRequestId, updatedBy]);
    return { tenantId, policies, hash, version: res.rows[0].version };
  });
}

/** Tenant-scoped read (RLS-visible via transaction-local context). */
async function getPolicySet(tenantId) {
  return pool.withTransaction(async (tx) => {
    await setLocal(tx, tenantId);
    const res = await tx.query(
      'SELECT tenant_id, policies, policies_hash, version FROM tenant_policy_sets WHERE tenant_id = $1',
      [tenantId],
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return { tenantId: row.tenant_id, policies: row.policies, hash: row.policies_hash, version: row.version };
  });
}

/** @returns {Promise<{tenantId, config, hash, version}>} */
async function upsertSemanticConfig({ tenantId, config, changeRequestId = null, updatedBy = null }) {
  const hash = crypto.createHash('sha256').update(stableStringify(config)).digest('hex');
  return pool.withTransaction(async (tx) => {
    await setLocal(tx, tenantId);
    const res = await tx.query(`
      INSERT INTO tenant_semantic_configs (tenant_id, config, config_hash, version, change_request_id, updated_by)
      VALUES ($1, $2::jsonb, $3, 1, $4, $5)
      ON CONFLICT (tenant_id) DO UPDATE SET
        config            = EXCLUDED.config,
        config_hash       = EXCLUDED.config_hash,
        version           = tenant_semantic_configs.version + 1,
        change_request_id = EXCLUDED.change_request_id,
        updated_by        = EXCLUDED.updated_by,
        updated_at        = now()
      RETURNING version
    `, [tenantId, JSON.stringify(config), hash, changeRequestId, updatedBy]);
    return { tenantId, config, hash, version: res.rows[0].version };
  });
}

async function getSemanticConfig(tenantId) {
  return pool.withTransaction(async (tx) => {
    await setLocal(tx, tenantId);
    const res = await tx.query(
      'SELECT tenant_id, config, config_hash, version FROM tenant_semantic_configs WHERE tenant_id = $1',
      [tenantId],
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return { tenantId: row.tenant_id, config: row.config, hash: row.config_hash, version: row.version };
  });
}

/** Platform-wide hydration reads (SECURITY DEFINER full-read functions). */
async function loadAllPolicySets() {
  const res = await rolePools.system.query('SELECT tenant_id, policies, policies_hash, version FROM qodiqa_tenant_policy_sets_full_read()', [], 'tenant_policy_sets_hydrate');
  return res.rows.map((r) => ({ tenantId: r.tenant_id, policies: r.policies, hash: r.policies_hash, version: r.version }));
}

async function loadAllSemanticConfigs() {
  const res = await rolePools.system.query('SELECT tenant_id, config, config_hash, version FROM qodiqa_tenant_semantic_configs_full_read()', [], 'tenant_semantic_configs_hydrate');
  return res.rows.map((r) => ({ tenantId: r.tenant_id, config: r.config, hash: r.config_hash, version: r.version }));
}

module.exports = {
  policiesHash,
  upsertPolicySet,
  getPolicySet,
  upsertSemanticConfig,
  getSemanticConfig,
  loadAllPolicySets,
  loadAllSemanticConfigs,
};
