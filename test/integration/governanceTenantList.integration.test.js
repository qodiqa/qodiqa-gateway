'use strict';

/**
 * Governance list of tenant-scoped change requests was RLS-blind for
 * operators (residual's closing notes): the by-id read already
 * fell back to a SECURITY DEFINER function (migration 051) when migration
 * 029's nullable-tenant RLS hid a tenant-scoped row from a contextless read,
 * but ChangeRequestStore.list() never did — an operator supplying an
 * explicit `tenantId` filter always got an empty page, indistinguishable
 * from "this tenant has no governance history" even when real rows existed.
 *
 * ChangeRequestStore.test.js's unit suite (mocked pool) proves the WIRING —
 * a tenantId filter now goes through pool.withTenantTransaction(), never
 * the plain contextless pool.query() path. This test proves the ACTUAL RLS
 * BEHAVIOUR against a real, freshly-migrated PostgreSQL database (migration
 * 029): a tenant-scoped list() call returns exactly that tenant's own rows
 * — not empty (the defect), not another tenant's rows (isolation), and not
 * platform-wide rows either (the explicit WHERE tenant_id=$1 filter, not
 * RLS's IS NULL branch, is what scopes the result) — while the pre-existing
 * no-filter path keeps returning only platform-scoped rows, unchanged.
 *
 * Same real-PostgreSQL harness as governanceReconciliation.integration.test.js
 *fresh scratch database, migrations run for real, dropped after.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

function connectionConfig(database, user, password) {
  return {
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database,
    user,
    password,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  };
}

// Migration 029's pcr_tenant_insert WITH CHECK (tenant_id IS NULL OR
// tenant_id = qodiqa_current_tenant()) rejects a tenant-scoped INSERT from
// a plain, contextless connection — exactly like ChangeRequestStore.create()
// itself, a tenant-scoped fixture row must be written under that tenant's
// own transaction-local context. Only a platform-scoped (tenantId: null)
// fixture can use the plain pgPool.query() path.
async function insertRequest(pgPool, { policyId, tenantId, status = 'DRAFT' }) {
  const sql = `INSERT INTO policy_change_requests
       (policy_id, tenant_id, request_type, status, payload, change_reason,
        author_id, author_username, author_role)
     VALUES ($1, $2, 'CREATE', $3, '{}'::jsonb, 'test fixture', 'author-1', 'author', 'admin')
     RETURNING id`;
  const params = [policyId, tenantId, status];

  if (tenantId) {
    const res = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(sql, params));
    return res.rows[0].id;
  }
  const res = await pgPool.query(sql, params);
  return res.rows[0].id;
}

describeOrSkip('governance tenant-scoped LIST (real PostgreSQL)', () => {
  let admin;
  let dbName;
  let pgPool;
  let ChangeRequestStore;

  beforeAll(async () => {
    const migrationUser     = process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres';
    const migrationPassword = process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD;
    admin = new Pool(connectionConfig(
      process.env.QODIQA_PG_DATABASE || 'qodiqa',
      migrationUser,
      migrationPassword,
    ));
    dbName = `qodiqa_f32_governance_list_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);

    const migrationPool = new Pool(connectionConfig(dbName, migrationUser, migrationPassword));
    const savedEnv = { ...process.env };
    process.env.QODIQA_PG_DATABASE = dbName;
    jest.resetModules();
    const { runMigrations } = require('../../src/infra/postgres/migrate');
    await runMigrations({ pool: migrationPool });
    await migrationPool.end();
    process.env = savedEnv;

    pgPool = require('../../src/infra/postgres/pool');
    process.env.QODIQA_PG_DATABASE = dbName;
    pgPool.initialize();

    ChangeRequestStore = require('../../src/core/policy/governance/ChangeRequestStore');
  }, 60000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown();
    if (admin && dbName) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await admin.end().catch(() => {});
    }
  }, 30000);

  test('GTL-01 an operator can enumerate a tenant\'s governance history without knowing any request id in advance', async () => {
    await insertRequest(pgPool, { policyId: 'gtl-policy-a1', tenantId: 'gtl-tenant-a' });
    await insertRequest(pgPool, { policyId: 'gtl-policy-a2', tenantId: 'gtl-tenant-a' });

    // No id supplied anywhere — this is exactly the enumeration capability
    // says an operator lacked ("only look up a request whose id they
    // already have"). Before the fix this returned {requests: [], total: 0}
    // for every tenant, indistinguishable from "no history".
    const { requests, total } = await ChangeRequestStore.list({ tenantId: 'gtl-tenant-a' });

    expect(total).toBe(2);
    expect(requests).toHaveLength(2);
    expect(requests.every((r) => r.tenant_id === 'gtl-tenant-a')).toBe(true);
  });

  test('GTL-02 cross-tenant isolation: tenant B\'s list never contains tenant A\'s rows, and vice versa', async () => {
    await insertRequest(pgPool, { policyId: 'gtl-policy-b1', tenantId: 'gtl-tenant-b' });

    const tenantA = await ChangeRequestStore.list({ tenantId: 'gtl-tenant-a' });
    const tenantB = await ChangeRequestStore.list({ tenantId: 'gtl-tenant-b' });

    expect(tenantA.requests.every((r) => r.tenant_id === 'gtl-tenant-a')).toBe(true);
    expect(tenantA.requests.some((r) => r.tenant_id === 'gtl-tenant-b')).toBe(false);

    expect(tenantB.total).toBe(1);
    expect(tenantB.requests.every((r) => r.tenant_id === 'gtl-tenant-b')).toBe(true);
    expect(tenantB.requests.some((r) => r.tenant_id === 'gtl-tenant-a')).toBe(false);
  });

  test('GTL-03 a tenant-scoped list excludes platform-scoped rows — the WHERE filter, not RLS\'s IS-NULL union, does the scoping', async () => {
    await insertRequest(pgPool, { policyId: 'gtl-policy-platform', tenantId: null });

    const tenantA = await ChangeRequestStore.list({ tenantId: 'gtl-tenant-a' });
    expect(tenantA.requests.some((r) => r.tenant_id === null)).toBe(false);
  });

  test('GTL-04 the no-tenantId (platform-wide) path is unchanged: it still sees only platform-scoped rows, never a tenant\'s', async () => {
    const platform = await ChangeRequestStore.list({});
    expect(platform.requests.length).toBeGreaterThanOrEqual(1);
    expect(platform.requests.every((r) => r.tenant_id === null)).toBe(true);
  });

  test('GTL-05 an unknown/empty tenant genuinely has no history — not a false RLS-blind empty page', async () => {
    const result = await ChangeRequestStore.list({ tenantId: 'gtl-tenant-nonexistent' });
    expect(result).toEqual({ requests: [], total: 0 });
  });
});
