'use strict';

/**
 * tenant configuration persistence against real PostgreSQL
 * (migration 051): upsert/read round trips, version increments, the strict
 * RLS posture (a plain read with no tenant context sees NOTHING), and the
 * SECURITY DEFINER full-read functions that serve boot hydration.
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true) — skipped entirely
 * otherwise. Database lifecycle: uniquely-named disposable database created
 * in beforeAll, dropped in afterAll — the established pattern of
 * test/integration/audit-chain-distributed.integration.test.js (FINDING-AUDIT-MIRROR-
 * RECURRENCE-REPORT.md §8 prevention layer 1); never touches a
 * pre-existing database.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto   = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_tenantcfg_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

describeOrSkip('tenant config store + RLS (real PostgreSQL)', () => {
  let pgPool;
  let tenantConfigStore;
  let _maintenancePool;
  let _originalDatabaseEnv;
  let _originalUserEnv;
  let _originalPasswordEnv;

  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }
    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    // Migrate with the elevated role, then TEAR THAT POOL DOWN and build a
    // fresh one as the ambient least-privilege role — this suite tests RLS
    // visibility, and a pool that keeps the CREATEDB/BYPASSRLS migration
    // role would make every RLS assertion vacuously wrong (qodiqa_test
    // bypasses RLS by design).
    jest.resetModules();
    const migPool = require('../../src/infra/postgres/pool');
    migPool.initialize();
    await migPool.runMigrations();
    await migPool.shutdown();

    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    tenantConfigStore = require('../../src/core/tenancy/tenantConfigStore');
  }, 60_000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_maintenancePool) {
      try {
        await _maintenancePool.query(
          `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
          [TEST_DB_NAME],
        );
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[tenantConfigStore.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  const POLICIES = [{ id: 'P-1', type: 'BLOCK_IP', enabled: true, priority: 5, config: { list: [] } }];

  test('TCS-1 policy-set upsert/read round trip; version increments on re-upsert', async () => {
    const first = await tenantConfigStore.upsertPolicySet({ tenantId: 't-int-a', policies: POLICIES, updatedBy: 'itest' });
    expect(first.version).toBe(1);
    const read = await tenantConfigStore.getPolicySet('t-int-a');
    expect(read.policies).toEqual(POLICIES);
    expect(read.hash).toBe(first.hash);
    const second = await tenantConfigStore.upsertPolicySet({ tenantId: 't-int-a', policies: [], updatedBy: 'itest' });
    expect(second.version).toBe(2);
  }, 20_000);

  test('TCS-2 semantic-config upsert/read round trip', async () => {
    const saved = await tenantConfigStore.upsertSemanticConfig({
      tenantId: 't-int-a', config: { thresholds: { REVIEW: 0.40 } }, updatedBy: 'itest',
    });
    expect(saved.version).toBe(1);
    const read = await tenantConfigStore.getSemanticConfig('t-int-a');
    expect(read.config).toEqual({ thresholds: { REVIEW: 0.40 } });
    expect(read.hash).toBe(saved.hash);
  }, 20_000);

  test('TCS-3 RLS: a plain SELECT with no tenant context sees ZERO rows; the full-read functions see all', async () => {
    await tenantConfigStore.upsertPolicySet({ tenantId: 't-int-b', policies: [], updatedBy: 'itest' });
    // No tenant context on this connection → strict RLS hides every row.
    const bare = await pgPool.query('SELECT COUNT(*)::int AS n FROM tenant_policy_sets', [], 'rls_probe');
    expect(bare.rows[0].n).toBe(0);
    // The SECURITY DEFINER hydration read sees the true row set.
    const all = await tenantConfigStore.loadAllPolicySets();
    expect(all.map((r) => r.tenantId).sort()).toEqual(['t-int-a', 't-int-b']);
  }, 20_000);

  test('TCS-4 cross-tenant isolation at the store: tenant A context cannot read tenant B\'s row', async () => {
    const asA = await tenantConfigStore.getPolicySet('t-int-a');
    expect(asA).not.toBeNull();
    // getPolicySet sets the context to the REQUESTED tenant only — asking
    // for B under B's context returns B, and there is no way to ask for B
    // under A's context through this API. Prove the RLS side directly:
    const pool = require('../../src/infra/postgres/pool');
    const { setLocal } = require('../../src/infra/postgres/tenantContext');
    const leaked = await pool.withTransaction(async (tx) => {
      await setLocal(tx, 't-int-a');
      const res = await tx.query('SELECT COUNT(*)::int AS n FROM tenant_policy_sets WHERE tenant_id = $1', ['t-int-b']);
      return res.rows[0].n;
    });
    expect(leaked).toBe(0);
  }, 20_000);

  test('TCS-5 loadAllSemanticConfigs serves hydration platform-wide', async () => {
    const all = await tenantConfigStore.loadAllSemanticConfigs();
    expect(all.some((r) => r.tenantId === 't-int-a')).toBe(true);
  }, 20_000);
});
