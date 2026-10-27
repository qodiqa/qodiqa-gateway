'use strict';

/**
 * usage-metering PostgreSQL aggregation against real PostgreSQL.
 *
 * Proves the two statements of the metering semantics agree on identical
 * evidence: the SQL aggregation (pg-audit-backend.js
 * aggregateUsageByTenantPg — the distributed-mode read path) and the
 * canonical pure reducer (src/core/usage/usageAggregation.js — the
 * window/file-mode read path). Also proves the RLS posture: a plain
 * app-role read of audit_chain with no tenant context sees no tenant rows,
 * and the tenant-scoped aggregation only ever sees its own tenant.
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true) — skipped entirely
 * otherwise. Database lifecycle: uniquely-named disposable database created
 * in beforeAll, dropped in afterAll — the established pattern of
 * test/integration/audit-chain-distributed.integration.test.js and
 * test/integration/tenantConfigStore.integration.test.js; never touches a
 * pre-existing database.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto   = require('crypto');
const { Pool } = require('pg');
const { dropTestDatabase } = require('../helpers/dropTestDatabase');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_usagemeter_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

const T0 = Date.parse('2026-08-10T00:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const RANGE_MS  = { fromMs: T0 - 5 * DAY, toMs: T0 + 5 * DAY };
const RANGE_ISO = {
  fromIso: new Date(RANGE_MS.fromMs).toISOString(),
  toIso:   new Date(RANGE_MS.toMs).toISOString(),
};

const BIG = Number.MAX_SAFE_INTEGER; // legal integer token count in evidence

// One fixture, two consumers: rows inserted into audit_chain for SQL, and
// the same logical entries handed to the JS reducer. Covers: plain usage,
// null tokenUsage (streaming), missing tokenUsage key (not metered),
// missing totalTokens (component derivation), a BLOCK with usage, an
// out-of-range row, a second tenant, and MAX_SAFE_INTEGER-scale counts.
const FIXTURE = [
  { tenant: 'acme',   id: 'um-a1', at: T0,            decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: { inputTokens: 100, outputTokens: 10, totalTokens: 110 } } },
  { tenant: 'acme',   id: 'um-a2', at: T0 + 3600_000, decision: 'BLOCK', ctx: { stage: 'SEMANTIC_POLICY_OUTPUT', tokenUsage: { inputTokens: 50, outputTokens: 5, totalTokens: 55 } } },
  { tenant: 'acme',   id: 'um-a3', at: T0 + DAY,      decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: null } },
  { tenant: 'acme',   id: 'um-a4', at: T0 + DAY + 1,  decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: { inputTokens: 7, outputTokens: 3, totalTokens: null } } },
  { tenant: 'acme',   id: 'um-a5', at: T0 + DAY + 2,  decision: 'BLOCK', ctx: { stage: 'PROVIDER_EXECUTION', reason: 'PROVIDER_ERROR' } }, // no tokenUsage key — not metered
  { tenant: 'acme',   id: 'um-a6', at: T0 + 2 * DAY,  decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: { inputTokens: BIG, outputTokens: 0, totalTokens: BIG } } },
  { tenant: 'acme',   id: 'um-a7', at: RANGE_MS.toMs, decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: { totalTokens: 999 } } }, // AT `to` — excluded (half-open)
  { tenant: 'globex', id: 'um-g1', at: T0,            decision: 'ALLOW', ctx: { stage: 'PROVIDER_EXECUTION', tokenUsage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 } } },
];

function jsEntries(tenant) {
  return FIXTURE.filter((f) => f.tenant === tenant).map((f) => ({
    artifactId: f.id,
    decision: f.decision,
    timestamp: new Date(f.at).toISOString(),
    tenantId: f.tenant,
    executionContext: f.ctx,
  }));
}

describeOrSkip('PG usage aggregation vs canonical reducer (real PostgreSQL)', () => {
  let pgPool;
  let pgAuditBackend;
  let reduceUsage;
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

    // Migrate with the elevated role, then tear that pool down and rebuild
    // as the ambient least-privilege role — this suite asserts RLS
    // behavior, which the migration role bypasses by design (same shape as
    // test/integration/tenantConfigStore.integration.test.js).
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
    pgAuditBackend = require('../../src/infra/postgres/pg-audit-backend');
    ({ reduceUsage } = require('../../src/core/usage/usageAggregation'));

    // Seed audit_chain directly (ac_system_insert is WITH CHECK true —
    // the audit system writes without per-entry tenant context).
    let prev = 'GENESIS';
    for (const f of FIXTURE) {
      const hash = crypto.createHash('sha256').update(`m05-${f.id}`).digest('hex');
      // eslint-disable-next-line no-await-in-loop
      await pgPool.query(`
        INSERT INTO audit_chain
          (hash, prev_hash, canonical, artifact_id, decision, recorded_at,
           high_res_time, input_hash, signature, request_hash, policy_hash,
           verification_result, tenant_id, execution_context)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
      `, [
        hash, prev, JSON.stringify({ m05Fixture: f.id }), f.id, f.decision,
        new Date(f.at).toISOString(), '0',
        'b'.repeat(64), 'm05-fixture-signature', 'c'.repeat(64), 'd'.repeat(64),
        f.decision === 'ALLOW', f.tenant, JSON.stringify(f.ctx),
      ], 'm05_fixture_insert');
      prev = hash;
    }
  }, 120_000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_maintenancePool) {
      // re-run the suite's own shutdown before each forced-drop attempt (a late write can
      // re-create a foreign-role pool after the shutdown above).
      const r = await dropTestDatabase(_maintenancePool, TEST_DB_NAME, { shutdown: () => (pgPool ? pgPool.shutdown() : Promise.resolve()) });
      // eslint-disable-next-line no-console
      if (!r.dropped) console.warn(`[usageMeteringPg.integration] failed to drop ${TEST_DB_NAME}: ${r.error} — attached: ${JSON.stringify(r.attached)}`);
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  test('UM-1 SQL aggregation equals the canonical reducer on identical evidence (both tenants)', async () => {
    for (const tenant of ['acme', 'globex']) {
      // eslint-disable-next-line no-await-in-loop
      const rows = await pgAuditBackend.aggregateUsageByTenantPg(tenant, RANGE_ISO);
      const expected = reduceUsage(jsEntries(tenant), RANGE_MS);
      const sqlSeries = rows.map((r) => ({
        day: r.day,
        executions:   Number(r.executions),
        inputTokens:  r.inputTokens  === null ? 0 : Number(BigInt(r.inputTokens)  <= BigInt(Number.MAX_SAFE_INTEGER) ? r.inputTokens  : NaN),
        outputTokens: r.outputTokens === null ? 0 : Number(r.outputTokens),
        totalTokens:  r.totalTokens,
      }));
      // compare day-by-day on the exact decimal strings to avoid double rounding
      expect(rows.map((r) => r.day)).toEqual(expected.series.map((s) => s.day));
      rows.forEach((r, i) => {
        const exp = expected.series[i];
        expect(Number(r.executions)).toBe(exp.executions);
        expect(BigInt(r.inputTokens  ?? 0).toString()).toBe(BigInt(exp.inputTokens).toString());
        expect(BigInt(r.outputTokens ?? 0).toString()).toBe(BigInt(exp.outputTokens).toString());
        expect(BigInt(r.totalTokens  ?? 0).toString()).toBe(BigInt(exp.totalTokens).toString());
      });
      void sqlSeries;
    }
  }, 20_000);

  test('UM-2 half-open range: the row recorded exactly at `to` is excluded by both implementations', async () => {
    const rows = await pgAuditBackend.aggregateUsageByTenantPg('acme', RANGE_ISO);
    const grandTotal = rows.reduce((a, r) => a + BigInt(r.totalTokens ?? 0), 0n);
    expect(grandTotal).toBe(BigInt(110 + 55 + 0 + 10 + 0) + BigInt(BIG)); // um-a7 (999) excluded
  }, 20_000);

  test('UM-3 re-running the SQL aggregation is idempotent — identical result, nothing double-counted', async () => {
    const first  = await pgAuditBackend.aggregateUsageByTenantPg('acme', RANGE_ISO);
    const second = await pgAuditBackend.aggregateUsageByTenantPg('acme', RANGE_ISO);
    expect(second).toEqual(first);
  }, 20_000);

  test('UM-4 the same logical execution cannot exist twice: audit_chain rejects a duplicate artifact_id', async () => {
    await expect(pgPool.query(`
      INSERT INTO audit_chain
        (hash, prev_hash, canonical, artifact_id, decision, recorded_at,
         high_res_time, input_hash, signature, request_hash, policy_hash,
         verification_result, tenant_id, execution_context)
      VALUES ($1, $2, '{}', 'um-a1', 'ALLOW', NOW(), '0', $3, 's', $4, $5, true, 'acme', '{"tokenUsage": {"totalTokens": 1}}'::jsonb)
    `, [crypto.createHash('sha256').update('m05-dup').digest('hex'), 'e'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64)], 'm05_dup_insert'))
      .rejects.toThrow(/duplicate key|idx_audit_chain_artifact_id/);
  }, 20_000);

  test('UM-5 RLS posture: a plain app-role read with NO tenant context sees no tenant-scoped rows', async () => {
    const res = await pgPool.query(
      `SELECT COUNT(*)::int AS n FROM audit_chain WHERE tenant_id IS NOT NULL`,
      [], 'm05_rls_probe',
    );
    expect(res.rows[0].n).toBe(0);
  }, 20_000);

  test("UM-6 tenant-scoped aggregation never sees another tenant's rows", async () => {
    const rows = await pgAuditBackend.aggregateUsageByTenantPg('globex', RANGE_ISO);
    const total = rows.reduce((a, r) => a + BigInt(r.totalTokens ?? 0), 0n);
    expect(total).toBe(2n); // um-g1 only — none of acme's volume
  }, 20_000);
});
