'use strict';

/**
 * behavioural contract — AlertStore dedup against a REAL PostgreSQL.
 *
 * The pure/SQL-shape assertions (index predicate vs. ON CONFLICT predicate
 * drift) live in src/alerting/storage/__tests__/AlertStore.dedupKeyContract.
 * test.js and need no database. What cannot be asserted there is whether
 * PostgreSQL actually infers migration 047's partial index as an arbiter — that
 * is exactly what failed before (42P10, "no unique or exclusion constraint
 * matching the ON CONFLICT specification"), and a mocked pool would happily
 * pretend it worked. So these two run for real:
 *
 *   1. repeated/concurrent saves of the same dedup_key, while active, collapse
 *      onto ONE row and increment deduplicated_count;
 *   2. the same dedup_key saved again AFTER resolution opens a genuinely NEW
 *      row — the behaviour a plain UNIQUE (dedup_key) would have lost.
 *
 * Runs on its own uniquely-named disposable database, created and dropped by
 * this suite (layer 1 — no suite in this repo may write to a shared
 * database).
 */

// Same convention as this suite's siblings (consentActionSemantics,
// audit-chain-verifier-pg): the suite resolves its own ambient config. Post-F18
// this is safe in both directions — an un-opted-in local run has already had
// QODIQA_PG_ENABLED set to 'false' by test/support/jest.setup.js, which dotenv cannot
// override, so this suite skips; an opted-in run or CI gets 'true' and runs
// against the disposable database created below, never a shared one.
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_f14_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

describeOrSkip('alert dedup upsert against a real PostgreSQL', () => {
  let alertStore, pgPool;
  let _maintenancePool = null;
  let _origDb, _origUser, _origPassword;

  function makeAlert(overrides = {}) {
    return {
      id: crypto.randomUUID(),
      type: 'OPERATIONAL',   // must satisfy qodiqa_alerts_type_check
      subtype: 'F14_DEDUP_PROBE',
      severity: 'HIGH',
      status: 'OPEN',
      riskScore: 50,
      confidence: 90,   // SMALLINT 0-100, not a 0-1 float
      title: 'dedup probe',
      description: 'synthetic alert for the regression contract',
      tags: [],
      sourceEvent: 'F14_SOURCE',
      requestId: null,
      artifactId: null,
      tenantId: 'f14-tenant',
      publicKeyId: null,
      clientIp: null,
      actorId: null,
      component: 'test',
      evidence: {},
      context: {},
      detectedAt: new Date(),
      nextEscalationAt: null,
      ...overrides,
    };
  }

  // as qodiqa_app this SELECT is itself subject to qa_tenant_select, whose
  // USING clause matches tenant_id against qodiqa_current_tenant(). So the
  // verification query needs the same tenant context the write path does, or it
  // reports 0 rows for alerts that were persisted perfectly well. That is the
  // RLS class under test applying to the test's own assertions — and it is
  // precisely what the previous qodiqa_test-based version of this suite could
  // never have surfaced.
  const countRows = async (dedupKey, tenantId = 'f14-tenant') => {
    const sql = 'SELECT id, status, deduplicated_count FROM qodiqa_alerts WHERE dedup_key = $1 ORDER BY detected_at';
    const { rows } = tenantId
      ? await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(sql, [dedupKey]))
      : await pgPool.query(sql, [dedupKey]);
    return rows;
  };

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

    const existing = await _maintenancePool.query('SELECT 1 FROM pg_database WHERE datname = $1', [TEST_DB_NAME]);
    if (existing.rows.length === 0) {
      await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    }

    _origDb = process.env.QODIQA_PG_DATABASE;
    _origUser = process.env.QODIQA_PG_USER;
    _origPassword = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;

    // Migrations need CREATEROLE/BYPASSRLS (002, 018), so they run elevated as
    // qodiqa_test — but ONLY the migrations.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER     = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pgPool     = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    await pgPool.shutdown();

    // test-fidelity fix — the assertions below MUST run as qodiqa_app, the
    // role the server actually runs as, not as the elevated qodiqa_test used
    // for migrations. The first version of this suite ran everything as
    // qodiqa_test and reported all green while the live server was still
    // failing every insert with 42501: qodiqa_test is not subject to the RLS
    // policies qodiqa_app is, so the suite validated a path production does not
    // take. A test that runs as a more privileged role than the code under test
    // is not a weaker test, it is a test of something else.
    process.env.QODIQA_PG_USER     = _origUser ?? 'qodiqa_app';
    process.env.QODIQA_PG_PASSWORD = _origPassword;

    jest.resetModules();
    pgPool     = require('../../src/infra/postgres/pool');
    alertStore = require('../../src/alerting/storage/AlertStore');
    pgPool.initialize();

    const who = await pgPool.query('SELECT current_user AS u');
    if (who.rows[0].u !== 'qodiqa_app') {
      throw new Error(
        `suite must run as qodiqa_app to be meaningful, but connected as "${who.rows[0].u}". ` +
        'Set QODIQA_PG_USER/QODIQA_PG_PASSWORD to the app role.',
      );
    }
  }, 180_000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _origDb;
    process.env.QODIQA_PG_USER     = _origUser;
    process.env.QODIQA_PG_PASSWORD = _origPassword;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[alertStoreDedup.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 60_000);

  it('persists an alert at all — the 42P10 that made every insert fail is gone', async () => {
    const alert = makeAlert({ sourceEvent: 'F14_PERSIST' });
    const saved = await alertStore.saveAlert(alert);
    const rows = await countRows(alertStore.buildDedupKey(alert));

    // Before migration 047 this returned 0 rows: the insert failed with 42P10
    // and saveAlert()'s catch pushed to memory, still returning the alert — so
    // asserting on the return value alone would have passed even then.
    expect(rows).toHaveLength(1);
    expect(saved.id).toBeDefined();
  });

  it('contract 1: concurrent saves of the same dedup_key, while active, collapse to one row', async () => {
    const shape = { sourceEvent: 'F14_CONCURRENT' };
    const dedupKey = alertStore.buildDedupKey(makeAlert(shape));

    // Fired in the same tick so the upsert is arbitrated by PostgreSQL, not by
    // client-side sequencing.
    await Promise.all(
      Array.from({ length: 6 }, () => alertStore.saveAlert(makeAlert(shape))),
    );

    const rows = await countRows(dedupKey);
    expect(rows).toHaveLength(1);
    // deduplicated_count counts OCCURRENCES and defaults to 1 on insert, so 6
    // saves onto one row read as 6: the insert seeds 1, five upserts add one each.
    expect(Number(rows[0].deduplicated_count)).toBe(6);
  });

  it('contract 2: the same dedup_key after resolution opens a NEW row', async () => {
    const shape = { sourceEvent: 'F14_AFTER_RESOLVE' };
    const dedupKey = alertStore.buildDedupKey(makeAlert(shape));

    const first = await alertStore.saveAlert(makeAlert(shape));
    expect(await countRows(dedupKey)).toHaveLength(1);

    // a tenant-scoped alert needs its tenant supplied — see updateAlertStatus's
    // meta.tenantId note. Without it the UPDATE matches zero rows under RLS.
    await alertStore.updateAlertStatus(first.id, 'RESOLVED', { actor: 'test', tenantId: 'f14-tenant' });

    // The resolved row has left the partial index, freeing its dedup_key.
    const second = await alertStore.saveAlert(makeAlert(shape));

    const rows = await countRows(dedupKey);
    expect(rows).toHaveLength(2);
    expect(second.id).not.toBe(first.id);
    // The resolved row keeps its own state; the recurrence is genuinely new,
    // not a counter bump on a closed alert — which is what a plain
    // UNIQUE (dedup_key) would have produced instead.
    const statuses = rows.map(r => r.status).sort();
    expect(statuses).toEqual(['OPEN', 'RESOLVED']);
    // Both rows are first-occurrences (default 1) — neither is a counter bump
    // on the other, which is exactly what a plain UNIQUE (dedup_key) would have
    // produced instead (one row, count 2).
    expect(rows.map(r => Number(r.deduplicated_count))).toEqual([1, 1]);
  });

  it('the arbiter is the partial index this fix shipped, by name', async () => {
    const { rows } = await pgPool.query(
      "SELECT indexdef FROM pg_indexes WHERE tablename = 'qodiqa_alerts' AND indexname = 'qodiqa_alerts_dedup_key_active_uq'",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].indexdef).toMatch(/CREATE UNIQUE INDEX/);
    expect(rows[0].indexdef).toMatch(/dedup_key/);
    for (const status of alertStore.ACTIVE_ALERT_STATUSES) {
      expect(rows[0].indexdef).toContain(status);
    }
  });
});
