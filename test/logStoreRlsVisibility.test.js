'use strict';

/**
 * logStore.js RLS-blind transaction audit, real-PostgreSQL proof.
 *
 * A read-only audit traced every
 * production caller of every transparency_log_entries query in logStore.js.
 * Confirmed: appendEntry() (the one write) is correct (registrar.js already
 * sets tenant context via tenantContext.js's setLocal() before it); every
 * read call site is legitimately global by design (five back the public,
 * UNAUTHENTICATED transparency verification router; the rest back genuinely
 * global admin/internal chain-integrity operations) and was silently blind
 * to tenant-owned rows the same way GapScanner was. Fixed via
 * SECURITY DEFINER functions (migration 050), same idiom as.
 *
 * The highest-severity fix in this set: registrar.js's generateRoot() uses
 * getEntriesInRange() to compute the ACTUAL SIGNED ROOT HASH — pre-fix, this
 * silently excluded tenant-owned entries from the Merkle tree at the moment
 * of cryptographic commitment, not just from a later read of it.
 *
 * Real disposable database (same precedent as
 * test/integration/gapScanner.rls.integration.test.js / test/auditChainPoolExhaustionRecovery.
 * integration.test.js), real signing keys (prepareIsolatedEnvironment(), same
 * as test/serverStartupSmoke.test.js), real entries created through the
 * REAL registrar.register()/generateRoot() (not raw INSERTs — this also
 * re-validates appendEntry()'s own tenant-context handling stays correct),
 * and — the non-negotiable discipline — every assertion below runs
 * through the real pooled qodiqa_app connection, never BYPASSRLS/superuser.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const REPO_ROOT = path.join(__dirname, '..');
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_f36_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _originalDatabaseEnv;
let _maintenancePool;
let _appPool;
let pgPool, logStore, registrar, envTempRoot;

jest.setTimeout(60_000);

describeOrSkip('logStore.js sees all tenants, RLS otherwise unchanged (real disposable Postgres)', () => {
  const ENTRIES = []; // { id, tenant_id, entry_hash, transparency_id, artifact_id }

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

    const _ownerPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _ownerPool.query(`GRANT ALL ON SCHEMA public TO ${process.env.QODIQA_PG_MIG_USER || 'qodiqa_mig'}`);
    await _ownerPool.end();

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;

    const { spawnSync } = require('child_process');
    const migrateRes = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        QODIQA_PG_DATABASE: TEST_DB_NAME,
        QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
        QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    if (migrateRes.status !== 0) {
      throw new Error(`migrate.js failed (status=${migrateRes.status}): \nstdout:\n${migrateRes.stdout}\nstderr:\n${migrateRes.stderr}`);
    }

    // Real signing keys — registrar.register()/generateRoot() need a real
    // active transparency signing key. jest.resetModules() first: same
    // reasoning as test/serverStartupSmoke.test.js's own comment (avoid
    // reusing test/support/jest.setup.js's already-cached 'default' client keystore).
    jest.resetModules();
    const { prepareIsolatedEnvironment } = require('../scripts/lib/devEnvironment');
    const { paths } = await prepareIsolatedEnvironment({ clientId: 'f36-test', tempPrefix: 'qodiqa-f36-env-' });
    envTempRoot = paths.root;

    pgPool    = require('../src/infra/postgres/pool');
    logStore  = require('../src/core/transparency/logStore');
    registrar = require('../src/core/transparency/registrar');

    pgPool.initialize(); // qodiqa_app, per QODIQA_PG_USER — the real pooled role

    _appPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    // ── Create real, tenant-interleaved entries through the REAL registrar ──
    // Deliberately ends on a tenant-owned entry (not null): getLatestEntry()
    // queries ORDER BY id DESC LIMIT 1 with no filter, so if the pattern
    // ended on a NULL-tenant row, the pre-fix (RLS-blind) code would
    // coincidentally still return the correct row and the test would never
    // discriminate the bug.
    const tenants = ['tenant-a', null, 'tenant-b', null, 'tenant-a', 'tenant-b'];
    for (const tenantId of tenants) {
      const result = await registrar.register({
        entryType: 'ARTIFACT',
        artifactId: `f36-artifact-${tenantId ?? 'null'}-${ENTRIES.length}`,
        payload: { test: true },
        tenantId,
      });
      ENTRIES.push({
        id: Number(result.row.id),
        tenant_id: tenantId,
        entry_hash: result.entryHash,
        transparency_id: result.transparencyId,
        artifact_id: `f36-artifact-${tenantId ?? 'null'}-${ENTRIES.length}`,
      });
    }
  }, 60_000);

  afterAll(async () => {
    if (_appPool) await _appPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;

    if (envTempRoot) {
      try { require('fs').rmSync(envTempRoot, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[logStoreRlsVisibility] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  test('F36-01 (highest severity): generateRoot() computes entryCount/rootHash over ALL tenants, not just NULL-tenant entries', async () => {
    expect(ENTRIES.length).toBe(6);
    const rootResult = await registrar.generateRoot();
    // Pre-fix, generateRoot()'s own getEntriesInRange() call only saw the 2
    // tenant_id IS NULL entries — entryCount would have been 2, and the
    // signed rootHash would have been computed over an incomplete,
    // WRONG leaf set, permanently excluding the 4 tenant-owned entries from
    // ever having a valid inclusion proof against any root.
    expect(rootResult.row).not.toBeNull();
    expect(Number(rootResult.row ? rootResult.entryCount : -1)).toBe(6);
  });

  test('F36-02 getByTransparencyId sees a tenant-owned entry', async () => {
    const tenantEntry = ENTRIES.find(e => e.tenant_id === 'tenant-a');
    const found = await logStore.getByTransparencyId(tenantEntry.transparency_id);
    expect(found).not.toBeNull();
    // the public lookup still finds a tenant-owned entry, but no
    // longer exposes tenant metadata — identity is checked by entry_hash instead.
    expect(found.entry_hash).toBe(tenantEntry.entry_hash);
    expect(found).not.toHaveProperty('tenant_id');
    expect(found).not.toHaveProperty('registered_by');
    expect(found).not.toHaveProperty('payload');
  });

  test('F36-03 getByEntryHash sees a tenant-owned entry', async () => {
    const tenantEntry = ENTRIES.find(e => e.tenant_id === 'tenant-b');
    const found = await logStore.getByEntryHash(tenantEntry.entry_hash);
    expect(found).not.toBeNull();
    // found, minimized.
    expect(found.transparency_id).toBe(tenantEntry.transparency_id);
    expect(found).not.toHaveProperty('tenant_id');
  });

  test('F36-04 getByArtifactId sees a tenant-owned entry', async () => {
    const tenantEntry = ENTRIES.find(e => e.tenant_id === 'tenant-a');
    const found = await logStore.getByArtifactId(tenantEntry.artifact_id);
    expect(found.length).toBe(1);
    expect(found[0].tenant_id).toBe('tenant-a');
  });

  test('F36-05 getByEvidenceChainId (dead code, fixed pre-emptively) returns cleanly with no error', async () => {
    const found = await logStore.getByEvidenceChainId(crypto.randomUUID());
    expect(found).toEqual([]);
  });

  test('F36-06 listEntries sees entries across all tenants', async () => {
    const result = await logStore.listEntries({ pageSize: 100 });
    expect(result.total).toBe(6);
    // every tenant's entry is listed (verification fields), and
    // no tenant metadata is exposed publicly.
    expect(new Set(result.entries.map(e => e.entry_hash))).toEqual(new Set(ENTRIES.map(e => e.entry_hash)));
    for (const e of result.entries) { expect(e).not.toHaveProperty('tenant_id'); expect(e).not.toHaveProperty('registered_by'); }
  });

  test('F36-07 getLatestEntry sees the true latest id, which is tenant-owned', async () => {
    const latest = await logStore.getLatestEntry();
    const trueLatest = ENTRIES[ENTRIES.length - 1];
    expect(trueLatest.tenant_id).not.toBeNull(); // sanity: the seed order must end tenant-owned for this test to be discriminating
    expect(Number(latest.id)).toBe(trueLatest.id);
    expect(latest.tenant_id).toBe(trueLatest.tenant_id);
  });

  test('F36-08 getEntriesInRange sees every entry in range, across all tenants', async () => {
    const first = ENTRIES[0].id;
    const last  = ENTRIES[ENTRIES.length - 1].id;
    const rangeEntries = await logStore.getEntriesInRange(first, last);
    expect(rangeEntries.length).toBe(6);
  });

  test('F36-09 aggregateStats totals reflect all tenants', async () => {
    const stats = await logStore.aggregateStats();
    expect(stats.entries.total).toBe(6);
  });

  test('F36-10 isolation unchanged: an ordinary plain SELECT as qodiqa_app, no tenant context, still only sees tenant_id IS NULL rows', async () => {
    const res = await _appPool.query('SELECT id, tenant_id FROM transparency_log_entries ORDER BY id ASC');
    const visibleTenantIds = new Set(res.rows.map(r => r.tenant_id));
    expect(visibleTenantIds).toEqual(new Set([null]));
    expect(res.rows.length).toBe(ENTRIES.filter(e => e.tenant_id === null).length);
  });

  test('F36-11 isolation unchanged: an ordinary plain SELECT with tenant-A context still cannot see tenant-B rows', async () => {
    const client = await _appPool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('qodiqa.tenant_id', 'tenant-a', true)`);
      const res = await client.query('SELECT id, tenant_id FROM transparency_log_entries ORDER BY id ASC');
      await client.query('COMMIT');
      const visibleTenantIds = new Set(res.rows.map(r => r.tenant_id));
      expect(visibleTenantIds).toEqual(new Set(['tenant-a', null]));
      expect(visibleTenantIds.has('tenant-b')).toBe(false);
    } finally {
      client.release();
    }
  });
});
