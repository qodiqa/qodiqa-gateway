'use strict';

/**
 * / RLS-1 — GapScanner tenant-blind transaction, real-PostgreSQL proof.
 *
 * GapScanner ran its whole scan inside pool.js's plain withTransaction() —
 * no tenant context set — so transparency_log_entries' own RLS policy
 * (migration 018's tle_tenant_select: USING (tenant_id IS NULL OR tenant_id
 * = qodiqa_current_tenant())) made every real tenant's row invisible to it,
 * exactly the same defect class fixed for audit_chain. Fixed via three
 * new SECURITY DEFINER functions (migration 049), one per GapScanner query
 * shape, mirroring migrations 043/044/048's own idiom.
 *
 * Real disposable database (created on the same PostgreSQL server this
 * project's own .env already points at, via the QODIQA_PG_TEST_USER role
 * that already exists for exactly this purpose — see
 * test/integration/auditChainPoolExhaustionRecovery.integration.test.js for the
 * identical precedent), real migrations, real qodiqa_app pooled connection
 * for both the code under test and the isolation-proof assertions below —
 * never a superuser/BYPASSRLS connection, which would pass vacuously
 * regardless of whether the fix actually works (the exact trap
 * already flagged).
 *
 * RLS1-01  GapScanner (real qodiqa_app connection, no tenant context) now
 *          sees every entry across all tenants — the gap it was
 *          structurally blind to is now correctly checked, not missed.
 * RLS1-02  No cross-tenant leakage introduced: an ordinary plain SELECT as
 *          qodiqa_app, no tenant context, still only sees tenant_id IS NULL
 *          rows — RLS enforcement for normal (non-GapScanner) query paths
 *          is completely unchanged by the fix.
 * RLS1-03  No cross-tenant leakage introduced: an ordinary plain SELECT as
 *          qodiqa_app with tenant A's context set still cannot see tenant
 *          B's rows — standard tenant isolation is intact.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const REPO_ROOT = path.join(__dirname, '..', '..');
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_rls1_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _originalDatabaseEnv;
let _maintenancePool;
let _appPool; // raw pg Pool connected AS qodiqa_app — the real pooled role, no BYPASSRLS
let pgPool, createGapScanner, computeEntryHash;

jest.setTimeout(60_000);

describeOrSkip('/ RLS-1 — GapScanner sees all tenants, RLS otherwise unchanged (real disposable Postgres)', () => {
  const ENTRIES = []; // { id, tenant_id, entry_hash } in insertion order

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

    // PG15+ default: only the database owner (qodiqa_test, the role that
    // just ran CREATE DATABASE) can CREATE in the fresh public schema.
    // qodiqa_mig (the migration runner's own role, unrelated to and no more
    // privileged than qodiqa_test here) needs it explicitly granted before
    // migrations below can create any table.
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

    // pgPool.runMigrations() (the in-process wrapper) would run under
    // QODIQA_PG_USER's own pool.js connection — qodiqa_app in this test,
    // deliberately, since the code under test must connect as the real
    // least-privilege application role. qodiqa_app correctly lacks CREATE on
    // a fresh database's public schema, so migrations must run through the
    // standalone CLI script instead, which uses QODIQA_PG_MIG_USER
    // (qodiqa_mig) as its own separate, more-privileged connection — same
    // invocation this project's own dev bootstrap uses.
    //
    // Migration 018 (rls_tenant_isolation) does role-attribute management
    // (GRANT BYPASSRLS) which the default QODIQA_PG_MIG_USER cannot perform
    // on a genuinely fresh database — migrate.js's own error names the
    // documented remedy: the qodiqa_test bootstrap role.
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

    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    ({ createGapScanner } = require('../../src/core/transparency/scanner/GapScanner'));
    ({ computeEntryHash } = require('../../src/core/transparency/log'));

    pgPool.initialize(); // qodiqa_app, per QODIQA_PG_USER — the real pooled role, migrations already applied above

    // Separate raw pool, connected AS qodiqa_app specifically (the real
    // pooled application role, per .env's QODIQA_PG_USER) — used both to
    // seed fixture data through the real INSERT policy and, later, to prove
    // ordinary SELECT paths are unaffected by the fix. Deliberately NOT
    // qodiqa_mig/postgres — a superuser or BYPASSRLS connection would pass
    // every assertion below regardless of whether the fix works.
    _appPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    // ── Seed a real, valid, tenant-interleaved hash chain ──────────────────
    // tle_system_insert's WITH CHECK (true) is unconditionally permissive for
    // the INSERT itself, but `RETURNING id` also reads the just-inserted row
    // back, which IS subject to the SELECT policy (tle_tenant_select) — with
    // no tenant context set, that fails for any tenant-scoped row even
    // though the insert itself would have succeeded. Each insert below sets
    // the matching tenant context first (transaction-scoped, same real
    // mechanism tenantContext.js's setLocal() uses), mirroring how the real
    // application writes a tenant-scoped entry.
    const tenants = ['tenant-a', 'tenant-b', null, 'tenant-a', 'tenant-b', null];
    let prevHash = null;
    const seedClient = await _appPool.connect();
    try {
      for (const tenantId of tenants) {
        const transparencyId = crypto.randomUUID();
        const canonical = {
          transparencyId,
          entryType:         'ARTIFACT',
          artifactId:        null,
          evidenceChainId:   null,
          verificationId:    null,
          payloadHash:       crypto.randomBytes(32).toString('hex'),
          previousEntryHash: prevHash,
          signerKeyId:       'rls1-test-key',
        };
        const entryHash = computeEntryHash(canonical);
        await seedClient.query('BEGIN');
        await seedClient.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, [tenantId ?? '']);
        const res = await seedClient.query(
          `INSERT INTO transparency_log_entries
             (transparency_id, entry_type, payload, payload_hash, previous_entry_hash,
              entry_hash, signer_key_id, signature, registered_by, tenant_id)
           VALUES ($1, $2, '{}', $3, $4, $5, $6, 'sig-test', 'system', $7)
           RETURNING id`,
          [transparencyId, canonical.entryType, canonical.payloadHash, prevHash,
            entryHash, canonical.signerKeyId, tenantId],
        );
        await seedClient.query('COMMIT');
        ENTRIES.push({ id: Number(res.rows[0].id), tenant_id: tenantId, entry_hash: entryHash });
        prevHash = entryHash;
      }
    } finally {
      seedClient.release();
    }
  }, 60_000);

  afterAll(async () => {
    if (_appPool) await _appPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[gapScanner.rls.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  test('RLS1-01 GapScanner (real qodiqa_app connection, no tenant context) sees every entry across all tenants, zero false gaps', async () => {
    expect(ENTRIES.length).toBe(6);
    expect(new Set(ENTRIES.map(e => e.tenant_id))).toEqual(new Set(['tenant-a', 'tenant-b', null]));

    const scanner = createGapScanner({
      config: { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: true, verifyRoots: false },
    });
    const result = await scanner.scan('FULL');

    expect(result.success).toBe(true);
    // Pre-fix, a plain SELECT with no tenant context only ever saw the 2
    // tenant_id IS NULL rows — entriesChecked would have been 2, not 6, and
    // the visible rows' own id sequence (skipping the invisible tenant-owned
    // ones) would have looked like real SEQUENCE_BREAK gaps.
    expect(result.entriesChecked).toBe(6);
    expect(result.gapsDetected).toBe(0);
    expect(result.lastScannedId).toBe(ENTRIES[ENTRIES.length - 1].id);
  });

  test('RLS1-02 ordinary plain SELECT as qodiqa_app, no tenant context, still only sees tenant_id IS NULL rows', async () => {
    const res = await _appPool.query('SELECT id, tenant_id FROM transparency_log_entries ORDER BY id ASC');
    const visibleTenantIds = new Set(res.rows.map(r => r.tenant_id));
    expect(visibleTenantIds).toEqual(new Set([null]));
    expect(res.rows.length).toBe(ENTRIES.filter(e => e.tenant_id === null).length);
  });

  test('RLS1-03 ordinary plain SELECT as qodiqa_app with tenant A context still cannot see tenant B rows', async () => {
    const client = await _appPool.connect();
    try {
      // set_config(..., true) is transaction-local — it must be set and read
      // within the same explicit transaction, exactly as tenantContext.js's
      // own setLocal() requires (see that module's header comment).
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
