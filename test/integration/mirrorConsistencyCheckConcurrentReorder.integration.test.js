'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * remediation, mechanism 1 — real Postgres reproduction of the
 * crossValidateRecords() positional-comparison false positive.
 *
 * Mirrors test/integration/audit-chain-verifier-pg.integration.test.js's disposable-
 * database pattern (real PostgreSQL, own uniquely-named DB, no mocking of
 * pg-audit-backend.js or pool.js).
 *
 * What this proves that mirrorConsistencyCheck.test.js's own CV-08 (a pure
 * in-memory unit test with synthetic reordered arrays) cannot: that the real
 * pg-audit-backend.js persistEntry()/loadChainFromPg() functions, against a
 * real PostgreSQL BIGSERIAL `seq` column, genuinely produce the exact
 * out-of-order-insertion shape Session 3 live-witnessed under real
 * sustained load — and that the
 * fixed, content-addressed crossValidateRecords() correctly treats it as
 * clean end to end, not just against a hand-built fixture.
 *
 * Reordering is driven deterministically here (persistEntry() calls issued
 * in a scrambled order, not the chain's own true logical order) rather than
 * relying on a genuine timing race — a real Promise.all race reproduces the
 * same shape non-deterministically (as Session 3's own live load
 * test confirmed happens under real concurrency) but would make this
 * specific regression test flaky in CI; issuing the same real INSERT calls
 * out of order is a real, deterministic instance of the identical root
 * cause (PostgreSQL's BIGSERIAL `seq` reflects INSERT-statement-execution
 * order, not any property of the data itself), not a synthetic stand-in for
 * it.
 *
 * MCR-01  A file chain and its real PG mirror, written via persistEntry()
 *         in a scrambled order, is reported clean by verifyMirrorConsistency()
 *         — the same function this repo's startup boot sequence calls.
 * MCR-02  Explicit "the server would have booted" framing: _exit is a
 *         jest.fn() that throws if ever invoked — proves the FATAL startup
 *         gate is never triggered by this benign reordering, where the
 * earlier positional comparison would have called it.
 * MCR-03  A REAL divergence (a genuinely corrupted PG row, not merely
 *         reordered) is still caught — the fix must not have traded away
 *         real detection for order-tolerance.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_mcr_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _originalDatabaseEnv;
let _originalUserEnv;
let _originalPasswordEnv;
let _maintenancePool;
let _fixturePool = null; // DB-05
let pgPool, pgAuditBackend, entryBuilder, mirrorCheck, realAuditLog;

describeOrSkip('mirrorConsistencyCheck concurrent-dual-write reordering (real PostgreSQL)', () => {
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

    // DB-05 (migration 076): the product pool's own startup options override PGOPTIONS, so this suite's audit_chain
    // resets and tamper simulations go through this fixture pool (same test identity, same disposable database), which
    // carries the declared fixture intent from test/helpers/auditMaintenance.js.
    _fixturePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
      max:      2,
    });

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pgPool         = require('../../src/infra/postgres/pool');
    pgAuditBackend = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder   = require('../../src/core/audit/entryBuilder');
    mirrorCheck    = require('../../src/core/audit/mirrorConsistencyCheck');
    realAuditLog   = require('../../src/core/audit/audit-log');

    pgPool.initialize();
    await pgPool.runMigrations();
  }, 60_000);

  afterAll(async () => { if (_fixturePool) await _fixturePool.end().catch(() => {}); });
  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[mirrorConsistencyCheckConcurrentReorder.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  function buildChain(n, prefix) {
    const entries = [];
    let prevHash = 'GENESIS';
    for (let i = 0; i < n; i++) {
      const entry = entryBuilder.buildEntry(
        entryBuilder.normalizeFields({
          artifactId: `${prefix}-${i}`,
          inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
          requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
        }),
        prevHash
      );
      entries.push(entry);
      prevHash = entry.hash;
    }
    return entries;
  }

  // every mirror INSERT is parent-guarded
  // (pg-audit-backend.js insertMirrorRow), so persistEntry() can no longer
  // produce the out-of-order state these tests need — that is the fix. The
  // condition still exists in every mirror written, and
  // mirrorConsistencyCheck must keep treating it as clean. legacyInsert() writes
  // exactly as earlier persistEntry() did: the real insertMirrorRow() INSERT
  // with its parent guard answered "ok", i.e. unguarded.
  async function legacyInsert(entry) {
    // the parent/self guard now runs as qodiqa_system; a simulated
    // earlier (unguarded) writer injects its answer via _guardQuery instead of a fake tx.
    await pgPool.withTransaction((tx) => pgAuditBackend.insertMirrorRow(tx, entry, {
      _guardQuery: async () => ({ rows: [{ parent_ok: true, self_exists: false }] }),
    }), { isolationLevel: 'READ COMMITTED' });
  }

  function fakeFileAuditLog(entries) {
    return {
      getChainStats: () => ({
        chainLength:  entries.length,
        modernLength: entries.length,
        headHash:     entries.length ? entries[0].hash : null,
        tailHash:     entries.length ? entries[entries.length - 1].hash : 'GENESIS',
      }),
      getModernChain: () => entries,
      verifyAuditChainDetailed: (list) => realAuditLog.verifyAuditChainDetailed(list),
    };
  }

  test('MCR-01 real PG rows inserted out of true logical order are reported clean, not a false divergence', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');

    const entries = buildChain(6, 'mcr01');

    // Scrambled insertion order — a real, deterministic instance of the same
    // root cause a genuine concurrent race produces: PostgreSQL's BIGSERIAL
    // `seq` reflects INSERT-execution order, which here differs from the
    // chain's own true logical (file) order at indices 4 and 5.
    const insertOrder = [0, 1, 2, 3, 5, 4];
    for (const idx of insertOrder) {
      await legacyInsert(entries[idx]);
    }

    // Confirm the scramble actually landed as intended — seq order really
    // does differ from file order, or this test would prove nothing.
    const seqRows = await pgPool.query('SELECT hash FROM audit_chain ORDER BY seq ASC');
    expect(seqRows.rows.map(r => r.hash)).toEqual([
      entries[0].hash, entries[1].hash, entries[2].hash,
      entries[3].hash, entries[5].hash, entries[4].hash,
    ]);

    const ok = await mirrorCheck.verifyMirrorConsistency({
      _auditLog:       fakeFileAuditLog(entries),
      _pgPool:         pgPool,
      _pgAuditBackend: pgAuditBackend,
      _exit:           () => { throw new Error('MCR-01: startup gate must not FATAL on benign reordering'); },
    });

    expect(ok).toBe(true);
  });

  test('MCR-01b the real persistEntry() refuses the out-of-order write: the child waits (queued), seq stays in chain order', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');
    const entries = buildChain(6, 'mcr01b');
    for (const idx of [0, 1, 2, 3, 5]) await pgAuditBackend.persistEntry(entries[idx]); // 5 before its parent 4
    let rows = await pgPool.query('SELECT hash FROM audit_chain ORDER BY seq ASC');
    expect(rows.rows.map((r) => r.hash)).toEqual(entries.slice(0, 4).map((e) => e.hash)); // entry 5 NOT inserted
    const queued = await pgPool.query("SELECT count(*)::int AS n FROM persistence_recovery_queue WHERE operation_type = 'AUDIT_CHAIN_PG_SAVE'");
    expect(queued.rows[0].n).toBeGreaterThanOrEqual(1);                                   // durably queued, not lost
    await pgAuditBackend.persistEntry(entries[4]);                                          // parent lands
    const handler = require('../../src/core/persistenceRecovery/recoveryManager')._builtinHandlers.AUDIT_CHAIN_PG_SAVE;
    expect((await handler({ payload: entries[5] })).success).toBe(true);                   // replay now succeeds
    rows = await pgPool.query('SELECT hash FROM audit_chain ORDER BY seq ASC');
    expect(rows.rows.map((r) => r.hash)).toEqual(entries.map((e) => e.hash));             // seq order == chain order
    await pgPool.query('DELETE FROM persistence_recovery_queue');
  });

  test('MCR-02 a healthy server boots under the same reordered-write condition (the earlier gate would have FATAL\'d)', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');

    const entries = buildChain(4, 'mcr02');
    // Reverse insertion order — the most extreme reordering shape, still a
    // completely healthy, unbroken hash chain by content.
    for (let i = entries.length - 1; i >= 0; i--) {
      await legacyInsert(entries[i]);
    }

    const exitFn = jest.fn(() => { throw new Error('startup would have exited — server would NOT have booted'); });
    const emitFn = jest.fn();

    const ok = await mirrorCheck.verifyMirrorConsistency({
      _auditLog:       fakeFileAuditLog(entries),
      _pgPool:         pgPool,
      _pgAuditBackend: pgAuditBackend,
      _exit:           exitFn,
      _emit:           emitFn,
    });

    expect(ok).toBe(true);
    expect(exitFn).not.toHaveBeenCalled();
    expect(emitFn).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', expect.any(Object));
  });

  test('MCR-03 a real, genuine divergence (not mere reordering) is still caught', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');

    const entries = buildChain(5, 'mcr03');
    // Insert only 4 of the 5 — entries[3] never reaches PG at all (a real
    // dropped/lost write, not a reordering artifact).
    for (let i = 0; i < entries.length; i++) {
      if (i === 3) continue;
      await legacyInsert(entries[i]);
    }

    const exitFn = jest.fn();
    const ok = await mirrorCheck.verifyMirrorConsistency({
      _auditLog:       fakeFileAuditLog(entries),
      _pgPool:         pgPool,
      _pgAuditBackend: pgAuditBackend,
      _exit:           exitFn,
      _emit:           jest.fn(),
    });

    expect(ok).toBe(false);
    expect(exitFn).toHaveBeenCalledWith(1);
  });
});
