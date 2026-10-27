'use strict';

/**
 * real end-to-end recovery test for a write dropped by genuine
 * PostgreSQL connection-pool exhaustion (not the synthetic PG_CIRCUIT_OPEN
 * breaker-open condition already covers — see
 * auditChainCircuitOpenRecovery.integration.test.js, unmodified, still the
 * regression proof for that trigger).
 *
 * Mirrors that file's own disposable-database pattern (real PostgreSQL, real
 * pool.js, no mocking) but forces the failure a structurally different way:
 * QODIQA_PG_POOL_MAX=2 and both connections held busy by real pg_sleep()
 * queries through the SAME pool.js singleton the code under test uses, so a
 * concurrent persistEntry() attempt genuinely queues for a free connection
 * and genuinely times out via pg-pool's own real connectionTimeoutMillis
 * budget — the exact real error ('timeout exceeded when trying to connect',
 * no .code at all)'s section live-
 * witnessed. Before this remediation, isPersistenceFailure() did not
 * recognize that message, so persistEntry() never called enqueue() at all —
 * the write vanished with no queue row and no journal entry, permanently.
 *
 * PXR-01  A write attempted while the pool is genuinely exhausted is NOT
 *         lost. The recovery-queue INSERT itself also needs a connection
 * from the same exhausted pool, so — like's ACOR-01 — it times
 *         out too, and recoveryManager's own FAILOVER-1 journal fallback
 *         engages: durably written to disk instead of dropped.
 * PXR-02  Once the pool genuinely drains (the holder queries complete) and
 *         PostgreSQL is reachable again: the journal entry replays into the
 *         real PG-backed queue, and draining that queue through the real
 *         worker handler backfills the exact row into audit_chain — correct
 *         hash/prevHash, confirmed via direct SQL, zero dangling reference.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_pxr_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

// Long enough to cover BOTH real connectionTimeoutMillis (5000ms) waits in
// sequence — persistEntry()'s own withTransaction() acquisition, then
// enqueue()'s queue.enqueue() acquisition attempt right after, since both go
// through the identical, still-exhausted pool — with margin. Held via two
// concurrent SELECT pg_sleep() queries through pool.js itself, not a
// separate connection, so this genuinely occupies the same singleton pool
// the code under test acquires from.
const HOLD_SECONDS = 11;

let _originalDatabaseEnv;
let _originalUserEnv;
let _originalPasswordEnv;
let _originalPoolMaxEnv;
let _maintenancePool;
let _verifyPool; // raw pg Pool, separate from pool.js's own — for assertions only
let pgPool, pgCircuitBreaker, pgAuditBackend, entryBuilder, queue, worker, recoveryManager, journal, journalWorker;

jest.setTimeout(60_000);

describeOrSkip('audit_chain write survives genuine connection-pool exhaustion (real disposable Postgres)', () => {
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
      // Safe: TEST_DB_NAME is generator-controlled (timestamp + random hex,
      // validated against SAFE_IDENTIFIER above), never derived from
      // external/user input.
      await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    }

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    _originalPoolMaxEnv  = process.env.QODIQA_PG_POOL_MAX;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }
    // The deliberately tiny pool this whole test exists to exhaust — matches
    // Session 3's own live-witness sizing exactly.
    process.env.QODIQA_PG_POOL_MAX = '2';

    // Dedicated, per-run journal directory — PXR-01's fallback path writes
    // real files; must never touch the real data/prq-journal directory
    // shared by an actual running server.
    const journalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-prq-journal-pxr-'));
    process.env.QODIQA_PRQ_JOURNAL_DIR = journalDir;

    jest.resetModules();
    pgPool           = require('../../src/infra/postgres/pool');
    pgCircuitBreaker  = require('../../src/infra/postgres/pgCircuitBreaker');
    pgAuditBackend    = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder      = require('../../src/core/audit/entryBuilder');
    queue             = require('../../src/core/persistenceRecovery/queue');
    worker            = require('../../src/core/persistenceRecovery/worker');
    recoveryManager   = require('../../src/core/persistenceRecovery/recoveryManager');
    journal           = require('../../src/core/persistenceRecovery/journal');
    journalWorker     = require('../../src/core/persistenceRecovery/journalWorker');

    pgPool.initialize();
    await pgPool.runMigrations();

    // Separate raw connection for assertions — never competes with the
    // 2-slot pool under test for one of its own connections.
    _verifyPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_USER,
      password: process.env.QODIQA_PG_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    // Register the REAL production handler for AUDIT_CHAIN_PG_SAVE — the
    // exact function persistEntry()'s own retry path relies on in
    // production, not a test stand-in.
    worker.registerHandler(
      recoveryManager.OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE,
      recoveryManager._builtinHandlers[recoveryManager.OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE],
    );
  }, 60_000);

  afterAll(async () => {
    pgCircuitBreaker?.reset();
    if (_verifyPool) await _verifyPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    process.env.QODIQA_PG_POOL_MAX = _originalPoolMaxEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[auditChainPoolExhaustionRecovery.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }

    if (process.env.QODIQA_PRQ_JOURNAL_DIR) {
      fs.rmSync(process.env.QODIQA_PRQ_JOURNAL_DIR, { recursive: true, force: true });
    }
  }, 30_000);

  afterEach(() => {
    pgCircuitBreaker.reset();
  });

  function buildTestEntry(artifactId) {
    const normalized = entryBuilder.normalizeFields({
      artifactId,
      inputHash:          'a'.repeat(64),
      decision:           'BLOCK',
      signature:          `sig-${artifactId}`,
      requestHash:        'b'.repeat(64),
      policyHash:         'c'.repeat(64),
      verificationResult: false,
    });
    return entryBuilder.buildEntry(normalized, 'GENESIS');
  }

  /**
   * Occupies both of the pool's 2 connections with real, held queries —
   * genuine exhaustion, not a simulated/mocked one. Returns the (unawaited)
   * holder promise so the caller can await it later once its own timing-
   * sensitive assertions are done.
   */
  function occupyBothPoolSlots() {
    return Promise.all([
      pgPool.query(`SELECT pg_sleep(${HOLD_SECONDS})`, [], 'pxr-holder-0'),
      pgPool.query(`SELECT pg_sleep(${HOLD_SECONDS})`, [], 'pxr-holder-1'),
    ]);
  }

  test('PXR-01: a write attempted while the pool is genuinely exhausted is durably journaled, not lost', async () => {
    const holders = occupyBothPoolSlots();
    // Let both holders actually acquire their connections before the write
    // attempt below, so it genuinely queues behind them rather than racing
    // for one of the two free slots.
    await new Promise((r) => setTimeout(r, 300));

    const entry = buildTestEntry('pxr-01-artifact');
    // Real code path — pool exhausted, real pg-pool
    // 'timeout exceeded when trying to connect' thrown from the real
    // withTransaction() -> _pool.connect() call, no mocking.
    await pgAuditBackend.persistEntry(entry);

    // Not in audit_chain — the write genuinely never reached PostgreSQL.
    const chainRow = await _verifyPool.query(
      'SELECT hash FROM audit_chain WHERE artifact_id = $1',
      [entry.artifactId],
    );
    expect(chainRow.rows).toHaveLength(0);

    // The recovery-queue INSERT itself also needs a connection from the same
    // still-exhausted pool, so it times out too — not in the PG-backed queue
    // table yet.
    const queueRow = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queueRow.rows).toHaveLength(0);

    // But durably journaled to disk instead — recoveryManager's own
    // FAILOVER-1 fallback. This is the fix:, isPersistenceFailure
    // returned false for this exact real message, persistEntry() never
    // called enqueue() at all, and this entry would not exist anywhere.
    const journalEntries = await journal.listEntries();
    const journaled = journalEntries.find((e) => e.operation.operationId === `acpg:${entry.artifactId}`);
    expect(journaled).toBeDefined();
    expect(journaled.operation.operationType).toBe('AUDIT_CHAIN_PG_SAVE');
    expect(journaled.operation.payload.hash).toBe(entry.hash);

    await holders; // let the pool genuinely drain before the next test
  });

  test('PXR-02: once the pool genuinely drains, journal replay + queue drain backfills the exact row into audit_chain', async () => {
    const holders = occupyBothPoolSlots();
    await new Promise((r) => setTimeout(r, 300));

    const entry = buildTestEntry('pxr-02-artifact');
    await pgAuditBackend.persistEntry(entry);

    const journalEntriesBefore = await journal.listEntries();
    const journaled = journalEntriesBefore.find((e) => e.operation.operationId === `acpg:${entry.artifactId}`);
    expect(journaled).toBeDefined();

    // "The pool is genuinely healthy again" — wait for the real holder
    // queries to actually complete and release their connections, not a
    // simulated/instant recovery.
    await holders;

    // Real journal replay path — journalWorker._replayOne() calls the real
    // queue.enqueue() (now succeeds, connections are free) and removes the
    // journal file.
    const replayed = await journalWorker._replayOne(journaled);
    expect(replayed).toBe(true);

    const journalEntriesAfter = await journal.listEntries();
    expect(journalEntriesAfter.find((e) => e.operation.operationId === `acpg:${entry.artifactId}`)).toBeUndefined();

    const queuedAfterReplay = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queuedAfterReplay.rows).toHaveLength(1);

    // Drain the queue through the REAL claim -> real handler -> real
    // markComplete path — no shortcuts, this is the exact production flow
    // worker.js's poll loop runs.
    const claimed = await queue.claimNext();
    expect(claimed).not.toBeNull();
    expect(claimed.operationId).toBe(`acpg:${entry.artifactId}`);
    await worker._processOne(claimed);

    // Now genuinely present in audit_chain, with the exact hash/prevHash
    // the original (dropped) write attempt carried — zero dangling
    // prev_hash reference.
    const chainRow = await _verifyPool.query(
      'SELECT hash, prev_hash FROM audit_chain WHERE artifact_id = $1',
      [entry.artifactId],
    );
    expect(chainRow.rows).toHaveLength(1);
    expect(chainRow.rows[0].hash).toBe(entry.hash);
    expect(chainRow.rows[0].prev_hash).toBe(entry.prevHash);

    // And removed from the queue (worker.js markComplete() deletes on success).
    const queuedAfter = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queuedAfter.rows).toHaveLength(0);
  });
});
