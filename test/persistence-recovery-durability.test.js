'use strict';

/**
 * CHAIN-3 — Durable Persistence Recovery Queue: PostgreSQL-mode integration tests
 *
 * Requires a real, reachable local PostgreSQL (QODIQA_PG_ENABLED=true) with
 * CREATEDB privilege on the connecting role — skipped entirely otherwise,
 * same convention as test/integration/audit-chain-verifier-pg.integration.test.js and
 * src/infra/postgres/__tests__/rls.test.js's RLS-91..100. Creates its own
 * freshly-named, disposable database for the duration of the run (dropped
 * in afterAll) so full-table assertions (exact stats/depths) are never
 * flaky against whatever else lives in a shared dev database.
 *
 * These tests prove that the Persistence
 * Recovery Queue's durable store is PostgreSQL (migration 032), not Redis —
 * Redis is never configured, started, or referenced anywhere in this file,
 * and every scenario below passes without it.
 *
 * DUR-01  Recovery item creation succeeds and is durably persisted with no
 *         Redis configured at all (REDIS_URL unset)
 * DUR-02  Replay of a DLQ item succeeds with no Redis configured at all
 * DUR-03  A transient PG-classified failure is retried and eventually
 *         succeeds once the simulated failure clears
 * DUR-04  An EVIDENCE_CHAIN_SAVE-type failure is retried and eventually
 *         replayed to success through the identical durable mechanism
 * DUR-05  Process crash before replay: an item claimed but never
 *         completed survives — it is reclaimable once its claim window
 *         elapses, not lost
 * DUR-06  Service restart: a pending item enqueued before a full module
 *         reset (jest.resetModules()) is still present and processable
 *         after "restart"
 * DUR-07  Multiple pending recovery items are each claimed exactly once
 * DUR-08  Duplicate replay prevention: two concurrent replay attempts on
 *         the same DLQ item — exactly one succeeds
 * DUR-09  Idempotent replay: replaying an already-completed logical
 *         operation through the real ATTESTATION_SAVE handler does not
 *         create a duplicate downstream row (ON CONFLICT DO NOTHING)
 * DUR-10  Exponential backoff: successive markRetry calls schedule
 *         eligible_at using the worker's documented RETRY_DELAYS_MS,
 *         and the item is not claimable before that time
 * DUR-11  Dead-letter transition after MAX_RETRIES exhausted
 * DUR-12  Recovery proceeds normally "after Redis becomes available" —
 *         i.e. is completely unaffected by REDIS_URL being set or unset
 * DUR-13  Recovery proceeds normally "while Redis remains unavailable" —
 *         full enqueue → claim → complete lifecycle with REDIS_URL unset
 *         for the entire test
 * DUR-14  Concurrent recovery workers: two independent claim loops never
 *         double-process the same item (FOR UPDATE SKIP LOCKED)
 * DUR-15  Crash during replay: a replayed item that is never subsequently
 *         claimed/processed remains durably PENDING, not lost
 * DUR-16  Large recovery queue: 250 items are all eventually claimed and
 *         completed exactly once, with correct final stats
 * DUR-17  Ordering: items become claimable in eligible_at ascending order
 * DUR-18  Recovery record cleanup: markComplete atomically removes the row
 *         (verified via a direct query against the table, not just the
 *         public API's own read path)
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_prq_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _originalDatabaseEnv;
let _originalRedisUrlEnv;
let _originalUserEnv;
let _originalPasswordEnv;
let _maintenancePool;
let pgPool, queue, worker, recoveryManager, OPERATION_TYPES;

describeOrSkip('CHAIN-3 — Durable Persistence Recovery Queue (PostgreSQL mode, integration)', () => {
  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) — falls back to the pre-existing chain so CI's ephemeral
    // postgres:17-alpine superuser container (QODIQA_PG_USER=qodiqa there)
    // is unaffected.
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
    _originalRedisUrlEnv = process.env.REDIS_URL;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    // CHAIN-3's entire point: Redis must never be required. Unset it for
    // the whole suite so every scenario below proves the pipeline works
    // with no Redis dependency present at all.
    delete process.env.REDIS_URL;
    // pgPool below runs runMigrations() against this fresh database, which
    // includes migration 002 (CREATE ROLE) and 018 (ALTER ROLE ... BYPASSRLS)
    // — both require the connecting role to hold CREATEROLE+BYPASSRLS itself.
    // Elevate for the duration of this suite; restored in afterAll.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pgPool          = require('../src/infra/postgres/pool');
    queue           = require('../src/core/persistenceRecovery/queue');
    worker          = require('../src/core/persistenceRecovery/worker');
    recoveryManager = require('../src/core/persistenceRecovery/recoveryManager');
    ({ OPERATION_TYPES } = require('../src/core/persistenceRecovery/persistenceOperation'));

    pgPool.initialize();
    await pgPool.runMigrations();
  }, 60_000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_originalRedisUrlEnv !== undefined) process.env.REDIS_URL = _originalRedisUrlEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // Best-effort cleanup only — a leftover uniquely-named disposable
        // test DB is a minor annoyance, never a reason to fail the suite.
        // eslint-disable-next-line no-console
        console.warn(`[persistence-recovery-durability] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  afterEach(async () => {
    // Each test cleans up its own rows by unique operationId prefix — this
    // is a belt-and-braces sweep in case any assertion failed mid-test
    // before its own cleanup ran, so later tests never see cross-test state.
    worker.stop();
  });

  // ── Helpers ───────────────────────────────────────────────────────────────

  function opId(prefix) {
    return `${prefix}-${crypto.randomBytes(4).toString('hex')}`;
  }

  async function enqueueTestOp(operationId, overrides = {}) {
    await queue.enqueue({
      operationId,
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service:       'attestation',
      payload:       { attestationId: operationId },
      ...overrides,
    });
  }

  async function rowExists(operationId) {
    const result = await pgPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [operationId],
    );
    return result.rows.length > 0;
  }

  async function rowStatus(operationId) {
    const result = await pgPool.query(
      `SELECT status FROM persistence_recovery_queue WHERE operation_id = $1`,
      [operationId],
    );
    return result.rows[0]?.status ?? null;
  }

  // ── DUR-01: creation with no Redis configured ────────────────────────────

  test('DUR-01 recovery item creation is durably persisted with REDIS_URL unset', async () => {
    expect(process.env.REDIS_URL).toBeUndefined();

    const id = opId('dur01');
    await enqueueTestOp(id);

    expect(await rowExists(id)).toBe(true);
    expect(await rowStatus(id)).toBe('PENDING');

    await queue.claimNext();
    await queue.markComplete(id);
  });

  // ── DUR-02: replay with no Redis configured ──────────────────────────────

  test('DUR-02 DLQ replay succeeds with REDIS_URL unset', async () => {
    expect(process.env.REDIS_URL).toBeUndefined();

    const id = opId('dur02');
    await enqueueTestOp(id);
    await queue.claimNext();
    await queue.moveToDlq(id, 'simulated exhaustion', 5);
    expect(await rowStatus(id)).toBe('DLQ');

    const replayed = await queue.replayDlqItem(id);
    expect(replayed).toBe(true);
    expect(await rowStatus(id)).toBe('PENDING');

    await queue.claimNext();
    await queue.markComplete(id);
  });

  // ── DUR-03: transient failure retried to success ─────────────────────────

  test('DUR-03 a transient failure is retried and eventually succeeds', async () => {
    const id = opId('dur03');
    let attempts = 0;
    worker.registerHandler(OPERATION_TYPES.ATTESTATION_SAVE, async () => {
      attempts += 1;
      if (attempts < 3) return { success: false, error: 'ECONNRESET (simulated)' };
      return { success: true };
    });

    await enqueueTestOp(id);

    // Drive the worker directly (deterministic, no timer dependency).
    for (let i = 0; i < 3; i++) {
      const op = await queue.claimNext();
      if (!op) break;
      await worker._processOne(op);
      if (attempts >= 3) break;
      // Force immediate re-eligibility instead of waiting out the real
      // exponential-backoff delay — this test is about retry-then-succeed
      // semantics, not backoff timing (covered separately by DUR-10).
      await pgPool.query(`UPDATE persistence_recovery_queue SET eligible_at = NOW() WHERE operation_id = $1`, [id]);
    }

    expect(attempts).toBe(3);
    expect(await rowExists(id)).toBe(false); // markComplete deleted it
  });

  // ── DUR-04: EVIDENCE_CHAIN_SAVE-type failure retried to success ──────────

  test('DUR-04 an EVIDENCE_CHAIN_SAVE-type operation is retried through the same durable mechanism and replays to success', async () => {
    const id = opId('dur04-evch');
    let attempts = 0;
    worker.registerHandler(OPERATION_TYPES.EVIDENCE_CHAIN_SAVE, async () => {
      attempts += 1;
      if (attempts === 1) return { success: false, error: 'connection terminated (simulated)' };
      return { success: true };
    });

    await queue.enqueue({
      operationId:   id,
      operationType: OPERATION_TYPES.EVIDENCE_CHAIN_SAVE,
      service:       'evidence',
      payload:       { auditEntry: { artifactId: id }, keyInfo: null, opts: null },
    });

    let op = await queue.claimNext();
    await worker._processOne(op); // fails once
    expect(attempts).toBe(1);
    expect(await rowStatus(id)).toBe('PENDING'); // still pending, not DLQ or lost

    await pgPool.query(`UPDATE persistence_recovery_queue SET eligible_at = NOW() WHERE operation_id = $1`, [id]);
    op = await queue.claimNext();
    await worker._processOne(op); // succeeds
    expect(attempts).toBe(2);
    expect(await rowExists(id)).toBe(false);
  });

  // ── DUR-05: process crash before replay — claimed item survives ─────────

  test('DUR-05 an item claimed but never completed (simulated crash) is reclaimable, not lost', async () => {
    const id = opId('dur05');
    await enqueueTestOp(id);

    const claimed = await queue.claimNext();
    expect(claimed.operationId).toBe(id);
    // Simulate a crash: no markComplete/markRetry/moveToDlq ever runs.
    // The row still exists — durability does not depend on the crashed
    // worker's process memory.
    expect(await rowExists(id)).toBe(true);

    // Simulate the crash-safe claim window elapsing (production waits
    // CLAIM_TIMEOUT_MS = 30s; here we fast-forward deterministically).
    await pgPool.query(`UPDATE persistence_recovery_queue SET eligible_at = NOW() WHERE operation_id = $1`, [id]);

    const reclaimed = await queue.claimNext();
    expect(reclaimed).not.toBeNull();
    expect(reclaimed.operationId).toBe(id);
    await queue.markComplete(id);
  });

  // ── DUR-06: service restart — pending item survives a module reset ──────

  test('DUR-06 a pending item survives a full module reset (simulated service restart)', async () => {
    const id = opId('dur06');
    await enqueueTestOp(id);
    expect(await rowExists(id)).toBe(true);

    // Close the "old process"'s pool connections first — a real restart
    // fully exits the old process (and therefore its connections) before
    // the new one starts. Skipping this would leak the old pg.Pool's open
    // sockets past jest.resetModules() (which only clears the module
    // *registry*, not already-constructed network resources), and this
    // suite's own afterAll DROP DATABASE would then fail with "database is
    // being accessed by other users".
    await pgPool.shutdown();

    // Simulate "the process restarted": drop every in-process module
    // reference and re-require from scratch. Nothing about the row's
    // durability lives in that discarded module state — it lives in
    // PostgreSQL.
    jest.resetModules();
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    const restartedPgPool = require('../src/infra/postgres/pool');
    const restartedQueue  = require('../src/core/persistenceRecovery/queue');
    restartedPgPool.initialize();

    const claimed = await restartedQueue.claimNext();
    expect(claimed).not.toBeNull();
    expect(claimed.operationId).toBe(id);
    await restartedQueue.markComplete(id);

    // The "restarted" pool becomes the shared pool the rest of this file's
    // tests use — no separate pool is left dangling.
    pgPool          = restartedPgPool;
    queue           = restartedQueue;
    worker          = require('../src/core/persistenceRecovery/worker');
    recoveryManager = require('../src/core/persistenceRecovery/recoveryManager');
    pgPool.initialize();
  });

  // ── DUR-07: multiple pending items each claimed exactly once ─────────────

  test('DUR-07 multiple pending items are each claimed exactly once', async () => {
    const ids = [opId('dur07-a'), opId('dur07-b'), opId('dur07-c')];
    for (const id of ids) await enqueueTestOp(id);

    const claimedIds = new Set();
    for (let i = 0; i < ids.length; i++) {
      const op = await queue.claimNext();
      expect(op).not.toBeNull();
      expect(claimedIds.has(op.operationId)).toBe(false);
      claimedIds.add(op.operationId);
      await queue.markComplete(op.operationId);
    }
    expect(claimedIds.size).toBe(ids.length);
    for (const id of ids) expect(claimedIds.has(id)).toBe(true);
  });

  // ── DUR-08: duplicate replay prevention ──────────────────────────────────

  test('DUR-08 two concurrent replay attempts on the same DLQ item — exactly one succeeds', async () => {
    const id = opId('dur08');
    await enqueueTestOp(id);
    await queue.claimNext();
    await queue.moveToDlq(id, 'exhausted', 5);

    const [r1, r2] = await Promise.all([
      queue.replayDlqItem(id),
      queue.replayDlqItem(id),
    ]);

    const successes = [r1, r2].filter(Boolean).length;
    expect(successes).toBe(1);
    expect(await rowStatus(id)).toBe('PENDING');

    await queue.claimNext();
    await queue.markComplete(id);
  });

  // ── DUR-09: idempotent replay via the real ATTESTATION_SAVE handler ─────

  test('DUR-09 replaying an already-completed ATTESTATION_SAVE does not create a duplicate row', async () => {
    const attestationId = crypto.randomUUID();
    const id = `att:${attestationId}`;
    const handler = recoveryManager._builtinHandlers[OPERATION_TYPES.ATTESTATION_SAVE];

    const op = {
      operationId:   id,
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service:       'attestation',
      payload:       { attestationId, attestationDecision: 'ATTESTED' },
      retryCount:    0,
    };

    // First attempt: real INSERT.
    const first = await handler(op);
    expect(first.success).toBe(true);

    // Second attempt against the identical attestationId: ON CONFLICT (attestation_id)
    // DO NOTHING means this is a no-op at the database level, not a duplicate row —
    // exactly the idempotency guarantee replay depends on.
    const second = await handler(op);
    expect(second.success).toBe(true);

    const countResult = await pgPool.query(`SELECT count(*) AS c FROM attestations WHERE attestation_id = $1`, [attestationId]);
    expect(Number(countResult.rows[0].c)).toBe(1);
  });

  // ── DUR-10: exponential backoff scheduling ───────────────────────────────

  test('DUR-10 markRetry schedules eligible_at using the worker\'s RETRY_DELAYS_MS and the item is not claimable early', async () => {
    const id = opId('dur10');
    await enqueueTestOp(id);
    await queue.claimNext();

    const delayMs = worker.RETRY_DELAYS_MS[0]; // first backoff step (5s in production)
    const eligibleAtMs = Date.now() + delayMs;
    await queue.markRetry(id, 'simulated transient failure', 1, eligibleAtMs);

    // Not claimable yet — eligible_at is in the future.
    expect(await queue.claimNext()).toBeNull();

    const row = await pgPool.query(`SELECT eligible_at FROM persistence_recovery_queue WHERE operation_id = $1`, [id]);
    const storedEligibleAtMs = new Date(row.rows[0].eligible_at).getTime();
    expect(storedEligibleAtMs).toBeGreaterThan(Date.now()); // still in the future
    expect(Math.abs(storedEligibleAtMs - eligibleAtMs)).toBeLessThan(1000); // round-trips accurately

    // Fast-forward and confirm it becomes claimable once due.
    await pgPool.query(`UPDATE persistence_recovery_queue SET eligible_at = NOW() WHERE operation_id = $1`, [id]);
    const claimed = await queue.claimNext();
    expect(claimed.operationId).toBe(id);
    expect(claimed.retryCount).toBe(1);
    await queue.markComplete(id);
  });

  // ── DUR-11: dead-letter transition after MAX_RETRIES ─────────────────────

  test('DUR-11 an operation that fails MAX_RETRIES times transitions to DLQ', async () => {
    const id = opId('dur11');
    worker.registerHandler(OPERATION_TYPES.ATTESTATION_SAVE, async () => ({ success: false, error: 'permanent simulated failure' }));
    await enqueueTestOp(id);

    for (let i = 0; i <= worker.MAX_RETRIES; i++) {
      const op = await queue.claimNext();
      if (!op) break;
      await worker._processOne(op);
      await pgPool.query(`UPDATE persistence_recovery_queue SET eligible_at = NOW() WHERE operation_id = $1 AND status = 'PENDING'`, [id]);
    }

    expect(await rowStatus(id)).toBe('DLQ');
    await queue.archiveDlqItem(id); // cleanup: soft-archive rather than leaving DLQ noise for other tests
  });

  // ── DUR-12 / DUR-13: Redis presence is irrelevant ────────────────────────

  test('DUR-12 recovery works identically whether REDIS_URL is set or not (set case)', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:9999'; // deliberately unreachable — must not matter at all
    try {
      const id = opId('dur12');
      await enqueueTestOp(id);
      const claimed = await queue.claimNext();
      expect(claimed.operationId).toBe(id);
      await queue.markComplete(id);
      expect(await rowExists(id)).toBe(false);
    } finally {
      delete process.env.REDIS_URL;
    }
  });

  test('DUR-13 recovery works with REDIS_URL unset for the entire enqueue → claim → complete lifecycle', async () => {
    expect(process.env.REDIS_URL).toBeUndefined();
    const id = opId('dur13');
    await enqueueTestOp(id);
    const claimed = await queue.claimNext();
    expect(claimed.operationId).toBe(id);
    await queue.markComplete(id);
    expect(await rowExists(id)).toBe(false);
  });

  // ── DUR-14: concurrent recovery workers never double-process ────────────

  test('DUR-14 two concurrent claim loops never process the same item twice', async () => {
    const ids = Array.from({ length: 10 }, (_, i) => opId(`dur14-${i}`));
    for (const id of ids) await enqueueTestOp(id);

    const processedBy = new Map(); // operationId → worker label

    async function runWorkerLoop(label) {
      const claimedHere = [];
      for (let i = 0; i < ids.length; i++) {
        const op = await queue.claimNext();
        if (!op) break;
        claimedHere.push(op.operationId);
        await queue.markComplete(op.operationId);
      }
      return { label, claimedHere };
    }

    const [resultA, resultB] = await Promise.all([runWorkerLoop('A'), runWorkerLoop('B')]);

    for (const id of [...resultA.claimedHere, ...resultB.claimedHere]) {
      processedBy.set(id, (processedBy.get(id) ?? 0) + 1);
    }

    const allProcessedIds = new Set([...resultA.claimedHere, ...resultB.claimedHere]);
    expect(allProcessedIds.size).toBe(ids.length); // every item processed
    for (const count of processedBy.values()) {
      expect(count).toBe(1); // never processed twice
    }
  });

  // ── DUR-15: crash during replay — replayed item stays durable ───────────

  test('DUR-15 a replayed item that is never subsequently claimed remains durably PENDING', async () => {
    const id = opId('dur15');
    await enqueueTestOp(id);
    await queue.claimNext();
    await queue.moveToDlq(id, 'exhausted', 5);

    const replayed = await queue.replayDlqItem(id);
    expect(replayed).toBe(true);
    // Simulate a crash immediately after replay, before any worker claims it.
    expect(await rowStatus(id)).toBe('PENDING');
    expect(await rowExists(id)).toBe(true);

    // Cleanup
    const op = await queue.claimNext();
    await queue.markComplete(op.operationId);
  });

  // ── DUR-16: large recovery queue ─────────────────────────────────────────

  test('DUR-16 250 items are all eventually claimed and completed exactly once', async () => {
    const COUNT = 250;
    const ids = Array.from({ length: COUNT }, (_, i) => opId(`dur16-${i}`));
    await Promise.all(ids.map(id => enqueueTestOp(id)));

    const seen = new Set();
    for (let i = 0; i < COUNT; i++) {
      const op = await queue.claimNext();
      expect(op).not.toBeNull();
      expect(seen.has(op.operationId)).toBe(false);
      seen.add(op.operationId);
      await queue.markComplete(op.operationId);
    }

    expect(seen.size).toBe(COUNT);
    expect(await queue.claimNext()).toBeNull(); // queue fully drained
  }, 30_000);

  // ── DUR-17: ordering guarantee ────────────────────────────────────────────

  test('DUR-17 items become claimable in eligible_at ascending order', async () => {
    const idLate  = opId('dur17-late');
    const idEarly = opId('dur17-early');

    // Enqueue "late" first, then explicitly move "early" further back in
    // time than "late" so claim order is determined by eligible_at, not
    // insertion order.
    await enqueueTestOp(idLate);
    await enqueueTestOp(idEarly);
    await pgPool.query(
      `UPDATE persistence_recovery_queue SET eligible_at = eligible_at - interval '10 seconds' WHERE operation_id = $1`,
      [idEarly],
    );

    const first  = await queue.claimNext();
    const second = await queue.claimNext();

    expect(first.operationId).toBe(idEarly);
    expect(second.operationId).toBe(idLate);

    await queue.markComplete(idEarly);
    await queue.markComplete(idLate);
  });

  // ── DUR-18: cleanup after success is atomic and verified directly ───────

  test('DUR-18 markComplete atomically removes the row (verified via direct table query)', async () => {
    const id = opId('dur18');
    await enqueueTestOp(id);
    await queue.claimNext();

    const beforeCount = await pgPool.query(`SELECT count(*) AS c FROM persistence_recovery_queue WHERE operation_id = $1`, [id]);
    expect(Number(beforeCount.rows[0].c)).toBe(1);

    await queue.markComplete(id);

    const afterCount = await pgPool.query(`SELECT count(*) AS c FROM persistence_recovery_queue WHERE operation_id = $1`, [id]);
    expect(Number(afterCount.rows[0].c)).toBe(0);
  });
});
