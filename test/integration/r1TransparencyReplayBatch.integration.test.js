'use strict';

/**
 * R1 / — recovery-queue replays of transparency registrations through the
 * transparency GROUP-COMMIT batch path (QODIQA_TRANSPARENCY_GROUP_COMMIT=true, forced in THIS file only; the shipped
 * default stays OFF), on real PostgreSQL (disposable DB), with the real bridge, recovery queue, worker and
 * TRANSPARENCY_SAVE handler.
 *
 * RB-01  outage while registering concurrently (another session holds transparency_log_head, statement timeout):
 *        batched registrations fail as a whole → every caller gets persisted:'pending' with entryHash null (no false
 *        success), nothing is written, the head is unchanged, each registration is in the queue under its preset id
 * RB-02  the queued registrations are replayed CONCURRENTLY → they are committed in multi-leaf batches; every preset
 *        transparencyId appears exactly once with its pending payload hash; ids are contiguous and follow the order
 *        in which the replays reached the registrar; the queue rows are gone; the head names the last leaf
 * RB-03  duplicate concurrent replays of the SAME preset ids inside one batch → the unique transparency_id stops the
 *        duplicate (per-leaf fallback), the handler recognises "already written", exactly one leaf per id, no
 *        duplicate entry, every handler call reports success, the chain continues correctly
 * RB-04  replay while the head is locked again → the batch fails, the handler reports failure, the queue rows stay
 *        PENDING with retry_count 1 (no false success), nothing written, head unchanged; after release the same
 *        operations are replayed and written
 * RB-05  the whole log is one valid hash chain and the head pointer equals its last leaf
 *
 * DB qodiqa_r1rb_<pid>_<hex>, name appended to %TEMP%/qodiqa-w3-ledger.jsonl BEFORE creation, dropped and verified gone
 * in afterAll (the same convention as test/integration/transparencyQueue.integration.test.js).
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_r1rb_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const asTest = (database) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false,
});
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/r1TransparencyReplayBatch.integration.test.js' }) + '\n');

jest.setTimeout(180_000);

describeOrSkip('R1 group commit — batched recovery-queue replay of transparency registrations (real PostgreSQL)', () => {
  let created = false; const saved = {}; let tmpDir; let verify;
  let pgPool, breaker, bridge, queue, worker, recoveryManager, registrar, log, T;
  const pending = [];       // RB-01 results (preset ids, pending payload hashes)

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-r1rb-'));
    ledger('planned');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); } finally { await m.end(); }
    created = true; ledger('created');
    const mp = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }

    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PRQ_JOURNAL_DIR',
      'QODIQA_PG_STATEMENT_TIMEOUT_MS', 'PRQ_ENABLED', 'QODIQA_TRANSPARENCY_GROUP_COMMIT', 'QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH']) saved[k] = process.env[k];
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_PG_USER: APP_USER,
      QODIQA_PRQ_JOURNAL_DIR: path.join(tmpDir, 'prq'), QODIQA_PG_STATEMENT_TIMEOUT_MS: '2000', PRQ_ENABLED: 'true',
      QODIQA_TRANSPARENCY_GROUP_COMMIT: 'true' });
    delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH; // the shipped default (64)
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    breaker = require('../../src/infra/postgres/pgCircuitBreaker');
    bridge = require('../../src/core/transparency/enforcementBridge');
    queue = require('../../src/core/persistenceRecovery/queue');
    worker = require('../../src/core/persistenceRecovery/worker');
    recoveryManager = require('../../src/core/persistenceRecovery/recoveryManager');
    registrar = require('../../src/core/transparency/registrar');
    log = require('../../src/core/transparency/log');
    T = recoveryManager.OPERATION_TYPES.TRANSPARENCY_SAVE;
    worker.registerHandler(T, recoveryManager._builtinHandlers[T]);
    verify = new Pool(asTest(DB));
    expect(registrar.groupCommitStats().enabled).toBe(true); // this file tests the batch path
  });

  afterAll(async () => {
    breaker?.reset();
    if (verify) await verify.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (created) {
      const m = new Client(asTest('postgres')); await m.connect();
      try {
        try { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); }
        ledger((await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0 ? 'dropped' : 'DROP-FAILED');
      } finally { await m.end(); }
    }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  afterEach(() => breaker.reset());

  const decision = (i) => ({ requestId: `r1rb-${i}`, decision: i % 2 ? 'BLOCK' : 'ALLOW', reason: 'ALL_CHECKS_PASSED', stage: 'PROVIDER_EXECUTION', tenantId: null });
  const rowsFor = async (tid) => (await verify.query('SELECT * FROM transparency_log_entries WHERE transparency_id = $1', [tid])).rows;
  const tail = async () => (await verify.query('SELECT tail_hash, tail_id FROM transparency_log_head')).rows[0];
  const queued = async (tid) => (await verify.query('SELECT status, operation_type, retry_count FROM persistence_recovery_queue WHERE operation_id = $1', [`tlog:${tid}`])).rows;
  const stats = () => registrar.groupCommitStats();
  const delta = (a, b) => Object.fromEntries(['batches', 'entries', 'fastBatches', 'fastFallbacks', 'batchFailures', 'leafFailures'].map((k) => [k, b[k] - a[k]]));
  async function withHeadLocked(fn) {
    const locker = await verify.connect();
    try {
      await locker.query('BEGIN');
      await locker.query('SELECT * FROM transparency_log_head FOR UPDATE');
      return await fn();
    } finally {
      await locker.query('ROLLBACK').catch(() => {});
      locker.release();
    }
  }
  async function claimAll(n) {
    const ops = [];
    for (let i = 0; i < n; i++) { const op = await queue.claimNext(); expect(op).not.toBeNull(); ops.push(op); }
    expect(await queue.claimNext()).toBeNull();
    return ops;
  }
  function recordRegisterOrder() {
    const order = [];
    const real = registrar.register;
    const spy = jest.spyOn(registrar, 'register').mockImplementation((args) => { order.push(args.transparencyId); return real.call(registrar, args); });
    return { order, restore: () => spy.mockRestore() };
  }

  test('RB-01 outage during concurrent registration → batched failure → every caller pending, nothing written (no false success)', async () => {
    const before = await tail();
    const s0 = stats();
    const results = await withHeadLocked(() => Promise.all(Array.from({ length: 6 }, (_, i) => bridge.registerEnforcementDecision(decision(i)))));
    const d = delta(s0, stats());
    expect(d.entries).toBe(6);
    expect(d.batchFailures).toBeGreaterThanOrEqual(1);
    expect(d.batches).toBeLessThan(6);                      // the outage hit batches, not 6 single transactions
    for (const r of results) {
      expect(r.persisted).toBe('pending');
      expect(r.entryHash).toBeNull();
      expect(r.transparencyId).toMatch(/^[0-9a-f-]{36}$/);
      expect(await rowsFor(r.transparencyId)).toHaveLength(0);
      expect(await queued(r.transparencyId)).toEqual([{ status: 'PENDING', operation_type: 'TRANSPARENCY_SAVE', retry_count: 0 }]);
      pending.push(r);
    }
    expect(new Set(results.map((r) => r.transparencyId)).size).toBe(6);
    expect(await tail()).toEqual(before);
  });

  test('RB-02 concurrent replay of the queued registrations → multi-leaf batches, each preset id exactly once, arrival order, queue drained', async () => {
    const before = await tail();
    const ops = await claimAll(pending.length);
    const s0 = stats();
    const rec = recordRegisterOrder();
    try { await Promise.all(ops.map((op) => worker._processOne(op))); } finally { rec.restore(); }
    const d = delta(s0, stats());
    expect(d.entries).toBe(pending.length);
    expect(d.batches).toBeLessThan(pending.length);           // real batching happened
    expect(d.fastBatches).toBeGreaterThanOrEqual(1);
    expect(d.fastFallbacks).toBe(0);
    expect(d.batchFailures).toBe(0);
    expect(d.leafFailures).toBe(0);
    expect(new Set(rec.order)).toEqual(new Set(pending.map((p) => p.transparencyId)));

    const leaves = [];
    for (const p of pending) {
      const rows = await rowsFor(p.transparencyId);
      expect(rows).toHaveLength(1);                            // no duplicate, no loss
      expect(rows[0].transparency_id).toBe(p.transparencyId);  // the preset id is kept
      expect(rows[0].payload_hash).toBe(p.payloadHash);        // the pending payload, unchanged
      expect(await queued(p.transparencyId)).toEqual([]);
      leaves.push(rows[0]);
    }
    leaves.sort((a, b) => Number(a.id) - Number(b.id));
    // contiguous ids, in the order the replays reached the registrar
    for (let i = 1; i < leaves.length; i++) expect(Number(leaves[i].id)).toBe(Number(leaves[i - 1].id) + 1);
    expect(leaves.map((l) => l.transparency_id)).toEqual(rec.order);
    // chained onto the pre-replay tail, then onto each other
    expect(leaves[0].previous_entry_hash).toBe(before.tail_hash);
    for (let i = 1; i < leaves.length; i++) expect(leaves[i].previous_entry_hash).toBe(leaves[i - 1].entry_hash);
    const t = await tail();
    expect(t.tail_hash).toBe(leaves[leaves.length - 1].entry_hash);
    expect(Number(t.tail_id)).toBe(Number(leaves[leaves.length - 1].id));
  });

  test('RB-03 duplicate concurrent replays of the same preset ids in one batch → one leaf per id, every call reports success', async () => {
    const handler = recoveryManager._builtinHandlers[T];
    const regs = Array.from({ length: 3 }, (_, i) => ({
      transparencyId: crypto.randomUUID(), entryType: 'AUDIT', artifactId: `r1rb-dup-${i}`,
      payload: { requestId: `r1rb-dup-${i}`, decision: 'ALLOW', recordedAt: new Date().toISOString() },
      registeredBy: 'ai-chat-enforcement', tenantId: null,
    }));
    const countBefore = Number((await verify.query('SELECT count(*) FROM transparency_log_entries')).rows[0].count);
    const s0 = stats();
    // each registration replayed twice at once (two workers / a journal + queue double delivery)
    const calls = regs.flatMap((r) => [r, r]).map((r) => handler({ operationId: `tlog:${r.transparencyId}`, payload: { registration: r } }));
    const out = await Promise.all(calls);
    const d = delta(s0, stats());
    for (const o of out) expect(o).toEqual({ success: true });
    for (const r of regs) {
      const rows = await rowsFor(r.transparencyId);
      expect(rows).toHaveLength(1);
      expect(rows[0].payload_hash).toBe(log.computePayloadHash(r.payload));
    }
    expect(Number((await verify.query('SELECT count(*) FROM transparency_log_entries')).rows[0].count)).toBe(countBefore + regs.length);
    // the duplicates reached the database and were refused there (unique transparency_id), not silently dropped
    expect(d.leafFailures + d.batchFailures).toBeGreaterThanOrEqual(1);
    // the head still names the newest leaf
    const newest = (await verify.query('SELECT entry_hash, id FROM transparency_log_entries ORDER BY id DESC LIMIT 1')).rows[0];
    expect((await tail()).tail_hash).toBe(newest.entry_hash);
  });

  test('RB-04 replay while the head is locked → handler failure, queue rows stay PENDING (no false success); after release they are written', async () => {
    const regs = Array.from({ length: 3 }, (_, i) => ({
      transparencyId: crypto.randomUUID(), entryType: 'AUDIT', artifactId: `r1rb-retry-${i}`,
      payload: { requestId: `r1rb-retry-${i}`, decision: 'ALLOW', recordedAt: new Date().toISOString() },
      registeredBy: 'ai-chat-enforcement', tenantId: null,
    }));
    for (const r of regs) {
      const { durable } = await recoveryManager.enqueueWithOutcome(T, { registration: r }, new Error('RB-04 setup'));
      expect(durable).toBe('queue');
    }
    const ops = await claimAll(regs.length);
    const before = await tail();
    const s0 = stats();
    await withHeadLocked(() => Promise.all(ops.map((op) => worker._processOne(op))));
    const d = delta(s0, stats());
    expect(d.batchFailures).toBeGreaterThanOrEqual(1);
    for (const r of regs) {
      expect(await rowsFor(r.transparencyId)).toHaveLength(0);
      const q = await queued(r.transparencyId);
      expect(q).toHaveLength(1);
      expect(q[0].status).toBe('PENDING');
      expect(q[0].retry_count).toBe(1);
    }
    expect(await tail()).toEqual(before);

    // healthy again: the same operations are replayed (as the worker's next eligible poll would) and written
    await Promise.all(ops.map((op) => worker._processOne({ ...op, retryCount: 1 })));
    for (const r of regs) {
      expect(await rowsFor(r.transparencyId)).toHaveLength(1);
      expect(await queued(r.transparencyId)).toEqual([]);
    }
  });

  test('RB-05 the whole log is one valid chain; the head equals its last leaf', async () => {
    const all = (await verify.query('SELECT * FROM transparency_log_entries ORDER BY id')).rows;
    expect(all.length).toBe(pending.length + 3 + 3);
    for (let i = 0; i < all.length; i++) {
      const v = log.verifyEntryIntegrity(all[i], i === 0 ? null : all[i - 1]);
      expect({ id: all[i].id, valid: v.valid, failed: v.failedCheck }).toEqual({ id: all[i].id, valid: true, failed: null });
    }
    expect(new Set(all.map((r) => r.transparency_id)).size).toBe(all.length);
    const t = await tail();
    expect(t.tail_hash).toBe(all[all.length - 1].entry_hash);
    expect(Number(t.tail_id)).toBe(Number(all[all.length - 1].id));
  });
});
