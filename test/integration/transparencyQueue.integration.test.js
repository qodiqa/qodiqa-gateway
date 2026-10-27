'use strict';

/**
 * (D3) — enforcement-decision transparency leaves survive
 * PostgreSQL being unavailable, on real PostgreSQL (disposable DB).
 *
 * TQ-01  healthy: persisted synchronously (persisted:true), unchanged
 * TQ-02  PG times out (a real statement_timeout while another session holds
 *        the transparency_log_head lock): the decision resolves
 *        persisted:'pending', the registration is in the PG recovery queue,
 *        no leaf exists yet; after the outage the real worker handler writes
 *        the leaf — same transparencyId, payload_hash equal to the pending
 *        payloadHash, chained to the prior tail, entry hash and signature
 *        present, head pointer advanced, queue row gone
 * TQ-03  PG refuses everything (circuit breaker OPEN): the recovery-queue
 *        INSERT fails too, so the registration lands in the crash-safe
 *        filesystem journal (durable:'journal'); after recovery the journal
 *        replays into the queue and the worker writes the leaf
 * TQ-04  replaying an already-written registration is idempotent (one leaf)
 * TQ-05  the whole log (healthy + recovered leaves) is one valid hash chain,
 *        a signed root covers the recovered leaves, and their inclusion
 *        proofs verify with a non-null merkleRoot
 *
 * DB qodiqa_w3tq_<pid>_<hex>, name appended to %TEMP%/qodiqa-w3-ledger.jsonl
 * BEFORE creation, dropped and verified gone in afterAll.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w3tq_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const asTest = (database) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false,
});
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/transparencyQueue.integration.test.js' }) + '\n');

jest.setTimeout(120_000);

describeOrSkip('D3 — transparency leaves survive a PostgreSQL outage (real PostgreSQL)', () => {
  let created = false; const saved = {}; let tmpDir; let verify;
  let pgPool, breaker, bridge, queue, worker, recoveryManager, journal, journalWorker, registrar, proofLookup, log;
  const recovered = [];

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w3tq-'));
    ledger('planned');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); } finally { await m.end(); }
    created = true; ledger('created');
    const mp = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }

    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PRQ_JOURNAL_DIR', 'QODIQA_PG_STATEMENT_TIMEOUT_MS', 'PRQ_ENABLED']) saved[k] = process.env[k];
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_PG_USER: APP_USER,
      QODIQA_PRQ_JOURNAL_DIR: path.join(tmpDir, 'prq'), QODIQA_PG_STATEMENT_TIMEOUT_MS: '2000', PRQ_ENABLED: 'true' });
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    breaker = require('../../src/infra/postgres/pgCircuitBreaker');
    bridge = require('../../src/core/transparency/enforcementBridge');
    queue = require('../../src/core/persistenceRecovery/queue');
    worker = require('../../src/core/persistenceRecovery/worker');
    recoveryManager = require('../../src/core/persistenceRecovery/recoveryManager');
    journal = require('../../src/core/persistenceRecovery/journal');
    journalWorker = require('../../src/core/persistenceRecovery/journalWorker');
    registrar = require('../../src/core/transparency/registrar');
    proofLookup = require('../../src/core/transparency/proofLookup');
    log = require('../../src/core/transparency/log');
    const T = recoveryManager.OPERATION_TYPES.TRANSPARENCY_SAVE;
    worker.registerHandler(T, recoveryManager._builtinHandlers[T]);
    verify = new Pool(asTest(DB));
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

  const decision = (i, d = 'ALLOW') => ({ requestId: `w3tq-${i}`, decision: d, reason: 'ALL_CHECKS_PASSED', stage: 'PROVIDER_EXECUTION', tenantId: null });
  const row = async (tid) => (await verify.query('SELECT * FROM transparency_log_entries WHERE transparency_id = $1', [tid])).rows;
  const tail = async () => (await verify.query('SELECT tail_hash, tail_id FROM transparency_log_head')).rows[0];
  const queued = async (tid) => (await verify.query('SELECT status, operation_type FROM persistence_recovery_queue WHERE operation_id = $1', [`tlog:${tid}`])).rows;

  async function drainOne() {
    const op = await queue.claimNext();
    expect(op).not.toBeNull();
    await worker._processOne(op);
    return op;
  }

  test('TQ-01 healthy → persisted synchronously', async () => {
    const r = await bridge.registerEnforcementDecision(decision(1));
    expect(r.persisted).toBe(true);
    expect(await row(r.transparencyId)).toHaveLength(1);
  });

  test('TQ-02 statement timeout under a held head lock → pending in the PG queue → drained into the chain', async () => {
    const before = await tail();
    const locker = await verify.connect();
    let r;
    try {
      await locker.query('BEGIN');
      await locker.query('SELECT * FROM transparency_log_head FOR UPDATE');
      r = await bridge.registerEnforcementDecision(decision(2));
    } finally {
      await locker.query('ROLLBACK').catch(() => {});
      locker.release();
    }
    expect(r.persisted).toBe('pending');
    expect(r.entryHash).toBeNull();
    expect(await row(r.transparencyId)).toHaveLength(0);
    expect(await queued(r.transparencyId)).toEqual([{ status: 'PENDING', operation_type: 'TRANSPARENCY_SAVE' }]);

    const op = await drainOne();
    expect(op.operationId).toBe(`tlog:${r.transparencyId}`);
    const rows = await row(r.transparencyId);
    expect(rows).toHaveLength(1);
    const leaf = rows[0];
    expect(leaf.payload_hash).toBe(r.payloadHash);
    expect(leaf.previous_entry_hash).toBe(before.tail_hash);
    expect(leaf.entry_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(leaf.signature).toBeTruthy();
    expect(leaf.payload.requestId).toBe('w3tq-2');
    expect((await tail()).tail_hash).toBe(leaf.entry_hash);
    expect(await queued(r.transparencyId)).toEqual([]);
    recovered.push(r.transparencyId);
  });

  test('TQ-03 circuit breaker OPEN → journal → replay → queue → drained into the chain', async () => {
    const b = breaker.getCircuitBreaker();
    for (let i = 0; i < 5; i++) b.onFailure();
    expect(b.state).toBe(breaker.STATE_OPEN);

    const r = await bridge.registerEnforcementDecision(decision(3, 'BLOCK'));
    expect(r.persisted).toBe('pending');
    const entries = await journal.listEntries();
    const mine = entries.filter((e) => e.operation?.operationId === `tlog:${r.transparencyId}`);
    expect(mine).toHaveLength(1);
    expect(await row(r.transparencyId)).toHaveLength(0);

    breaker.reset(); // PostgreSQL healthy again
    const before = await tail();
    expect(await journalWorker._replayOne(mine[0])).toBe(true);
    expect(await queued(r.transparencyId)).toEqual([{ status: 'PENDING', operation_type: 'TRANSPARENCY_SAVE' }]);
    await drainOne();
    const rows = await row(r.transparencyId);
    expect(rows).toHaveLength(1);
    expect(rows[0].payload_hash).toBe(r.payloadHash);
    expect(rows[0].previous_entry_hash).toBe(before.tail_hash);
    expect(rows[0].payload.decision).toBe('BLOCK');
    recovered.push(r.transparencyId);
  });

  test('TQ-04 replaying an already-written registration is idempotent', async () => {
    const tid = recovered[0];
    const leaf = (await row(tid))[0];
    const registration = { transparencyId: tid, entryType: 'AUDIT', artifactId: leaf.artifact_id, payload: leaf.payload, registeredBy: 'ai-chat-enforcement', tenantId: null };
    const { durable } = await recoveryManager.enqueueWithOutcome(recoveryManager.OPERATION_TYPES.TRANSPARENCY_SAVE, { registration }, new Error('test'));
    expect(durable).toBe('queue');
    await drainOne();
    expect(await row(tid)).toHaveLength(1);
    expect(await queued(tid)).toEqual([]);
  });

  test('TQ-05 one valid chain; a signed root covers the recovered leaves; proofs verify with a merkleRoot', async () => {
    for (let i = 10; i < 14; i++) expect((await bridge.registerEnforcementDecision(decision(i))).persisted).toBe(true);
    const all = (await verify.query('SELECT * FROM transparency_log_entries ORDER BY id')).rows;
    for (let i = 0; i < all.length; i++) {
      const v = log.verifyEntryIntegrity(all[i], i === 0 ? null : all[i - 1]);
      expect({ id: all[i].id, valid: v.valid, failed: v.failedCheck }).toEqual({ id: all[i].id, valid: true, failed: null });
    }
    const root = await registrar.generateRoot({ generatedBy: 'w3-test' });
    expect(root).toBeTruthy();
    expect((await verify.query('SELECT count(*)::int AS n FROM transparency_roots')).rows[0].n).toBe(1);
    for (const tid of recovered) {
      const leaf = (await row(tid))[0];
      const { proof, proofVerification } = await proofLookup.getInclusionProofForEntry(leaf);
      expect(proofVerification.valid).toBe(true);
      expect(proof.proof.merkleRoot).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
