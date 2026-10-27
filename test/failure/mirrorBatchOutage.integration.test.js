'use strict';

/**
 * the BATCHED single-node audit mirror (pg-audit-backend.persistEntries, phase 9) under real
 * PostgreSQL failures, through the PRODUCTION pool / circuit breaker / persistence-recovery queue / file journal /
 * recovery worker. PostgreSQL is taken away by a TCP fault proxy owned by this test (test/helpers/faultProxy.js);
 * the server itself is never stopped.
 *
 * Gap closed: test/integration/preLiveMirrorBatch.integration.test.js proves the batched path on a HEALTHY database (plus a
 * non-contiguous batch); nothing exercised a batch that meets an outage or a failing statement inside the batch
 * transaction.
 *
 *   MBO-01  healthy baseline: a batch is mirrored, chain-ordered, evidence gap-free
 *   MBO-02  PG DOWN during a batch: persistEntries() never throws and settles within a bound; NOTHING of the batch is
 *           committed; EVERY entry (mirror + evidence) is durably recorded in the file journal (PG is down, so the
 *           recovery queue itself is unreachable) — none silently dropped
 *   MBO-03  recovery without a restart: once PG is reachable the journal is replayed into the queue and the worker
 *           backfills the mirror — complete, seq order = chain order, evidence chain gap-free and linked, queue and
 *           journal drained, nothing in the DLQ
 *   MBO-04  a statement failing INSIDE the batch transaction (an entry the mirror cannot represent: nonce > 256 chars,
 *           SQLSTATE 22001) rolls the whole batch back and falls back per entry: the entries before it are mirrored,
 *           the failing entry is not, and the entry after it is NOT committed out of order — it is queued
 *           (AUDIT_MIRROR_PARENT_MISSING), not dropped. (The consequence that the mirror then stalls behind that entry
 * permanently is defect PH16-D3)
 *
 * Disposable database qodiqa_ph16mb_<tag> on the disposable cluster ONLY (test/helpers/disposableTargets.js refuses
 * 5432 / unset targets), migrated directly (not through the proxy), dropped in afterAll. Runs the migration chain →
 * belongs in test:component:serial.
 *
 * Run: bash npx jest test/failure/mirrorBatchOutage.integration.test.js --runInBand
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');
const { pgTarget } = require('../helpers/disposableTargets');
const { createFaultProxy } = require('../helpers/faultProxy');

const TARGET = pgTarget();
const describeOrSkip = TARGET.available ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_ph16mb_${TAG}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

jest.setTimeout(180_000);

describeOrSkip('batched audit mirror under PostgreSQL outage / in-batch failure (real PG)', () => {
  const asTest = (database) => ({ host: TARGET.host, port: TARGET.port, database, user: TARGET.adminUser,
    password: TARGET.adminPassword, ssl: false, connectionTimeoutMillis: 5000 });
  let proxy; let fx; let mods; let created = false; let journalDir; const saved = {};
  let prev = 'GENESIS'; let n = 0;

  const build = (count, extra = () => ({})) => {
    const out = [];
    for (let i = 0; i < count; i++, n++) {
      const e = mods.entryBuilder.buildEntry(mods.entryBuilder.normalizeFields({ artifactId: `ph16mb-${TAG}-${n}`, inputHash: 'a'.repeat(64),
        decision: 'ALLOW', outputHash: mods.entryBuilder.EMPTY_OUTPUT_HASH, signature: 'sig', requestHash: 'b'.repeat(64),
        policyHash: 'c'.repeat(64), verificationResult: true, ...extra(i) }), prev);
      out.push(e); prev = e.hash;
    }
    return out;
  };
  const mirrored = async (entries) => (await fx.query('SELECT hash FROM audit_chain WHERE hash = ANY($1)', [entries.map((e) => e.hash)])).rows.map((r) => r.hash.trim());
  const chainOk = async () => (await fx.query('SELECT bool_and(ok) ok, count(*)::int n FROM (SELECT prev_hash = lag(hash) OVER (ORDER BY seq) OR lag(hash) OVER (ORDER BY seq) IS NULL ok FROM audit_chain) s')).rows[0];
  const evidenceLinked = async () => {
    const rows = (await fx.query('SELECT id::int, previous_evidence_hash p, evidence_hash h FROM evidence_chain_records ORDER BY id')).rows;
    for (let i = 1; i < rows.length; i++) { if (rows[i].id !== rows[i - 1].id + 1 || rows[i].p !== rows[i - 1].h) return { ok: false, at: i, n: rows.length }; }
    return { ok: true, n: rows.length };
  };
  const queued = async (type) => Number((await fx.query("SELECT count(*) n FROM persistence_recovery_queue WHERE operation_type = $1 AND status = 'PENDING'", [type])).rows[0].n);
  const dlq = async () => Number((await fx.query("SELECT count(*) n FROM persistence_recovery_queue WHERE status = 'DLQ'")).rows[0].n);

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); created = true; } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();

    proxy = createFaultProxy({ targetHost: TARGET.host, targetPort: TARGET.port });
    const port = await proxy.listen();
    journalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ph16mb-journal-'));
    const env = {
      QODIQA_PG_DATABASE: DB, QODIQA_PG_PORT: String(port), QODIQA_PRQ_JOURNAL_DIR: journalDir,
      PRQ_POLL_INTERVAL_MS: '100', PRQ_JOURNAL_POLL_INTERVAL_MS: '200',
      QODIQA_PG_ACQUIRE_TIMEOUT_MS: '500', QODIQA_PG_CB_RECOVERY_MS: '300', QODIQA_PG_CB_SUCCESS_THRESHOLD: '1',
    };
    for (const [k, v] of Object.entries(env)) { saved[k] = process.env[k]; process.env[k] = v; }
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    const recovery = require('../../src/core/persistenceRecovery');
    await recovery.initialize();
    mods = { pgPool, recovery, breaker: require('../../src/infra/postgres/pgCircuitBreaker'),
      backend: require('../../src/infra/postgres/pg-audit-backend'), entryBuilder: require('../../src/core/audit/entryBuilder') };
  });

  afterAll(async () => {
    if (mods) { await mods.recovery.shutdown().catch(() => {}); await mods.pgPool.shutdown().catch(() => {}); }
    if (proxy) await proxy.close();
    if (fx) await fx.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (journalDir) fs.rmSync(journalDir, { recursive: true, force: true });
    if (!created) return;
    const m = new Pool(asTest('postgres'));
    try { await require('../helpers/dropTestDatabase').dropTestDatabase(m, DB); } finally { await m.end(); }
  });

  let healthy; let outage;

  test('MBO-01 healthy baseline: batch mirrored, chain-ordered, evidence gap-free', async () => {
    healthy = build(8);
    await mods.backend.persistEntries(healthy);
    expect((await mirrored(healthy)).length).toBe(8);
    expect(await chainOk()).toEqual({ ok: true, n: 8 });
    expect(await evidenceLinked()).toEqual({ ok: true, n: 8 });
  });

  test('MBO-02 PG DOWN during a batch: never throws, bounded, nothing committed, every entry durably journaled', async () => {
    outage = build(12);
    proxy.refuse();
    const t0 = Date.now();
    await expect(mods.backend.persistEntries(outage)).resolves.toBeUndefined();
    expect(Date.now() - t0).toBeLessThan(15_000);
    expect(proxy.stats().refused).toBeGreaterThan(0);                 // the outage was real at the socket level
    const j = await mods.recovery.journal.listEntries();
    const audit = new Set(j.filter((e) => e.operation.operationType === 'AUDIT_CHAIN_PG_SAVE').map((e) => e.operation.payload.hash));
    const evidence = j.filter((e) => e.operation.operationType === 'EVIDENCE_CHAIN_SAVE').length;
    expect(outage.every((e) => audit.has(e.hash))).toBe(true);       // none silently dropped
    expect(audit.size).toBe(12);
    expect(evidence).toBe(12);
    expect(await mirrored(outage)).toEqual([]);                        // fixture connection is direct: PG really has none
    expect(await chainOk()).toEqual({ ok: true, n: 8 });
  });

  test('MBO-03 recovery without restart: journal → queue → worker backfills the mirror completely and in order', async () => {
    proxy.heal();
    const t0 = Date.now(); let state;
    while (Date.now() - t0 < 90_000) {
      state = { m: (await mirrored(outage)).length, ev: await evidenceLinked(), j: (await mods.recovery.journal.listEntries()).length,
        qa: await queued('AUDIT_CHAIN_PG_SAVE'), qe: await queued('EVIDENCE_CHAIN_SAVE') };
      if (state.m === 12 && state.ev.n === 20 && state.j === 0 && state.qa === 0 && state.qe === 0) break;
      await sleep(250);
    }
    expect(state).toEqual({ m: 12, ev: { ok: true, n: 20 }, j: 0, qa: 0, qe: 0 });
    expect(await chainOk()).toEqual({ ok: true, n: 20 });              // seq order = chain order after the backfill
    expect(await dlq()).toBe(0);
    expect(mods.breaker.getCircuitBreaker().state).toBe('CLOSED');
  });

  test('MBO-04 a statement failing inside the batch transaction: no partial batch, no out-of-order row, successor queued', async () => {
    const before = (await chainOk()).n;
    const batch = build(4, (i) => (i === 2 ? { nonce: 'n'.repeat(300) } : {}));  // audit_chain.nonce is VARCHAR(256)
    await mods.backend.persistEntries(batch);
    expect((await mirrored(batch)).sort()).toEqual([batch[0].hash, batch[1].hash].sort());
    expect(await chainOk()).toEqual({ ok: true, n: before + 2 });
    const successorQueued = Number((await fx.query("SELECT count(*) n FROM persistence_recovery_queue WHERE operation_type = 'AUDIT_CHAIN_PG_SAVE' AND payload->>'hash' = $1", [batch[3].hash])).rows[0].n);
    expect(successorQueued).toBe(1);                                   // waits for its parent; never dropped
  });
});
