'use strict';

/**
 * R1 / — transparency group commit on REAL PostgreSQL. Adapted from
 *the flag is OPT-IN
 * (QODIQA_TRANSPARENCY_GROUP_COMMIT=true), default OFF.
 *
 * GI-01 queued registrations commit as one batch: every leaf persisted, ids in arrival order, the whole log one valid
 *       hash chain (log.verifyEntryIntegrity), head pointer = last leaf; tenant and NULL-tenant leaves mixed pass RLS
 * GI-02 equivalence: the same input sequence appended sequentially with the flag OFF in a second database produces
 *       identical (transparency_id, previous_entry_hash, entry_hash, signature) rows AND an identical root hash
 * GI-03 per-entry isolation: a duplicate transparencyId (23505) inside a batch fails only that caller
 * GI-04 fail closed: a statement timeout on the head lock fails every caller with the original error; nothing written
 * GI-05 concurrency: 300 concurrent callers (bounded batches) → contiguous ids, no duplicate, no gap, valid chain
 * GI-06 COMMIT failure (a deferred constraint trigger raising at COMMIT): every caller of the batch rejects, no leaf of
 *       the batch is visible, head unchanged; the next registration chains from the old head
 * GI-07 crash of the batch's backend (pg_terminate_backend while it waits on the head lock): every caller rejects,
 *       nothing visible; after restart (fresh pool) appends continue on a valid chain
 *
 * Databases qodiqa_r1_<ts>_{a,b} on the DISPOSABLE cluster only (run through
 *), created by this suite and dropped (and verified gone) in afterAll —
 * the same own-fixture pattern as test/integration/transparencyQueue.integration.test.js; the gate's orphan-DB assertion checks it.
 */

const fs = require('fs');
const path = require('path');
const { Pool, Client } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const BASE = `qodiqa_r1_${Date.now()}`;
const DBS = { a: `${BASE}_a`, b: `${BASE}_b` };
const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const asTest = (database) => ({
  host: process.env.QODIQA_PG_HOST || '127.0.0.1', port: parseInt(process.env.QODIQA_PG_PORT || '0', 10),
  database, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false,
});
const created = []; // own fixtures: exactly the databases this suite creates in beforeAll
const ENV_KEYS = ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PG_STATEMENT_TIMEOUT_MS',
  'QODIQA_TRANSPARENCY_GROUP_COMMIT', 'QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH'];

jest.setTimeout(180_000);

describeOrSkip('/ R1 — transparency group commit (real PostgreSQL)', () => {
  const saved = {}; const verify = {};
  let mods = null;

  function boot(db, { groupCommit, statementTimeoutMs = '5000', maxBatch = null }) {
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DBS[db], QODIQA_PG_USER: APP_USER, QODIQA_PG_STATEMENT_TIMEOUT_MS: statementTimeoutMs });
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    if (groupCommit) process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT = 'true'; else delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT;
    if (maxBatch) process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH = String(maxBatch); else delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH;
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    mods = { pgPool, registrar: require('../../src/core/transparency/registrar'), log: require('../../src/core/transparency/log'), breaker: require('../../src/infra/postgres/pgCircuitBreaker') };
    return mods;
  }
  async function shutdown() { if (mods) { mods.breaker.reset(); await mods.pgPool.shutdown().catch(() => {}); mods = null; } }

  beforeAll(async () => {
    if (asTest('x').port === 5432) throw new Error('refusing the 5432 cluster — run through pl-env.sh');
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    for (const db of Object.values(DBS)) {
      if (!/^qodiqa_r1_[0-9]+_[ab]$/.test(db)) throw new Error('unsafe db name');
      const m = new Client(asTest('postgres')); await m.connect();
      try { await m.query(`CREATE DATABASE "${db}"`); } finally { await m.end(); }
      created.push(db);
      const mp = new Pool(asTest(db));
      try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }
    }
    verify.a = new Pool(asTest(DBS.a)); verify.b = new Pool(asTest(DBS.b));
  });

  afterAll(async () => {
    await shutdown();
    for (const p of Object.values(verify)) await p.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (created.length) {
      const m = new Client(asTest('postgres')); await m.connect();
      try {
        for (const db of created) {
          await m.query(`DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
          if ((await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [db])).rowCount !== 0) throw new Error(`own fixture database ${db} was not dropped`);
        }
      } finally { await m.end(); }
    }
  });

  afterEach(shutdown);

  const reg = (i, extra = {}) => ({ entryType: 'AUDIT', artifactId: `r1-${i}`, payload: { i, decision: 'ALLOW' }, registeredBy: 'r1-test',
    tenantId: i % 3 === 0 ? 'tenant-r1' : null, transparencyId: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, ...extra });
  const rows = async (db) => (await verify[db].query('SELECT * FROM transparency_log_entries ORDER BY id')).rows;
  const head = async (db) => (await verify[db].query('SELECT tail_hash, tail_id::text AS tail_id FROM transparency_log_head')).rows[0];
  const settle = (p) => p.then((v) => ({ v }), (e) => ({ e }));
  const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms));

  async function holdHead(db) {
    const c = await verify[db].connect();
    await c.query('BEGIN'); await c.query('SELECT 1 FROM transparency_log_head FOR UPDATE');
    return async () => { await c.query('ROLLBACK'); c.release(); };
  }
  function assertChain(all, log) {
    for (let i = 0; i < all.length; i++) {
      const v = log.verifyEntryIntegrity(all[i], i === 0 ? null : all[i - 1]);
      expect({ id: all[i].id, valid: v.valid, failed: v.failedCheck }).toEqual({ id: all[i].id, valid: true, failed: null });
    }
  }
  const IDS = Array.from({ length: 12 }, (_, k) => k + 1);

  test('GI-01 queued registrations commit as one batch: all persisted, arrival order, one valid chain, head = tail', async () => {
    const { registrar, log } = boot('a', { groupCommit: true });
    const release = await holdHead('a');
    const ps = IDS.map((i) => settle(registrar.register(reg(i))));
    await tick(); await release();
    const res = await Promise.all(ps);
    for (const r of res) expect(r.v && r.v.persisted).toBe(true);
    const all = await rows('a');
    expect(all.map((r) => r.transparency_id)).toEqual(IDS.map((i) => reg(i).transparencyId));
    assertChain(all, log);
    expect(await head('a')).toEqual({ tail_hash: all[all.length - 1].entry_hash, tail_id: String(all[all.length - 1].id) });
    expect(all.some((r) => r.tenant_id === 'tenant-r1') && all.some((r) => r.tenant_id === null)).toBe(true);
    expect(registrar.groupCommitStats().maxBatch).toBeGreaterThanOrEqual(IDS.length - 1);
    expect(registrar.groupCommitStats()).toMatchObject({ fastBatches: 1, fastFallbacks: 0 });
  });

  test('GI-02 identical leaves AND root hash to the legacy one-transaction-per-leaf path', async () => {
    let { registrar } = boot('b', { groupCommit: false });
    for (const i of IDS) expect((await registrar.register(reg(i))).persisted).toBe(true);
    expect(registrar.groupCommitStats()).toMatchObject({ enabled: false, batches: 0 });
    const pick = (rs) => rs.map((r) => [r.transparency_id, r.previous_entry_hash, r.entry_hash, r.signature, r.signer_key_id]);
    const a12 = (await rows('a')).slice(0, IDS.length);
    expect(pick(await rows('b'))).toEqual(pick(a12));
    const rootB = await registrar.generateRoot({ generatedBy: 'r1-test' });
    await shutdown();
    ({ registrar } = boot('a', { groupCommit: true }));
    const rootA = await registrar.generateRoot({ generatedBy: 'r1-test' });
    expect([rootA.seqFrom, rootA.seqTo, rootA.entryCount, rootA.rootHash]).toEqual([rootB.seqFrom, rootB.seqTo, rootB.entryCount, rootB.rootHash]);
  });

  test('GI-03 a duplicate transparencyId inside a batch fails only its caller; batch-mates persisted; chain valid', async () => {
    const { registrar, log } = boot('a', { groupCommit: true });
    const before = (await rows('a')).length;
    const release = await holdHead('a');
    const first = settle(registrar.register(reg(101)));
    await tick();
    const batch = [settle(registrar.register(reg(102))), settle(registrar.register(reg(5, { artifactId: 'r1-dup' }))), settle(registrar.register(reg(103)))];
    await tick(); await release();
    expect((await first).v.persisted).toBe(true);
    const [r102, dup, r103] = await Promise.all(batch);
    expect(dup.e && dup.e.code).toBe('23505');
    expect(r102.v.persisted).toBe(true);
    expect(r103.v.persisted).toBe(true);
    const all = await rows('a');
    expect(all.length).toBe(before + 3);
    assertChain(all, log);
    expect((await head('a')).tail_hash).toBe(all[all.length - 1].entry_hash);
    expect(registrar.groupCommitStats().fastFallbacks).toBe(1);
  });

  test('GI-08 multi-tenant batch (two tenants + NULL interleaved): fast path tenant runs pass RLS; all persisted, chained', async () => {
    const { registrar, log } = boot('a', { groupCommit: true });
    const before = (await rows('a')).length;
    const release = await holdHead('a');
    const first = settle(registrar.register(reg(501)));
    await tick();
    const tenants = ['tenant-x', null, 'tenant-y', 'tenant-y', null, 'tenant-x', null];
    const ps = tenants.map((t, k) => settle(registrar.register(reg(502 + k, { tenantId: t }))));
    await tick(); await release();
    const res = [await first, ...(await Promise.all(ps))];
    for (const r of res) expect(r.v && r.v.persisted).toBe(true);
    const all = await rows('a');
    expect(all.slice(before).map((r) => r.tenant_id)).toEqual([reg(501).tenantId, ...tenants]);
    assertChain(all, log);
    expect(registrar.groupCommitStats()).toMatchObject({ fastBatches: 1, fastFallbacks: 0 });
  });

  test('GI-04 head-lock statement timeout fails every caller closed with the original error; nothing written', async () => {
    const { registrar } = boot('a', { groupCommit: true, statementTimeoutMs: '1500' });
    const before = await rows('a'); const headBefore = await head('a');
    const release = await holdHead('a');
    const res = await Promise.all([201, 202, 203, 204].map((i) => settle(registrar.register(reg(i)))));
    await release();
    for (const r of res) expect(r.e && r.e.code).toBe('57014');
    expect((await rows('a')).length).toBe(before.length);
    expect(await head('a')).toEqual(headBefore);
  });

  test('GI-05 300 concurrent callers: contiguous ids, no duplicates, no gaps, valid chain, head = tail', async () => {
    const { registrar, log } = boot('a', { groupCommit: true, maxBatch: 16 });
    const before = await rows('a');
    const N = 300;
    const res = await Promise.all(Array.from({ length: N }, (_, k) => settle(registrar.register(reg(1000 + k)))));
    for (const r of res) expect(r.v && r.v.persisted).toBe(true);
    const all = await rows('a');
    const added = all.slice(before.length);
    expect(added.length).toBe(N);
    const ids = added.map((r) => Number(r.id));
    for (let k = 1; k < ids.length; k++) expect(ids[k]).toBe(ids[k - 1] + 1);
    expect(new Set(added.map((r) => r.transparency_id)).size).toBe(N);
    // arrival order == id order (one process, FIFO queue)
    expect(added.map((r) => r.transparency_id)).toEqual(Array.from({ length: N }, (_, k) => reg(1000 + k).transparencyId));
    assertChain(all, log);
    expect((await head('a')).tail_id).toBe(String(ids[ids.length - 1]));
    const st = registrar.groupCommitStats();
    expect(st.maxBatch).toBeLessThanOrEqual(16);
    expect(st.batches).toBeLessThan(N);
  });

  test('GI-06 COMMIT failure: every caller of the batch rejects, nothing visible, head unchanged, chain resumes', async () => {
    // A deferred constraint trigger fires at COMMIT; it raises when any leaf of the transaction carries the marker.
    const admin = verify.a;
    await admin.query(`CREATE OR REPLACE FUNCTION r1_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.payload->>'failAtCommit' = 'yes' THEN RAISE EXCEPTION 'r1 injected commit failure' USING ERRCODE = '40001'; END IF; RETURN NULL; END $$`);
    await admin.query(`CREATE CONSTRAINT TRIGGER r1_fail_at_commit AFTER INSERT ON transparency_log_entries
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION r1_fail_at_commit()`);
    // The trigger only fires on the marker payload, so it is left in place (no DROP in this task's rules).
    {
      const { registrar, log } = boot('a', { groupCommit: true });
      const before = await rows('a'); const headBefore = await head('a');
      const release = await holdHead('a');
      // 301 is committed alone (it starts the drain); 302-304 queue behind it and form ONE batch containing the marker.
      const first = settle(registrar.register(reg(301)));
      await tick();
      const ps = [302, 303, 304].map((i) => settle(registrar.register(reg(i, i === 303 ? { payload: { i, failAtCommit: 'yes' } } : {}))));
      await tick(); await release();
      expect((await first).v.persisted).toBe(true);
      const res = await Promise.all(ps);
      for (const r of res) expect(r.e && r.e.message).toMatch(/r1 injected commit failure/);
      const after = await rows('a');
      expect(after.length).toBe(before.length + 1);
      expect(after[after.length - 1].transparency_id).toBe(reg(301).transparencyId);
      const headAfterFail = await head('a');
      expect(headAfterFail.tail_hash).toBe(after[after.length - 1].entry_hash);
      expect(registrar.groupCommitStats().batchFailures).toBe(1);
      expect((await registrar.register(reg(305))).persisted).toBe(true);
      const all = await rows('a');
      assertChain(all, log);
      expect(all[all.length - 1].previous_entry_hash).toBe(headAfterFail.tail_hash);
      expect(headBefore.tail_hash).not.toBe(headAfterFail.tail_hash);
    }
  });

  test('GI-07 backend crash mid-batch: every caller rejects, nothing visible; after restart the chain continues', async () => {
    let { registrar, log } = boot('a', { groupCommit: true });
    const before = await rows('a'); const headBefore = await head('a');
    const release = await holdHead('a');
    const ps = [401, 402, 403].map((i) => settle(registrar.register(reg(i))));
    await tick(200);
    const victims = await verify.a.query(`SELECT pid FROM pg_stat_activity WHERE datname = $1 AND application_name = 'qodiqa-app'
      AND wait_event_type = 'Lock'`, [DBS.a]);
    expect(victims.rows.length).toBe(1); // exactly one backend: the batch transaction
    await verify.a.query('SELECT pg_terminate_backend($1)', [victims.rows[0].pid]);
    const res = await Promise.all(ps);
    await release();
    for (const r of res) expect(r.e).toBeTruthy();
    expect((await rows('a')).length).toBe(before.length);
    expect(await head('a')).toEqual(headBefore);
    await shutdown();
    ({ registrar, log } = boot('a', { groupCommit: true }));
    const out = await Promise.all([404, 405, 406].map((i) => registrar.register(reg(i))));
    expect(out.every((o) => o.persisted)).toBe(true);
    assertChain(await rows('a'), log);
  });
});
