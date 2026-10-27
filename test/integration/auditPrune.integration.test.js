'use strict';

/**
 * step 6, option 2 of 2026-09-30) — REAL PostgreSQL proof of the operator retention prune
 * (scripts/audit/prune.js): archive → verify → delete → verify, with crash injection and tamper controls.
 *
 * PR-01 refusals: no --confirm-server-stopped, no retention period, --transparency, a WAL present, and a
 *          prune identity without BYPASSRLS/DELETE (the request-serving role) — nothing touched
 *   PR-02  --dry-run: the plan (checkpoint, file range, PG rows, evidence bound) and not one byte / row changed
 *   PR-03  crash injection: stopped after each step (archive, anchor, base, log) the chain still boots and verifies,
 *          and the next run RESUMES and completes
 *   PR-04  after the prune: file rebased on the signed base record, PG rows before the checkpoint gone (its own row
 *          kept), evidence up to E gone, audit_chain_prunes row carries the base; a fresh boot, the durable-store
 *          full scan, the mirror check, the evidence range/record verifiers and the independent verifier
 *          (archive + base + suffix, and the PG export) all VALID; the compliance collector reports the retention
 *          boundary
 *   PR-05  a SECOND prune (prior base carried): stopped after writing its base record the log boots from the prior
 *          base (full-file), resumes, and the two archives chain end to end in the independent verifier
 *   PR-06  dr:verify (offline) accepts the base record in the file backup path and refuses a forged one
 *   PR-07  tamper controls — each must FAIL: flipped archive byte; flipped archive byte with the manifest re-hashed;
 *          flipped suffix byte; forged base record; a validly signed checkpoint moved to another position; a deleted
 *          suffix line; the base record missing; a kept evidence record deleted; the first kept evidence record's link
 *          altered
 * Files tampered in PR-07 are COPIES in this suite's own temp directory; PG tampering runs in this suite's
 * disposable database, last.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w10pr_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PRUNE = path.join(__dirname, '..', '..', 'scripts', 'audit', 'prune.js');
const DAY = 86_400_000;
jest.setTimeout(300_000);

describeOrSkip('operator retention prune: archive → verify → delete → verify (real PostgreSQL)', () => {
  const saved = {};
  let maint; let admin; let pgPool; let rolePools; let auditLog; let backend; let cpMod; let writer;
  let getActiveKey; let signArtifact;
  let tmp; let archiveRoot; let pruneUrl; let appUrl; let LOG;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const pgBase = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10) });
  const url = (user, pw) => `postgres://${encodeURIComponent(user)}:${encodeURIComponent(pw)}@${pgBase().host}:${pgBase().port}/${DB}`;

  function runPrune(args, extraEnv = {}) {
    const r = spawnSync(process.execPath, [PRUNE, ...args], { env: { ...process.env, QODIQA_PG_PRUNE_URL: pruneUrl, ...extraEnv }, encoding: 'utf8', timeout: 240_000 });
    let out = null;
    try { out = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { /* crash point: no result line */ }
    return { status: r.status, out, stderr: r.stderr };
  }
  /** A fresh process loads the chain like a boot (read-only), and runs the durable-store full scan. */
  function bootProbe(env = {}) {
    const code = "let a;try{a=require(process.argv[1])}catch(e){require(process.argv[2]).flush();console.log('\\n'+JSON.stringify({ok:false,error:e.message}));process.exit(0)}(async()=>{const r=await a.validateChainIntegrityFromDurableStoreChunked();const s=a.getChainStart();const m=a.memorySnapshot();require(process.argv[2]).flush();console.log('\\n'+JSON.stringify({ok:true,valid:r.chainValid,state:s.state,startCount:s.startCount,modernCount:m.modernCount}))})().catch(e=>{console.log('\\n'+JSON.stringify({ok:false,error:e.message}))})";
    const r = spawnSync(process.execPath, ['-e', code, require.resolve('../../src/core/audit/audit-log'), require.resolve('../../services/logger')],
      { env: { ...process.env, QODIQA_AUDIT_FOLLOWER: 'true', ...env }, encoding: 'utf8', timeout: 240_000 });
    try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return { ok: false, error: (r.stderr || r.stdout || '').slice(-600) }; }
  }
  const indep = (args) => require('../../scripts/audit-repro/verify/qodiqa-audit-verify').verify(args);
  const keysFile = () => { const f = path.join(tmp, 'cp-keys.json'); fs.writeFileSync(f, JSON.stringify({ keys: require('../../src/core/audit/checkpoint/checkpointKeyStore').publishedKeys().map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiDerB64, status: k.status })) })); return f; };

  const sign = (requestId = crypto.randomUUID()) => {
    const K = getActiveKey('w10pr'); const now = Date.now();
    return signArtifact({ payload: { action: 'w10pr', requestId, tenantId: 'w10pr' }, timestamp: now, expiry: now + 600_000, publicKeyId: K.keyId }, K.privDer);
  };
  async function appendN(n) {
    const ids = [];
    for (let i = 0; i < n; i++) {
      const a = sign(); ids.push(a.payload.requestId);
      await auditLog.append({ artifactId: a.payload.requestId, requestId: a.payload.requestId, inputHash: crypto.createHash('sha256').update(a.payload.requestId).digest('hex'),
        decision: i % 3 === 0 ? 'BLOCK' : 'ALLOW', outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH, /* v7 (R-5): synthetic, delivers nothing */ signature: a.signature, requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: i % 3 !== 0,
        nonce: `n-${a.payload.requestId}`, tenantId: 'w10pr', publicKeyId: a.publicKeyId, provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION' });
    }
    await auditLog.drainMirrorWriter();
    // S33: prune requires a STOPPED server (confirm-server-stopped; it refuses while a WAL file exists). This
    // in-process writer is stopped cleanly here — drainPendingWrites() is the graceful-shutdown step, after which the
    // reused WAL is absent (approved on-disk contract: WAL absent or empty while running, absent after a clean stop).
    await auditLog.drainPendingWrites();
    for (let t = 0; t < 20_000; t += 50) {   // evidence is written fire-and-forget after the mirror
      const { rows } = await admin.query('SELECT count(*)::int n FROM evidence_chain_records WHERE artifact_id = ANY($1)', [ids]);
      if (rows[0].n === ids.length) return ids;
      await sleep(50);
    }
    throw new Error('evidence records did not appear');
  }
  /** A signed checkpoint at the current head, created `daysAgo` in the past (the retention cutoff is on createdAt). */
  async function pastCheckpoint(daysAgo) {
    const snap = auditLog.memorySnapshot();
    const head = await auditLog.getModernEntryAt(snap.modernCount - 1);
    const tail = await backend.getChainTail();
    const ev = (await admin.query('SELECT tail_id, tail_hash FROM evidence_chain_head')).rows[0];
    const prev = await writer.latestSignedCheckpoint({ emit: () => {} });
    const signed = cpMod.signCheckpoint({ chainLength: snap.modernCount, headHash: head.hash, pgSeq: Number(tail.seq),
      evidenceHead: { id: Number(ev.tail_id), hash: String(ev.tail_hash).trim() }, transparencyAnchor: null,
      previousCheckpointHash: prev ? prev.payloadHash : null, createdAt: new Date(Date.now() - daysAgo * DAY).toISOString() });
    await backend.insertSignedCheckpoint(signed, 'w10pr');
    fs.appendFileSync(writer.sidecarPath(LOG), JSON.stringify(signed) + '\n');
    return signed;
  }
  const flipByte = (src, dst, at) => { const b = fs.readFileSync(src); const i = at(b); b[i] = b[i] === 0x61 ? 0x62 : 0x61; fs.writeFileSync(dst, b); };
  /** Copy the live log set into dir (log, anchor, base, sidecar) — tamper controls work on copies only. */
  function copySet(dir) {
    fs.mkdirSync(dir, { recursive: true });
    const d = path.join(dir, 'audit.log');
    for (const [s, t] of [[LOG, d], [LOG + '.sum', d + '.sum'], [LOG + '.base.json', d + '.base.json'], [LOG + '.checkpoints.jsonl', d + '.checkpoints.jsonl']]) if (fs.existsSync(s)) fs.copyFileSync(s, t);
    return d;
  }

  beforeAll(async () => {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD']) saved[k] = process.env[k];
    maint = new Pool({ ...pgBase(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    process.env.QODIQA_PG_DATABASE = DB;
    Object.assign(process.env, { QODIQA_PG_USER: process.env.QODIQA_PG_TEST_USER, QODIQA_PG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD });
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    rolePools = require('../../src/infra/postgres/rolePools');
    pgPool.initialize();
    await pgPool.runMigrations();
    admin = new Pool({ ...pgBase(), database: DB, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });
    pruneUrl = url(process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);   // BYPASSRLS, table owner: the operator identity here
    appUrl = saved.QODIQA_PG_USER === 'qodiqa_app' ? url('qodiqa_app', saved.QODIQA_PG_PASSWORD) : null;
    backend = require('../../src/infra/postgres/pg-audit-backend');
    auditLog = require('../../src/core/audit/audit-log');
    cpMod = require('../../src/core/audit/checkpoint/checkpoint');
    writer = require('../../src/core/audit/checkpoint/checkpointWriter');
    require('../../services/artifact/keyManager').rotate('w10pr');
    ({ getActiveKey } = require('../../services/artifact/keyStore'));
    ({ signArtifact } = require('../../src/validation/signArtifact'));
    LOG = auditLog.LOG_PATH;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'w10pr-'));
    archiveRoot = path.join(tmp, 'archive');
  }, 300_000);

  afterAll(async () => {
    if (admin) await admin.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (rolePools) await rolePools.shutdownAll().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try { await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch (e) { console.warn(`[w10pr] could not drop ${DB}: ${e.message}`); }
      await maint.end();
    }
  }, 60_000);

  let C1; let E1; let EV1; let firstLen;
  test('PR-01 refusals — nothing touched', async () => {
    await appendN(24);
    C1 = await pastCheckpoint(3);        // entries 1..24, created 3 days ago
    await appendN(12);                    // entries 25..36 stay
    firstLen = auditLog.memorySnapshot().modernCount;
    const before = fs.readFileSync(LOG);
    const cases = [
      [['--retention-days', '1'], {}, /confirm-server-stopped/],
      [['--confirm-server-stopped'], { QODIQA_AUDIT_RETENTION_DAYS: '' }, /no retention period/],
      [['--confirm-server-stopped', '--retention-days', '1', '--transparency'], {}, /--transparency is not available yet/],
    ];
    for (const [a, env, re] of cases) { const r = runPrune(a, env); expect(r.status).toBe(2); expect(r.out.reason).toMatch(re); }
    const walDir = path.join(tmp, 'wal'); const walLog = copySet(walDir); fs.writeFileSync(walLog + '.wal', '');
    const w = runPrune(['--confirm-server-stopped', '--retention-days', '1'], { QODIQA_AUDIT_LOG: walLog });
    expect(w.status).toBe(2); expect(w.out.reason).toMatch(/WAL file exists/);
    if (appUrl) {
      const r = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot], { QODIQA_PG_PRUNE_URL: appUrl });
      expect(r.status).toBe(2); expect(r.out.reason).toMatch(/lacks: bypass/);
    }
    expect(fs.readFileSync(LOG).equals(before)).toBe(true);
    expect(fs.existsSync(LOG + '.base.json')).toBe(false);
  });

  test('PR-02 --dry-run: the plan, and nothing changed', async () => {
    const before = fs.readFileSync(LOG);
    const n0 = (await admin.query('SELECT (SELECT count(*) FROM audit_chain)::int a, (SELECT count(*) FROM evidence_chain_records)::int e')).rows[0];
    const r = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot, '--dry-run']);
    expect(r.status).toBe(0);
    expect(r.out.result).toBe('DRY_RUN');
    expect(r.out.plan).toMatchObject({ checkpointId: C1.payload.checkpointId, fromCount: 0, toCount: 24, fileEntries: 24,
      pg: { auditRows: 23, keptAnchorSeq: C1.payload.pgSeq, evidenceFromIdExclusive: 0 } });
    E1 = r.out.plan.pg.evidenceToId; EV1 = r.out.plan.pg.evidenceRows;
    expect(E1).toBeGreaterThan(0);
    expect(EV1).toBeGreaterThan(0); expect(EV1).toBeLessThanOrEqual(E1);
    expect(fs.readFileSync(LOG).equals(before)).toBe(true);
    expect(fs.existsSync(archiveRoot)).toBe(false);
    expect((await admin.query('SELECT (SELECT count(*) FROM audit_chain)::int a, (SELECT count(*) FROM evidence_chain_records)::int e')).rows[0]).toEqual(n0);
  });

  test('PR-03 crash injection: stopped after each step the chain boots and verifies; the next run resumes', async () => {
    const seen = [];
    for (const step of ['archive', 'anchor', 'base', 'log']) {
      const r = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot], { QODIQA_PRUNE_TEST_STOP_AFTER: step });
      expect(r.status).toBe(99);
      const b = bootProbe();
      seen.push({ step, ...b });
      expect(b).toMatchObject({ ok: true, valid: true, modernCount: firstLen });
      // S4: a prune stopped at any crash point never leaves the audit_chain counter drifted (real reconciler).
      const rec = await require('../../src/core/audit/mirrorCountReconciler').reconcileOnce({ trigger: 'MANUAL', emitFn: () => {} });
      expect(rec).toMatchObject({ status: 'IN_SYNC' });
      expect(rec.stored).toBe(Number((await admin.query('SELECT count(*) n FROM audit_chain')).rows[0].n));
    }
    expect(seen.map((s) => `${s.step}:${s.state}:${s.startCount}`)).toEqual(['archive:none:0', 'anchor:none:0', 'base:full-file:0', 'log:rebased:24']);
    const r = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot]);
    expect(r.status).toBe(0);
    expect(r.out).toMatchObject({ result: 'RESUMED', checkpointId: C1.payload.checkpointId, toCount: 24, pgRowsDeleted: { audit: 23, evidence: EV1 },
      postBoot: { state: 'rebased', startCount: 24, modernCount: firstLen } });
    const again = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot]);
    expect(again.out.result).toBe('NOTHING_TO_PRUNE');
  });

  test('PR-04 after the prune: every verifier accepts the kept chain; the compliance collector reports the boundary', async () => {
    const first = JSON.parse(fs.readFileSync(LOG, 'utf8').split('\n')[0]);
    expect(first.prevHash).toBe(C1.payload.headHash);
    const base = JSON.parse(fs.readFileSync(LOG + '.base.json', 'utf8'));
    expect(base.checkpoint.payloadHash).toBe(C1.payloadHash);
    const pgc = (await admin.query('SELECT min(seq)::int s, count(*)::int n FROM audit_chain')).rows[0];
    expect(pgc).toEqual({ s: C1.payload.pgSeq, n: firstLen - 24 + 1 });
    // S2: the real prune DELETE kept the derived audit_chain row counter exact (migration 073 statement trigger).
    expect(Number((await admin.query('SELECT row_count FROM audit_chain_mirror_count')).rows[0].row_count)).toBe(pgc.n);
    expect((await admin.query('SELECT min(id)::int m FROM evidence_chain_records')).rows[0].m).toBe(E1 + 1);
    const pr = (await admin.query('SELECT checkpoint_id, from_count, to_count, audit_rows_deleted, evidence_rows_deleted, base_record FROM audit_chain_prunes')).rows;
    expect(pr).toHaveLength(1);
    expect(pr[0]).toMatchObject({ checkpoint_id: C1.payload.checkpointId, audit_rows_deleted: '23', evidence_rows_deleted: String(EV1) });
    expect(pr[0].base_record.checkpoint.payloadHash).toBe(C1.payloadHash);

    // The in-process modules reload from disk as a server boot would.
    await pgPool.shutdown(); await rolePools.shutdownAll();
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); rolePools = require('../../src/infra/postgres/rolePools'); pgPool.initialize();
    auditLog = require('../../src/core/audit/audit-log');
    backend = require('../../src/infra/postgres/pg-audit-backend'); writer = require('../../src/core/audit/checkpoint/checkpointWriter'); cpMod = require('../../src/core/audit/checkpoint/checkpoint');
    expect(auditLog.getChainStart()).toMatchObject({ state: 'rebased', startCount: 24, startHash: C1.payload.headHash });
    expect(auditLog.memorySnapshot().modernCount).toBe(firstLen);
    expect((await auditLog.validateChainIntegrityFromDurableStoreChunked()).chainValid).toBe(true);
    const mirror = require('../../src/core/audit/mirrorConsistencyCheck');
    expect(await mirror.verifyMirrorConsistency({ _exit: (c) => { throw new Error(`mirror exit ${c}`); }, _emit: () => {} })).toBe(true);
    expect(await require('../../src/core/audit/checkpoint/checkpointWriter').verifyLatestCheckpointAtBoot({ emit: () => {} })).toMatchObject({ checked: true });
    // S4: after the legitimate prune the boot reconciliation finds the counter exact — no drift, no CRITICAL.
    const recEv = [];
    expect(await require('../../src/core/audit/mirrorCountReconciler').validateAtBoot({ emitFn: (l, t) => recEv.push(`${l}:${t}`) }))
      .toMatchObject({ status: 'IN_SYNC', trigger: 'BOOT', stored: pgc.n, exact: pgc.n });
    expect(recEv).toEqual(['INFO:AUDIT_MIRROR_COUNT_RECONCILED']);

    const chainStore = require('../../src/core/evidence/chainStore');
    const maxId = (await admin.query('SELECT max(id)::int m FROM evidence_chain_records')).rows[0].m;
    const range = await chainStore.verifyChainRange({ startId: E1 + 1, endId: maxId, limit: 10_000, verifiedBy: 'w10pr' });
    expect(range).toMatchObject({ valid: true, complete: true });
    const inPrefix = await chainStore.verifyChainRange({ startId: 1, endId: maxId, limit: 10_000, verifiedBy: 'w10pr' });
    expect(inPrefix.valid).toBe(false); expect(inPrefix.failureDetail).toMatch(/pruned prefix/);
    const firstKept = (await admin.query('SELECT evidence_id FROM evidence_chain_records WHERE id = $1', [E1 + 1])).rows[0].evidence_id;
    const one = await chainStore.verifyEvidence(firstKept, { verifiedBy: 'w10pr' });
    expect(one.stepsPassed).toEqual(expect.arrayContaining(['CHAIN_LINK', 'CHAIN_CONTINUITY']));

    const coll = await require('../../src/core/compliance/evidenceCollector').collectAll({ periodStart: new Date(Date.now() - 10 * DAY), periodEnd: new Date(Date.now() + 60_000) });
    expect(JSON.stringify(coll)).toMatch(new RegExp(`"periodTruncated":true,"prunedThrough":"[^"]+","prunedEntries":24,"checkpointId":"${C1.payload.checkpointId}"`));

    const archive = path.join(archiveRoot, C1.payload.checkpointId);
    const v = indep({ audit: LOG, format: 'ndjson', base: LOG + '.base.json', archive, 'checkpoint-keys': keysFile(), anchor: LOG + '.sum' });
    expect({ verdict: v.verdict, base: v.base.valid, archive: v.archives[0].valid, audit: v.audit.valid, state: v.audit.startState, anchor: v.anchor.ok }).toEqual(
      { verdict: 'VALID', base: true, archive: true, audit: true, state: 'rebased', anchor: true });
    const rowsFile = path.join(tmp, 'pg-rows.json');
    fs.writeFileSync(rowsFile, JSON.stringify((await admin.query('SELECT * FROM audit_chain ORDER BY seq')).rows));
    const vp = indep({ audit: rowsFile, format: 'pg-json', base: LOG + '.base.json', 'checkpoint-keys': keysFile() });
    expect(vp.verdict).toBe('VALID');
    const noBase = indep({ audit: LOG, format: 'ndjson' });
    expect(noBase.verdict).toBe('INVALID'); expect(noBase.audit.baseHint).toMatch(/AUDIT_BASE_MISSING/);
  });

  let C2;
  test('PR-05 a second prune: interrupted after its base record the log boots from the prior base; archives chain end to end', async () => {
    await appendN(10);
    C2 = await pastCheckpoint(2);        // entries 25..firstLen+10
    await appendN(5);
    const len = auditLog.memorySnapshot().modernCount;
    await pgPool.shutdown(); await rolePools.shutdownAll();
    const stop = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot], { QODIQA_PRUNE_TEST_STOP_AFTER: 'base' });
    expect(stop.status).toBe(99);
    expect(bootProbe()).toMatchObject({ ok: true, valid: true, state: 'full-file', startCount: 24, modernCount: len });
    const r = runPrune(['--confirm-server-stopped', '--retention-days', '1', '--archive-root', archiveRoot]);
    expect(r.out).toMatchObject({ result: 'RESUMED', checkpointId: C2.payload.checkpointId, fromCount: 24, toCount: C2.payload.chainLength,
      postBoot: { state: 'rebased', startCount: C2.payload.chainLength, modernCount: len } });
    const archives = [C1, C2].map((c) => path.join(archiveRoot, c.payload.checkpointId)).join(',');
    const v = indep({ audit: LOG, format: 'ndjson', base: LOG + '.base.json', archive: archives, 'checkpoint-keys': keysFile(), anchor: LOG + '.sum' });
    expect({ verdict: v.verdict, archives: v.archives.map((a) => [a.from.count, a.to.count, a.valid]) }).toEqual(
      { verdict: 'VALID', archives: [[0, 24, true], [24, C2.payload.chainLength, true]] });
    expect((await admin.query('SELECT count(*)::int n FROM audit_chain_prunes')).rows[0].n).toBe(2);
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); rolePools = require('../../src/infra/postgres/rolePools'); pgPool.initialize();
    auditLog = require('../../src/core/audit/audit-log');
    const mirror = require('../../src/core/audit/mirrorConsistencyCheck');
    expect(await mirror.verifyMirrorConsistency({ _exit: (c) => { throw new Error(`mirror exit ${c}`); }, _emit: () => {} })).toBe(true);
    const chainStore = require('../../src/core/evidence/chainStore');
    const b = await require('../../src/core/evidence/evidenceBase').getEvidenceBase();
    expect(b.error).toBeUndefined();
    const maxId = (await admin.query('SELECT max(id)::int m FROM evidence_chain_records')).rows[0].m;
    expect(await chainStore.verifyChainRange({ startId: b.lastPrunedId + 1, endId: maxId, limit: 10_000, verifiedBy: 'w10pr' })).toMatchObject({ valid: true });
  });

  test('PR-06 dr:verify (offline) checks the base record in the file backup path', () => {
    const { runBackup } = require('../../scripts/dr/backup');
    return Promise.resolve(runBackup({ outDir: path.join(tmp, 'bk'), includePostgres: false })).then((res) => {
      const dir = path.join(tmp, 'bk');
      const { verifyBackup } = require('../../scripts/dr/verify');
      const ok = verifyBackup(dir);
      // this suite's data dir holds no policy store (a required component unrelated to the audit base) — the base check itself must be clean
      expect({ state: ok.auditBaseState, baseErrors: ok.errors.filter((e) => /AUDIT_BASE/.test(e)) }).toEqual({ state: 'rebased', baseErrors: [] });
      // forge the backed-up base record (and re-hash the manifest so only the signature check can catch it)
      const man = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
      const comp = man.components.find((c) => c.name === 'auditLogBase');
      const f = path.join(dir, comp.archiveFile);
      const rec = JSON.parse(fs.readFileSync(f, 'utf8')); rec.checkpoint.payload.chainLength += 1;
      fs.writeFileSync(f, JSON.stringify(rec));
      comp.sha256 = crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); comp.sizeBytes = fs.statSync(f).size;
      const { manifestChecksum, ...rest } = man; void manifestChecksum;   // re-seal the manifest as a forger would
      fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ ...rest, manifestChecksum: require('../../scripts/dr/manifest').computeManifestChecksum(rest) }, null, 2));
      const bad = verifyBackup(dir);
      expect(bad.valid).toBe(false);
      expect(bad.errors.join(' ')).toMatch(/AUDIT_BASE_SIGNATURE_INVALID/);
      void res;
    });
  });

  test('PR-07 tamper controls — every one fails', async () => {
    const results = {};
    const keys = keysFile();
    const a1 = path.join(archiveRoot, C1.payload.checkpointId);
    // (a) flipped archive byte; (a') the same with the manifest re-hashed
    const ta = path.join(tmp, 't-archive'); fs.cpSync(a1, ta, { recursive: true });
    flipByte(path.join(a1, 'audit.log.segment'), path.join(ta, 'audit.log.segment'), (b) => b.indexOf(0x61, 200));
    results.archiveByte = indep({ archive: ta, 'checkpoint-keys': keys }).archives[0].reason;
    const man = JSON.parse(fs.readFileSync(path.join(ta, 'manifest.json'), 'utf8'));
    man.files['audit.log.segment'].sha256 = crypto.createHash('sha256').update(fs.readFileSync(path.join(ta, 'audit.log.segment'))).digest('hex');
    fs.writeFileSync(path.join(ta, 'manifest.json'), JSON.stringify(man));
    results.archiveByteRehashed = indep({ archive: ta, 'checkpoint-keys': keys }).archives[0].reason;
    // (b) flipped suffix byte
    const sb = copySet(path.join(tmp, 't-suffix'));
    flipByte(LOG, sb, (b) => b.indexOf(0x61, 300));
    results.suffixIndep = indep({ audit: sb, format: 'ndjson', base: sb + '.base.json', 'checkpoint-keys': keys }).verdict;
    const sbBoot = bootProbe({ QODIQA_AUDIT_LOG: sb });
    results.suffixBoot = sbBoot.ok && sbBoot.valid ? 'VALID' : 'FAILED';
    // (c) forged base record (headHash changed, signature kept)
    const fc = copySet(path.join(tmp, 't-forged'));
    const rec = JSON.parse(fs.readFileSync(fc + '.base.json', 'utf8')); rec.checkpoint.payload.headHash = 'e'.repeat(64);
    fs.writeFileSync(fc + '.base.json', JSON.stringify(rec));
    results.forgedIndep = indep({ audit: fc, format: 'ndjson', base: fc + '.base.json', 'checkpoint-keys': keys }).audit.reason;
    results.forgedBoot = bootProbe({ QODIQA_AUDIT_LOG: fc }).error || 'BOOTED';
    // (d) a validly signed checkpoint moved: the base record now holds C1 while the log starts after C2
    const mc = copySet(path.join(tmp, 't-moved'));
    const moved = JSON.parse(fs.readFileSync(mc + '.base.json', 'utf8')); moved.checkpoint = C1; moved.priorBase = null;
    fs.writeFileSync(mc + '.base.json', JSON.stringify(moved));
    results.movedIndep = indep({ audit: mc, format: 'ndjson', base: mc + '.base.json', 'checkpoint-keys': keys }).audit.reason;
    results.movedBoot = bootProbe({ QODIQA_AUDIT_LOG: mc }).error || 'BOOTED';
    // (e) a deleted suffix line (the second)
    const dl = copySet(path.join(tmp, 't-delline'));
    const lines = fs.readFileSync(LOG, 'utf8').split('\n'); lines.splice(1, 1); fs.writeFileSync(dl, lines.join('\n'));
    results.deletedLineIndep = indep({ audit: dl, format: 'ndjson', base: dl + '.base.json', 'checkpoint-keys': keys }).audit.reason;
    const dlBoot = bootProbe({ QODIQA_AUDIT_LOG: dl });
    results.deletedLineBoot = dlBoot.ok && dlBoot.valid ? 'VALID' : 'FAILED';
    // (f) the base record missing
    const mb = copySet(path.join(tmp, 't-nobase'));
    fs.renameSync(mb + '.base.json', mb + '.base.json.moved-aside');
    results.missingBaseBoot = bootProbe({ QODIQA_AUDIT_LOG: mb }).error || 'BOOTED';
    results.missingBaseIndep = indep({ audit: mb, format: 'ndjson' }).verdict;
    // (g) PG: a kept evidence record deleted; (h) the first kept evidence record's link altered — last, in this suite's DB
    const chainStore = require('../../src/core/evidence/chainStore');
    const b = await require('../../src/core/evidence/evidenceBase').getEvidenceBase();
    const maxId = (await admin.query('SELECT max(id)::int m FROM evidence_chain_records')).rows[0].m;
    await admin.query('DELETE FROM evidence_chain_records WHERE id = $1', [b.lastPrunedId + 3]);
    results.evidenceRowDeleted = (await chainStore.verifyChainRange({ startId: b.lastPrunedId + 1, endId: maxId, limit: 10_000, verifiedBy: 'w10pr' })).valid;
    await admin.query('UPDATE evidence_chain_records SET previous_evidence_hash = $1 WHERE id = $2', ['f'.repeat(64), b.lastPrunedId + 1]);
    results.evidenceLinkAltered = (await chainStore.verifyChainRange({ startId: b.lastPrunedId + 1, endId: b.lastPrunedId + 2, limit: 10_000, verifiedBy: 'w10pr' })).valid;

    expect(results).toMatchObject({
      archiveByte: expect.stringMatching(/ARCHIVE_FILE_SHA256_MISMATCH/),
      archiveByteRehashed: expect.stringMatching(/ARCHIVE_SEGMENT_/),
      suffixIndep: 'INVALID', suffixBoot: 'FAILED',
      forgedIndep: expect.stringMatching(/AUDIT_BASE_SIGNATURE_INVALID/), forgedBoot: expect.stringMatching(/AUDIT_BASE_SIGNATURE_INVALID|AUDIT_INTEGRITY/),
      movedIndep: 'AUDIT_BASE_MISMATCH', movedBoot: expect.stringMatching(/AUDIT_BASE_MISMATCH/),
      deletedLineIndep: expect.stringMatching(/AUDIT_CHAIN_BROKEN/), deletedLineBoot: 'FAILED',
      missingBaseBoot: expect.stringMatching(/AUDIT_BASE_MISSING/), missingBaseIndep: 'INVALID',
      evidenceRowDeleted: false, evidenceLinkAltered: false,
    });
  });
});
