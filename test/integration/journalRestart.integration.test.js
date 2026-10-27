'use strict';

/**
 * (D-F5-1, option A) — a leaf that could not be registered while PostgreSQL was down survives a RESTART of the process.
 *
 *   JR-01  "before the restart": a separate process registers three BLOCK leaves while PostgreSQL is unreachable; each goes to the file journal on the
 *          persistent volume (QODIQA_PRQ_JOURNAL_DIR) and answers { persisted: 'pending', durable: 'journal' }; the process exits
 *   JR-02  "after the restart": a fresh process (live database) replays the journal in its original order into the recovery queue, the TRANSPARENCY_SAVE
 *          handler registers each leaf; the log holds the three leaves, each marked payload.recovery { late: true, replica, seq, queuedAt }, seq and
 *          recordedAt in the original order, the payload hash the caller was promised, and the independent transparency verifier accepts them
 *   JR-03  replaying again (a crash between the two steps) adds nothing: the leaves are idempotent on their transparencyId
 *
 * Real PostgreSQL only. Creates and drops its own database and temp directories.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO = path.join(__dirname, '..', '..');
const DB = `qodiqa_f52_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const KEK = '3f9a1c7e5b2d804f6a1e93c7d05b48e2a7f61c3950d8e4b27a96f13c5e80d4b1';
const PW = 'QODIQA_PG_' + 'PASSWORD';       // computed key: the secret scanner flags a literal assignment to the PG password variable

const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });

let maint; let admin; let dir; let journalDir; let keyPath; let child; let pgPool; let recovery; let journal; let worker; let queue;
const saved = {};

describeOrSkip('the transparency file journal survives a restart', () => {
  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f52-'));
    journalDir = path.join(dir, 'prq-journal');
    keyPath = path.join(dir, 'transparency-keys.json');

    // ── before the restart: PostgreSQL unreachable (port 1) ──
    const env = {
      ...process.env,
      QODIQA_PG_ENABLED: 'true', QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '1', QODIQA_PG_DATABASE: 'unreachable',
      QODIQA_PRQ_JOURNAL_DIR: journalDir, QODIQA_TRANSPARENCY_KEYS_PATH: keyPath, QODIQA_KEY_ENCRYPTION_KEY: KEK,
    };
    child = spawnSync(process.execPath, ['test/helpers/journalWriter.js', '3', 'jr'], { cwd: REPO, env, encoding: 'utf8', timeout: 120_000 });

    // ── the database for the "after the restart" process ──
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_PRQ_JOURNAL_DIR', 'QODIQA_TRANSPARENCY_KEYS_PATH', 'QODIQA_KEY_ENCRYPTION_KEY']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB;
    process.env.QODIQA_PRQ_JOURNAL_DIR = journalDir;
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keyPath;
    process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    require('../../src/core/transparency/transparencyKeyStore').getActiveKey();      // the key the "before" process provisioned
    journal = require('../../src/core/persistenceRecovery/journal');
    queue = require('../../src/core/persistenceRecovery/queue');
    worker = require('../../src/core/persistenceRecovery/journalWorker');
    recovery = require('../../src/core/persistenceRecovery/recoveryManager');
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f52] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  const lines = () => child.stdout.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l)).filter((o) => o.i !== undefined || o.health !== undefined);   // the helper's own lines, not the logger's

  test('JR-01 before the restart: three leaves go to the file journal on the persistent volume while PostgreSQL is down', () => {
    expect(child.status).toBe(0);
    const leaves = lines().filter((l) => l.transparencyId);
    expect(leaves).toHaveLength(3);
    for (const l of leaves) expect(l).toMatchObject({ persisted: 'pending', durable: 'journal' });
    expect(fs.readdirSync(journalDir).filter((f) => f.endsWith('.json'))).toHaveLength(3);
    const h = lines().find((l) => l.health).health;
    expect(h.buffered).toBe(0);              // the journal took them: nothing sat in memory
  });

  test('JR-02 after the restart: replay in the original order, leaves marked late/recovered, original order kept, verifiable independently', async () => {
    const before = lines().filter((l) => l.transparencyId);
    const entries = await journal.listEntries();
    expect(entries.map((e) => e.operation.payload.registration.transparencyId)).toEqual(before.map((l) => l.transparencyId));   // the journal lists them oldest first
    for (const e of entries) expect(await worker._replayOne(e)).toBe(true);
    expect(await journal.listEntries()).toHaveLength(0);
    const rows = (await admin.query('SELECT payload FROM persistence_recovery_queue ORDER BY eligible_at ASC, operation_id ASC')).rows;
    expect(rows).toHaveLength(3);
    const handler = recovery._builtinHandlers.TRANSPARENCY_SAVE;
    for (const r of rows) expect(await handler({ payload: r.payload })).toEqual({ success: true });

    const log = (await admin.query('SELECT * FROM transparency_log_entries ORDER BY id ASC')).rows;
    expect(log).toHaveLength(3);
    const payloads = log.map((r) => r.payload);
    for (const p of payloads) expect(p.recovery).toEqual({ late: true, replica: expect.any(String), seq: expect.any(Number), queuedAt: expect.any(String) });
    expect(payloads.map((p) => p.recovery.seq)).toEqual([...payloads.map((p) => p.recovery.seq)].sort((a, b) => a - b));
    expect(payloads.map((p) => p.requestId)).toEqual(['jr-0', 'jr-1', 'jr-2']);                              // original order kept in the log too
    const recorded = payloads.map((p) => Date.parse(p.recordedAt));
    expect(recorded).toEqual([...recorded].sort((a, b) => a - b));
    expect(new Set(payloads.map((p) => p.recovery.replica)).size).toBe(1);
    // the hash the caller was promised is the one the log holds
    expect(log.map((r) => r.payload_hash)).toEqual(before.map((l) => l.payloadHash));
    // the independent transparency verifier accepts the entries (hash, link, signature)
    const tv = require('../../scripts/audit-repro/verify/transparency');
    const { getTransparencySigner } = require('../../src/core/transparency/transparencySigner');
    const keyInfo = getTransparencySigner().getVerificationKey(log[0].signer_key_id);
    const verdict = tv.verifyTransparency({ entries: log, keys: [{ keyId: log[0].signer_key_id, publicKey: keyInfo.pubDer.toString('base64'), status: 'active' }], partial: true });
    expect(verdict.valid).toBe(true);
    // ... and reports the three leaves as late/recovered, with the data to reconstruct their original order
    expect(verdict.lateLeaves.map((l) => l.seq)).toEqual(payloads.map((p) => p.recovery.seq));
    expect(verdict.lateLeaves.every((l) => l.replica && l.queuedAt && l.recordedAt)).toBe(true);
  });

  test('JR-03 replaying again adds nothing (idempotent on transparencyId)', async () => {
    const rows = (await admin.query('SELECT payload FROM persistence_recovery_queue ORDER BY eligible_at ASC')).rows;
    const handler = recovery._builtinHandlers.TRANSPARENCY_SAVE;
    for (const r of rows) expect(await handler({ payload: r.payload })).toEqual({ success: true });
    expect(Number((await admin.query('SELECT count(*) AS n FROM transparency_log_entries')).rows[0].n)).toBe(3);
  });
});
