'use strict';

/**
 * closure S33 — the reused WAL file.
 *
 * Real files in a temp dir, the real module, crashes simulated the way walCrashReplay.test.js does it: the writer is
 * frozen (a promise that never settles) at the exact step, so every file-system call that completed before it is on
 * disk (process-crash / OS-alive semantics) and the caller is never answered; a fresh require() is the restart.
 *
 * approved on-disk contract: WAL absent or empty while running; absent after recovery and after a clean stop.
 *
 *   WR-01  empty WAL while the writer is active (and the WAL bytes of a batch are exactly its log lines)
 *   WR-02  crash before the WAL fsync                     → restart: the batch's complete WAL is replayed once
 *   WR-03  crash after the WAL fsync, before the log append → restart: replayed once
 *   WR-04  crash after the log append, before the log fsync → restart: NOT duplicated (already at the log tail)
 *   WR-05  crash after the log fsync (checksum not written) → restart: not duplicated; lagging checksum delta-replayed
 *   WR-06  crash during the post-commit WAL truncation    → restart: committed WAL not replayed, no duplicate
 *   WR-06b a FAILED post-commit truncation never lets the next batch write over stale bytes
 *   WR-07  restart with an empty WAL                      → invalidated, removed, chain intact
 *   WR-08  restart with a valid (uncommitted) WAL         → replayed once
 *   WR-09  restart with a torn WAL                        → quarantined, discarded, chain intact
 *   WR-10  restart with a torn audit-log tail (prefix of the WAL entry) → repaired once
 *   WR-11  graceful drain removes the empty WAL; the writer reopens it on the next append
 *   WR-12  prune refuses while a non-empty WAL exists (and while an empty one exists); proceeds past the check after a clean stop
 *   WR-13  boot recovery handles a leftover WAL exactly once (second restart: nothing to replay)
 *   WR-14  rollback switch QODIQA_AUDIT_WAL_REUSE=false: create/unlink per batch, WAL absent between batches
 * WR-15 B' on the reused WAL: a failed batch is invalidated through the held handle before the caller is told
 *   WR-AM  appendMandatory() on the reused WAL: a transient handle-write failure is retried; ENOSPC fails closed
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..', '..');
const hang = () => new Promise(() => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function entryFields(overrides = {}) {
  return {
    artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true, ...overrides,
  };
}

describe('S33 — reused WAL file', () => {
  let saved; let logPath; let walPath; let FHP;
  const lines = () => (fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean) : []);
  const count = (id) => lines().filter((l) => l.includes(id)).length;
  const walSize = () => (fs.existsSync(walPath) ? fs.statSync(walPath).size : -1);
  const restart = () => { jest.resetModules(); return require('../audit-log.js'); };
  const waitFor = async (cond) => { for (let i = 0; i < 100 && !cond(); i++) await sleep(10); await sleep(20); };
  const quarantined = () => (fs.existsSync(logPath + '.quarantine') ? fs.readdirSync(logPath + '.quarantine') : []);

  beforeAll(async () => {
    const probe = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-walreuse-fh-')), 'p');
    const fh = await fs.promises.open(probe, 'w'); FHP = Object.getPrototypeOf(fh); await fh.close();
  });
  beforeEach(() => {
    saved = { log: process.env.QODIQA_AUDIT_LOG, reuse: process.env.QODIQA_AUDIT_WAL_REUSE };
    logPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-walreuse-')), 'audit.log');
    walPath = logPath + '.wal';
    process.env.QODIQA_AUDIT_LOG = logPath;
    delete process.env.QODIQA_AUDIT_WAL_REUSE;
    jest.resetModules();
  });
  afterEach(() => {
    jest.restoreAllMocks();
    if (saved.log === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved.log;
    if (saved.reuse === undefined) delete process.env.QODIQA_AUDIT_WAL_REUSE; else process.env.QODIQA_AUDIT_WAL_REUSE = saved.reuse;
    jest.resetModules();
  });

  test('WR-01 the WAL is reused and EMPTY between batches while the writer runs; a batch\'s WAL bytes are exactly its log lines', async () => {
    const a = require('../audit-log.js');
    expect(a.getStorageReport()).toMatchObject({ groupCommit: true, walReuse: true, walReuseRollbackSwitch: 'QODIQA_AUDIT_WAL_REUSE=false' });
    for (let i = 0; i < 5; i++) { await a.append(entryFields()); expect(walSize()).toBe(0); }
    // capture one batch's WAL bytes by freezing the log append right after the WAL fsync
    const spy = jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(hang);
    const f = entryFields();
    a.append(f);
    await waitFor(() => walSize() > 0);
    const walBytes = fs.readFileSync(walPath, 'utf8');
    spy.mockRestore();
    const b = restart();
    expect(b.getChainLength()).toBe(6);
    expect(lines()[5] + '\n').toBe(walBytes);           // the replayed log line is byte-identical to the WAL content
    expect(JSON.parse(walBytes).artifactId).toBe(f.artifactId);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-02 crash before the WAL fsync → the complete WAL batch is replayed once; the caller was never answered', async () => {
    const a = require('../audit-log.js');
    const e1 = await a.append(entryFields());
    const realSync = FHP.sync;
    let n = 0;
    jest.spyOn(FHP, 'sync').mockImplementation(function (...args) { n++; return n === 1 ? hang() : realSync.apply(this, args); });
    const f2 = entryFields(); let answered = false;
    a.append(f2).then(() => { answered = true; }, () => { answered = true; });
    await waitFor(() => walSize() > 0);
    expect(answered).toBe(false);
    expect(count(f2.artifactId)).toBe(0);                   // the log was never touched
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect((await b.getArtifactById(f2.artifactId)).prevHash).toBe(e1.hash);
    expect(b.getStorageReport().recovery).toMatchObject({ walFound: true, walReplayed: 1, walAlreadyCommitted: 0 });
    expect(fs.existsSync(walPath)).toBe(false);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-03 crash after the WAL fsync, before the log append → replayed once', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(hang);
    const f2 = entryFields();
    a.append(f2);
    await waitFor(() => walSize() > 0);
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect(b.getStorageReport().recovery.walReplayed).toBe(1);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-04 crash after the log append, before the log fsync → NOT duplicated', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    const realSync = FHP.sync;
    let n = 0;   // per batch: sync #1 = WAL (held handle), sync #2 = log (_fsyncAsync)
    jest.spyOn(FHP, 'sync').mockImplementation(function (...args) { n++; return n === 2 ? hang() : realSync.apply(this, args); });
    const f2 = entryFields();
    a.append(f2);
    await waitFor(() => count(f2.artifactId) === 1);
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect(b.getStorageReport().recovery).toMatchObject({ walAlreadyCommitted: 1, walReplayed: 0 });
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-05 crash after the log fsync, before the checksum → not duplicated; the lagging checksum is delta-replayed', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    const sumBefore = fs.readFileSync(logPath + '.sum', 'utf8');
    jest.spyOn(fs.promises, 'writeFile').mockImplementationOnce(hang);   // the next writeFile is the checksum tmp
    const f2 = entryFields(); let answered = false;
    a.append(f2).then(() => { answered = true; }, () => { answered = true; });
    await waitFor(() => count(f2.artifactId) === 1);
    expect(answered).toBe(false);
    expect(fs.readFileSync(logPath + '.sum', 'utf8')).toBe(sumBefore);  // checksum still at entry #1
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect(b.getStorageReport().recovery.walReplayed).toBe(0);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-06 crash during the post-commit WAL truncation → the committed WAL is not replayed, no duplicate', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    jest.spyOn(FHP, 'truncate').mockImplementationOnce(hang);           // the next truncate = the post-commit one
    const f2 = entryFields();
    a.append(f2);
    await waitFor(() => count(f2.artifactId) === 1 && walSize() > 0);
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect(b.getStorageReport().recovery).toMatchObject({ walFound: true, walAlreadyCommitted: 1, walReplayed: 0 });
    expect(fs.existsSync(walPath)).toBe(false);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-06b a failed post-commit truncation: the entry is committed, and the next batch never writes over stale bytes', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields({ requestHash: 'x'.repeat(64) }));
    jest.spyOn(FHP, 'truncate').mockImplementationOnce(() => Promise.reject(Object.assign(new Error('EIO: injected'), { code: 'EIO' })));
    const f2 = entryFields();
    await a.append(f2);                                                  // committed (durable) — truncation is post-commit
    jest.restoreAllMocks();
    expect(walSize()).toBeGreaterThan(0);                                // stale committed batch left (dirty)
    const f3 = entryFields();
    jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(hang);  // freeze batch 3 after its WAL fsync
    a.append(f3);
    await waitFor(() => fs.readFileSync(walPath, 'utf8').includes(f3.artifactId));
    const wal = fs.readFileSync(walPath, 'utf8');
    expect(wal.includes(f2.artifactId)).toBe(false);                     // the stale bytes were truncated first
    expect(wal.split('\n').filter(Boolean)).toHaveLength(1);
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getChainLength()).toBe(3);
    expect(count(f2.artifactId)).toBe(1);
    expect(count(f3.artifactId)).toBe(1);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-07 restart with an empty WAL → invalidated, removed, chain intact', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    expect(walSize()).toBe(0);                                           // the crash between batches leaves this
    const b = restart();
    expect(b.getStorageReport().recovery).toMatchObject({ walFound: true, walEmptyInvalidated: true, walReplayed: 0 });
    expect(fs.existsSync(walPath)).toBe(false);
    expect(b.getChainLength()).toBe(1);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
    await b.append(entryFields());                                       // and the writer works after it
    expect(b.getChainLength()).toBe(2);
  });

  test('WR-08 restart with a valid uncommitted WAL → replayed exactly once', async () => {
    const a = require('../audit-log.js');
    const e1 = await a.append(entryFields());
    const eb = require('../entryBuilder');
    const e2 = eb.buildEntry(eb.normalizeFields(entryFields()), e1.hash);
    fs.writeFileSync(walPath, JSON.stringify(e2) + '\n', 'utf8');
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(count(e2.artifactId)).toBe(1);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-09 restart with a torn WAL → quarantined and discarded, nothing appended, chain intact', async () => {
    const a = require('../audit-log.js');
    const e1 = await a.append(entryFields());
    const eb = require('../entryBuilder');
    const e2 = eb.buildEntry(eb.normalizeFields(entryFields()), e1.hash);
    fs.writeFileSync(walPath, (JSON.stringify(e2) + '\n').slice(0, 80), 'utf8');
    const b = restart();
    expect(b.getStorageReport().recovery.walTornDiscarded).toBe(true);
    expect(quarantined().some((q) => q.includes('torn-wal'))).toBe(true);
    expect(b.getChainLength()).toBe(1);
    expect(count(e2.artifactId)).toBe(0);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-10 restart with a torn audit-log tail that is a prefix of the WAL entry → repaired, entry present once', async () => {
    const a = require('../audit-log.js');
    const e1 = await a.append(entryFields());
    const eb = require('../entryBuilder');
    const e2 = eb.buildEntry(eb.normalizeFields(entryFields()), e1.hash);
    const line2 = JSON.stringify(e2) + '\n';
    fs.writeFileSync(walPath, line2, 'utf8');
    fs.appendFileSync(logPath, line2.slice(0, 61), 'utf8');
    const b = restart();
    expect(b.getStorageReport().recovery.tornTailRepaired).toMatchObject({ bytes: 61, walEntryHash: e2.hash });
    expect(b.getChainLength()).toBe(2);
    expect(count(e2.artifactId)).toBe(1);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-11 graceful drain removes the empty WAL; the next append reopens it; drain removes it again', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    expect(walSize()).toBe(0);
    await a.drainPendingWrites();
    expect(fs.existsSync(walPath)).toBe(false);
    await a.append(entryFields());
    expect(walSize()).toBe(0);
    await a.drainPendingWrites();
    expect(fs.existsSync(walPath)).toBe(false);
    const b = restart();
    expect(b.getStorageReport().recovery.walFound).toBe(false);          // clean stop: nothing for recovery
    expect(b.getChainLength()).toBe(2);
  });

  test('WR-12 prune refuses while a non-empty (or an empty) WAL exists; after a clean stop it gets past that check', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    const prune = () => spawnSync(process.execPath, [path.join(REPO, 'scripts/audit/prune.js'), '--confirm-server-stopped', '--retention-days', '1', '--dry-run'], {
      cwd: REPO, encoding: 'utf8', timeout: 60000,
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, NODE_ENV: 'test', QODIQA_AUDIT_LOG: logPath, QODIQA_PG_ENABLED: 'false', QODIQA_AUDIT_WAL_REUSE: '' },
    });
    const walRefusal = /a WAL file exists/;
    fs.writeFileSync(walPath, fs.readFileSync(logPath, 'utf8'), 'utf8');      // non-empty (a committed batch)
    let r = prune();
    expect(r.status).toBe(2);
    expect(r.stdout + r.stderr).toMatch(walRefusal);
    fs.writeFileSync(walPath, '', 'utf8');                                     // empty (crash between batches)
    r = prune();
    expect(r.status).toBe(2);
    expect(r.stdout + r.stderr).toMatch(walRefusal);
    fs.truncateSync(walPath, 0);
    await a.drainPendingWrites();                                              // clean stop
    expect(fs.existsSync(walPath)).toBe(false);
    r = prune();
    expect(r.stdout + r.stderr).not.toMatch(walRefusal);
  });

  test('WR-13 a leftover WAL is handled by boot recovery exactly once', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(hang);
    const f2 = entryFields();
    a.append(f2);
    await waitFor(() => walSize() > 0);
    jest.restoreAllMocks();
    const b = restart();
    expect(b.getStorageReport().recovery.walReplayed).toBe(1);
    const c = restart();
    expect(c.getStorageReport().recovery).toMatchObject({ walFound: false, walReplayed: 0 });
    expect(c.getChainLength()).toBe(2);
    expect(count(f2.artifactId)).toBe(1);
    expect(c.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-14 QODIQA_AUDIT_WAL_REUSE=false restores create/unlink per batch: no WAL file between batches', async () => {
    process.env.QODIQA_AUDIT_WAL_REUSE = 'false';
    const a = require('../audit-log.js');
    expect(a.getStorageReport()).toMatchObject({ groupCommit: true, walReuse: false });
    const unlink = jest.spyOn(fs.promises, 'unlink');
    for (let i = 0; i < 3; i++) { await a.append(entryFields()); expect(fs.existsSync(walPath)).toBe(false); }
    expect(unlink.mock.calls.filter((c) => c[0] === walPath)).toHaveLength(3);
    const b = restart();
    expect(b.getChainLength()).toBe(3);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test("WR-15 B' with the reused WAL: a failed batch is invalidated (empty, fsynced) before its caller is told; its retry commits once", async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(() => Promise.reject(Object.assign(new Error('EIO: injected'), { code: 'EIO' })));
    const f2 = entryFields();
    await expect(a.append(f2)).rejects.toThrow('EIO: injected');
    jest.restoreAllMocks();
    expect(walSize()).toBe(0);
    await a.append(f2);
    expect(count(f2.artifactId)).toBe(1);
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(b.getStorageReport().recovery.walReplayed).toBe(0);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });

  test('WR-AM appendMandatory on the reused WAL: a transient handle-write failure is retried once and commits once; ENOSPC fails closed', async () => {
    const a = require('../audit-log.js');
    await a.append(entryFields());
    jest.spyOn(FHP, 'write').mockImplementationOnce(() => Promise.reject(Object.assign(new Error('EBUSY: injected'), { code: 'EBUSY' })));
    const f2 = entryFields();
    const r = await a.appendMandatory(f2, { retryDelayMs: 1 });
    expect(r.artifactId).toBe(f2.artifactId);
    expect(count(f2.artifactId)).toBe(1);
    jest.restoreAllMocks();
    jest.spyOn(FHP, 'write').mockImplementation(() => Promise.reject(Object.assign(new Error('ENOSPC: injected'), { code: 'ENOSPC' })));
    const f3 = entryFields();
    await expect(a.appendMandatory(f3, { maxRetries: 2, retryDelayMs: 1 })).rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);
    jest.restoreAllMocks();
    expect(count(f3.artifactId)).toBe(0);
    expect(walSize()).toBe(0);
    const b = restart();
    expect(b.getChainLength()).toBe(2);
    expect(b.validateChainIntegrity().chainValid).toBe(true);
  });
});
