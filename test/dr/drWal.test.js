'use strict';

/**
 * — scripts/dr/backup.js / restore.js: the audit WAL must belong with the backed-up log.
 *
 * The WAL is captured BEFORE the log, so it can hold a batch that is already committed inside the log
 * prefix the backup then copies; restoring it made boot refuse ("the WAL batch does not continue the log" — found at
 * real size for the script). Every case here uses a REAL chain written by src/core/audit/audit-log.js in a child
 * process and the REAL restore gate (the production chain probe):
 *
 *   W-1  committed batch → omitted from the backup (recorded), restore valid, nothing replayed
 *   W-2  the defect itself: the same restored log WITH that WAL fails the production probe; reconcile → valid
 *   W-3  uncommitted batch (crash after WAL fsync, before the log append) → kept; restore replays it (20 entries)
 *   W-4  partial write: a torn log tail is excluded by the prefix, its batch kept in the WAL → restore replays it
 *   W-5  torn (half-written) WAL → kept; boot discards it (never acknowledged) → restore valid at the log's length
 *   W-6  a WAL from another chain → backup fails closed, no manifest; the interrupted backup cannot be restored
 *   W-7  corrupted WAL archive → CHECKSUM_MISMATCH; a foreign WAL in a restored target → RESTORED_WAL_INCONSISTENT
 *   W-8  log replaced between its copy and the WAL check → BACKUP_SOURCE_REPLACED
 *   W-9  backups taken WHILE a separate process appends: every one restores and passes the production probe
 *   W-10 the .sum is read whole and must parse: a torn read is retried; one that never parses fails the backup closed
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

jest.setTimeout(240000);

const REPO = path.join(__dirname, '..', '..');
const KEYS = {
  QODIQA_BACKUP_ENCRYPTION_KEY: `aut20-enc-${crypto.randomBytes(16).toString('hex')}`,
  QODIQA_BACKUP_HMAC_KEY: `aut20-mac-${crypto.randomBytes(16).toString('hex')}`,
};
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));

// Appends n real entries (production module) to <log>; with LOOP=1 keeps appending until killed.
const GEN = `
const a = require(${JSON.stringify(path.join(REPO, 'src/core/audit/audit-log.js'))});
const { EMPTY_OUTPUT_HASH } = require(${JSON.stringify(path.join(REPO, 'src/core/audit/entryBuilder'))});
const crypto = require('crypto');
const one = (i) => a.append({ artifactId: 'aut20-' + i + '-' + crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: i % 3 ? 'ALLOW' : 'BLOCK',
  outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true });
(async () => {
  if (process.env.LOOP) { let i = 0; process.stdout.write('ready\\n'); for (;;) { await Promise.all([one(i++), one(i++), one(i++)]); } }
  for (let i = 0; i < Number(process.argv[1]); i++) await one(i);
  if (a.drainPendingWrites) await a.drainPendingWrites();
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });`;
const childEnv = (log, extra = {}) => ({ ...process.env, NODE_ENV: 'test', QODIQA_PG_ENABLED: 'false', QODIQA_AUDIT_LOG: log, ...extra });
function gen(log, n) {
  const r = spawnSync(process.execPath, ['-e', GEN, String(n)], { env: childEnv(log), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`gen failed: ${r.stderr}`);
}
const lines = (p) => fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => `${l}\n`);

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}

function fixture() {
  const dir = tmp('aut20-src-');
  const d = (...p) => path.join(dir, ...p);
  fs.mkdirSync(d('data'));
  fs.writeFileSync(d('data', 'keys.json'), '{"keys":{}}');
  fs.writeFileSync(d('data', 'policy-store.json'), '{"policies":{}}');
  const env = {
    QODIQA_AUDIT_LOG: d('audit.log'), QODIQA_KEYS_PATH: d('data', 'keys.json'), QODIQA_KEYS_ARCHIVE_PATH: d('data', 'key-archive.json'),
    QODIQA_CHECKPOINT_KEYS_PATH: d('data', 'checkpoint-keys.json'), QODIQA_TRANSPARENCY_KEYS_PATH: d('data', 'transparency-keys.json'),
    QODIQA_MAC_KEYS_PATH: d('data', 'mac-keys.json'), QODIQA_PRQ_JOURNAL_DIR: d('data', 'prq-journal'),
    QODIQA_ANCHOR_EXPORT_PATH: d('anchors.jsonl'), QODIQA_WITNESS_MODE: undefined, QODIQA_WITNESS_LOG_PATH: undefined,
    QODIQA_POLICY_STORE: d('data', 'policy-store.json'), ORG_STORE_PATH: d('data', 'organizations.json'), TENANT_STORE_PATH: d('data', 'tenants.json'),
    NODE_ENV: 'test', QODIQA_CONTROL_PLANE_BACKEND: undefined, QODIQA_AUDIT_ORDERING_MODE: undefined, QODIQA_BACKUP_WINDOW_UTC: undefined,
  };
  let k = 0;
  const out = () => path.join(dir, '..', `${path.basename(dir)}-backup-${++k}`);
  const target = () => path.join(dir, '..', `${path.basename(dir)}-restored-${++k}`);
  return { dir, log: d('audit.log'), env, out, target };
}
const dr = () => { jest.resetModules(); return { ...require('../../scripts/dr/backup'), ...require('../../scripts/dr/restore'), ...require('../../scripts/dr/validate') }; };
const backup = (fx, outDir) => withEnv({ ...fx.env, ...KEYS }, () => dr().runBackup({ outDir }));
const restore = (backupDir, targetRoot) => withEnv(KEYS, () => dr().runRestore({ backupDir, targetRoot }));
const walComp = (manifest) => manifest.components.find((c) => c.name === 'auditLogWal');

/** 18 committed entries (+ their .sum), and the 2 entries the next batch would append (real hashes, chained). */
function crashedAfterWalFsync(fx) {
  gen(fx.log, 18);
  const log18 = fs.readFileSync(fx.log); const sum18 = fs.readFileSync(`${fx.log}.sum`);
  gen(fx.log, 2);
  const next = lines(fx.log).slice(18);
  fs.writeFileSync(fx.log, log18); fs.writeFileSync(`${fx.log}.sum`, sum18);
  return next;
}

describe('DR backup/restore: the audit WAL must belong with the backed-up log', () => {
  test('W-1 a batch already committed inside the log is omitted (recorded); restore passes the production probe', async () => {
    const fx = fixture(); gen(fx.log, 20);
    fs.writeFileSync(`${fx.log}.wal`, lines(fx.log).slice(10, 12).join(''));   // batch of entries 11-12, long since committed
    const out = fx.out();
    const { manifest } = await backup(fx, out);
    expect(walComp(manifest)).toMatchObject({ present: false, omitted: { reason: 'WAL_BATCH_COMMITTED_IN_LOG', entries: 2 } });
    const t = fx.target();
    const r = await restore(out, t);
    expect(r.auditChainCheck).toMatchObject({ valid: true, chainLength: 20 });
    expect(fs.existsSync(path.join(t, 'audit.log.wal'))).toBe(false);
    expect(fs.readFileSync(path.join(t, 'audit.log')).equals(fs.readFileSync(fx.log))).toBe(true);
  });

  test('W-2 the defect: the restored log WITH that WAL fails the production probe; reconcile sets it aside → valid', async () => {
    const fx = fixture(); gen(fx.log, 20);
    const t = fx.target(); fs.mkdirSync(t);
    for (const f of ['audit.log', 'audit.log.sum']) fs.copyFileSync(path.join(fx.dir, f), path.join(t, f));
    fs.writeFileSync(path.join(t, 'audit.log.wal'), lines(fx.log).slice(10, 12).join(''));   // what an earlier backup restored
    const { verifyAuditChainIntegrity, reconcileRestoredWal } = dr();
    // probe on a COPY (boot recovery writes into the directory it checks)
    const probeOn = (src) => { const c = tmp('aut20-probe-'); for (const f of fs.readdirSync(src)) fs.copyFileSync(path.join(src, f), path.join(c, f)); return verifyAuditChainIntegrity({ mode: 'single-node', auditLogPath: path.join(c, 'audit.log') }); };
    const before = probeOn(t);
    expect(before.valid).toBe(false);
    expect(before.reason).toMatch(/the WAL batch does not continue the log/);
    const rec = reconcileRestoredWal([{ name: 'auditLog', destPath: path.join(t, 'audit.log') }, { name: 'auditLogWal', destPath: path.join(t, 'audit.log.wal') }]);
    expect(rec).toMatchObject({ action: 'set-aside', disposition: 'committed', entries: 2 });
    expect(fs.existsSync(path.join(t, 'audit.log.wal.committed-batch'))).toBe(true);    // renamed, never deleted
    fs.renameSync(path.join(t, 'audit.log.wal.committed-batch'), path.join(tmp('aut20-aside-'), 'kept'));
    expect(probeOn(t)).toMatchObject({ valid: true, chainLength: 20 });
  });

  test('W-3 an uncommitted batch (crash after the WAL fsync) is kept and replayed at restore', async () => {
    const fx = fixture(); const next = crashedAfterWalFsync(fx);
    fs.writeFileSync(`${fx.log}.wal`, next.join(''));
    const out = fx.out();
    const { manifest } = await backup(fx, out);
    expect(walComp(manifest)).toMatchObject({ present: true, walDisposition: 'continues' });
    const r = await restore(out, fx.target());
    expect(r.walReconciliation).toMatchObject({ action: 'kept', disposition: 'continues' });
    expect(r.auditChainCheck).toMatchObject({ valid: true, chainLength: 20 });   // 18 in the log + 2 replayed from the WAL
  });

  test('W-4 partial write: a torn log tail is excluded, its batch stays in the WAL and is replayed', async () => {
    const fx = fixture(); const next = crashedAfterWalFsync(fx);
    fs.writeFileSync(`${fx.log}.wal`, next.join(''));
    fs.appendFileSync(fx.log, next[0].slice(0, 100));                 // the log append was cut mid-line
    const out = fx.out();
    const { manifest } = await backup(fx, out);
    expect(manifest.components.find((c) => c.name === 'auditLog').sourceBytes).toBe(fs.statSync(fx.log).size - 100);
    expect(walComp(manifest)).toMatchObject({ present: true, walDisposition: 'continues' });
    expect((await restore(out, fx.target())).auditChainCheck).toMatchObject({ valid: true, chainLength: 20 });
  });

  test('W-5 a torn (half-written) WAL is kept; boot discards it — the batch was never acknowledged', async () => {
    const fx = fixture(); const next = crashedAfterWalFsync(fx);
    fs.writeFileSync(`${fx.log}.wal`, next[0].slice(0, 120));
    const out = fx.out();
    const { manifest } = await backup(fx, out);
    expect(walComp(manifest)).toMatchObject({ present: true, walDisposition: 'torn' });
    expect((await restore(out, fx.target())).auditChainCheck).toMatchObject({ valid: true, chainLength: 18 });
  });

  test('W-6 a WAL from another chain fails the backup closed; the interrupted backup cannot be restored', async () => {
    const fx = fixture(); gen(fx.log, 10);
    const other = path.join(tmp('aut20-other-'), 'audit.log'); gen(other, 6);
    fs.writeFileSync(`${fx.log}.wal`, lines(other).slice(3, 5).join(''));
    const out = fx.out();
    await expect(backup(fx, out)).rejects.toMatchObject({ code: 'BACKUP_WAL_INCONSISTENT' });
    expect(fs.existsSync(path.join(out, 'manifest.json'))).toBe(false);
    await expect(restore(out, fx.target())).rejects.toMatchObject({ name: 'RestoreError' });
    fs.writeFileSync(`${fx.log}.wal`, '{"not":"a wal entry"}\n');      // parses, but carries no hash chain
    await expect(backup(fx, fx.out())).rejects.toMatchObject({ code: 'BACKUP_WAL_INCONSISTENT' });
  });

  test('W-7 a corrupted WAL archive is refused; a foreign WAL in a restored target fails closed', async () => {
    const fx = fixture(); const next = crashedAfterWalFsync(fx);
    fs.writeFileSync(`${fx.log}.wal`, next.join(''));
    const out = fx.out();
    const { manifest } = await backup(fx, out);
    const a = path.join(out, walComp(manifest).archiveFile); const b = fs.readFileSync(a); b[b.length - 1] ^= 1; fs.writeFileSync(a, b);
    await expect(restore(out, fx.target())).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
    const t = tmp('aut20-foreign-');
    fs.copyFileSync(fx.log, path.join(t, 'audit.log'));
    const other = path.join(tmp('aut20-other-'), 'audit.log'); gen(other, 4);
    fs.writeFileSync(path.join(t, 'audit.log.wal'), lines(other).slice(2).join(''));
    expect(() => dr().reconcileRestoredWal([{ name: 'auditLog', destPath: path.join(t, 'audit.log') }, { name: 'auditLogWal', destPath: path.join(t, 'audit.log.wal') }]))
      .toThrow(expect.objectContaining({ code: 'RESTORED_WAL_INCONSISTENT' }));
  });

  test('W-8 the log replaced between its copy and the WAL check → BACKUP_SOURCE_REPLACED', async () => {
    const fx = fixture(); gen(fx.log, 10);
    fs.writeFileSync(`${fx.log}.wal`, lines(fx.log).slice(4, 5).join(''));
    const real = fs.statSync; let n = 0;
    const spy = jest.spyOn(fs, 'statSync').mockImplementation((p, ...rest) => {
      const st = real(p, ...rest);
      if (p === fx.log && ++n >= 3) return { ...st, ino: -1, dev: st.dev, size: st.size, isFile: () => true };   // calls 1-2: the copy itself (-1: NTFS inode numbers exceed 2^53, so ino+1 may equal ino)
      return st;
    });
    try { await expect(backup(fx, fx.out())).rejects.toMatchObject({ code: 'BACKUP_SOURCE_REPLACED' }); } finally { spy.mockRestore(); }
  });

  test('W-10 a torn .sum read (Windows non-atomic rename fallback) is re-read; one that never parses fails closed', async () => {
    const fx = fixture(); gen(fx.log, 6);
    const good = fs.readFileSync(`${fx.log}.sum`);
    const realRead = fs.readFileSync; let reads = 0;
    const spy = jest.spyOn(fs, 'readFileSync').mockImplementation((p, ...rest) => {
      if (p === `${fx.log}.sum` && ++reads <= 2) return Buffer.alloc(good.length);   // zero-filled, as observed
      return realRead(p, ...rest);
    });
    let manifest;
    try { ({ manifest } = await backup(fx, fx.out())); } finally { spy.mockRestore(); }
    expect(reads).toBe(3);
    expect(manifest.components.find((c) => c.name === 'auditLogSum')).toMatchObject({ present: true });
    fs.writeFileSync(`${fx.log}.sum`, Buffer.alloc(good.length));
    await expect(backup(fx, fx.out())).rejects.toMatchObject({ code: 'BACKUP_COMPONENT_INVALID' });
  });

  test('W-9 backups taken while another process appends: every one restores and passes the production probe', async () => {
    const fx = fixture(); gen(fx.log, 5);
    const child = spawn(process.execPath, ['-e', GEN, '0'], { env: childEnv(fx.log, { LOOP: '1' }), stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((res) => child.stdout.once('data', res));
    const dispositions = {};
    try {
      for (let i = 0; i < 6; i++) {
        await new Promise((res) => setTimeout(res, 150));
        const out = fx.out();
        const { manifest } = await backup(fx, out);
        const w = walComp(manifest);
        const disp = w.present ? w.walDisposition : (w.omitted ? 'omitted-committed' : 'absent');
        dispositions[disp] = (dispositions[disp] || 0) + 1;
        const t = fx.target();
        const r = await restore(out, t);
        expect(r.auditChainCheck.valid).toBe(true);
        expect(r.auditChainCheck.chainLength).toBeGreaterThanOrEqual(manifest.components.find((c) => c.name === 'auditLog').sourceBytes > 0 ? 5 : 0);
      }
    } finally { child.kill(); }
    // eslint-disable-next-line no-console
    console.log(`W-9 WAL dispositions under load: ${JSON.stringify(dispositions)}`);
  });
});
