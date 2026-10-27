'use strict';

/**
 * PL13-12 — backup artifacts that
 * hold plaintext are created owner-only.
 *
 *   BP-01 scripts/dr/backup.js creates its backup directory 0700 (it holds pg_<table>.json: every tenant's rows read
 * as the BYPASSRLS backup role, in plaintext — plus key-store copies)
 *   BP-02 (POSIX only) the directory really is 0700 on disk, whatever the process umask
 *   BP-03 (POSIX only) scripts/backup-audit-log.sh writes its audit-log copies 0600 and its metrics file 0644
 *
 * NTFS has no POSIX modes, so BP-02/BP-03 run on Linux (CI, the backup image); the Linux run of the same checks
 * against the cached backup image is recorded in DEPLOY-BACKUP.md (raw/linux-privacy-proof.txt).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const posixOnly = process.platform === 'win32' ? test.skip : test;

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; process.env[k] = env[k]; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}

function scratchEnv(dir) {
  // every file component points into an empty scratch directory: nothing real is read
  return {
    QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'),
    QODIQA_KEYS_PATH: path.join(dir, 'data', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(dir, 'data', 'key-archive.json'),
    QODIQA_POLICY_STORE: path.join(dir, 'data', 'policy-store.json'),
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'data', 'transparency-keys.json'),
    QODIQA_CHECKPOINT_KEYS_PATH: path.join(dir, 'data', 'checkpoint-keys.json'),
    ORG_STORE_PATH: path.join(dir, 'data', 'organizations.json'),
    TENANT_STORE_PATH: path.join(dir, 'data', 'tenants.json'),
  };
}

describe('PL13-12 DR / audit-log backup artifacts are owner-only', () => {
  test('BP-01 runBackup creates its backup directory with mode 0700', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl1312-'));
    const out = path.join(dir, 'qodiqa-backup-x');
    const spy = jest.spyOn(fs, 'mkdirSync');
    try {
      const { runBackup } = require('../../scripts/dr/backup');
      await withEnv(scratchEnv(dir), () => runBackup({ outDir: out }));
      const call = spy.mock.calls.find(([p]) => path.resolve(String(p)) === path.resolve(out));
      expect(call).toBeDefined();
      expect(call[1]).toMatchObject({ recursive: true, mode: 0o700 });
      expect(fs.existsSync(path.join(out, 'manifest.json'))).toBe(true);
    } finally { spy.mockRestore(); }
  });

  posixOnly('BP-02 the DR backup directory is 0700 on disk even with umask 022', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl1312-'));
    const out = path.join(dir, 'qodiqa-backup-y');
    const prev = process.umask(0o022);
    try {
      const { runBackup } = require('../../scripts/dr/backup');
      await withEnv(scratchEnv(dir), () => runBackup({ outDir: out }));
    } finally { process.umask(prev); }
    expect(fs.statSync(out).mode & 0o777).toBe(0o700);
  });

  posixOnly('BP-03 backup-audit-log.sh writes owner-only copies and a collector-readable metrics file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl1312-'));
    fs.writeFileSync(path.join(dir, 'audit.log'), '{"seq":1}\n');
    fs.writeFileSync(path.join(dir, 'audit.log.sum'), 'abc\n');
    const backups = path.join(dir, 'backups');
    const r = spawnSync('bash', ['-c', `umask 022; exec "${path.join(REPO, 'scripts', 'backup-audit-log.sh')}" backup`], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: dir, QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'), QODIQA_AUDIT_BACKUP_DIR: backups,
        QODIQA_BACKUP_HMAC_KEY: 'pl1312-test-hmac-key-0123456789abcdef-xyz' },
    });
    expect(r.status).toBe(0);
    const copies = fs.readdirSync(backups).filter((f) => /^audit-.*\.gz$/.test(f));
    expect(copies.length).toBe(2); // the log and its .sum companion
    for (const f of copies) expect({ f, mode: (fs.statSync(path.join(backups, f)).mode & 0o777).toString(8) }).toEqual({ f, mode: '600' });
    expect(fs.statSync(path.join(backups, 'metrics', 'qodiqa_audit_log_backup.prom')).mode & 0o777).toBe(0o644);
  });
});
