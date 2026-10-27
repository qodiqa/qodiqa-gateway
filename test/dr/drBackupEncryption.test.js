'use strict';

/**
 * — the DR JSON backup (scripts/dr/backup.js, shipped as the
 * hourly qodiqa-dr-backup CronJob) wrote every tenant's data in plaintext. It is now encrypted-then-sealed with the
 * SAME mechanism as scripts/pg-backup.sh (openssl AES-256-CBC / PBKDF2-SHA256 200 000 + HMAC-SHA256 seal), and a
 * plaintext DR backup is refused under QODIQA_BACKUP_REQUIRE_ENCRYPTION=true or NODE_ENV=production unless the
 * explicit, loudly-logged QODIQA_BACKUP_ALLOW_PLAINTEXT=true override is set (never against an explicit require).
 *
 *   DE-01 encrypted backup: only *.enc archives + manifest + seal; no plaintext marker anywhere; restore round-trips
 *   DE-02 an encrypted archive decrypts with the plain openssl command pg-backup.sh uses (operator independence)
 *   DE-03 dr:verify accepts the encrypted backup, and refuses it without keys / with a wrong seal key
 *   DE-04 tampered ciphertext / tampered-and-rechecksummed manifest / missing seal → restore fails closed
 *   DE-05 NODE_ENV=production or REQUIRE_ENCRYPTION=true without a key → refused before anything is written
 *   DE-06 production + ALLOW_PLAINTEXT=true → plaintext allowed with a BACKUP_PLAINTEXT_OVERRIDE warning;
 *         an explicit REQUIRE_ENCRYPTION=true is NOT lifted by the override
 *   DE-07 key validation mirrors pg-backup.sh (placeholder, short, missing HMAC key, HMAC key = encryption key)
 *   DE-08 restore / verify refuse a plaintext backup when encryption is required
 *   DE-09 the shipped CronJobs (qodiqa-dr-backup, qodiqa-dr-restore-validation) require both key secrets
 * DE-10 (todo, blocked) deploy/docker/backup.Dockerfile PostgreSQL 18 client — needs a newer pinned Alpine base
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const MARKER = `tenant-secret-marker-${crypto.randomBytes(6).toString('hex')}`;
// Throwaway, test-only keys (never real secrets): random per run.
const KEYS = {
  QODIQA_BACKUP_ENCRYPTION_KEY: `dd005-test-enc-${crypto.randomBytes(16).toString('hex')}`,
  QODIQA_BACKUP_HMAC_KEY: `dd005-test-mac-${crypto.randomBytes(16).toString('hex')}`,
};
const POLICY_KEYS = ['QODIQA_BACKUP_ENCRYPTION_KEY', 'QODIQA_BACKUP_HMAC_KEY', 'QODIQA_BACKUP_REQUIRE_ENCRYPTION', 'QODIQA_BACKUP_ALLOW_PLAINTEXT', 'NODE_ENV'];

jest.setTimeout(120_000);

function withEnv(env, fn) {
  const keys = [...new Set([...POLICY_KEYS, ...Object.keys(env)])];
  const saved = {};
  for (const k of keys) saved[k] = process.env[k];
  for (const k of POLICY_KEYS) delete process.env[k];
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}

/** Scratch file components holding a recognisable marker; nothing real is read. */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dd005-'));
  fs.mkdirSync(path.join(dir, 'data'));
  fs.writeFileSync(path.join(dir, 'audit.log'), '');
  fs.writeFileSync(path.join(dir, 'data', 'policy-store.json'), JSON.stringify({ version: 1, policies: {}, note: MARKER }, null, 2));
  fs.writeFileSync(path.join(dir, 'data', 'tenants.json'), JSON.stringify({ tenants: [{ id: 'tenant-a', secret: MARKER }] }));
  fs.writeFileSync(path.join(dir, 'data', 'organizations.json'), JSON.stringify({ orgs: [{ id: 'org-a', note: MARKER }] }));
  fs.writeFileSync(path.join(dir, 'data', 'keys.json'), JSON.stringify({ keys: {}, note: MARKER })); // required component (shape only)
  const env = {
    QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'),
    QODIQA_KEYS_PATH: path.join(dir, 'data', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(dir, 'data', 'key-archive.json'),
    QODIQA_POLICY_STORE: path.join(dir, 'data', 'policy-store.json'),
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'data', 'transparency-keys.json'),
    QODIQA_CHECKPOINT_KEYS_PATH: path.join(dir, 'data', 'checkpoint-keys.json'),
    // the components added to the DR set resolve inside the scratch dir too (nothing real is read)
    QODIQA_MAC_KEYS_PATH: path.join(dir, 'data', 'mac-keys.json'),
    QODIQA_PRQ_JOURNAL_DIR: path.join(dir, 'data', 'prq-journal'),
    ORG_STORE_PATH: path.join(dir, 'data', 'organizations.json'),
    TENANT_STORE_PATH: path.join(dir, 'data', 'tenants.json'),
  };
  return { dir, env, out: path.join(dir, 'backup'), target: path.join(dir, 'restored') };
}

const load = () => {
  jest.resetModules();
  return {
    ...require('../../scripts/dr/backup'),
    ...require('../../scripts/dr/restore'),
    ...require('../../scripts/dr/verify'),
    computeManifestChecksum: require('../../scripts/dr/manifest').computeManifestChecksum,
  };
};

async function encryptedBackup() {
  const fx = fixture();
  const { runBackup } = load();
  const res = await withEnv({ ...fx.env, ...KEYS }, () => runBackup({ outDir: fx.out }));
  return { fx, ...res };
}

describe('DR JSON backup encryption at rest', () => {
  test('DE-01 encrypted backup writes only ciphertext, seals the manifest, and restores byte-identically', async () => {
    const { fx, manifest } = await encryptedBackup();
    expect(manifest.encryption).toMatchObject({ scheme: 'openssl-enc/aes-256-cbc/pbkdf2-hmac-sha256/200000/salted', sealFile: 'manifest.json.seal' });
    const files = fs.readdirSync(fx.out).sort();
    expect(files).toContain('manifest.json.seal');
    const data = files.filter((f) => !['manifest.json', 'manifest.json.seal'].includes(f));
    expect(data.length).toBeGreaterThanOrEqual(4);
    expect(data.filter((f) => !f.endsWith('.enc'))).toEqual([]);
    for (const f of files) expect(fs.readFileSync(path.join(fx.out, f)).includes(MARKER)).toBe(false);
    expect(fs.readFileSync(path.join(fx.out, 'manifest.json.seal'), 'utf8')).toMatch(/^[0-9a-f]{64}\n$/);
    for (const c of manifest.components.filter((x) => x.present)) {
      expect(c.archiveFile).toMatch(/\.dat\.enc$/);
      expect(c.sha256).toBe(crypto.createHash('sha256').update(fs.readFileSync(path.join(fx.out, c.archiveFile))).digest('hex'));
    }

    const { runRestore } = load();
    const { restored } = await withEnv({ ...fx.env, ...KEYS }, () => runRestore({ backupDir: fx.out, targetRoot: fx.target }));
    for (const name of ['policyStore', 'tenants', 'organizations']) {
      const r = restored.find((x) => x.name === name);
      const src = { policyStore: fx.env.QODIQA_POLICY_STORE, tenants: fx.env.TENANT_STORE_PATH, organizations: fx.env.ORG_STORE_PATH }[name];
      expect(fs.readFileSync(r.destPath).equals(fs.readFileSync(src))).toBe(true);
    }
  });

  const OPENSSL = spawnSync('openssl', ['version'], { encoding: 'utf8' }).status === 0;
  (OPENSSL ? test : test.skip)('DE-02 an archive decrypts with the exact openssl command pg-backup.sh uses', async () => {
    const { fx, manifest } = await encryptedBackup();
    const comp = manifest.components.find((c) => c.name === 'tenants');
    const r = spawnSync('openssl', ['enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-md', 'sha256',
      '-pass', 'env:QODIQA_BACKUP_ENCRYPTION_KEY', '-in', path.join(fx.out, comp.archiveFile)],
    { env: { ...process.env, QODIQA_BACKUP_ENCRYPTION_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY } });
    expect(r.status).toBe(0);
    expect(r.stdout.equals(fs.readFileSync(fx.env.TENANT_STORE_PATH))).toBe(true);
  });

  test('DE-03 dr:verify accepts the encrypted backup, refuses it without keys or with the wrong seal key', async () => {
    const { fx } = await encryptedBackup();
    const { verifyBackup } = load();
    const ok = await withEnv({ ...KEYS }, () => verifyBackup(fx.out));
    expect(ok.errors).toEqual([]);
    expect(ok.valid).toBe(true);
    const noKeys = await withEnv({}, () => verifyBackup(fx.out));
    expect(noKeys.valid).toBe(false);
    expect(noKeys.errors.join(' ')).toMatch(/BACKUP_KEYS_MISSING/);
    const wrong = await withEnv({ ...KEYS, QODIQA_BACKUP_HMAC_KEY: `wrong-mac-key-${'x'.repeat(40)}` }, () => verifyBackup(fx.out));
    expect(wrong.valid).toBe(false);
    expect(wrong.errors.join(' ')).toMatch(/BACKUP_SEAL_MISMATCH/);
  });

  test('DE-04 tampering fails closed: ciphertext byte flip, re-checksummed manifest edit, missing seal', async () => {
    // (a) one ciphertext byte flipped → checksum mismatch, nothing restored
    {
      const { fx, manifest } = await encryptedBackup();
      const comp = manifest.components.find((c) => c.name === 'tenants');
      const p = path.join(fx.out, comp.archiveFile);
      const b = fs.readFileSync(p); b[b.length - 1] ^= 0x01; fs.writeFileSync(p, b);
      const { runRestore } = load();
      await expect(withEnv({ ...KEYS }, () => runRestore({ backupDir: fx.out, targetRoot: fx.target })))
        .rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
      expect(fs.existsSync(fx.target)).toBe(false);
    }
    // (b) the manifest edited AND its unkeyed manifestChecksum recomputed (what an attacker can do) → seal mismatch
    {
      const { fx } = await encryptedBackup();
      const mp = path.join(fx.out, 'manifest.json');
      const m = JSON.parse(fs.readFileSync(mp, 'utf8'));
      const { computeManifestChecksum, runRestore } = load();
      m.components.find((c) => c.name === 'tenants').description = 'edited';
      const { manifestChecksum, ...rest } = m; // eslint-disable-line no-unused-vars
      m.manifestChecksum = computeManifestChecksum(rest);
      fs.writeFileSync(mp, JSON.stringify(m, null, 2));
      await expect(withEnv({ ...KEYS }, () => runRestore({ backupDir: fx.out, targetRoot: fx.target })))
        .rejects.toMatchObject({ code: 'BACKUP_SEAL_MISMATCH' });
    }
    // (c) the seal file removed → refused (moved aside, not deleted: the test keeps it)
    {
      const { fx } = await encryptedBackup();
      fs.renameSync(path.join(fx.out, 'manifest.json.seal'), path.join(fx.dir, 'seal.moved'));
      const { runRestore } = load();
      await expect(withEnv({ ...KEYS }, () => runRestore({ backupDir: fx.out, targetRoot: fx.target })))
        .rejects.toMatchObject({ code: 'BACKUP_SEAL_MISSING' });
    }
  });

  test.each([
    ['NODE_ENV=production', { NODE_ENV: 'production' }],
    ['QODIQA_BACKUP_REQUIRE_ENCRYPTION=true', { QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true' }],
    ['explicit require + plaintext override', { QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true', QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true', NODE_ENV: 'production' }],
  ])('DE-05 %s without a key → BACKUP_ENCRYPTION_REQUIRED, nothing written', async (_label, env) => {
    const fx = fixture();
    const { runBackup } = load();
    await expect(withEnv({ ...fx.env, ...env }, () => runBackup({ outDir: fx.out })))
      .rejects.toMatchObject({ code: 'BACKUP_ENCRYPTION_REQUIRED' });
    expect(fs.existsSync(fx.out)).toBe(false);
  });

  // a production backup now also requires the database (the production control plane — RBAC,
  // signing identities, tenants, policies — lives in PostgreSQL), so the file-only run this test used is refused before
  // anything is written. The plaintext-override policy itself is unchanged and is asserted at its own layer; the
  // production refusal is asserted alongside it.
  test('DE-06 production + QODIQA_BACKUP_ALLOW_PLAINTEXT=true → plaintext allowed, loudly logged', async () => {
    const fx = fixture();
    const { resolveBackupEncryption } = require('../../scripts/dr/archiveCrypto');
    const { runBackup } = load();
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const r = resolveBackupEncryption({ NODE_ENV: 'production', QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' });
      expect(r).toEqual({ encrypt: false, overrideUsed: true });
      expect(spy.mock.calls.map((c) => String(c[0])).join('\n')).toMatch(/"event":"BACKUP_PLAINTEXT_OVERRIDE"/);
      await expect(withEnv({ ...fx.env, NODE_ENV: 'production', QODIQA_BACKUP_ALLOW_PLAINTEXT: 'true' }, () => runBackup({ outDir: fx.out })))
        .rejects.toMatchObject({ code: 'BACKUP_POSTGRES_REQUIRED' });
    } finally { spy.mockRestore(); }
    expect(fs.existsSync(fx.out)).toBe(false);   // refused before anything was written
  });

  test.each([
    ['placeholder encryption key', { QODIQA_BACKUP_ENCRYPTION_KEY: 'REPLACE_WITH_REAL_BACKUP_ENCRYPTION_KEY_BEFORE_DEPLOY', QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY }, 'BACKUP_ENCRYPTION_KEY_INVALID'],
    ['short encryption key', { QODIQA_BACKUP_ENCRYPTION_KEY: 'short', QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_HMAC_KEY }, 'BACKUP_ENCRYPTION_KEY_INVALID'],
    ['no HMAC key', { QODIQA_BACKUP_ENCRYPTION_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY }, 'BACKUP_ENCRYPTION_NEEDS_HMAC'],
    ['HMAC key equal to the encryption key', { QODIQA_BACKUP_ENCRYPTION_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY, QODIQA_BACKUP_HMAC_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY }, 'BACKUP_HMAC_KEY_INVALID'],
    ['short HMAC key', { QODIQA_BACKUP_ENCRYPTION_KEY: KEYS.QODIQA_BACKUP_ENCRYPTION_KEY, QODIQA_BACKUP_HMAC_KEY: 'short' }, 'BACKUP_HMAC_KEY_INVALID'],
  ])('DE-07 %s → %s, nothing written', async (_label, env, code) => {
    const fx = fixture();
    const { runBackup } = load();
    await expect(withEnv({ ...fx.env, ...env }, () => runBackup({ outDir: fx.out }))).rejects.toMatchObject({ code });
    expect(fs.existsSync(fx.out)).toBe(false);
  });

  test('DE-08 restore and verify refuse a plaintext backup when encryption is required', async () => {
    const fx = fixture();
    const { runBackup, runRestore, verifyBackup } = load();
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try { await withEnv({ ...fx.env }, () => runBackup({ outDir: fx.out })); } finally { spy.mockRestore(); }
    for (const env of [{ NODE_ENV: 'production' }, { QODIQA_BACKUP_REQUIRE_ENCRYPTION: 'true', ...KEYS }]) {
      await expect(withEnv(env, () => runRestore({ backupDir: fx.out, targetRoot: fx.target })))
        .rejects.toMatchObject({ code: 'BACKUP_PLAINTEXT_REFUSED' });
      const v = await withEnv(env, () => verifyBackup(fx.out));
      expect(v.valid).toBe(false);
      expect(v.errors.join(' ')).toMatch(/BACKUP_PLAINTEXT_REFUSED/);
    }
  });
});

describe('/ shipped packaging', () => {
  const yaml = require('js-yaml');
  const docs = yaml.loadAll(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/base/backup-cronjobs.yaml'), 'utf8')).filter(Boolean);
  const container = (name) => docs.find((d) => d.metadata && d.metadata.name === name).spec.jobTemplate.spec.template.spec.containers[0];

  test.each(['qodiqa-dr-backup', 'qodiqa-dr-restore-validation'])('DE-09 %s requires encryption and both key secrets (not optional)', (name) => {
    const env = Object.fromEntries(container(name).env.map((e) => [e.name, e]));
    expect(env.QODIQA_BACKUP_REQUIRE_ENCRYPTION).toEqual({ name: 'QODIQA_BACKUP_REQUIRE_ENCRYPTION', value: 'true' });
    for (const [k, secretKey] of [['QODIQA_BACKUP_ENCRYPTION_KEY', 'backup-encryption-key'], ['QODIQA_BACKUP_HMAC_KEY', 'backup-hmac-key']]) {
      expect(env[k].valueFrom.secretKeyRef).toEqual({ name: 'qodiqa-secrets', key: secretKey });
    }
    expect(env.QODIQA_BACKUP_ALLOW_PLAINTEXT).toBeUndefined();
  });

  // DE-10 BLOCKED: switching deploy/docker/backup.Dockerfile to postgresql18-client breaks the image build — the
  // pinned Alpine 3.21 base ships no PostgreSQL 18 client — so that change was reverted. It needs an approved, newer
  // pinned base-image digest (network). Kept visible as a todo rather than asserting either state.
  test.todo('DE-10 deploy/docker/backup.Dockerfile installs the PostgreSQL 18 client');
});
