'use strict';

/**
 * Non-destructive backup verification — remediation.
 *
 * Proves verifyBackup() (scripts/dr/verify.js) correctly reports a real
 * backup produced by backup.js as valid, and correctly detects every
 * corruption scenario restore.js itself fails closed on — without ever
 * writing to a restore target (this is the whole point of a scheduled,
 * non-destructive verification job).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { runBackup } = require('../../scripts/dr/backup');
const { verifyBackup } = require('../../scripts/dr/verify');

jest.setTimeout(30_000);

function makeSourceEnv() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-source-'));
  return {
    dir: base,
    QODIQA_AUDIT_LOG: path.join(base, 'audit.log'),
    QODIQA_KEYS_PATH: path.join(base, 'data', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(base, 'data', 'key-archive.json'),
    // INJ-3/#283: matches what scripts/dr/components.js now resolves for the
    // policyStore component (the live src/core/policy/store.js's own env var).
    QODIQA_POLICY_STORE: path.join(base, 'data', 'policy-store.json'),
    ORG_STORE_PATH: path.join(base, 'data', 'organizations.json'),
    TENANT_STORE_PATH: path.join(base, 'data', 'tenants.json'),
  };
}

describe('verifyBackup', () => {
  let scratch;
  let backupDir;

  beforeAll(async () => {
    const env = makeSourceEnv();
    const prevEnv = {};
    for (const k of Object.keys(env)) {
      if (k === 'dir') continue;
      prevEnv[k] = process.env[k];
      process.env[k] = env[k];
    }

    fs.mkdirSync(path.dirname(env.QODIQA_KEYS_PATH), { recursive: true });
    fs.writeFileSync(env.QODIQA_AUDIT_LOG, JSON.stringify({ line: 1 }) + '\n');
    fs.writeFileSync(env.QODIQA_KEYS_PATH, JSON.stringify({ keys: [] }));
    fs.writeFileSync(env.QODIQA_POLICY_STORE, JSON.stringify({ versions: [] }));

    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-backup-'));
    backupDir = path.join(scratch, 'backup');
    await runBackup({ outDir: backupDir });

    for (const k of Object.keys(prevEnv)) {
      if (prevEnv[k] === undefined) delete process.env[k];
      else process.env[k] = prevEnv[k];
    }
  });

  afterAll(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  test('reports a freshly produced backup as valid', () => {
    const result = verifyBackup(backupDir);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.backupId).toEqual(expect.any(String));
    expect(result.componentsChecked).toBeGreaterThan(0);
  });

  test('detects a missing manifest.json', () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-empty-'));
    try {
      const result = verifyBackup(emptyDir);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/MANIFEST_MISSING/);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  test('detects a tampered manifest checksum', () => {
    const tamperedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-tampered-manifest-'));
    try {
      fs.cpSync(backupDir, tamperedDir, { recursive: true });
      const manifestPath = path.join(tamperedDir, 'manifest.json');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      manifest.backupId = 'tampered-id';
      fs.writeFileSync(manifestPath, JSON.stringify(manifest));

      const result = verifyBackup(tamperedDir);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/MANIFEST_CHECKSUM_MISMATCH/);
    } finally {
      fs.rmSync(tamperedDir, { recursive: true, force: true });
    }
  });

  test('detects a corrupted component archive (checksum mismatch)', () => {
    const corruptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-corrupt-archive-'));
    try {
      fs.cpSync(backupDir, corruptDir, { recursive: true });
      fs.appendFileSync(path.join(corruptDir, 'auditLog.dat'), 'CORRUPTION');

      const result = verifyBackup(corruptDir);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => /CHECKSUM_MISMATCH/.test(e))).toBe(true);
    } finally {
      fs.rmSync(corruptDir, { recursive: true, force: true });
    }
  });

  test('detects a missing required component archive file', () => {
    const missingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-missing-archive-'));
    try {
      fs.cpSync(backupDir, missingDir, { recursive: true });
      fs.rmSync(path.join(missingDir, 'auditLog.dat'));

      const result = verifyBackup(missingDir);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => /ARCHIVE_FILE_MISSING/.test(e))).toBe(true);
    } finally {
      fs.rmSync(missingDir, { recursive: true, force: true });
    }
  });

  test('never writes anything to a restore target — only reads within backupDir', () => {
    const before = fs.readdirSync(backupDir).sort();
    verifyBackup(backupDir);
    const after = fs.readdirSync(backupDir).sort();
    expect(after).toEqual(before);
  });

  test('detects a postgres component row-count mismatch without connecting to any database', () => {
    const pgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-verify-pg-mismatch-'));
    try {
      fs.cpSync(backupDir, pgDir, { recursive: true });
      fs.writeFileSync(path.join(pgDir, 'pg_widgets.json'), JSON.stringify([{ id: 1 }]));

      const manifestPath = path.join(pgDir, 'manifest.json');
      const { buildManifest } = require('../../scripts/dr/manifest');
      const original = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const rebuilt = buildManifest({
        backupId: original.backupId,
        createdAt: original.createdAt,
        appVersion: original.appVersion,
        components: original.components,
        postgres: {
          dumpedAt: new Date().toISOString(),
          tables: [{ table: 'widgets', present: true, rowCount: 5, archiveFile: 'pg_widgets.json' }],
        },
      });
      fs.writeFileSync(manifestPath, JSON.stringify(rebuilt));

      const result = verifyBackup(pgDir);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => /POSTGRES_ROW_COUNT_MISMATCH/.test(e))).toBe(true);
    } finally {
      fs.rmSync(pgDir, { recursive: true, force: true });
    }
  });
});
