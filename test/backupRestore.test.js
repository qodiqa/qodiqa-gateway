'use strict';

/**
 * Backup -> Restore Disaster Recovery Validation — end-to-end.
 *
 * Proves the full cycle for every file-based persistent component:
 *   synthetic live state -> backup -> wipe -> restore into a CLEAN target
 *   -> validate that the restored files are not just byte-identical but
 *      actually FUNCTIONAL (real audit-log.js / policyStore.js / keyStore.js
 *      loaded against them in fresh child processes).
 *
 * Also covers the required failure scenarios: corrupted archive, missing
 * file, bad checksum, tampered manifest, restoring over a non-empty target.
 *
 * Postgres/Redis components (scripts/dr/postgres.js, redis.js) are NOT
 * exercised here — this sandbox has no live Postgres/Redis (verified: no
 * pg_dump/psql/redis-server binaries present). They are covered by the CI
 * workflow's service containers instead (.github/workflows/backup-restore.yml).
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

const { runBackup }  = require('../scripts/dr/backup');
const { runRestore, RestoreError } = require('../scripts/dr/restore');
const { validateRestoredState } = require('../scripts/dr/validate');
const { sha256File } = require('../scripts/dr/checksum');

jest.setTimeout(30_000);

// ── Build a realistic "live" source data set using the REAL production modules ──

function makeSourceEnv() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dr-source-'));
  return {
    dir: base,
    QODIQA_AUDIT_LOG: path.join(base, 'audit.log'),
    QODIQA_KEYS_PATH: path.join(base, 'data', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(base, 'data', 'key-archive.json'),
    // INJ-3/#283: this is what the live policy store (src/core/policy/store.js)
    // actually reads — the dead policy/policyStore.js's QODIQA_POLICY_STORE_PATH
    // is gone along with that module.
    QODIQA_POLICY_STORE: path.join(base, 'data', 'policy-store.json'),
    // src/core/policy/store.js's createPolicy() ALSO persists to POLICY_FILE
    // (a separate, legacy-format mirror of the same data) — without this
    // override it defaults to the repository's real policies.json, so
    // populateSource() below would otherwise write test data straight into
    // the checked-out repo on every test run.
    POLICY_FILE: path.join(base, 'policies.json'),
    ORG_STORE_PATH: path.join(base, 'data', 'organizations.json'),
    TENANT_STORE_PATH: path.join(base, 'data', 'tenants.json'),
    // the components added to the DR set resolve here too — their defaults point into the repository's own
    // data/ (e.g. data/prq-journal), which a fixture must never read.
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(base, 'data', 'transparency-keys.json'),
    QODIQA_MAC_KEYS_PATH: path.join(base, 'data', 'mac-keys.json'),
    QODIQA_PRQ_JOURNAL_DIR: path.join(base, 'data', 'prq-journal'),
  };
}

/** Populate a fresh source environment with real audit/policy/key state. */
async function populateSource(env) {
  const prevEnv = {};
  for (const k of Object.keys(env)) {
    if (k === 'dir') continue;
    prevEnv[k] = process.env[k];
    process.env[k] = env[k];
  }

  jest.resetModules();
  const auditLog    = require('../src/core/audit/audit-log.js');
  const policyStore = require('../src/core/policy/store.js');
  const keyStore     = require('../services/artifact/keyStore.js');
  const tenantRegistry = require('../src/core/tenancy/tenantRegistry.js');
  // control-plane state is a process-wide snapshot (memory mode) —
  // each populated source is a fresh single-node instance, so start it empty.
  policyStore._reset();
  tenantRegistry._reset();

  keyStore.rotateKey('default');

  for (let i = 0; i < 3; i++) {
    await auditLog.append({
      artifactId: crypto.randomUUID(),
      inputHash: 'a'.repeat(64),
      decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64),
      requestHash: 'r'.repeat(64),
      policyHash: 'p'.repeat(64),
      verificationResult: true,
    });
  }

  // S33: the source instance is stopped cleanly before it is backed up — drainPendingWrites() is the graceful-
  // shutdown step, after which the reused WAL is absent (approved on-disk contract: WAL absent or empty while running,
  // absent after a clean stop). A backup of a running writer would also carry its empty WAL, which restore-time
  // recovery then (correctly) consumes — not the byte-identity property this fixture checks.
  await auditLog.drainPendingWrites();

  policyStore.createPolicy({
    id:       'dr-test-policy',
    type:     'REQUIRE_CONSENT',
    priority: 10,
    config:   { requireValidArtifact: true },
    actor:    'dr-test',
    comment:  'DR backup/restore test policy',
  });
  // the stores no longer write files at runtime. This DR cycle backs
  // up a file-based (dev/test memory-mode) instance, so its seed files are
  // written explicitly — the same hand-off scripts/dr/seed.js performs.
  policyStore.exportSeedFixture();
  tenantRegistry.exportSeedFixture();

  const expectedChainLength = auditLog.getChainLength();
  const expectedActiveKey   = keyStore.getActiveKey('default');
  const expectedPolicyCount = policyStore.listPolicies({ status: 'ACTIVE', pageSize: Number.MAX_SAFE_INTEGER }).total;

  for (const k of Object.keys(prevEnv)) {
    if (prevEnv[k] === undefined) delete process.env[k];
    else process.env[k] = prevEnv[k];
  }
  jest.resetModules();

  return { expectedChainLength, expectedActiveKeyId: expectedActiveKey.keyId, expectedPolicyCount };
}

async function withEnv(envOverrides, fn) {
  const prev = {};
  for (const k of Object.keys(envOverrides)) {
    prev[k] = process.env[k];
    process.env[k] = envOverrides[k];
  }
  try {
    return await fn();
  } finally {
    for (const k of Object.keys(prev)) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ── 1. Full happy-path cycle ─────────────────────────────────────────────────

describe('Backup -> Restore — full cycle', () => {
  test('backup captures every populated component with correct checksums', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { manifest } = await withEnv(env, () => runBackup({ outDir: backupOut }));

    const byName = Object.fromEntries(manifest.components.map(c => [c.name, c]));

    expect(byName.auditLog.present).toBe(true);
    expect(byName.keyStore.present).toBe(true);
    expect(byName.policyStore.present).toBe(true);

    // Every present component's stored checksum matches the actual archive file.
    for (const comp of manifest.components) {
      if (!comp.present) continue;
      const archivePath = path.join(backupOut, comp.archiveFile);
      expect(sha256File(archivePath)).toBe(comp.sha256);
    }

    // Optional components not created in this source (organizations/tenants) are
    // recorded as absent, not fabricated, and are not required.
    expect(byName.organizations.present).toBe(false);
    expect(byName.organizations.required).toBe(false);

    expect(manifest.protocolVersion).toBe('v1');
    expect(manifest.appVersion).toBe(require('../package.json').version);
    expect(typeof manifest.manifestChecksum).toBe('string');
  });

  test('restore into a clean target reproduces byte-identical files', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));

    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { manifest, restored } = await runRestore({ backupDir, targetRoot: restoreTarget });

    expect(restored.length).toBeGreaterThan(0);

    for (const r of restored) {
      expect(fs.existsSync(r.destPath)).toBe(true);
      const comp = manifest.components.find(c => c.name === r.name);
      expect(sha256File(r.destPath)).toBe(comp.sha256);
    }
  });

  test('restored state is FUNCTIONAL — real audit-log/policyStore/keyStore modules accept it', async () => {
    const env = makeSourceEnv();
    const expectations = await populateSource(env);

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));

    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget });

    const result = await validateRestoredState(restored);

    expect(result.auditChain.valid).toBe(true);
    expect(result.auditChain.chainLength).toBe(expectations.expectedChainLength);
    expect(result.auditChain.tamperingDetected).toBe(false);

    expect(result.policyStore.valid).toBe(true);
    expect(result.policyStore.policyCount).toBe(expectations.expectedPolicyCount);

    expect(result.keyStore.valid).toBe(true);
    expect(result.keyStore.cryptoRoundTrip.ok).toBe(true);
    const defaultClient = result.keyStore.cryptoRoundTrip.perClient.find(c => c.clientId === 'default');
    expect(defaultClient.signVerifyOk).toBe(true);
    expect(defaultClient.keyId).toBe(expectations.expectedActiveKeyId);

    // the KEK round trip (encrypt -> simulate recovery -> recover KEK
    // -> decrypt -> compare plaintext) must have actually run and passed,
    // not merely be attempted.
    expect(result.keyStore.cryptoRoundTrip.kekRoundTrip.ok).toBe(true);
    expect(result.keyStore.cryptoRoundTrip.kekRoundTrip.plaintextMatch).toBe(true);

    expect(result.overallValid).toBe(true);
  });

  test('key fingerprint is IDENTICAL before and after restore (no cryptographic drift)', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const beforeFingerprint = await withEnv(env, () => {
      jest.resetModules();
      const keyStore = require('../services/artifact/keyStore.js');
      const active = keyStore.getActiveKey('default');
      return crypto.createHash('sha256').update(active.pubDer.toString('base64'), 'utf8').digest('hex');
    });

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));
    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget });
    const result = await validateRestoredState(restored);

    const afterFingerprint = result.keyStore.cryptoRoundTrip.perClient.find(c => c.clientId === 'default').keyFingerprint;
    expect(afterFingerprint).toBe(beforeFingerprint);
  });
});

// ── 2. Determinism ────────────────────────────────────────────────────────────

describe('Backup -> Restore — determinism', () => {
  test('two backups of the same unchanged source produce identical archive checksums', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const out1 = tmpDir('qodiqa-dr-backup-a-');
    const out2 = tmpDir('qodiqa-dr-backup-b-');
    const { manifest: m1 } = await withEnv(env, () => runBackup({ outDir: out1 }));
    const { manifest: m2 } = await withEnv(env, () => runBackup({ outDir: out2 }));

    const sums1 = Object.fromEntries(m1.components.filter(c => c.present).map(c => [c.name, c.sha256]));
    const sums2 = Object.fromEntries(m2.components.filter(c => c.present).map(c => [c.name, c.sha256]));
    expect(sums2).toEqual(sums1);
  });
});

// ── 3. Failure scenarios ──────────────────────────────────────────────────────

describe('Backup -> Restore — failure scenarios (must fail closed, deterministically)', () => {
  async function makeValidBackup() {
    const env = makeSourceEnv();
    await populateSource(env);
    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));
    return targetDir;
  }

  test('missing manifest.json is detected', async () => {
    const backupDir = await makeValidBackup();
    fs.unlinkSync(path.join(backupDir, 'manifest.json'));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'MANIFEST_MISSING' });
  });

  test('corrupted (invalid JSON) manifest is detected', async () => {
    const backupDir = await makeValidBackup();
    fs.writeFileSync(path.join(backupDir, 'manifest.json'), '{ not valid json ');

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'MANIFEST_CORRUPT' });
  });

  test('tampered manifest (checksum mismatch) is detected', async () => {
    const backupDir = await makeValidBackup();
    const manifestPath = path.join(backupDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.appVersion = '999.999.999'; // tamper without recomputing manifestChecksum
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'MANIFEST_CHECKSUM_MISMATCH' });
  });

  test('missing archive file for a present component is detected', async () => {
    const backupDir = await makeValidBackup();
    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, 'manifest.json'), 'utf8'));
    const auditComp = manifest.components.find(c => c.name === 'auditLog');
    fs.unlinkSync(path.join(backupDir, auditComp.archiveFile));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'ARCHIVE_FILE_MISSING' });
  });

  test('corrupted archive (checksum mismatch) is detected — single flipped byte', async () => {
    const backupDir = await makeValidBackup();
    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, 'manifest.json'), 'utf8'));
    const auditComp = manifest.components.find(c => c.name === 'auditLog');
    const archivePath = path.join(backupDir, auditComp.archiveFile);
    const buf = fs.readFileSync(archivePath);
    buf[0] = buf[0] ^ 0xFF; // flip a byte — simulates bit rot / truncated transfer
    fs.writeFileSync(archivePath, buf);

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
  });

  test('truncated archive (size mismatch) is detected — simulates interrupted backup', async () => {
    const backupDir = await makeValidBackup();
    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, 'manifest.json'), 'utf8'));
    const auditComp = manifest.components.find(c => c.name === 'auditLog');
    const archivePath = path.join(backupDir, auditComp.archiveFile);
    const buf = fs.readFileSync(archivePath);
    fs.writeFileSync(archivePath, buf.subarray(0, Math.floor(buf.length / 2)));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
  });

  test('missing REQUIRED component fails restore even if everything else is intact', async () => {
    const backupDir = await makeValidBackup();
    const manifestPath = path.join(backupDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const keyComp = manifest.components.find(c => c.name === 'keyStore');
    fs.unlinkSync(path.join(backupDir, keyComp.archiveFile));
    keyComp.present = false;
    delete keyComp.archiveFile;
    delete keyComp.sha256;
    // Recompute the manifest checksum honestly (simulating "manifest correctly
    // describes a backup that was missing this file to begin with").
    const { computeManifestChecksum } = require('../scripts/dr/manifest');
    const { manifestChecksum, ...rest } = manifest;
    manifest.manifestChecksum = computeManifestChecksum(rest);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'REQUIRED_COMPONENT_MISSING' });
  });

  test('nonexistent backup directory is detected', async () => {
    await expect(runRestore({ backupDir: path.join(os.tmpdir(), 'qodiqa-dr-does-not-exist'), targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'BACKUP_DIR_MISSING' });
  });

  test('restoring into a non-empty target directory is refused (never overwrite a live instance)', async () => {
    const backupDir = await makeValidBackup();
    const restoreTarget = tmpDir('qodiqa-dr-r-');
    fs.writeFileSync(path.join(restoreTarget, 'some-existing-file.txt'), 'live data — do not clobber');

    await expect(runRestore({ backupDir, targetRoot: restoreTarget }))
      .rejects.toMatchObject({ code: 'TARGET_NOT_CLEAN' });

    // The pre-existing file must be untouched.
    expect(fs.readFileSync(path.join(restoreTarget, 'some-existing-file.txt'), 'utf8'))
      .toBe('live data — do not clobber');
  });

  test('allowExisting:true permits restoring into a non-empty target when explicitly requested', async () => {
    const backupDir = await makeValidBackup();
    const restoreTarget = tmpDir('qodiqa-dr-r-');
    fs.writeFileSync(path.join(restoreTarget, 'unrelated.txt'), 'ok to coexist');

    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget, allowExisting: true });
    expect(restored.length).toBeGreaterThan(0);
  });

  test('validation phase writes NOTHING to the target when it fails (all-or-nothing)', async () => {
    const backupDir = await makeValidBackup();
    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, 'manifest.json'), 'utf8'));
    const auditComp = manifest.components.find(c => c.name === 'auditLog');
    const archivePath = path.join(backupDir, auditComp.archiveFile);
    const buf = fs.readFileSync(archivePath);
    buf[0] = buf[0] ^ 0xFF;
    fs.writeFileSync(archivePath, buf);

    const restoreTarget = path.join(tmpDir('qodiqa-dr-r-'), 'clean');
    await expect(runRestore({ backupDir, targetRoot: restoreTarget })).rejects.toThrow(RestoreError);

    // Nothing was written — the failure was caught (restoreComponents).
    expect(fs.existsSync(restoreTarget)).toBe(false);
  });

  test('restore refuses to report success when the restored audit chain itself fails integrity verification, even though every checksum matches', async () => {
    // Distinct from the "corrupted archive" tests above: here the SOURCE
    // audit log is tampered BEFORE backup runs, so the backup's own checksum
    // is computed over the already-broken chain and matches perfectly at
    // restore time — (manifest/checksum validation) and
    // (file copy) both succeed. Only the mandatory audit-chain
    // integrity gate can catch
    // this: a byte-perfect restore of an already-inconsistent snapshot must
    // never be reported as a successful restore.
    const env = makeSourceEnv();
    await populateSource(env);

    const lines = fs.readFileSync(env.QODIQA_AUDIT_LOG, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[1]);
    tampered.decision = tampered.decision === 'ALLOW' ? 'BLOCK' : 'ALLOW';
    lines[1] = JSON.stringify(tampered);
    fs.writeFileSync(env.QODIQA_AUDIT_LOG, lines.join('\n') + '\n');

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));

    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    await expect(runRestore({ backupDir, targetRoot: restoreTarget }))
      .rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
  });

  test('malformed manifest.components (not an array) is detected', async () => {
    const backupDir = await makeValidBackup();
    const manifestPath = path.join(backupDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.components = 'not-an-array';
    const { computeManifestChecksum } = require('../scripts/dr/manifest');
    const { manifestChecksum, ...rest } = manifest;
    manifest.manifestChecksum = computeManifestChecksum(rest);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    await expect(runRestore({ backupDir, targetRoot: path.join(tmpDir('qodiqa-dr-r-'), 'x') }))
      .rejects.toMatchObject({ code: 'MANIFEST_MALFORMED' });
  });
});

// ── 4. Post-restore integrity: tampering must be caught by the real modules ───

describe('Backup -> Restore — restored-content tamper detection', () => {
  test('a hash-chain break introduced into the restored audit log is caught by validateChainIntegrity', async () => {
    const env = makeSourceEnv();
    await populateSource(env);
    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));

    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget });

    // Simulate an operator manually editing the restored NDJSON file after a
    // restore (not through backup.js/restore.js — a direct file edit).
    const auditPath = restored.find(r => r.name === 'auditLog').destPath;
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[1]);
    tampered.decision = tampered.decision === 'ALLOW' ? 'BLOCK' : 'ALLOW';
    lines[1] = JSON.stringify(tampered);
    fs.writeFileSync(auditPath, lines.join('\n') + '\n');

    const result = await validateRestoredState(restored);
    expect(result.auditChain.valid).toBe(false);
    expect(result.auditChain.tamperingDetected).toBe(true);
    expect(result.overallValid).toBe(false);
  });
});

// ── 5. KEK recovery drill must actually prove cryptographic recovery ────

describe('KEK recovery drill detects intentionally broken recovery', () => {
  test('recovering the WRONG KEK is detected as invalid, not silently accepted', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));
    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget });

    // Simulate an operator recovering the WRONG out-of-band KEK during a
    // real DR drill — a different (but well-formed) 256-bit hex key than the
    // one that actually encrypted this key store. keyStore.js is fail-closed
    // on decrypt failure (a wrong KEK fails AES-256-GCM auth-tag
    // verification), so this must never report a successful drill.
    const wrongKek = 'a'.repeat(64) === process.env.QODIQA_KEY_ENCRYPTION_KEY
      ? 'b'.repeat(64)
      : 'a'.repeat(64);

    const result = await withEnv({ QODIQA_KEY_ENCRYPTION_KEY: wrongKek }, () => validateRestoredState(restored));

    expect(result.keyStore.valid).toBe(false);
    expect(result.overallValid).toBe(false);
  });

  test('QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true fails closed when no KEK was recovered at all', async () => {
    const env = makeSourceEnv();
    await populateSource(env);

    const backupOut = tmpDir('qodiqa-dr-backup-');
    const { targetDir: backupDir } = await withEnv(env, () => runBackup({ outDir: backupOut }));
    const restoreTarget = path.join(tmpDir('qodiqa-dr-restore-'), 'restored');
    const { restored } = await runRestore({ backupDir, targetRoot: restoreTarget });

    // keyStore.js's own structural load is already fail-closed for a
    // populated store without a KEK (it cannot even decrypt to check
    // invariants) — QODIQA_DR_REQUIRE_KEK_ROUNDTRIP's explicit
    // KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT reason exists for the case where
    // it wouldn't be (an empty/no-active-keys store — see the next test).
    // Either way, the drill must never report success.
    const prevKek = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    let result;
    try {
      result = await withEnv({ QODIQA_DR_REQUIRE_KEK_ROUNDTRIP: 'true' }, () => validateRestoredState(restored));
    } finally {
      process.env.QODIQA_KEY_ENCRYPTION_KEY = prevKek;
    }

    expect(result.keyStore.valid).toBe(false);
    expect(result.overallValid).toBe(false);
  });

  test('QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true fails closed even for an empty key store where structural validation alone would otherwise pass', async () => {
    // An empty/never-rotated key store is the one case where
    // keyStore.validateKeyStore() succeeds without ever needing the KEK
    // (there is no encrypted key material to decrypt yet) — exactly the
    // scenario the explicit KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT check in
    // keyStoreProbe.js exists for, since the pre-existing fail-closed
    // decrypt path (previous test) never even gets triggered here.
    const scratch = tmpDir('qodiqa-dr-empty-keystore-');
    const keysPath = path.join(scratch, 'keys.json');
    fs.writeFileSync(keysPath, JSON.stringify({ version: 1, clients: {} }), 'utf8');

    const prevKek = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    let result;
    try {
      result = await withEnv({ QODIQA_DR_REQUIRE_KEK_ROUNDTRIP: 'true' }, () =>
        validateRestoredState([{ name: 'keyStore', destPath: keysPath }]));
    } finally {
      process.env.QODIQA_KEY_ENCRYPTION_KEY = prevKek;
    }

    expect(result.keyStore.reason).toBe('KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT');
    expect(result.keyStore.valid).toBe(false);
    expect(result.overallValid).toBe(false);
  });
});
