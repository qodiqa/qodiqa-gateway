'use strict';

/**
 * KEK-fingerprint guard rail — tracked finding from the 2026-07-30
 * "Dev KeyStore startup failure" session (Step 4): a silent
 * QODIQA_KEY_ENCRYPTION_KEY edit orphaned 16 signing keys across two trust
 * domains (services/artifact/keyStore.js and
 * src/core/transparency/transparencyKeyStore.js) with no warning until the
 * next decrypt attempt — surfacing days later as a generic GCM auth-tag
 * failure, forcing manual forensic reconstruction across files and
 * timestamps to even diagnose.
 *
 * This suite covers the guard for the artifact key store and the shared
 * primitives in keyEncryption.js. See
 * src/core/transparency/__tests__/transparencyKeyStore.kekFingerprint.test.js
 * for the independent transparency-store coverage.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-kek-fp-'));
  return path.join(dir, 'keys.json');
}

const KEK_A = 'a'.repeat(64);
const KEK_B = 'b'.repeat(64);

function loadFreshKeyStore(keysPath, kek) {
  jest.resetModules();
  if (kek !== undefined) {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
  } else {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
  }
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../secrets/secretsProvider')._clearCache();
  return require('./keyStore');
}

// ── keyEncryption.js primitives ────────────────────────────────────────────

describe('keyEncryption — computeKekFingerprint / assertKekFingerprint', () => {
  function loadFreshKeyEncryption(kek) {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
    require('../secrets/secretsProvider')._clearCache();
    return require('./keyEncryption');
  }

  test('is deterministic for the same KEK', () => {
    const ke = loadFreshKeyEncryption(KEK_A);
    expect(ke.computeKekFingerprint()).toBe(ke.computeKekFingerprint());
  });

  test('differs across different KEKs', () => {
    const keA = loadFreshKeyEncryption(KEK_A);
    const fpA = keA.computeKekFingerprint();
    const keB = loadFreshKeyEncryption(KEK_B);
    const fpB = keB.computeKekFingerprint();
    expect(fpA).not.toBe(fpB);
  });

  test('never reproduces the KEK itself (not merely re-encoded)', () => {
    const ke = loadFreshKeyEncryption(KEK_A);
    const fp = ke.computeKekFingerprint();
    expect(fp).not.toBe(KEK_A);
    expect(fp.toLowerCase()).not.toContain(KEK_A.toLowerCase());
  });

  test('assertKekFingerprint is a no-op when no fingerprint is stored (predates the guard)', () => {
    const ke = loadFreshKeyEncryption(KEK_A);
    expect(() => ke.assertKekFingerprint(null, '/some/path.json')).not.toThrow();
    expect(() => ke.assertKekFingerprint(undefined, '/some/path.json')).not.toThrow();
    expect(() => ke.assertKekFingerprint('', '/some/path.json')).not.toThrow();
  });

  test('assertKekFingerprint is a no-op when the stored fingerprint matches the current KEK', () => {
    const ke = loadFreshKeyEncryption(KEK_A);
    const fp = ke.computeKekFingerprint();
    expect(() => ke.assertKekFingerprint(fp, '/some/path.json')).not.toThrow();
  });

  test('assertKekFingerprint throws a specific KEK_FINGERPRINT_MISMATCH error when the KEK changed', () => {
    const keA = loadFreshKeyEncryption(KEK_A);
    const fpUnderA = keA.computeKekFingerprint();

    const keB = loadFreshKeyEncryption(KEK_B);
    expect(() => keB.assertKekFingerprint(fpUnderA, '/some/path.json')).toThrow(/KEK_FINGERPRINT_MISMATCH/);
  });
});

// ── services/artifact/keyStore.js integration ──────────────────────────────

describe('keyStore — KEK-fingerprint guard rail', () => {
  test('saveKeys() writes a kekFingerprint matching the active KEK', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath, KEK_A);
    ks.rotateKey('kek-fp-write');

    const onDisk = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const { computeKekFingerprint } = require('./keyEncryption');
    expect(onDisk.kekFingerprint).toBe(computeKekFingerprint());
  });

  test('loading the same file under the SAME KEK succeeds', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath, KEK_A);
    ks1.rotateKey('kek-fp-match');

    const ks2 = loadFreshKeyStore(keysPath, KEK_A);
    expect(() => ks2.getActiveKey('kek-fp-match')).not.toThrow();
  });

  test('loading the same file under a DIFFERENT KEK fails BEFORE any decrypt attempt, with a specific error', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath, KEK_A);
    ks1.rotateKey('kek-fp-mismatch');

    const ks2 = loadFreshKeyStore(keysPath, KEK_B);
    expect(() => ks2.getActiveKey('kek-fp-mismatch')).toThrow(/KEK_FINGERPRINT_MISMATCH/);
    // Must NOT be the generic decrypt failure this guard replaces.
    expect(() => ks2.getActiveKey('kek-fp-mismatch')).not.toThrow(/Unsupported state|unable to authenticate/);
  });

  test('a legacy file with no kekFingerprint (predates the guard) still loads normally under its real KEK', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath, KEK_A);
    ks1.rotateKey('kek-fp-legacy');

    // Simulate a pre-guard file by stripping the field a real save would set.
    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    delete raw.kekFingerprint;
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    const ks2 = loadFreshKeyStore(keysPath, KEK_A);
    expect(() => ks2.getActiveKey('kek-fp-legacy')).not.toThrow();
  });

  test('a legacy file with no kekFingerprint is backfilled with one on load, protecting the NEXT KEK change', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath, KEK_A);
    ks1.rotateKey('kek-fp-backfill');

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    delete raw.kekFingerprint;
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');
    expect(JSON.parse(fs.readFileSync(keysPath, 'utf8')).kekFingerprint).toBeUndefined();

    const ks2 = loadFreshKeyStore(keysPath, KEK_A);
    ks2.getActiveKey('kek-fp-backfill'); // triggers lazy bootstrap + backfill save

    const { computeKekFingerprint } = require('./keyEncryption');
    const after = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    expect(after.kekFingerprint).toBe(computeKekFingerprint());

    // And the backfilled file now correctly detects a subsequent KEK change.
    const ks3 = loadFreshKeyStore(keysPath, KEK_B);
    expect(() => ks3.getActiveKey('kek-fp-backfill')).toThrow(/KEK_FINGERPRINT_MISMATCH/);
  });

  // D10 (FINDINGS-GROUP-A): an EMPTY store (no clients yet) has nothing to
  // backfill -- unlike the "legacy file with no kekFingerprint" tests above,
  // which all start from a store that already has a client, this pins the
  // empty-store edge case directly at the keyStore.js level (not via the
  // spawned DR-probe child process backupRestore.test.js exercises for the
  // same scenario) -- an empty store must not attempt the KEK-requiring
  // backfill save, even when no KEK is configured at all.
  test('an EMPTY store (no clients) with no kekFingerprint does NOT attempt a backfill save, even with the KEK absent', () => {
    const keysPath = makeTempPath();
    fs.writeFileSync(keysPath, JSON.stringify({ version: 1, clients: {} }), 'utf8');

    const ks = loadFreshKeyStore(keysPath); // no KEK argument -> QODIQA_KEY_ENCRYPTION_KEY deleted

    // Must not throw -- a backfill save would require the (absent) KEK, but
    // an empty store has no key material for a fingerprint to ever protect.
    expect(() => ks.validateKeyStore()).not.toThrow();

    // The file on disk must be untouched -- confirms no backfill write was
    // attempted at all (a real backfill would add a kekFingerprint field).
    const onDisk = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    expect(onDisk.kekFingerprint).toBeUndefined();
    expect(onDisk.clients).toEqual({});
  });
});
