'use strict';

/**
 * KEK-fingerprint guard rail — transparency-store coverage.
 *
 * See services/artifact/kekFingerprint.test.js for the full rationale (the
 * 2026-07-30 "Dev KeyStore startup failure" session, Step 4) and the
 * artifact-store equivalent of these tests. This suite proves the same
 * guard behaves identically in the independent transparency trust domain
 * (src/core/transparency/transparencyKeyStore.js), which shares the same
 * KEK as the artifact store but a completely separate key file.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-tks-kek-fp-'));
  return path.join(dir, 'transparency-keys.json');
}

const KEK_A = 'a'.repeat(64);
const KEK_B = 'b'.repeat(64);

function loadFreshTransparencyKeyStore(keysPath, kek) {
  jest.resetModules();
  process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keysPath;
  process.env.QODIQA_KEY_ENCRYPTION_KEY     = kek;
  require('../../../../services/secrets/secretsProvider')._clearCache();
  return require('../transparencyKeyStore');
}

describe('transparencyKeyStore — KEK-fingerprint guard rail', () => {
  test('rotateKey() (provisioning) writes a kekFingerprint matching the active KEK', () => {
    const keysPath = makeTempPath();
    const tks = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks.rotateKey();

    const onDisk = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const { computeKekFingerprint } = require('../../../../services/artifact/keyEncryption');
    expect(onDisk.kekFingerprint).toBe(computeKekFingerprint());
  });

  test('loading the same file under the SAME KEK succeeds', () => {
    const keysPath = makeTempPath();
    const tks1 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks1.rotateKey();

    const tks2 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    expect(() => tks2.getActiveKey()).not.toThrow();
  });

  test('loading the same file under a DIFFERENT KEK fails BEFORE any decrypt attempt, with a specific error', () => {
    const keysPath = makeTempPath();
    const tks1 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks1.rotateKey();

    const tks2 = loadFreshTransparencyKeyStore(keysPath, KEK_B);
    expect(() => tks2.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
  });

  test('a legacy file with no kekFingerprint (predates the guard) still loads normally under its real KEK', () => {
    const keysPath = makeTempPath();
    const tks1 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks1.rotateKey();

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    delete raw.kekFingerprint;
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    const tks2 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    expect(() => tks2.getActiveKey()).not.toThrow();
  });

  test('a legacy file with no kekFingerprint is backfilled with one on load, protecting the NEXT KEK change', () => {
    const keysPath = makeTempPath();
    const tks1 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks1.rotateKey();

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    delete raw.kekFingerprint;
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');
    expect(JSON.parse(fs.readFileSync(keysPath, 'utf8')).kekFingerprint).toBeUndefined();

    const tks2 = loadFreshTransparencyKeyStore(keysPath, KEK_A);
    tks2.getActiveKey(); // triggers lazy bootstrap + backfill save

    const { computeKekFingerprint } = require('../../../../services/artifact/keyEncryption');
    const after = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    expect(after.kekFingerprint).toBe(computeKekFingerprint());

    const tks3 = loadFreshTransparencyKeyStore(keysPath, KEK_B);
    expect(() => tks3.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
  });
});
