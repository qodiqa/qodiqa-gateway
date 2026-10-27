'use strict';

/**
 * phase 6 — MAC keyring KEK-fingerprint guard, boot-time decryptability, single-KEK rotation
 *.
 *
 *   PL-K13-01  a new keyring records the KEK fingerprint; under another KEK it fails MAC_KEYRING_KEK_MISMATCH
 *              before any decrypt
 *   PL-K13-02  assertUsable() (the server/startup.js production boot check) passes on a good keyring, returns no key
 *              material, and throws on a corrupt keyring and — in production — on a missing one
 *   PL-K13-03  a keyring written before the guard (no fingerprint) still loads under the right KEK and is refused
 *              under a wrong one
 *   PL-K13-04  rotate() after an in-process KEK change re-encrypts every non-retired key under the CURRENT KEK
 *              (no mixed-KEK document); the previous key still verifies
 *   PL-K13-05  rotate() refuses — and writes nothing — when a key can be neither decrypted nor taken from memory
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const KEK_A = 'a1'.repeat(32);
const KEK_B = 'b2'.repeat(32);
let dir;
let ringPath;

function load(kek) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
  process.env.QODIQA_MAC_KEYS_PATH = ringPath;
  require('../../../../services/secrets/secretsProvider')._clearCache();
  return require('../macKeyring');
}
const read = () => JSON.parse(fs.readFileSync(ringPath, 'utf8'));

const ORIG = { MAC: process.env.QODIQA_MAC_KEYS_PATH, NODE_ENV: process.env.NODE_ENV, KEK: process.env.QODIQA_KEY_ENCRYPTION_KEY };
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-mackeyring-'));
  ringPath = path.join(dir, 'mac-keys.json');
});
afterEach(() => {
  for (const [k, v] of [['QODIQA_MAC_KEYS_PATH', ORIG.MAC], ['NODE_ENV', ORIG.NODE_ENV], ['QODIQA_KEY_ENCRYPTION_KEY', ORIG.KEK]]) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('PL-K13-01 the keyring records the KEK fingerprint and refuses another KEK before decrypting', () => {
  load(KEK_A).init();
  expect(read().kekFingerprint).toMatch(/^[0-9a-f]{64}$/);
  const ring = load(KEK_B);
  let err;
  try { ring.assertUsable(); } catch (e) { err = e; }
  expect(err).toBeDefined();
  expect(err.code).toBe('MAC_KEYRING_KEK_MISMATCH');
  expect(err.message).toMatch(/KEK_FINGERPRINT_MISMATCH/);
  expect(() => ring.sign(ring.PURPOSES.REVOCATION, 'x')).toThrow(/KEK_FINGERPRINT_MISMATCH/);
});

test('PL-K13-02 assertUsable(): good keyring passes with public status only; corrupt or (production) missing keyring throws', () => {
  const ring = load(KEK_A);
  ring.init();
  const st = ring.assertUsable();
  expect(st).toEqual({ path: ringPath, activeKid: expect.stringMatching(/^mk_/), verifiableKids: [st.activeKid], kekFingerprintChecked: true });
  expect(JSON.stringify(st)).not.toMatch(/enc|key"/i);

  const doc = read();
  const ct = Buffer.from(doc.keys[0].enc.encryptedPrivateKey, 'base64');
  ct[0] ^= 0xff;
  doc.keys[0].enc.encryptedPrivateKey = ct.toString('base64');
  fs.writeFileSync(ringPath, JSON.stringify(doc));
  expect(() => load(KEK_A).assertUsable()).toThrow();

  fs.rmSync(ringPath);
  process.env.NODE_ENV = 'production';
  let err;
  try { load(KEK_A).assertUsable(); } catch (e) { err = e; }
  expect(err && err.code).toBe('MAC_KEYRING_MISSING');
  expect(fs.existsSync(ringPath)).toBe(false);
});

test('PL-K13-03 a pre-guard keyring (no fingerprint) loads under the right KEK and is refused under a wrong one', () => {
  load(KEK_A).init();
  const doc = read();
  delete doc.kekFingerprint;
  fs.writeFileSync(ringPath, JSON.stringify(doc));
  expect(load(KEK_A).assertUsable().kekFingerprintChecked).toBe(false);
  expect(() => load(KEK_B).assertUsable()).toThrow();
});

test('PL-K13-04 rotate() after an in-process KEK change leaves every non-retired key decryptable under the new KEK', () => {
  const ring = load(KEK_A);
  ring.init();
  const oldTag = ring.sign(ring.PURPOSES.REVOCATION, 'm');
  // the KEK changes in-process (keyProviderFactory.wireIntoSecretsProvider after a KMS rotation)
  require('../../../../services/secrets/secretsProvider')._setExternalKek(Buffer.from(KEK_B, 'hex'));
  ring.rotate({ by: 'test' });
  // a fresh process under the NEW KEK decrypts the whole document — active AND previous
  const fresh = load(KEK_B);
  const st = fresh.assertUsable();
  expect(st.verifiableKids).toHaveLength(2);
  expect(fresh.verify(fresh.PURPOSES.REVOCATION, 'm', oldTag).ok).toBe(true);
  expect(read().kekFingerprint).not.toBe(undefined);
  expect(() => load(KEK_A).assertUsable()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
});

test('PL-K13-05 rotate() refuses and writes nothing when a key is neither decryptable nor held in memory', () => {
  const ring = load(KEK_A);
  ring.init();
  ring.status(); // this process has loaded (and holds) the keyring
  // another writer adds a key this process cannot decrypt (e.g. written under a different KEK)
  const d = read();
  d.keys.push({ kid: 'mk_20260101_deadbeef', status: 'previous', createdAt: new Date().toISOString(), enc: {
    keyId: 'mk_20260101_deadbeef', algorithm: 'aes-256-gcm', encryptedPrivateKey: require('crypto').randomBytes(32).toString('base64'),
    iv: require('crypto').randomBytes(12).toString('base64'), authTag: require('crypto').randomBytes(16).toString('base64'),
  } });
  fs.writeFileSync(ringPath, JSON.stringify(d, null, 2));
  const snapshot = fs.readFileSync(ringPath, 'utf8');
  let err;
  try { ring.rotate({ by: 'test' }); } catch (e) { err = e; }
  expect(err && err.code).toBe('MAC_KEYRING_REENCRYPT_FAILED');
  expect(fs.readFileSync(ringPath, 'utf8')).toBe(snapshot);
});

