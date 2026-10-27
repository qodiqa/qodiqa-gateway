'use strict';

/**
 * keystore half of the fenced rotation protocol (services/artifact/keyStore.js).
 * The rotation lock (src/infra/keys/rotationLock.js) hands out a strictly increasing fence; the keystore accepts a
 * rotation commit only when its fence is greater than the last one it recorded for that client, and records the new
 * fence in the SAME keys.json write as the mutation.
 *
 * a newer fence commits and is persisted (rotationFences in keys.json)
 * a stale fence (equal or lower) is refused with KEYSTORE_STALE_FENCE and the file is unchanged
 * the recorded fence survives a reload: another instance sharing keys.json refuses the stale holder too
 *          (the multi-process case — a paused rotator resuming after its lock was taken over)
 * no fence (callers outside the lock protocol, bootstrap) behaves exactly as before
 * keyAdmin maps KEYSTORE_STALE_FENCE / KEY_ROTATION_LOCK_LOST to the existing 409 ROTATION_IN_PROGRESS path
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const tmpKeys = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-fence-ks-')), 'keys.json');
function loadInstance(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../secrets/secretsProvider')._clearCache();
  return require('../keyStore');
}
const fences = (p) => JSON.parse(fs.readFileSync(p, 'utf8')).rotationFences;

test('newer fence commits and is persisted; a stale fence is refused and changes nothing', () => {
  const p = tmpKeys(); const ks = loadInstance(p);
  ks.rotateKey('fc', { fence: 5 });                                   // provisioning under a fence
  expect(fences(p)).toEqual({ fc: 5 });
  ks.rotateKey('fc', { mode: 'emergency', fence: 7 });
  expect(fences(p)).toEqual({ fc: 7 });
  const before = fs.readFileSync(p, 'utf8');
  expect(() => ks.rotateKey('fc', { mode: 'emergency', fence: 7 })).toThrow(expect.objectContaining({ code: 'KEYSTORE_STALE_FENCE' }));
  expect(() => ks.rotateKey('fc', { mode: 'emergency', fence: 6 })).toThrow(expect.objectContaining({ code: 'KEYSTORE_STALE_FENCE' }));
  expect(fs.readFileSync(p, 'utf8')).toBe(before);
  expect(ks.getActiveKey('fc').keyId).toBe('fc:key_v2');
});

test('a second instance (paused rotator) is refused after the file recorded a newer fence', () => {
  const p = tmpKeys();
  const stale = loadInstance(p); stale.rotateKey('fc', { fence: 1 });   // instance A, holder of fence 2 later pauses
  const fresh = loadInstance(p); fresh.rotateKey('fc', { mode: 'emergency', fence: 3 }); // B took the lock over
  // A resumes with its old fence 2
  const a = loadInstance(p);
  expect(() => a.rotateKey('fc', { mode: 'emergency', fence: 2 })).toThrow(expect.objectContaining({ code: 'KEYSTORE_STALE_FENCE' }));
  expect(loadInstance(p).getActiveKey('fc').keyId).toBe('fc:key_v2');   // exactly B's generation, no overwrite
});

test('no fence: unchanged behaviour, nothing recorded', () => {
  const p = tmpKeys(); const ks = loadInstance(p);
  ks.rotateKey('nf'); ks.rotateKey('nf', { mode: 'emergency' });
  expect(fences(p)).toBeUndefined();
  expect(ks.getActiveKey('nf').keyId).toBe('nf:key_v2');
});

test('keyAdmin maps a stale fence to 409 ROTATION_IN_PROGRESS (source contract)', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'src', 'api', 'routes', 'keyAdmin.js'), 'utf8');
  expect(src).toMatch(/err\.code === 'KEYSTORE_STALE_FENCE' \|\| err\.code === 'KEY_ROTATION_LOCK_LOST'/);
  expect(src).toMatch(/return await fn\(\{ fence: lockResult\.fence \}\)/);
  expect((src.match(/fence:\s+lock\.fence/g) || []).length).toBe(3);   // rotate, rotate-graceful, recover
});
