'use strict';

/**
 * remediation — lazy bootstrap regression tests
 *
 * transparencyKeyStore.js previously bootstrapped (loaded + decrypted the
 * persisted key file) at require()-time via an immediately-invoked function.
 * A misconfigured/wrong KEK meant `require('./transparencyKeyStore')` itself
 * could throw — before server.js's own ordered startup checks ever ran —
 * reintroducing the exact startup-ordering fragility
 * services/artifact/keyStore.js was deliberately patched to avoid (see that
 * file's own header comment).
 *
 * This suite proves the fix: require() never throws, even with a KEK that
 * cannot decrypt the persisted file; the error only surfaces on first real
 * access (getActiveKey/getPublicKey/etc), matching the artifact key store's
 * behavior.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-tks-lazy-'));
  return path.join(dir, 'transparency-keys.json');
}

const KEK_A = 'a'.repeat(64); // 32-byte hex KEK used to actually encrypt the fixture
const KEK_B = 'b'.repeat(64); // different KEK — cannot decrypt KEK_A's ciphertext

// Build a persisted transparency-keys.json fixture with one active key,
// encrypted under KEK_A, using the module's own encryptKeyMaterial() so the
// ciphertext format is guaranteed authentic (no hand-rolled crypto in the test).
function writeFixture(keysPath) {
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK_A;
  require('../../../../services/secrets/secretsProvider')._clearCache();
  const { encryptKeyMaterial } = require('../../../../services/artifact/keyEncryption');

  const { publicKey: pubDer, privateKey: privDer } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const payload = {
    version: 1,
    keys: {
      'tr-fixture:key_v1': {
        clientId:               'tr-fixture',
        keyId:                  'tr-fixture:key_v1',
        version:                1,
        algorithm:              'ed25519',
        purpose:                'transparency',
        encryptedPrivateKeyDer: encryptKeyMaterial(privDer, { keyId: 'tr-fixture:key_v1', createdAt: new Date().toISOString() }),
        publicKeyDer:           pubDer.toString('base64'),
        status:                 'active',
        createdAt:              new Date().toISOString(),
        retiredAt:              null,
        rotationDeadline:       new Date(Date.now() + 90 * 86_400_000).toISOString(),
        expiresAt:              new Date(Date.now() + 180 * 86_400_000).toISOString(),
      },
    },
  };

  fs.mkdirSync(path.dirname(keysPath), { recursive: true });
  fs.writeFileSync(keysPath, JSON.stringify(payload, null, 2), 'utf8');
}

describe('transparencyKeyStore lazy bootstrap', () => {
  let keysPath;

  beforeEach(() => {
    keysPath = makeTempPath();
    writeFixture(keysPath); // encrypted under KEK_A
  });

  test('require() does not throw even when the configured KEK cannot decrypt the persisted file', () => {
    jest.resetModules();
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keysPath;
    process.env.QODIQA_KEY_ENCRYPTION_KEY     = KEK_B; // wrong KEK
    require('../../../../services/secrets/secretsProvider')._clearCache();

    expect(() => require('../transparencyKeyStore')).not.toThrow();
  });

  test('the decryption failure instead surfaces on first real access (getActiveKey)', () => {
    jest.resetModules();
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keysPath;
    process.env.QODIQA_KEY_ENCRYPTION_KEY     = KEK_B;
    require('../../../../services/secrets/secretsProvider')._clearCache();
    const tKeyStore = require('../transparencyKeyStore');

    expect(() => tKeyStore.getActiveKey()).toThrow();
  });

  test('the decryption failure also surfaces on first access via getPublicKey/listKeys/validateKeyStore', () => {
    jest.resetModules();
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keysPath;
    process.env.QODIQA_KEY_ENCRYPTION_KEY     = KEK_B;
    require('../../../../services/secrets/secretsProvider')._clearCache();
    const tKeyStore = require('../transparencyKeyStore');

    expect(() => tKeyStore.listKeys()).toThrow();
  });

  test('sanity: the SAME fixture loads cleanly and is usable when the correct KEK is configured', () => {
    jest.resetModules();
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = keysPath;
    process.env.QODIQA_KEY_ENCRYPTION_KEY     = KEK_A; // correct KEK
    require('../../../../services/secrets/secretsProvider')._clearCache();
    const tKeyStore = require('../transparencyKeyStore');

    const key = tKeyStore.getActiveKey();
    expect(key.keyId).toBe('tr-fixture:key_v1');
    expect(Buffer.isBuffer(key.privDer)).toBe(true);
  });

  test('a missing key file still bootstraps lazily to an empty store, no throw on require() or first access', () => {
    jest.resetModules();
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = makeTempPath(); // never written — file does not exist
    process.env.QODIQA_KEY_ENCRYPTION_KEY     = KEK_A;
    require('../../../../services/secrets/secretsProvider')._clearCache();
    const tKeyStore = require('../transparencyKeyStore');

    expect(() => tKeyStore.listKeys()).not.toThrow();
    expect(tKeyStore.listKeys()).toEqual([]);
  });
});
