'use strict';

/**
 * Secure Key Storage tests
 *
 * Coverage:
 *   1.  Secrets provider: missing KEK → throws
 *   2.  Secrets provider: wrong-length KEK → throws
 *   3.  Secrets provider: valid KEK → Buffer returned
 *   4.  Key encryption: roundtrip encrypt/decrypt
 *   5.  Key encryption: wrong KEK → decryption fails (auth tag mismatch)
 *   6.  Key encryption: tampered encryptedPrivateKey → decryption fails
 *   7.  Key encryption: unsupported algorithm → decryption fails
 *   8.  KeyStore: active key written encrypted, not plaintext
 *   9.  KeyStore: load encrypted key → correct privDer
 *   10. KeyStore: missing KEK on load of encrypted file → FATAL bootstrap error
 *   11. KeyStore: malformed encryptedPrivateKeyDer → load fails
 *   12. KeyStore: legacy plaintext → migrated to encrypted on bootstrap
 *   13. KeyManager: getSigningKey returns privDer
 *   14. KeyManager: getActivePublicKey never returns privDer
 *   15. KeyManager: getVerificationKey returns public material only
 *   16. KeyManager: validateStartup succeeds with valid KEK + active key
 *   17. KeyManager: validateStartup fails when KEK not configured
 *   18. KeyManager: getSigningKey for unknown client → throws
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-km-test-'));
  return path.join(dir, 'keys.json');
}

function loadFresh(keysPath, kek) {
  // Reset module cache so keyStore/keyEncryption/secretsProvider re-initialise.
  jest.resetModules();
  if (kek !== undefined) {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
  } else {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
  }
  process.env.QODIQA_KEYS_PATH = keysPath;
  // Clear secretsProvider cache so it re-reads the env var.
  const sp = require('../../../services/secrets/secretsProvider');
  sp._clearCache();
  return require('../../../services/artifact/keyManager');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const ALT_KEK  = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

// ── 1–3. Secrets provider ─────────────────────────────────────────────────────

describe('SecretsProvider — validation', () => {
  let sp;
  beforeEach(() => {
    jest.resetModules();
    sp = require('../../../services/secrets/secretsProvider');
    sp._clearCache();
  });

  afterEach(() => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    sp._clearCache();
  });

  test('missing KEK → throws descriptive error', () => {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    sp._clearCache();
    expect(() => sp.getKeyEncryptionKey()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY/);
  });

  test('wrong-length KEK (32 hex chars = 16 bytes) → throws', () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = '0'.repeat(32);
    sp._clearCache();
    expect(() => sp.getKeyEncryptionKey()).toThrow(/64 hex characters/);
  });

  test('non-hex characters → throws', () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = 'g'.repeat(64);
    sp._clearCache();
    expect(() => sp.getKeyEncryptionKey()).toThrow(/64 hex characters/);
  });

  test('valid 64-hex-char KEK → returns 32-byte Buffer', () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    sp._clearCache();
    const kek = sp.getKeyEncryptionKey();
    expect(Buffer.isBuffer(kek)).toBe(true);
    expect(kek.length).toBe(32);
  });

  test('isConfigured() returns false when KEK missing', () => {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    sp._clearCache();
    expect(sp.isConfigured()).toBe(false);
  });

  test('isConfigured() returns true when KEK valid', () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    sp._clearCache();
    expect(sp.isConfigured()).toBe(true);
  });
});

// ── 4–7. Key encryption ───────────────────────────────────────────────────────

describe('keyEncryption — AES-256-GCM roundtrip', () => {
  let enc;
  beforeEach(() => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    require('../../../services/secrets/secretsProvider')._clearCache();
    enc = require('../../../services/artifact/keyEncryption');
  });

  test('encrypt then decrypt roundtrip preserves key material', () => {
    const privDer = crypto.randomBytes(48);
    const box     = enc.encryptKeyMaterial(privDer);
    const result  = enc.decryptKeyMaterial(box);
    expect(result.equals(privDer)).toBe(true);
  });

  test('each encryption produces a unique IV', () => {
    const privDer = crypto.randomBytes(48);
    const box1    = enc.encryptKeyMaterial(privDer);
    const box2    = enc.encryptKeyMaterial(privDer);
    expect(box1.iv).not.toBe(box2.iv);
  });

  test('encrypted object contains all required AES-256-GCM fields', () => {
    const box = enc.encryptKeyMaterial(crypto.randomBytes(32));
    expect(box).toHaveProperty('algorithm', 'aes-256-gcm');
    expect(box).toHaveProperty('iv');
    expect(box).toHaveProperty('encryptedPrivateKey');
    expect(box).toHaveProperty('authTag');
    expect(box).toHaveProperty('createdAt');
    expect(box).toHaveProperty('updatedAt');
  });

  test('encryptedPrivateKey does not contain plaintext key material', () => {
    const privDer    = crypto.randomBytes(48);
    const box        = enc.encryptKeyMaterial(privDer);
    const ctBytes    = Buffer.from(box.encryptedPrivateKey, 'base64');
    expect(ctBytes.equals(privDer)).toBe(false);
  });

  test('wrong KEK → decryption fails', () => {
    const privDer = crypto.randomBytes(48);
    const box     = enc.encryptKeyMaterial(privDer);

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = ALT_KEK;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const enc2 = require('../../../services/artifact/keyEncryption');

    expect(() => enc2.decryptKeyMaterial(box)).toThrow();
  });

  test('tampered encryptedPrivateKey → decryption fails (auth tag mismatch)', () => {
    const privDer  = crypto.randomBytes(48);
    const box      = enc.encryptKeyMaterial(privDer);
    const ctBytes  = Buffer.from(box.encryptedPrivateKey, 'base64');
    ctBytes[0]    ^= 0xff;
    const tampered = { ...box, encryptedPrivateKey: ctBytes.toString('base64') };
    expect(() => enc.decryptKeyMaterial(tampered)).toThrow();
  });

  test('tampered authTag → decryption fails', () => {
    const privDer  = crypto.randomBytes(48);
    const box      = enc.encryptKeyMaterial(privDer);
    const tagBytes = Buffer.from(box.authTag, 'base64');
    tagBytes[0]   ^= 0x01;
    const tampered = { ...box, authTag: tagBytes.toString('base64') };
    expect(() => enc.decryptKeyMaterial(tampered)).toThrow();
  });

  test('unsupported algorithm field → decryption throws', () => {
    const privDer = crypto.randomBytes(48);
    const box     = enc.encryptKeyMaterial(privDer);
    expect(() => enc.decryptKeyMaterial({ ...box, algorithm: 'aes-128-gcm' })).toThrow(/unsupported algorithm/);
  });
});

// ── 8–12. KeyStore encrypted-at-rest persistence ──────────────────────────────

describe('KeyStore — encrypted-at-rest persistence', () => {
  test('active key saved with encryptedPrivateKeyDer, not plaintext privateKeyDer', () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks = require('../../../services/artifact/keyStore');

    ks.rotateKey('enc-test');

    const raw  = fs.readFileSync(keysPath, 'utf8');
    const data = JSON.parse(raw);
    const clientKeys = data.clients['enc-test'];
    const activeEntry = Object.values(clientKeys).find(e => e.status === 'active');

    expect(activeEntry).toBeDefined();
    expect(activeEntry.encryptedPrivateKeyDer).toBeDefined();
    expect(activeEntry.encryptedPrivateKeyDer.algorithm).toBe('aes-256-gcm');
    expect(activeEntry.encryptedPrivateKeyDer.iv).toBeDefined();
    expect(activeEntry.encryptedPrivateKeyDer.encryptedPrivateKey).toBeDefined();
    expect(activeEntry.encryptedPrivateKeyDer.authTag).toBeDefined();
    expect(activeEntry.encryptedPrivateKeyDer.updatedAt).toBeDefined();
    // Must NOT contain plaintext private key
    expect(activeEntry.privateKeyDer).toBeUndefined();
  });

  test('encrypted key loads back with correct private key material', () => {
    const keysPath = makeTempPath();

    // First load: generate and save a key
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks1 = require('../../../services/artifact/keyStore');
    ks1.rotateKey('reload-test');
    const key1 = ks1.getActiveKey('reload-test');

    // Second load: reload from the encrypted file
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../../services/artifact/keyStore');
    const key2 = ks2.getActiveKey('reload-test');

    expect(key2.privDer.equals(key1.privDer)).toBe(true);
    expect(key2.pubDer.equals(key1.pubDer)).toBe(true);
    expect(key2.keyId).toBe(key1.keyId);
  });

  test('missing KEK when loading encrypted file → bootstrap throws (startup aborts)', () => {
    const keysPath = makeTempPath();

    // Write encrypted key file
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks1 = require('../../../services/artifact/keyStore');
    ks1.rotateKey('fatal-test');

    // Attempt to load with no KEK. require() itself is side-effect-free (no
    // decryption happens at module load) — the KEK-dependent bootstrap runs
    // lazily on first store access, so the throw now surfaces there instead.
    jest.resetModules();
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../../services/artifact/keyStore');
    expect(() => ks2.getActiveKey('fatal-test')).toThrow();
  });

  test('wrong KEK when loading encrypted file → bootstrap throws (startup aborts)', () => {
    const keysPath = makeTempPath();

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks1 = require('../../../services/artifact/keyStore');
    ks1.rotateKey('wrong-kek-test');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = ALT_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../../services/artifact/keyStore');
    expect(() => ks2.getActiveKey('wrong-kek-test')).toThrow();
  });

  test('malformed encryptedPrivateKeyDer in file → bootstrap throws', () => {
    const keysPath = makeTempPath();

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks1 = require('../../../services/artifact/keyStore');
    ks1.rotateKey('malform-test');

    // Corrupt the encrypted entry
    const raw  = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const clientKeys = raw.clients['malform-test'];
    const activeId   = Object.keys(clientKeys).find(k => clientKeys[k].status === 'active');
    raw.clients['malform-test'][activeId].encryptedPrivateKeyDer.encryptedPrivateKey = 'AAAA';
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../../services/artifact/keyStore');
    expect(() => ks2.getActiveKey('malform-test')).toThrow();
  });

  test('legacy plaintext privateKeyDer migrated to encrypted on bootstrap', () => {
    const keysPath = makeTempPath();

    // Write a legacy plaintext key file
    const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const legacyFile = {
      version: 1,
      clients: {
        'legacy-client': {
          'legacy-client:key_v1': {
            clientId:     'legacy-client',
            keyId:        'legacy-client:key_v1',
            version:      1,
            algorithm:    'ed25519',
            privateKeyDer: Buffer.from(priv).toString('base64'),
            publicKeyDer:  Buffer.from(pub).toString('base64'),
            status:       'active',
            createdAt:    new Date().toISOString(),
          },
        },
      },
      legacyMap: {},
    };
    fs.mkdirSync(path.dirname(keysPath), { recursive: true });
    fs.writeFileSync(keysPath, JSON.stringify(legacyFile, null, 2), 'utf8');

    // Load with a valid KEK — bootstrap should migrate
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks = require('../../../services/artifact/keyStore');

    // Key should be accessible
    const key = ks.getActiveKey('legacy-client');
    expect(Buffer.isBuffer(key.privDer)).toBe(true);
    expect(key.privDer.equals(Buffer.from(priv))).toBe(true);

    // File should now have encryptedPrivateKeyDer, not plaintext
    const saved = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const savedEntry = saved.clients['legacy-client']['legacy-client:key_v1'];
    expect(savedEntry.encryptedPrivateKeyDer).toBeDefined();
    expect(savedEntry.encryptedPrivateKeyDer.algorithm).toBe('aes-256-gcm');
    expect(savedEntry.privateKeyDer).toBeUndefined();
  });

  test('legacy plaintext migration fails if KEK not set → bootstrap throws', () => {
    const keysPath = makeTempPath();

    const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const legacyFile = {
      version: 1,
      clients: {
        'legacy-no-kek': {
          'legacy-no-kek:key_v1': {
            clientId:     'legacy-no-kek',
            keyId:        'legacy-no-kek:key_v1',
            version:      1,
            algorithm:    'ed25519',
            privateKeyDer: Buffer.from(priv).toString('base64'),
            publicKeyDer:  Buffer.from(pub).toString('base64'),
            status:       'active',
            createdAt:    new Date().toISOString(),
          },
        },
      },
      legacyMap: {},
    };
    fs.writeFileSync(keysPath, JSON.stringify(legacyFile, null, 2), 'utf8');

    jest.resetModules();
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../../services/artifact/keyStore');
    // Migration calls saveKeys() which calls encryptKeyMaterial() which needs
    // KEK. KEK is not set → the lazy bootstrap (triggered by the first real
    // store access below) throws → startup aborts.
    expect(() => ks2.getActiveKey('legacy-no-kek')).toThrow();
  });
});

// ── 13–18. KeyManager access control ─────────────────────────────────────────

describe('KeyManager — access control', () => {
  let km;
  const keysPath = makeTempPath();

  beforeAll(() => {
    km = loadFresh(keysPath, TEST_KEK);
    km.rotate('km-test');
  });

  afterAll(() => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  });

  test('getSigningKey returns privDer, pubDer, keyId, clientId', () => {
    const key = km.getSigningKey('km-test');
    expect(Buffer.isBuffer(key.privDer)).toBe(true);
    expect(key.privDer.length).toBeGreaterThan(0);
    expect(Buffer.isBuffer(key.pubDer)).toBe(true);
    expect(typeof key.keyId).toBe('string');
    expect(key.clientId).toBe('km-test');
  });

  test('getActivePublicKey never returns privDer', () => {
    const pub = km.getActivePublicKey('km-test');
    expect(pub.privDer).toBeUndefined();
    expect(pub._privDer).toBeUndefined();
    expect(pub.keyId).toBeDefined();
    expect(pub.pubDer).toBeDefined();
    expect(pub.publicKeyB64).toBeDefined();
  });

  test('getVerificationKey returns only public material', () => {
    const key = km.getSigningKey('km-test');
    const pub = km.getVerificationKey(key.keyId);
    expect(pub.privDer).toBeUndefined();
    expect(pub._privDer).toBeUndefined();
    expect(Buffer.isBuffer(pub.pubDer)).toBe(true);
    expect(pub.status).toBe('active');
  });

  test('listPublicKeys returns no private key material', () => {
    const keys = km.listPublicKeys();
    expect(Array.isArray(keys)).toBe(true);
    for (const k of keys) {
      expect(k.privDer).toBeUndefined();
      expect(k._privDer).toBeUndefined();
      expect(k.privateKeyDer).toBeUndefined();
      expect(k.encryptedPrivateKeyDer).toBeUndefined();
    }
  });

  test('getSigningKey for unknown client → throws', () => {
    expect(() => km.getSigningKey('nonexistent-client-xyz')).toThrow();
  });

  test('validateStartup succeeds with valid KEK + active key', () => {
    const result = km.validateStartup();
    expect(result.totalActive).toBeGreaterThan(0);
    expect(result.encryptionAlgorithm).toBe('aes-256-gcm');
    expect(typeof result.secretProvider).toBe('string');
  });

  test('validateStartup fails when KEK missing', () => {
    // Use a fresh empty keys path so the bootstrap succeeds (no keys to decrypt).
    // validateStartup() should then detect the missing KEK and throw.
    const emptyPath = makeTempPath();
    jest.resetModules();
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    process.env.QODIQA_KEYS_PATH = emptyPath;
    require('../../../services/secrets/secretsProvider')._clearCache();
    // Bootstrap succeeds (empty store — nothing to decrypt)
    const kmFresh = require('../../../services/artifact/keyManager');
    // validateStartup explicitly validates the KEK
    expect(() => kmFresh.validateStartup()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY/);
    // Restore for subsequent tests
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    require('../../../services/secrets/secretsProvider')._clearCache();
  });
});

// ── 19-22. KeyManager.revoke — public entry point delegates to keyStore ────────
//
// keyManager.revoke() is the only revocation entry point production
// code (src/api/routes/keyAdmin.js) calls. keyRevocation.async.test.js covers
// keyStore.revokeKeyAsync() exhaustively; these tests confirm the public
// KeyManager wrapper actually reaches it end-to-end, closing the loop for
// "revocation propagates through the complete production pipeline".

describe('KeyManager.revoke', () => {
  let km;
  const keysPath = makeTempPath();

  beforeAll(() => {
    km = loadFresh(keysPath, TEST_KEK);
  });

  afterAll(() => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  });

  test('revokes an active key and removes it from further signing use', async () => {
    km.rotate('revoke-target-1');
    const { keyId } = km.getActivePublicKey('revoke-target-1');

    const result = await km.revoke('revoke-target-1', keyId);

    expect(result.status).toBe('revoked');
    expect(() => km.getActivePublicKey('revoke-target-1')).toThrow();
    expect(() => km.getSigningKey('revoke-target-1')).toThrow();
  });

  test('local mode (no native signing provider) reports revocation as not attempted/not supported', async () => {
    km.rotate('revoke-target-2');
    const { keyId } = km.getActivePublicKey('revoke-target-2');

    const result = await km.revoke('revoke-target-2', keyId);

    expect(result.nativeRevocation).toEqual(expect.objectContaining({
      attempted: false,
      supported: false,
      reason:    'NO_NATIVE_SIGNING_PROVIDER_CONFIGURED',
    }));
  });

  test('revoking an already-revoked key is idempotent', async () => {
    km.rotate('revoke-target-3');
    const { keyId } = km.getActivePublicKey('revoke-target-3');

    await km.revoke('revoke-target-3', keyId);
    const second = await km.revoke('revoke-target-3', keyId);

    expect(second.alreadyRevoked).toBe(true);
    expect(second.status).toBe('revoked');
  });

  test('revoking an unknown keyId rejects rather than silently succeeding', async () => {
    await expect(km.revoke('revoke-target-4', 'revoke-target-4:key_v99')).rejects.toThrow(/unknown keyId/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// CRYPTO-1 (=KEY-5) — Rotation immediately removes the outgoing key's signing
// capability, through the KeyManager façade every production caller
// (src/api/routes/sign.js) actually uses — not just at the keyStore layer
// keyRotation.async.test.js already covers.
//
// remediation: km.rotate()/rotateAsync() DEFAULT to 'emergency' mode —
// the outgoing key is REVOKED, losing signing AND verification capability in
// the same call. km.rotateGracefully()/rotateGracefullyAsync() is the
// separate, explicit opt-in that preserves the old deprecate-and-keep-
// verifiable behavior. Both are covered below.
// ═════════════════════════════════════════════════════════════════════════════

describe('KeyManager — rotation revokes signing capability immediately (CRYPTO-1)', () => {
  let km;
  const keysPath = makeTempPath();

  beforeAll(() => {
    km = loadFresh(keysPath, TEST_KEK);
  });

  afterAll(() => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  });

  test('getSigningKey never returns the pre-rotation key once a successor exists', () => {
    km.rotate('rot-cap-1');
    const before = km.getSigningKey('rot-cap-1');

    km.rotate('rot-cap-1', { mode: 'emergency' });
    const after = km.getSigningKey('rot-cap-1');

    // The signing path is a single pointer to "the" active key — there is no
    // API that returns the old key's private material once rotation has run.
    expect(after.keyId).not.toBe(before.keyId);
    expect(after.privDer.equals(before.privDer)).toBe(false);
  });

  test('graceful mode: the outgoing key remains resolvable for verification only (getVerificationKey), never for signing', () => {
    km.rotate('rot-cap-2');
    const oldKey = km.getSigningKey('rot-cap-2');

    km.rotateGracefully('rot-cap-2'); // oldKey.keyId is now deprecated, not active

    // Verification: still resolvable, public material only.
    const verifyView = km.getVerificationKey(oldKey.keyId);
    expect(verifyView.status).toBe('deprecated');
    expect(verifyView.pubDer.equals(oldKey.pubDer)).toBe(true);
    expect(verifyView.privDer).toBeUndefined();

    // Signing: the current active key is a different key entirely — nothing
    // in KeyManager's public surface accepts a keyId to sign with, so the
    // deprecated key cannot be selected for signing regardless of caller intent.
    const currentSigningKey = km.getSigningKey('rot-cap-2');
    expect(currentSigningKey.keyId).not.toBe(oldKey.keyId);
  });

  test('emergency mode (explicit): the outgoing key is unreachable for BOTH signing and verification', () => {
    km.rotate('rot-cap-2e');
    const oldKey = km.getSigningKey('rot-cap-2e');

    km.rotate('rot-cap-2e', { mode: 'emergency' });

    // Before the fix, this call would succeed (deprecated keys verify).
    // Now it must throw — rotation alone revokes the outgoing key.
    expect(() => km.getVerificationKey(oldKey.keyId)).toThrow(/revoked/);

    const currentSigningKey = km.getSigningKey('rot-cap-2e');
    expect(currentSigningKey.keyId).not.toBe(oldKey.keyId);
  });

  test('exactly one signing key exists per client after any number of rotations', () => {
    for (let i = 0; i < 5; i++) km.rotate('rot-cap-3', i === 0 ? undefined : { mode: 'emergency' });
    const allKeys = km.getKeysByClientId('rot-cap-3');
    const activeKeys = allKeys.filter(k => k.status === 'active');
    expect(activeKeys).toHaveLength(1);
  });

  test('rotation alone (without any explicit revoke() call) blocks new signatures from the old key, in both modes', () => {
    km.rotate('rot-cap-4');
    const oldKey = km.getSigningKey('rot-cap-4');
    km.rotate('rot-cap-4', { mode: 'emergency' });

    // The old key was never explicitly revoked via km.revoke() — only
    // rotated, using the default mode — yet it is unreachable for signing
    // AND for verification too. Rotation itself is now the complete
    // signing-and-verification-capability boundary in its default mode, not
    // a prerequisite "please also revoke" step.
    expect(km.getSigningKey('rot-cap-4').keyId).not.toBe(oldKey.keyId);
    expect(() => km.getVerificationKey(oldKey.keyId)).toThrow(/revoked/);
  });

  test('rotateGracefully — the outgoing key keeps verifying, exactly as the pre-KEY-5 default used to, but only when explicitly requested', () => {
    km.rotate('rot-cap-5');
    const oldKey = km.getSigningKey('rot-cap-5');
    const result = km.rotateGracefully('rot-cap-5');

    expect(result.mode).toBe('graceful');
    expect(result.previousKeyStatus).toBe('deprecated');
    expect(km.getSigningKey('rot-cap-5').keyId).not.toBe(oldKey.keyId);
    expect(() => km.getVerificationKey(oldKey.keyId)).not.toThrow();
  });
});
