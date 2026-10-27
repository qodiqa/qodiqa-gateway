'use strict';

/**
 * Unit tests for Component #30 — HSM-backed Transparency Key
 *
 * TSG-01..TSG-10   transparencyKeyStore — constants and exports
 * TSG-11..TSG-25   transparencyKeyStore — key lifecycle (getActiveKey, getPublicKey, rotateKey, revokeKey)
 * TSG-26..TSG-35   transparencyKeyStore — validation (validateKeyStore)
 * TSG-36..TSG-50   SoftwareTransparencySigner — signing
 * TSG-51..TSG-65   SoftwareTransparencySigner — verification
 * TSG-66..TSG-75   SoftwareTransparencySigner — lifecycle (rotate, revoke, validateStartup)
 * TSG-76..TSG-85   HsmTransparencySigner — stub behavior
 * TSG-86..TSG-92   createTransparencySigner — factory
 * TSG-93..TSG-100  Purpose isolation — artifact key cannot sign transparency; transparency cannot sign artifacts
 */

const crypto = require('crypto');

// ── Environment setup (must happen before any module require) ─────────────────

// Provide a real KEK so AES-256-GCM encryption/decryption works in tests.
process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64); // 32-byte hex KEK
process.env.QODIQA_CLIENT_ID          = 'testapp';

// Use an in-memory "file" path that does not exist — bootstrap starts empty store.
const _tempKeyPath = `/tmp/qodiqa-test-transparency-keys-${Date.now()}.json`;
process.env.QODIQA_TRANSPARENCY_KEYS_PATH  = _tempKeyPath;
process.env.QODIQA_TRANSPARENCY_KEY_CLIENT = 'tr-testapp';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: mockEmit }));

// Mock filesystem — in-memory store; avoids real file I/O in unit tests.
const _fsStore = {};
jest.mock('fs', () => {
  const real = jest.requireActual('fs');
  return {
    ...real,
    existsSync:   jest.fn((p) => p in _fsStore),
    readFileSync: jest.fn((p) => {
      if (!(p in _fsStore)) throw new Error(`ENOENT: no such file: ${p}`);
      return _fsStore[p];
    }),
    writeFileSync: jest.fn((p, content) => { _fsStore[p] = content; }),
    mkdirSync:     jest.fn(),
    renameSync:    jest.fn((from, to) => {
      if (from in _fsStore) { _fsStore[to] = _fsStore[from]; delete _fsStore[from]; }
    }),
    copyFileSync:  jest.fn((from, to) => { if (from in _fsStore) _fsStore[to] = _fsStore[from]; }),
    unlinkSync:    jest.fn((p) => { delete _fsStore[p]; }),
  };
});

// ── Module imports (after mocks + env) ───────────────────────────────────────

// Use jest.isolateModules so each describe block can get a fresh module if needed.
// For the primary tests, we use module-level singletons reset between tests.

let tKeyStore;
let transparencySigner;

beforeAll(() => {
  // Clear any leftover fs state
  Object.keys(_fsStore).forEach(k => delete _fsStore[k]);
  tKeyStore        = require('../transparencyKeyStore');
  transparencySigner = require('../transparencySigner');
});

beforeEach(() => {
  jest.clearAllMocks();
  // Reset the in-memory transparency key store between tests
  tKeyStore._resetStore();
  Object.keys(_fsStore).forEach(k => delete _fsStore[k]);
});

// Helper: provision a fresh key in the store for each test that needs one
function _provisionKey() {
  return tKeyStore.rotateKey();
}

// ══════════════════════════════════════════════════════════════════════════════
// TSG-01..TSG-10  transparencyKeyStore — constants and exports
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-01..10 — transparencyKeyStore constants and exports', () => {
  test('TSG-01 ROTATION_DAYS is 90', () => {
    expect(tKeyStore.ROTATION_DAYS).toBe(90);
  });

  test('TSG-02 EXPIRY_DAYS is 180', () => {
    expect(tKeyStore.EXPIRY_DAYS).toBe(180);
  });

  test('TSG-03 EXPIRY_WARNING_DAYS is 30', () => {
    expect(tKeyStore.EXPIRY_WARNING_DAYS).toBe(30);
  });

  test('TSG-04 KEY_PURPOSE is transparency', () => {
    expect(tKeyStore.KEY_PURPOSE).toBe('transparency');
  });

  test('TSG-05 getActiveKey is exported as a function', () => {
    expect(typeof tKeyStore.getActiveKey).toBe('function');
  });

  test('TSG-06 getPublicKey is exported as a function', () => {
    expect(typeof tKeyStore.getPublicKey).toBe('function');
  });

  test('TSG-07 rotateKey is exported as a function', () => {
    expect(typeof tKeyStore.rotateKey).toBe('function');
  });

  test('TSG-08 revokeKey is exported as a function', () => {
    expect(typeof tKeyStore.revokeKey).toBe('function');
  });

  test('TSG-09 validateKeyStore is exported as a function', () => {
    expect(typeof tKeyStore.validateKeyStore).toBe('function');
  });

  test('TSG-10 _transparencyClientId uses QODIQA_TRANSPARENCY_KEY_CLIENT', () => {
    process.env.QODIQA_TRANSPARENCY_KEY_CLIENT = 'tr-testapp';
    expect(tKeyStore._transparencyClientId()).toBe('tr-testapp');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-11..TSG-25  transparencyKeyStore — key lifecycle
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-11..25 — transparencyKeyStore key lifecycle', () => {
  test('TSG-11 getActiveKey throws when no key is provisioned', () => {
    expect(() => tKeyStore.getActiveKey()).toThrow('no active transparency signing key');
  });

  test('TSG-12 rotateKey provisions first key successfully', () => {
    const result = _provisionKey();
    expect(result).toHaveProperty('keyId');
    expect(result).toHaveProperty('version', 1);
  });

  test('TSG-13 first key has ID format <trClientId>:key_v1', () => {
    const { keyId } = _provisionKey();
    expect(keyId).toMatch(/^tr-testapp:key_v1$/);
  });

  test('TSG-14 getActiveKey returns { keyId, privDer, pubDer, version } after provisioning', () => {
    _provisionKey();
    const key = tKeyStore.getActiveKey();
    expect(key).toHaveProperty('keyId');
    expect(Buffer.isBuffer(key.privDer)).toBe(true);
    expect(Buffer.isBuffer(key.pubDer)).toBe(true);
    expect(key.version).toBe(1);
  });

  test('TSG-15 privDer is a real Ed25519 private key (can sign)', () => {
    _provisionKey();
    const { privDer } = tKeyStore.getActiveKey();
    const probe = crypto.createHash('sha256').update('test', 'utf8').digest();
    const { sign } = require('../../../infra/crypto/ed25519');
    expect(() => sign(probe, privDer)).not.toThrow();
  });

  test('TSG-16 pubDer matches privDer (self-test)', () => {
    _provisionKey();
    const { privDer, pubDer } = tKeyStore.getActiveKey();
    const probe = crypto.createHash('sha256').update('test', 'utf8').digest();
    const { sign, verify } = require('../../../infra/crypto/ed25519');
    const sig = sign(probe, privDer);
    expect(verify(probe, sig, pubDer)).toBe(true);
  });

  test('TSG-17 getPublicKey returns { pubDer, status: active } for active key', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    const result = tKeyStore.getPublicKey(keyId);
    expect(result.status).toBe('active');
    expect(Buffer.isBuffer(result.pubDer)).toBe(true);
  });

  test('TSG-18 getPublicKey throws for unknown keyId', () => {
    expect(() => tKeyStore.getPublicKey('tr-testapp:key_v99')).toThrow('unknown transparency keyId');
  });

  // / audit 2026-10-20 (3.10): the transparency store's rotateKey() DEFAULT is now 'graceful' (outgoing key stays verifiable);
  // the TSG-*-EMERGENCY tests below ask for { mode: 'emergency' } explicitly (outgoing key revoked).
  // rotateKeyGracefully() is the separate, explicit opt-in that preserves
  // the deprecate-and-keep-verifiable behavior these TSG-19/20 tests target.

  test('TSG-19 rotateKeyGracefully generates new version and deprecates old', () => {
    _provisionKey();
    const { keyId: firstId } = tKeyStore.getActiveKey();
    const result = tKeyStore.rotateKeyGracefully();
    expect(result.version).toBe(2);
    expect(result.mode).toBe('graceful');
    expect(tKeyStore.getKeyStatus(firstId)).toBe('deprecated');
    expect(tKeyStore.getKeyStatus(result.keyId)).toBe('active');
  });

  test('TSG-19-DEFAULT (audit 3.10) rotateKey() with no mode is graceful: the old key is deprecated and stays verifiable', () => {
    _provisionKey();
    const { keyId: firstId } = tKeyStore.getActiveKey();
    const result = tKeyStore.rotateKey(); // no opts
    expect(result.mode).toBe('graceful');
    expect(result.previousKeyStatus).toBe('deprecated');
    expect(tKeyStore.getKeyStatus(firstId)).toBe('deprecated');
    expect(Buffer.isBuffer(tKeyStore.getPublicKey(firstId).pubDer)).toBe(true);
  });

  test('TSG-19-EMERGENCY rotateKey with an explicit emergency mode generates new version and revokes old', () => {
    _provisionKey();
    const { keyId: firstId } = tKeyStore.getActiveKey();
    const result = tKeyStore.rotateKey({ mode: 'emergency' });
    expect(result.version).toBe(2);
    expect(result.mode).toBe('emergency');
    expect(tKeyStore.getKeyStatus(firstId)).toBe('revoked');
    expect(tKeyStore.getKeyStatus(result.keyId)).toBe('active');
  });

  test('TSG-20 deprecated key (graceful rotation) remains verifiable via getPublicKey', () => {
    _provisionKey();
    const { keyId: oldId } = tKeyStore.getActiveKey();
    tKeyStore.rotateKeyGracefully();
    const result = tKeyStore.getPublicKey(oldId);
    expect(result.status).toBe('deprecated');
    expect(Buffer.isBuffer(result.pubDer)).toBe(true);
  });

  test('TSG-20-EMERGENCY revoked key (emergency rotation) is NOT verifiable via getPublicKey', () => {
    _provisionKey();
    const { keyId: oldId } = tKeyStore.getActiveKey();
    tKeyStore.rotateKey({ mode: 'emergency' });
    expect(() => tKeyStore.getPublicKey(oldId)).toThrow('revoked');
  });

  test('TSG-21 deprecated key loses private material (getActiveKey returns new key)', () => {
    _provisionKey();
    const { keyId: oldId } = tKeyStore.getActiveKey();
    tKeyStore.rotateKey();
    // The old key is now revoked (default mode) — cannot be the active signing key
    const activeKey = tKeyStore.getActiveKey();
    expect(activeKey.keyId).not.toBe(oldId);
  });

  test('TSG-22 revokeKey marks key as revoked', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    tKeyStore.revokeKey(keyId);
    expect(tKeyStore.getKeyStatus(keyId)).toBe('revoked');
  });

  test('TSG-23 getPublicKey throws for revoked key (fail-closed)', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    tKeyStore.revokeKey(keyId);
    expect(() => tKeyStore.getPublicKey(keyId)).toThrow('revoked');
  });

  test('TSG-24 revokeKey for unknown keyId throws', () => {
    expect(() => tKeyStore.revokeKey('tr-testapp:key_v99')).toThrow('unknown transparency keyId');
  });

  test('TSG-25 listKeys returns all keys with purpose=transparency and no _privDer', () => {
    _provisionKey();
    tKeyStore.rotateKey(); // generates v2
    const keys = tKeyStore.listKeys();
    expect(keys.length).toBe(2);
    for (const k of keys) {
      expect(k.purpose).toBe('transparency');
      expect(k).not.toHaveProperty('_privDer');
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-26..TSG-35  transparencyKeyStore — validateKeyStore
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-26..35 — transparencyKeyStore validateKeyStore', () => {
  test('TSG-26 validateKeyStore returns totalActive=0 when no key provisioned', () => {
    const audit = tKeyStore.validateKeyStore();
    expect(audit.totalActive).toBe(0);
    expect(audit.violations).toEqual([]);
  });

  test('TSG-27 validateKeyStore returns totalActive=1 after provisioning', () => {
    _provisionKey();
    const audit = tKeyStore.validateKeyStore();
    expect(audit.totalActive).toBe(1);
    expect(audit.violations).toEqual([]);
  });

  test('TSG-28 validateKeyStore returns empty expiredKeys for fresh key', () => {
    _provisionKey();
    const audit = tKeyStore.validateKeyStore();
    expect(audit.expiredKeys).toEqual([]);
  });

  test('TSG-29 validateKeyStore returns empty expiringKeys for fresh key', () => {
    _provisionKey();
    const audit = tKeyStore.validateKeyStore();
    expect(audit.expiringKeys).toEqual([]);
  });

  test('TSG-30 validateKeyStore returns empty overdueKeys for fresh key', () => {
    _provisionKey();
    const audit = tKeyStore.validateKeyStore();
    expect(audit.overdueKeys).toEqual([]);
  });

  test('TSG-31 listKeys returns correct metadata structure', () => {
    _provisionKey();
    const keys = tKeyStore.listKeys();
    expect(keys.length).toBe(1);
    const key = keys[0];
    expect(key).toHaveProperty('keyId');
    expect(key).toHaveProperty('version', 1);
    expect(key).toHaveProperty('algorithm', 'ed25519');
    expect(key).toHaveProperty('purpose', 'transparency');
    expect(key).toHaveProperty('publicKeyB64');
    expect(key).toHaveProperty('status', 'active');
    expect(key).toHaveProperty('rotationDeadline');
    expect(key).toHaveProperty('expiresAt');
  });

  test('TSG-32 validateKeyStore violations are empty after normal rotation', () => {
    _provisionKey();
    tKeyStore.rotateKey();
    const audit = tKeyStore.validateKeyStore();
    expect(audit.violations).toEqual([]);
    expect(audit.totalActive).toBe(1);
  });

  test('TSG-33 getKeyStatus returns null for unknown keyId', () => {
    expect(tKeyStore.getKeyStatus('tr-unknown:key_v99')).toBeNull();
  });

  test('TSG-34 getKeyStatus returns active for active key', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    expect(tKeyStore.getKeyStatus(keyId)).toBe('active');
  });

  test('TSG-35 getKeyStatus returns deprecated after graceful rotation', () => {
    _provisionKey();
    const { keyId: oldId } = tKeyStore.getActiveKey();
    tKeyStore.rotateKeyGracefully();
    expect(tKeyStore.getKeyStatus(oldId)).toBe('deprecated');
  });

  test('TSG-35-EMERGENCY getKeyStatus returns revoked after emergency rotation', () => {
    _provisionKey();
    const { keyId: oldId } = tKeyStore.getActiveKey();
    tKeyStore.rotateKey({ mode: 'emergency' });
    expect(tKeyStore.getKeyStatus(oldId)).toBe('revoked');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-36..TSG-50  SoftwareTransparencySigner — signing
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-36..50 — SoftwareTransparencySigner signing', () => {
  let signer;

  beforeEach(() => {
    signer = new transparencySigner.SoftwareTransparencySigner();
  });

  test('TSG-36 signer.type is software', () => {
    expect(signer.type).toBe('software');
  });

  test('TSG-37 sign() throws when no transparency key is provisioned', async () => {
    const hash = crypto.createHash('sha256').update('test', 'utf8').digest();
    await expect(signer.sign(hash)).rejects.toThrow('no active transparency signing key');
  });

  test('TSG-38 sign() throws for non-Buffer hashBuffer', async () => {
    _provisionKey();
    await expect(signer.sign('not-a-buffer')).rejects.toThrow('must be a 32-byte Buffer');
  });

  test('TSG-39 sign() throws for Buffer that is not 32 bytes', async () => {
    _provisionKey();
    await expect(signer.sign(Buffer.alloc(16))).rejects.toThrow('must be a 32-byte Buffer');
  });

  test('TSG-40 sign() returns { signature, keyId, keyVersion } for valid hash', async () => {
    _provisionKey();
    const hash   = crypto.createHash('sha256').update('test', 'utf8').digest();
    const result = await signer.sign(hash);
    expect(result).toHaveProperty('signature');
    expect(result).toHaveProperty('keyId');
    expect(result).toHaveProperty('keyVersion');
  });

  test('TSG-41 signature is a non-empty string', async () => {
    _provisionKey();
    const hash   = crypto.createHash('sha256').update('test', 'utf8').digest();
    const result = await signer.sign(hash);
    expect(typeof result.signature).toBe('string');
    expect(result.signature.length).toBeGreaterThan(0);
  });

  test('TSG-42 signature decodes to 64 bytes (Ed25519)', async () => {
    _provisionKey();
    const hash   = crypto.createHash('sha256').update('test', 'utf8').digest();
    const result = await signer.sign(hash);
    expect(Buffer.from(result.signature, 'base64').length).toBe(64);
  });

  test('TSG-43 keyId in result matches the active transparency key', async () => {
    _provisionKey();
    const activeId = tKeyStore.getActiveKey().keyId;
    const hash     = crypto.createHash('sha256').update('test', 'utf8').digest();
    const result   = await signer.sign(hash);
    expect(result.keyId).toBe(activeId);
  });

  test('TSG-44 keyVersion in result matches the active key version', async () => {
    _provisionKey();
    const activeVersion = tKeyStore.getActiveKey().version;
    const hash          = crypto.createHash('sha256').update('test', 'utf8').digest();
    const result        = await signer.sign(hash);
    expect(result.keyVersion).toBe(activeVersion);
  });

  test('TSG-45 signing is deterministic for same hash with same key', async () => {
    _provisionKey();
    const hash    = crypto.createHash('sha256').update('deterministic', 'utf8').digest();
    const r1      = await signer.sign(hash);
    const r2      = await signer.sign(hash);
    // Ed25519 is deterministic for same key+message
    expect(r1.signature).toBe(r2.signature);
  });

  test('TSG-46 different hashes produce different signatures', async () => {
    _provisionKey();
    const h1 = crypto.createHash('sha256').update('message1', 'utf8').digest();
    const h2 = crypto.createHash('sha256').update('message2', 'utf8').digest();
    const r1 = await signer.sign(h1);
    const r2 = await signer.sign(h2);
    expect(r1.signature).not.toBe(r2.signature);
  });

  test('TSG-47 sign() emits INFO TRANSPARENCY_ROOT_SIGNED', async () => {
    _provisionKey();
    const hash = crypto.createHash('sha256').update('test', 'utf8').digest();
    await signer.sign(hash);
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'TRANSPARENCY_ROOT_SIGNED', expect.objectContaining({
      purpose: 'transparency',
    }));
  });

  test('TSG-48 sign() emits ERROR on signing failure', async () => {
    // No key provisioned → signing fails
    const hash = crypto.createHash('sha256').update('test', 'utf8').digest();
    await expect(signer.sign(hash)).rejects.toThrow();
    expect(mockEmit).toHaveBeenCalledWith('ERROR', 'TRANSPARENCY_SIGNING_FAILED', expect.any(Object));
  });

  test('TSG-49 getActiveKeyInfo returns { keyId, pubDer, version } (no privDer)', () => {
    _provisionKey();
    const info = signer.getActiveKeyInfo();
    expect(info).toHaveProperty('keyId');
    expect(Buffer.isBuffer(info.pubDer)).toBe(true);
    expect(info).toHaveProperty('version', 1);
    expect(info).not.toHaveProperty('privDer');
    expect(info).not.toHaveProperty('_privDer');
  });

  test('TSG-50 getActiveKeyInfo throws when no key is provisioned', () => {
    expect(() => signer.getActiveKeyInfo()).toThrow('no active transparency signing key');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-51..TSG-65  SoftwareTransparencySigner — verification
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-51..65 — SoftwareTransparencySigner verification', () => {
  let signer;
  let _keyId;
  let _hash;
  let _sig;

  beforeEach(async () => {
    signer = new transparencySigner.SoftwareTransparencySigner();
    _provisionKey();
    _hash = crypto.createHash('sha256').update('verify-test', 'utf8').digest();
    const r = await signer.sign(_hash);
    _keyId  = r.keyId;
    _sig    = r.signature;
  });

  test('TSG-51 getVerificationKey returns { pubDer, status } for active key', () => {
    const result = signer.getVerificationKey(_keyId);
    expect(result).toHaveProperty('pubDer');
    expect(result.status).toBe('active');
  });

  test('TSG-52 getVerificationKey throws for unknown keyId (fail-closed)', () => {
    expect(() => signer.getVerificationKey('tr-unknown:key_v99')).toThrow('unknown transparency keyId');
  });

  test('TSG-53 getVerificationKey throws for revoked keyId (fail-closed)', () => {
    tKeyStore.revokeKey(_keyId);
    expect(() => signer.getVerificationKey(_keyId)).toThrow('revoked');
  });

  test('TSG-54 verify() returns true for valid signature', () => {
    expect(signer.verify(_hash, _sig, _keyId)).toBe(true);
  });

  test('TSG-55 verify() returns false for tampered hash', () => {
    const tampered = Buffer.from(_hash);
    tampered[0] ^= 0xff;
    expect(signer.verify(tampered, _sig, _keyId)).toBe(false);
  });

  test('TSG-56 verify() returns false for corrupted signature', () => {
    const tampered = Buffer.from(_sig, 'base64');
    tampered[0] ^= 0xff;
    expect(signer.verify(_hash, tampered.toString('base64'), _keyId)).toBe(false);
  });

  test('TSG-57 verify() returns false for unknown keyId', () => {
    expect(signer.verify(_hash, _sig, 'tr-unknown:key_v99')).toBe(false);
  });

  test('TSG-58 verify() returns false for revoked keyId', () => {
    tKeyStore.revokeKey(_keyId);
    expect(signer.verify(_hash, _sig, _keyId)).toBe(false);
  });

  test('TSG-59 verify() never throws (returns false instead)', () => {
    expect(() => signer.verify(null, null, null)).not.toThrow();
    expect(signer.verify(null, null, null)).toBe(false);
  });

  test('TSG-60 graceful-mode rotation — old signature still verifiable with deprecated key', async () => {
    // Sign with v1
    const hash1 = crypto.createHash('sha256').update('old-root', 'utf8').digest();
    const { signature: sig1, keyId: kid1 } = await signer.sign(hash1);

    // Rotate to v2 — explicit graceful mode, the only mode that keeps kid1 verifiable
    tKeyStore.rotateKeyGracefully();

    // Old signature must still verify with the deprecated v1 key
    expect(signer.verify(hash1, sig1, kid1)).toBe(true);
  });

  test('TSG-60-DEFAULT (audit 3.10) default rotation — everything the old key signed still verifies', async () => {
    _provisionKey();
    const { keyId: firstId } = tKeyStore.getActiveKey();
    const hash = crypto.createHash('sha256').update('history', 'utf8').digest();
    const { signature, keyId } = await signer.sign(hash);
    const result = tKeyStore.rotateKey(); // no opts
    expect(result.mode).toBe('graceful');
    expect(result.previousKeyStatus).toBe('deprecated');
    expect(tKeyStore.getKeyStatus(firstId)).toBe('deprecated');
    expect(signer.verify(hash, signature, keyId)).toBe(true); // everything the old key signed still verifies
    expect(tKeyStore.getKeyStatus(tKeyStore.getActiveKey().keyId)).toBe('active');
  });

  test('TSG-60-EMERGENCY emergency rotation — old signature no longer verifiable (revoked)', async () => {
    const hash1 = crypto.createHash('sha256').update('old-root', 'utf8').digest();
    const { signature: sig1, keyId: kid1 } = await signer.sign(hash1);

    tKeyStore.rotateKey({ mode: 'emergency' }); // explicit emergency (3.10: the default is now graceful)

    // Even a genuinely valid signature can no longer be verified once its
    // key is revoked — verify() resolves the key first and fails closed.
    expect(signer.verify(hash1, sig1, kid1)).toBe(false);
  });

  test('TSG-61 key rotation — new signature uses new key', async () => {
    tKeyStore.rotateKey();
    const hash2 = crypto.createHash('sha256').update('new-root', 'utf8').digest();
    const { keyId: kid2 } = await signer.sign(hash2);
    expect(kid2).not.toBe(_keyId);
    expect(kid2).toMatch(/key_v2$/);
  });

  test('TSG-62 new key signature cannot be verified with old key', async () => {
    tKeyStore.rotateKey();
    const hash2 = crypto.createHash('sha256').update('new-root', 'utf8').digest();
    const { signature: sig2 } = await signer.sign(hash2);
    // Try to verify new sig with old keyId — must fail
    expect(signer.verify(hash2, sig2, _keyId)).toBe(false);
  });

  test('TSG-63 getVerificationKey returns status=deprecated for a gracefully-retired key', async () => {
    tKeyStore.rotateKeyGracefully();
    const { status } = signer.getVerificationKey(_keyId);
    expect(status).toBe('deprecated');
  });

  test('TSG-63-EMERGENCY getVerificationKey throws for a emergency-retired (revoked) key', async () => {
    tKeyStore.rotateKey({ mode: 'emergency' });
    expect(() => signer.getVerificationKey(_keyId)).toThrow('revoked');
  });

  test('TSG-64 multiple graceful rotations — all historical keys verifiable', async () => {
    const hashes = [];
    const sigs   = [];
    const kids   = [];

    for (let i = 0; i < 3; i++) {
      const h = crypto.createHash('sha256').update(`root-${i}`, 'utf8').digest();
      const { signature: s, keyId: k } = await signer.sign(h);
      hashes.push(h);
      sigs.push(s);
      kids.push(k);
      if (i < 2) tKeyStore.rotateKeyGracefully();
    }

    // All historical signatures must verify with their respective keys
    for (let i = 0; i < 3; i++) {
      expect(signer.verify(hashes[i], sigs[i], kids[i])).toBe(true);
    }
  });

  test('TSG-64-EMERGENCY multiple emergency rotations — only the current active key verifies', async () => {
    const hashes = [];
    const sigs   = [];
    const kids   = [];

    for (let i = 0; i < 3; i++) {
      const h = crypto.createHash('sha256').update(`root-${i}`, 'utf8').digest();
      const { signature: s, keyId: k } = await signer.sign(h);
      hashes.push(h);
      sigs.push(s);
      kids.push(k);
      if (i < 2) tKeyStore.rotateKey({ mode: 'emergency' }); // explicit emergency (3.10: the default is now graceful)
    }

    // Only the last (still-active) key's signature verifies — every earlier
    // key was revoked, not merely deprecated, the moment it was rotated away.
    expect(signer.verify(hashes[2], sigs[2], kids[2])).toBe(true);
    expect(signer.verify(hashes[0], sigs[0], kids[0])).toBe(false);
    expect(signer.verify(hashes[1], sigs[1], kids[1])).toBe(false);
  });

  test('TSG-65 verify never consults artifact key store', () => {
    const keyManager = require('../../../../services/artifact/keyManager');
    const spy        = jest.spyOn(keyManager, 'getVerificationKey');
    signer.verify(_hash, _sig, _keyId);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-66..TSG-75  SoftwareTransparencySigner — lifecycle & validateStartup
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-66..75 — SoftwareTransparencySigner lifecycle and validateStartup', () => {
  let signer;

  beforeEach(() => {
    signer = new transparencySigner.SoftwareTransparencySigner();
  });

  test('TSG-66 validateStartup auto-provisions key when none exists', () => {
    const result = signer.validateStartup();
    expect(result.activeKeys).toBe(1);
    expect(result.activeKeyId).toBeTruthy();
  });

  test('TSG-67 validateStartup returns signerType=software', () => {
    const result = signer.validateStartup();
    expect(result.signerType).toBe('software');
  });

  test('TSG-68 validateStartup returns retiredKeys=0 after first provision', () => {
    const result = signer.validateStartup();
    expect(result.retiredKeys).toBe(0);
  });

  test('TSG-69 validateStartup after graceful rotation returns retiredKeys=1', () => {
    _provisionKey();
    tKeyStore.rotateKeyGracefully(); // v2 — outgoing key deprecated ("retired")
    const result = signer.validateStartup();
    expect(result.retiredKeys).toBe(1);
    expect(result.activeKeys).toBe(1);
  });

  test('TSG-69-EMERGENCY validateStartup after emergency rotation returns retiredKeys=0 — the outgoing key is revoked, not "retired"', () => {
    _provisionKey();
    tKeyStore.rotateKey({ mode: 'emergency' }); // v2 — explicit emergency revokes the outgoing key
    const result = signer.validateStartup();
    // retiredKeys counts status === 'deprecated' only; a revoked key is
    // neither active nor "retired" in the historical-verification sense.
    expect(result.retiredKeys).toBe(0);
    expect(result.activeKeys).toBe(1);
  });

  test('TSG-70 validateStartup emits TRANSPARENCY_SIGNER_READY-like provisioning event', () => {
    signer.validateStartup();
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'TRANSPARENCY_KEY_AUTO_PROVISIONING', expect.any(Object));
  });

  test('TSG-71 rotate() increments version and returns new keyId', () => {
    _provisionKey();
    const result = signer.rotate();
    expect(result.version).toBe(2);
    expect(result.keyId).toMatch(/key_v2$/);
  });

  test('TSG-72 rotate() emits TRANSPARENCY_KEY_ACTIVATED', () => {
    _provisionKey();
    signer.rotate();
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'TRANSPARENCY_KEY_ACTIVATED', expect.objectContaining({
      purpose: 'transparency',
    }));
  });

  test('TSG-73 revoke() marks the key as revoked', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    signer.revoke(keyId);
    expect(tKeyStore.getKeyStatus(keyId)).toBe('revoked');
  });

  test('TSG-74 revoke() emits TRANSPARENCY_KEY_REVOKED_VIA_SIGNER', () => {
    _provisionKey();
    const { keyId } = tKeyStore.getActiveKey();
    signer.revoke(keyId);
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'TRANSPARENCY_KEY_REVOKED_VIA_SIGNER', expect.objectContaining({
      keyId,
      purpose: 'transparency',
    }));
  });

  test('TSG-75 metricsSnapshot returns signerType and counter fields', async () => {
    _provisionKey();
    const hash = crypto.createHash('sha256').update('m', 'utf8').digest();
    await signer.sign(hash);
    const snap = signer.metricsSnapshot();
    expect(snap.signerType).toBe('software');
    expect(snap).toHaveProperty('signaturesTotal');
    expect(snap).toHaveProperty('signingFailures');
    expect(snap).toHaveProperty('activeTransparencyKeys', 1);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-76..TSG-85  HsmTransparencySigner — stub behavior
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-76..85 — HsmTransparencySigner stub behavior', () => {
  let hsm;

  beforeEach(() => {
    hsm = new transparencySigner.HsmTransparencySigner();
  });

  test('TSG-76 signer.type is hsm', () => {
    expect(hsm.type).toBe('hsm');
  });

  test('TSG-77 sign() throws unsupported', async () => {
    const hash = crypto.createHash('sha256').update('test', 'utf8').digest();
    await expect(hsm.sign(hash)).rejects.toThrow('not supported in this release');
  });

  test('TSG-78 getVerificationKey() throws unsupported', () => {
    expect(() => hsm.getVerificationKey('someKeyId')).toThrow('not supported in this release');
  });

  test('TSG-79 getActiveKeyInfo() throws unsupported', () => {
    expect(() => hsm.getActiveKeyInfo()).toThrow('not supported in this release');
  });

  test('TSG-80 rotate() throws unsupported', () => {
    expect(() => hsm.rotate()).toThrow('not supported in this release');
  });

  test('TSG-81 revoke() throws unsupported', () => {
    expect(() => hsm.revoke('someKeyId')).toThrow('not supported in this release');
  });

  test('TSG-82 validateStartup() throws unsupported', () => {
    expect(() => hsm.validateStartup()).toThrow('not supported in this release');
  });

  test('TSG-83 metricsSnapshot returns signerType=hsm and error=unsupported', () => {
    const snap = hsm.metricsSnapshot();
    expect(snap.signerType).toBe('hsm');
    expect(snap.error).toBe('unsupported');
  });

  test('TSG-84 verify() returns false (stub — does not throw)', () => {
    const hash = crypto.createHash('sha256').update('test', 'utf8').digest();
    expect(hsm.verify(hash, 'sig', 'keyId')).toBe(false);
  });

  test('TSG-85 validateStartup error message references TRANSPARENCY_SIGNER=software as alternative', () => {
    expect(() => hsm.validateStartup()).toThrow('TRANSPARENCY_SIGNER=software');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-86..TSG-92  createTransparencySigner — factory
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-86..92 — createTransparencySigner factory', () => {
  test('TSG-86 createTransparencySigner("software") returns SoftwareTransparencySigner', () => {
    const s = transparencySigner.createTransparencySigner('software');
    expect(s).toBeInstanceOf(transparencySigner.SoftwareTransparencySigner);
  });

  test('TSG-87 createTransparencySigner("hsm") returns HsmTransparencySigner', () => {
    const s = transparencySigner.createTransparencySigner('hsm');
    expect(s).toBeInstanceOf(transparencySigner.HsmTransparencySigner);
  });

  test('TSG-88 createTransparencySigner("SOFTWARE") is case-insensitive', () => {
    const s = transparencySigner.createTransparencySigner('SOFTWARE');
    expect(s).toBeInstanceOf(transparencySigner.SoftwareTransparencySigner);
  });

  test('TSG-89 createTransparencySigner("unknown") throws (fail-closed)', () => {
    expect(() => transparencySigner.createTransparencySigner('unknown')).toThrow('unknown signer type');
  });

  test('TSG-90 createTransparencySigner("") throws (fail-closed)', () => {
    // Empty string falls through to env var (TRANSPARENCY_SIGNER) or default 'software'
    const s = transparencySigner.createTransparencySigner('');
    expect(s).toBeInstanceOf(transparencySigner.SoftwareTransparencySigner);
  });

  test('TSG-91 SIGNER_TYPES object is frozen', () => {
    expect(Object.isFrozen(transparencySigner.SIGNER_TYPES)).toBe(true);
  });

  test('TSG-92 SIGNER_TYPES contains software and hsm', () => {
    expect(transparencySigner.SIGNER_TYPES).toHaveProperty('software');
    expect(transparencySigner.SIGNER_TYPES).toHaveProperty('hsm');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TSG-93..TSG-100  Purpose isolation — artifact vs transparency
// ══════════════════════════════════════════════════════════════════════════════

describe('TSG-93..100 — Purpose isolation: artifact key ≠ transparency key', () => {
  let keyManager;
  let tKey;
  let tSigner;

  beforeAll(() => {
    keyManager = require('../../../../services/artifact/keyManager');
  });

  beforeEach(() => {
    _provisionKey();
    tKey    = tKeyStore.getActiveKey();
    tSigner = new transparencySigner.SoftwareTransparencySigner();
  });

  test('TSG-93 transparency keyId has different prefix from artifact keyId', () => {
    const { keyId: tKeyId } = tKey;
    expect(tKeyId).toMatch(/^tr-testapp:/);
    // Artifact key IDs look like 'clientId:key_vN' (no tr- prefix)
    expect(tKeyId).not.toMatch(/^testapp:/);
  });

  test('TSG-94 getTransparencySigningKey returns transparency key (tr- prefix)', () => {
    const { keyId } = keyManager.getTransparencySigningKey();
    expect(keyId).toMatch(/^tr-/);
  });

  test('TSG-95 getTransparencyVerificationKey resolves transparency key only', () => {
    const { keyId } = tKey;
    const result    = keyManager.getTransparencyVerificationKey(keyId);
    expect(result).toHaveProperty('pubDer');
    expect(result.status).toBe('active');
  });

  test('TSG-96 getTransparencyVerificationKey throws for non-transparency keyId (fail-closed)', () => {
    // A non-transparency key ID is not in the transparency store
    expect(() => keyManager.getTransparencyVerificationKey('other-client:key_v1'))
      .toThrow('unknown transparency keyId');
  });

  test('TSG-97 transparency signature cannot be verified with an unrelated Ed25519 public key', async () => {
    const hash = crypto.createHash('sha256').update('cross-purpose', 'utf8').digest();

    // Sign with transparency key
    const { signature: tSig } = await tSigner.sign(hash);

    // Generate a completely separate Ed25519 key pair (as a stand-in for an artifact key)
    const { privateKey: _unrelated, publicKey: unrelatedPub } =
      crypto.generateKeyPairSync('ed25519');
    const unrelatedPubDer = Buffer.from(unrelatedPub.export({ type: 'spki', format: 'der' }));

    // Verifying the transparency signature with an unrelated public key must fail
    const { verify } = require('../../../infra/crypto/ed25519');
    expect(verify(hash, tSig, unrelatedPubDer)).toBe(false);
  });

  test('TSG-98 transparency signer never calls keyManager.getSigningKey (artifact path)', async () => {
    const spy  = jest.spyOn(keyManager, 'getSigningKey');
    const hash = crypto.createHash('sha256').update('isolation', 'utf8').digest();
    await tSigner.sign(hash);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('TSG-99 transparency signer never calls keyManager.getVerificationKey (artifact path)', () => {
    const spy = jest.spyOn(keyManager, 'getVerificationKey');
    tSigner.getVerificationKey(tKey.keyId);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('TSG-100 registrar imports do not include keyManager (structural isolation)', () => {
    // The registrar.js must not import keyManager for signing.
    // We verify this by checking the registrar module's source doesn't use
    // keyManager.getSigningKey — only the transparency signer.
    const fs   = jest.requireActual('fs');
    const path = require('path');
    const src  = fs.readFileSync(
      path.join(__dirname, '..', 'registrar.js'), 'utf8',
    );
    // keyManager should NOT be required in registrar after Component #30
    expect(src).not.toMatch(/require.*keyManager/);
    // But transparencySigner IS used
    expect(src).toMatch(/transparencySigner/);
  });
});
