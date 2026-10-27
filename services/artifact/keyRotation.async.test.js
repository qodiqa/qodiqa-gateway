'use strict';

/**
 * Key rotation lifecycle enhancements — Tests
 *
 * Coverage:
 *   KFP-01…04   Fingerprint computation
 *   KRA-01…04   rotateKeyAsync delegates to sync path when no native provider is active
 *   KRA-05…13   rotateKeyAsync with a native signing provider (Vault Transit / HSM style)
 * KRA-14 rotateKeyAsync vs. a concurrent reload on the same instance
 *   KRL-01…07   reloadFromDisk() — cross-instance / cluster-safety hot reload
 *   KHV-01…03   Historical verification survives async rotation
 *
 * rotateKey()/rotateKeyAsync() have no default mode — every
 * genuine rotation of an existing active key must pass opts.mode explicitly
 * as 'graceful' or 'emergency' (omitted/invalid throws; see keyStore.js's
 * "Rotation" section header). Tests that exercise the deprecate-and-keep-
 * verifiable behavior pass { mode: 'graceful' } explicitly
 * (rotateKeyGracefully()/rotateKeyGracefullyAsync() equivalent). Paired
 * '-EMERGENCY' tests pass { mode: 'emergency' } explicitly to exercise the
 * revoke-on-rotation behavior — no test relies on an implicit default.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-krot-test-'));
  return path.join(dir, 'keys.json');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

function loadFreshKeyStore(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../secrets/secretsProvider')._clearCache();
  return require('./keyStore');
}

// ═════════════════════════════════════════════════════════════════════════════
// KFP-01…04  Fingerprint computation
// ═════════════════════════════════════════════════════════════════════════════

describe('Fingerprint computation', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('KFP-01: rotateKey returns a fingerprint alongside keyId/version', () => {
    const result = ks.rotateKey('fp-client');
    expect(typeof result.fingerprint).toBe('string');
    expect(result.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  test('KFP-02: fingerprint is the SHA-256 hex digest of the public key DER', () => {
    const { fingerprint } = ks.rotateKey('fp-client-2');
    const key = ks.getActiveKey('fp-client-2');
    const expected = crypto.createHash('sha256').update(key.pubDer).digest('hex');
    expect(fingerprint).toBe(expected);
  });

  test('KFP-03: rotating again produces a different fingerprint (new key material)', () => {
    const first  = ks.rotateKey('fp-client-3');
    const second = ks.rotateKey('fp-client-3', { mode: 'emergency' });
    expect(second.fingerprint).not.toBe(first.fingerprint);
  });

  test('KFP-04: fingerprint is stable across a fresh load of the same file', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath);
    const { fingerprint } = ks1.rotateKey('fp-reload-client');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ks2 = require('./keyStore');
    const key2 = ks2.getActiveKey('fp-reload-client');
    const recomputed = crypto.createHash('sha256').update(key2.pubDer).digest('hex');
    expect(recomputed).toBe(fingerprint);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRA-01…04  rotateKeyAsync — local provider (default, no native signing)
// ═════════════════════════════════════════════════════════════════════════════

describe('rotateKeyAsync — local provider delegation', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('KRA-01: with no KMS provider configured, rotateKeyAsync behaves like the sync path', async () => {
    const result = await ks.rotateKeyAsync('async-local-client');
    expect(result.keyId).toBe('async-local-client:key_v1');
    expect(result.version).toBe(1);
    expect(typeof result.fingerprint).toBe('string');
  });

  test('KRA-02: rotateKeyAsync revokes the previous key on subsequent rotation', async () => {
    await ks.rotateKeyAsync('async-local-client-2');
    const result = await ks.rotateKeyAsync('async-local-client-2', { mode: 'emergency' });
    const keys = ks.getKeysByClient('async-local-client-2');
    const statuses = keys.map(k => k.status).sort();
    expect(statuses).toEqual(['active', 'revoked']);
    expect(result.mode).toBe('emergency');
    expect(result.previousKeyStatus).toBe('revoked');
  });

  test('KRA-02b: rotateKeyAsync deprecates (not revokes) the previous key when { mode: "graceful" } is explicit', async () => {
    await ks.rotateKeyAsync('async-local-client-2b');
    const result = await ks.rotateKeyAsync('async-local-client-2b', { mode: 'graceful' });
    const keys = ks.getKeysByClient('async-local-client-2b');
    const statuses = keys.map(k => k.status).sort();
    expect(statuses).toEqual(['active', 'deprecated']);
    expect(result.mode).toBe('graceful');
    expect(result.previousKeyStatus).toBe('deprecated');
  });

  test('KRA-03: rotateKeyAsync accepts reason/triggeredBy opts without altering the returned shape', async () => {
    const result = await ks.rotateKeyAsync('async-local-client-3', { reason: 'SCHEDULED_ROTATION', triggeredBy: 'scheduler' });
    expect(result).toEqual(expect.objectContaining({
      clientId: 'async-local-client-3', version: 1,
    }));
  });

  test('KRA-04: rotateKeyAsync rejects an invalid clientId', async () => {
    await expect(ks.rotateKeyAsync('')).rejects.toThrow(TypeError);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRA-05…12  rotateKeyAsync — native signing provider
// ═════════════════════════════════════════════════════════════════════════════

describe('rotateKeyAsync — native signing provider (Vault Transit / HSM style)', () => {
  let ks;
  let mockProvider;
  let keysPath;

  // Builds a NativeSigningProvider test double backed by genuinely matching
  // Ed25519 keypairs (per keyName), so sign()/verify() round-trips inside
  // keyStore.js's remote self-test are cryptographically real, not faked.
  // keyStore.js lazily requires keyProviderFactory via a relative path from
  // its own directory; jest.mock resolves by absolute path, so mocking the
  // same specifier from this co-located test file intercepts the same module.
  function _installMockKpf(providerOverrides = {}) {
    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const _pairs = {};

    mockProvider = {
      name: 'vault:transit:test',
      generateKeyPair: jest.fn(async (keyName) => {
        const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding:  { type: 'spki',  format: 'der' },
          privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });
        _pairs[keyName] = { priv: Buffer.from(priv), pub: Buffer.from(pub) };
        return { publicKeyDer: Buffer.from(pub), keyName };
      }),
      sign: jest.fn(async (keyName, messageHash) => {
        const pair = _pairs[keyName];
        if (!pair) throw new Error(`no key ${keyName} in mock provider`);
        return ed25519Sign(messageHash, pair.priv);
      }),
      deprecateKey: jest.fn(async () => {}),
      getRevocationCapabilities: jest.fn(() => ['disable']),
      revokeKey:    jest.fn(async (keyName, opts) => ({
        method: opts.method, provider: 'vault:transit:test',
        revokedAt: new Date().toISOString(), providerResponse: { disabled: true, keyName },
      })),
      ...providerOverrides,
    };

    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
  }

  beforeEach(() => {
    jest.resetModules();
    keysPath = makeTempPath();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    _installMockKpf();
    ks = require('./keyStore');
  });

  afterEach(() => {
    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });

  test('KRA-05: first provisioning calls provider.generateKeyPair and stores only the public key locally', async () => {
    const result = await ks.rotateKeyAsync('native-client');
    expect(mockProvider.generateKeyPair).toHaveBeenCalledWith('native-client:key_v1');
    const key = ks.getActiveKey('native-client');
    expect(key.privDer).toBeNull();
    expect(Buffer.isBuffer(key.pubDer)).toBe(true);
    expect(result.keyId).toBe('native-client:key_v1');
  });

  test('KRA-06: graceful-mode rotation on an existing native client generates a new key and deprecates the old one in the provider', async () => {
    await ks.rotateKeyAsync('native-client-2');
    await ks.rotateKeyAsync('native-client-2', { mode: 'graceful' });
    expect(mockProvider.generateKeyPair).toHaveBeenCalledWith('native-client-2:key_v2');
    expect(mockProvider.deprecateKey).toHaveBeenCalledWith('native-client-2:key_v1');
    expect(mockProvider.revokeKey).not.toHaveBeenCalled();
  });

  test('KRA-06-EMERGENCY: explicit emergency-mode rotation on an existing native client revokes the old key at the provider', async () => {
    await ks.rotateKeyAsync('native-client-2e');
    await ks.rotateKeyAsync('native-client-2e', { mode: 'emergency' });
    expect(mockProvider.generateKeyPair).toHaveBeenCalledWith('native-client-2e:key_v2');
    expect(mockProvider.revokeKey).toHaveBeenCalledWith('native-client-2e:key_v1', expect.objectContaining({ method: 'disable' }));
    expect(mockProvider.deprecateKey).not.toHaveBeenCalled();
  });

  test('KRA-07: graceful-mode local bookkeeping mirrors the provider — old key deprecated, new key active', async () => {
    await ks.rotateKeyAsync('native-client-3');
    await ks.rotateKeyAsync('native-client-3', { mode: 'graceful' });
    const keys = ks.getKeysByClient('native-client-3');
    const active     = keys.find(k => k.status === 'active');
    const deprecated = keys.find(k => k.status === 'deprecated');
    expect(active.keyId).toBe('native-client-3:key_v2');
    expect(deprecated.keyId).toBe('native-client-3:key_v1');
  });

  test('KRA-07-EMERGENCY: explicit emergency-mode local bookkeeping mirrors the provider — old key revoked, new key active', async () => {
    await ks.rotateKeyAsync('native-client-3e');
    await ks.rotateKeyAsync('native-client-3e', { mode: 'emergency' });
    const keys = ks.getKeysByClient('native-client-3e');
    const active  = keys.find(k => k.status === 'active');
    const revoked = keys.find(k => k.status === 'revoked');
    expect(active.keyId).toBe('native-client-3e:key_v2');
    expect(revoked.keyId).toBe('native-client-3e:key_v1');

    const inventoryEntry = ks.getInventory().entries.find(e => e.keyId === 'native-client-3e:key_v1');
    expect(inventoryEntry.nativeRevocation).toEqual(expect.objectContaining({ attempted: true, success: true, provider: 'vault:transit:test' }));
  });

  test('KRA-08: remote self-test failure (provider returns a bad signature) aborts before activation', async () => {
    _installMockKpf({});
    mockProvider.sign = jest.fn(async () => Buffer.alloc(64, 0)); // garbage signature
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksBad = require('./keyStore');
    await expect(ksBad.rotateKeyAsync('native-selftest-fail')).rejects.toThrow(/self-test failed/);
    // Fail-closed: no client bucket should have been created for a key that never passed self-test.
    expect(ksBad.getKeysByClient('native-selftest-fail')).toEqual([]);
  });

  test('KRA-09: provider-side deprecate failure aborts a graceful-mode rotation — old key remains sole active key', async () => {
    await ks.rotateKeyAsync('native-client-4');
    mockProvider.deprecateKey = jest.fn(async () => { throw new Error('vault unreachable'); });

    await expect(ks.rotateKeyAsync('native-client-4', { mode: 'graceful' })).rejects.toThrow('vault unreachable');

    const keys = ks.getKeysByClient('native-client-4');
    expect(keys).toHaveLength(1);
    expect(keys[0].status).toBe('active');
    expect(keys[0].keyId).toBe('native-client-4:key_v1');
  });

  test('KRA-09-EMERGENCY: provider-side revoke failure aborts an explicit emergency-mode rotation — old key remains sole active key', async () => {
    await ks.rotateKeyAsync('native-client-4e');
    mockProvider.revokeKey = jest.fn(async () => { throw new Error('vault unreachable'); });

    await expect(ks.rotateKeyAsync('native-client-4e', { mode: 'emergency' })).rejects.toThrow('vault unreachable');

    const keys = ks.getKeysByClient('native-client-4e');
    expect(keys).toHaveLength(1);
    expect(keys[0].status).toBe('active');
    expect(keys[0].keyId).toBe('native-client-4e:key_v1');
  });

  test('KRA-09b-EMERGENCY: provider declaring no revocation capability aborts an explicit emergency-mode rotation without touching local state', async () => {
    await ks.rotateKeyAsync('native-client-4f');
    mockProvider.getRevocationCapabilities = jest.fn(() => []);

    await expect(ks.rotateKeyAsync('native-client-4f', { mode: 'emergency' })).rejects.toThrow(/no supported revocation method/);

    const keys = ks.getKeysByClient('native-client-4f');
    expect(keys).toHaveLength(1);
    expect(keys[0].status).toBe('active');
  });

  test('KRA-10: fingerprint is computed for native-provider keys too', async () => {
    const result = await ks.rotateKeyAsync('native-client-5');
    expect(result.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  test('KRA-11: KEY_ROTATED audit event for a native rotation includes the provider name', async () => {
    const emitted = [];
    jest.doMock('../logger', () => ({ emit: (...args) => emitted.push(args) }));
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksLogged = require('./keyStore');
    await ksLogged.rotateKeyAsync('native-client-6');
    await ksLogged.rotateKeyAsync('native-client-6', { mode: 'emergency' });
    const rotatedEvent = emitted.find(([, name]) => name === 'KEY_ROTATED');
    expect(rotatedEvent[2]).toEqual(expect.objectContaining({ provider: 'vault:transit:test' }));
    jest.dontMock('../logger');
  });

  test('KRA-12: getSigningKey continues to report nativeSigning:true after an async rotation', async () => {
    const keyManager = require('./keyManager');
    await ks.rotateKeyAsync('native-client-7');
    const signingKey = keyManager.getSigningKey('native-client-7');
    expect(signingKey.nativeSigning).toBe(true);
    expect(signingKey.privDer).toBeNull();
  });

  test('KRA-13: a native-provider active key survives a fresh module load (process restart) without error', async () => {
    // Regression guard: an active key whose private material lives entirely
    // in the NativeSigningProvider persists no encryptedPrivateKeyDer (by
    // design — see saveKeys()'s `nativeKey: true` marker). Before that
    // marker existed, _tryLoadFromFile() treated the absence of any private
    // key field on an active record as file corruption and threw — meaning
    // ANY restart (not just cross-instance reload) of a native-provider
    // deployment would fail closed at startup after the first rotation.
    await ks.rotateKeyAsync('native-restart-client');
    await ks.rotateKeyAsync('native-restart-client', { mode: 'graceful' }); // exercise the deprecate+activate path too

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksRestarted = require('./keyStore');

    // Must not throw — this is the exact call server.js makes at startup.
    expect(() => ksRestarted.validateKeyStore()).not.toThrow();

    const active = ksRestarted.getActiveKey('native-restart-client');
    expect(active.keyId).toBe('native-restart-client:key_v2');
    expect(active.privDer).toBeNull();

    // Lifecycle timestamps from the original rotation must be preserved
    // across the restart, not silently reset to "now".
    const [rec] = ksRestarted.getKeysByClient('native-restart-client').filter(k => k.status === 'active');
    expect(rec.createdAt).toBeTruthy();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // CRYPTO-1 (=KEY-5): rotation alone — no explicit revocation — must make the
  // outgoing key immediately and permanently unable to sign through the
  // official API. KRV-06 (keyRevocation.async.test.js) proves this for an
  // explicitly REVOKED key; KRA-15 below proves the same fail-closed signing
  // enforcement fires for a graceful-mode DEPRECATED (rotated-away) key.
  // KRA-15-EMERGENCY proves the actual fix: the DEFAULT rotation mode
  // blocks VERIFICATION too, not just signing — closing the original finding
  // ("rotation alone does not stop signature acceptance").
  // ═══════════════════════════════════════════════════════════════════════════

  test('KRA-15: nativeSignLocked refuses a graceful-mode-deprecated key, which nonetheless still verifies', async () => {
    const { keyId: oldKeyId } = await ks.rotateKeyAsync('native-client-9');
    await ks.rotateKeyAsync('native-client-9', { mode: 'graceful' }); // deprecates oldKeyId, activates v2

    const [rec] = ks.getKeysByClient('native-client-9').filter(k => k.keyId === oldKeyId);
    expect(rec.status).toBe('deprecated'); // never touched revokeKeyAsync

    // mockProvider.sign was already legitimately called with oldKeyId once —
    // rotateKeyAsync's own remote self-test signs a probe with a key at the
    // moment it is CREATED (while still active), before the second rotation
    // ever deprecates it. Snapshot the call count here rather than asserting
    // "never called with oldKeyId" globally, so this test asserts the right
    // thing: the REJECTED post-rotation attempt below must never reach the
    // provider, not that the key was never legitimately signed with while active.
    const signCallsBeforeForgedAttempt = mockProvider.sign.mock.calls.length;

    await expect(
      ks.nativeSignLocked(oldKeyId, crypto.createHash('sha256').update('forged').digest()),
    ).rejects.toThrow(/not active/);

    // The rejected call must never have reached the provider at all.
    expect(mockProvider.sign.mock.calls.length).toBe(signCallsBeforeForgedAttempt);

    // Deprecated is verification-only, by explicit opt-in — this is the one
    // legitimate case where the outgoing key remains resolvable.
    expect(() => ks.getPublicKey(oldKeyId)).not.toThrow();
  });

  test('KRA-15-EMERGENCY: default-mode rotation blocks BOTH signing and verification of the outgoing key immediately', async () => {
    const { keyId: oldKeyId } = await ks.rotateKeyAsync('native-client-9e');
    await ks.rotateKeyAsync('native-client-9e', { mode: 'emergency' }); // revokes oldKeyId

    const [rec] = ks.getKeysByClient('native-client-9e').filter(k => k.keyId === oldKeyId);
    expect(rec.status).toBe('revoked');

    const signCallsBeforeForgedAttempt = mockProvider.sign.mock.calls.length;
    await expect(
      ks.nativeSignLocked(oldKeyId, crypto.createHash('sha256').update('forged').digest()),
    ).rejects.toThrow(/not active/);
    expect(mockProvider.sign.mock.calls.length).toBe(signCallsBeforeForgedAttempt);

    // This is the actual finding: before this remediation, rotation
    // alone left the outgoing key fully able to verify. It must not anymore.
    expect(() => ks.getPublicKey(oldKeyId)).toThrow(/revoked/);
    expect(() => ks.getKey('native-client-9e', oldKeyId)).toThrow(/revoked/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRA-14 rotateKeyAsync vs. a concurrent reload on the SAME instance
// ═════════════════════════════════════════════════════════════════════════════
//
// See the equivalent KRV-18 test in keyRevocation.async.test.js for the full
// rationale: decoupled trust-store reload from rotation, so reload now
// runs on its own timer regardless of the caller, and can interleave with
// any in-flight native-provider round-trip on this same instance. Before the
// fix (services/artifact/keyStore.js `_liveClientStore()`), rotateKeyAsync's
// deprecate/activate writes went through a `_store[cid]` reference captured
// before `await provider.deprecateKey(...)` — if a reload swapped `_store`
// during that await, the rotation's result was silently orphaned: never
// persisted, never visible to any reader, while the provider had ALREADY
// deprecated the old key — the worst outcome, since it leaves the client
// unable to sign at all until manually recovered.

describe('rotateKeyAsync vs. concurrent reload on the same instance', () => {
  test('KRA-14: a reload firing mid-rotation does not orphan the new active key', async () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();

    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const _pairs = {};
    const deprecateGate = (() => {
      let resolve;
      const promise = new Promise(r => { resolve = r; });
      return { promise, resolve };
    })();

    const mockProvider = {
      name: 'vault:transit:test',
      generateKeyPair: jest.fn(async (keyName) => {
        const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding:  { type: 'spki',  format: 'der' },
          privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });
        _pairs[keyName] = { priv: Buffer.from(priv), pub: Buffer.from(pub) };
        return { publicKeyDer: Buffer.from(pub), keyName };
      }),
      sign: jest.fn(async (keyName, messageHash) => ed25519Sign(messageHash, _pairs[keyName].priv)),
      // Blocks until the test releases it — the window during which the
      // test simulates this instance's own independent reload timer firing
      // while the rotation is still in flight.
      deprecateKey: jest.fn(async () => { await deprecateGate.promise; }),
      getRevocationCapabilities: jest.fn(() => ['disable']),
      revokeKey: jest.fn(async (keyName, opts) => ({ method: opts.method, provider: 'vault:transit:test', revokedAt: new Date().toISOString() })),
    };
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));

    const ks = require('./keyStore');
    await ks.rotateKeyAsync('rotate-race-client'); // v1

    // Explicit graceful mode: this test's mock blocks on deprecateKey() to
    // create the race window, so it must exercise the code path that calls
    // deprecateKey() (graceful mode) rather than the emergency default's
    // revokeKey() call — see KRA-14-EMERGENCY below for the twin coverage of
    // the emergency-mode provider round trip under the same race.
    const rotatePromise = ks.rotateKeyAsync('rotate-race-client', { mode: 'graceful' }); // v2, will block on deprecateKey

    // Let rotateKeyAsync reach `await provider.deprecateKey(activeId)`.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    // Simulate this instance's independent reload timer firing mid-rotation.
    const reloadResult = ks.reloadFromDisk();
    expect(reloadResult.reloaded).toBe(true);

    deprecateGate.resolve();
    const result = await rotatePromise;
    expect(result.keyId).toBe('rotate-race-client:key_v2');

    // The new key must be live in THIS instance's store, not orphaned...
    const keys = ks.getKeysByClient('rotate-race-client');
    const active     = keys.find(k => k.status === 'active');
    const deprecated = keys.find(k => k.status === 'deprecated');
    expect(active).toBeDefined();
    expect(active.keyId).toBe('rotate-race-client:key_v2');
    expect(deprecated).toBeDefined();
    expect(deprecated.keyId).toBe('rotate-race-client:key_v1');

    // ...and durably persisted, so every OTHER instance's reload sees it too.
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ksReloaded = require('./keyStore');
    const diskActive = ksReloaded.getKeysByClient('rotate-race-client').find(k => k.status === 'active');
    expect(diskActive.keyId).toBe('rotate-race-client:key_v2');

    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });

  test('KRA-14-EMERGENCY: a reload firing mid-rotation does not orphan the new active key under the default (revoke) provider round trip', async () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();

    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const _pairs = {};
    const revokeGate = (() => {
      let resolve;
      const promise = new Promise(r => { resolve = r; });
      return { promise, resolve };
    })();

    const mockProvider = {
      name: 'vault:transit:test',
      generateKeyPair: jest.fn(async (keyName) => {
        const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding:  { type: 'spki',  format: 'der' },
          privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });
        _pairs[keyName] = { priv: Buffer.from(priv), pub: Buffer.from(pub) };
        return { publicKeyDer: Buffer.from(pub), keyName };
      }),
      sign: jest.fn(async (keyName, messageHash) => ed25519Sign(messageHash, _pairs[keyName].priv)),
      deprecateKey: jest.fn(async () => {}),
      getRevocationCapabilities: jest.fn(() => ['disable']),
      // Blocks until the test releases it — same race window as KRA-14, but
      // on the default 'emergency' mode's provider call.
      revokeKey: jest.fn(async (keyName, opts) => {
        await revokeGate.promise;
        return { method: opts.method, provider: 'vault:transit:test', revokedAt: new Date().toISOString() };
      }),
    };
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));

    const ks = require('./keyStore');
    await ks.rotateKeyAsync('rotate-race-client-e'); // v1

    const rotatePromise = ks.rotateKeyAsync('rotate-race-client-e', { mode: 'emergency' }); // v2, will block on revokeKey

    // Let rotateKeyAsync reach `await provider.revokeKey(activeId, ...)`.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    const reloadResult = ks.reloadFromDisk();
    expect(reloadResult.reloaded).toBe(true);

    revokeGate.resolve();
    const result = await rotatePromise;
    expect(result.keyId).toBe('rotate-race-client-e:key_v2');

    const keys    = ks.getKeysByClient('rotate-race-client-e');
    const active  = keys.find(k => k.status === 'active');
    const revoked = keys.find(k => k.status === 'revoked');
    expect(active).toBeDefined();
    expect(active.keyId).toBe('rotate-race-client-e:key_v2');
    expect(revoked).toBeDefined();
    expect(revoked.keyId).toBe('rotate-race-client-e:key_v1');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ksReloaded = require('./keyStore');
    const diskActive = ksReloaded.getKeysByClient('rotate-race-client-e').find(k => k.status === 'active');
    expect(diskActive.keyId).toBe('rotate-race-client-e:key_v2');

    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRL-01…07  reloadFromDisk() — cross-instance hot reload
// ═════════════════════════════════════════════════════════════════════════════

describe('reloadFromDisk — cross-instance visibility', () => {
  test('KRL-01: reload with no file on disk is a safe no-op', () => {
    const ks = loadFreshKeyStore(makeTempPath());
    const result = ks.reloadFromDisk();
    expect(result.reloaded).toBe(false);
    expect(result.error).toBeNull();
  });

  test('KRL-02: reload picks up a rotation written by a different process to the same file', () => {
    const keysPath = makeTempPath();
    const ksA = loadFreshKeyStore(keysPath);
    ksA.rotateKey('shared-client');

    // Simulate a second instance ("ksB") performing a rotation and persisting it.
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ksB = require('./keyStore');
    const { keyId: newKeyId } = ksB.rotateKey('shared-client', { mode: 'emergency' });

    // ksA has not restarted — its in-memory store still only knows about v1
    // until it reloads.
    const before = ksA.getKeysByClient('shared-client');
    expect(before.some(k => k.keyId === newKeyId)).toBe(false);

    const result = ksA.reloadFromDisk();
    expect(result.reloaded).toBe(true);

    const after = ksA.getKeysByClient('shared-client');
    expect(after.some(k => k.keyId === newKeyId)).toBe(true);
  });

  test('KRL-03: reload never partially replaces the store on a corrupt file — old state is retained', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath);
    ks.rotateKey('corrupt-test-client');
    const before = ks.getKeysByClient('corrupt-test-client');

    fs.writeFileSync(keysPath, '{ not valid json', 'utf8');

    const result = ks.reloadFromDisk();
    expect(result.reloaded).toBe(false);
    expect(result.error).toBeTruthy();

    const after = ks.getKeysByClient('corrupt-test-client');
    expect(after).toEqual(before);
  });

  test('KRL-04: after reload, the new active key is immediately usable for signing (getActiveKey)', () => {
    const keysPath = makeTempPath();
    const ksA = loadFreshKeyStore(keysPath);
    ksA.rotateKey('signing-after-reload');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ksB = require('./keyStore');
    const { keyId: newKeyId } = ksB.rotateKey('signing-after-reload', { mode: 'emergency' });

    ksA.reloadFromDisk();
    const active = ksA.getActiveKey('signing-after-reload');
    expect(active.keyId).toBe(newKeyId);
    expect(Buffer.isBuffer(active.privDer)).toBe(true);
  });

  test('KRL-05: reload is safe to call repeatedly with no changes on disk', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath);
    ks.rotateKey('idempotent-reload-client');
    const r1 = ks.reloadFromDisk();
    const r2 = ks.reloadFromDisk();
    expect(r1.reloaded).toBe(true);
    expect(r2.reloaded).toBe(true);
    expect(ks.getKeysByClient('idempotent-reload-client')).toHaveLength(1);
  });

  test('KRL-06: reload does not resurrect a client deleted from disk by another process', () => {
    // Not a supported operational flow (keys are never manually deleted from
    // the file), but the reload path must not crash if a client bucket
    // disappears — it should simply reflect what is currently on disk.
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath);
    ks.rotateKey('will-disappear');
    expect(ks.getKeysByClient('will-disappear')).toHaveLength(1);

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    delete raw.clients['will-disappear'];
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    ks.reloadFromDisk();
    expect(ks.getKeysByClient('will-disappear')).toEqual([]);
  });

  test('KRL-07: KEYSTORE_RELOADED audit event reports client/active counts', () => {
    const emitted = [];
    jest.doMock('../logger', () => ({ emit: (...args) => emitted.push(args) }));
    jest.resetModules();
    const keysPath = makeTempPath();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ks = require('./keyStore');
    ks.rotateKey('reload-audit-client');
    ks.reloadFromDisk();
    const reloadedEvent = emitted.find(([, name]) => name === 'KEYSTORE_RELOADED');
    expect(reloadedEvent[2]).toEqual(expect.objectContaining({ clients: expect.any(Number), active: expect.any(Number) }));
    jest.dontMock('../logger');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KHV-01…03  Historical verification survives async rotation
// ═════════════════════════════════════════════════════════════════════════════

describe('Historical verification after async rotation', () => {
  test('KHV-01: a graceful-mode-deprecated (pre-rotation) key remains resolvable via getPublicKey', async () => {
    const ks = loadFreshKeyStore(makeTempPath());
    const { keyId: oldKeyId } = await ks.rotateKeyAsync('hv-client');
    await ks.rotateKeyAsync('hv-client', { mode: 'graceful' });
    const { pubDer, status } = ks.getPublicKey(oldKeyId);
    expect(status).toBe('deprecated');
    expect(Buffer.isBuffer(pubDer)).toBe(true);
  });

  test('KHV-01-EMERGENCY: the explicit-emergency-revoked (pre-rotation) key is NOT resolvable via getPublicKey', async () => {
    const ks = loadFreshKeyStore(makeTempPath());
    const { keyId: oldKeyId } = await ks.rotateKeyAsync('hv-client-e');
    await ks.rotateKeyAsync('hv-client-e', { mode: 'emergency' });
    expect(() => ks.getPublicKey(oldKeyId)).toThrow(/revoked/);
  });

  test('KHV-02: an artifact-style signature made with the old key still verifies after a graceful-mode rotation', async () => {
    const { verify: ed25519Verify } = require('../../src/infra/crypto/ed25519');
    const ks = loadFreshKeyStore(makeTempPath());
    await ks.rotateKeyAsync('hv-client-2');
    const oldKey = ks.getActiveKey('hv-client-2');
    const message = crypto.createHash('sha256').update('some artifact payload').digest();
    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const sig = ed25519Sign(message, oldKey.privDer);

    await ks.rotateKeyAsync('hv-client-2', { mode: 'graceful' }); // rotate away from oldKey

    const { pubDer } = ks.getPublicKey(oldKey.keyId);
    expect(ed25519Verify(message, sig, pubDer)).toBe(true);
  });

  test('KHV-02-EMERGENCY: an artifact-style signature made with the old key can no longer be resolved for verification after explicit emergency-mode rotation', async () => {
    const ks = loadFreshKeyStore(makeTempPath());
    await ks.rotateKeyAsync('hv-client-2e');
    const oldKey = ks.getActiveKey('hv-client-2e');
    const message = crypto.createHash('sha256').update('some artifact payload').digest();
    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const sig = ed25519Sign(message, oldKey.privDer);
    void sig; // the signature itself is still mathematically valid — the point is it can no longer be resolved to a trusted key at all

    await ks.rotateKeyAsync('hv-client-2e', { mode: 'emergency' }); // revokes oldKey

    // This is precisely the scenario: even a signature that WOULD
    // verify (produced by the legitimate holder before rotation, or forged
    // by an attacker who stole the key material) can no longer be resolved
    // to a trusted key at all — resolution fails before Ed25519 verification
    // is ever attempted.
    expect(() => ks.getPublicKey(oldKey.keyId)).toThrow(/revoked/);
  });

  test('KHV-03: a rotation-revoked key stays excluded from verification even after reload', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath);
    const { keyId } = ks.rotateKey('hv-client-3');
    ks.rotateKey('hv-client-3', { mode: 'emergency' }); // revokes keyId, activates v2
    ks.revokeKey(keyId); // idempotent — already revoked by rotation
    ks.reloadFromDisk();
    expect(() => ks.getPublicKey(keyId)).toThrow(/revoked/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRM-01…10 Part 7 — rotation mode is mandatory, no implicit default
//
// Every case below rotates an EXISTING active key (the only branch where a
// mode decision is meaningful — first-time provisioning and no-active-key
// recovery never call _resolveRotationMode() at all, since there is no
// outgoing key for a mode to apply to; see keyStore.js's "Rotation" header).
// ═════════════════════════════════════════════════════════════════════════════

describe('Part 7 — rotation mode is mandatory (sync rotateKey)', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('KRM-01: first-time provisioning (no opts at all) still succeeds — no mode decision applies', () => {
    expect(() => ks.rotateKey('krm-provision')).not.toThrow();
  });

  const invalidModeCases = [
    ['omitted entirely (no opts object)', undefined],
    ['opts with no mode key',              {}],
    ['null mode',                          { mode: null }],
    ['undefined mode',                     { mode: undefined }],
    ['empty string mode',                  { mode: '' }],
    ['unknown string mode',                { mode: 'planned' }],
    ['case-mismatched mode',               { mode: 'Emergency' }],
    ['numeric mode',                       { mode: 1 }],
    ['boolean mode',                       { mode: true }],
    ['object mode',                        { mode: { mode: 'emergency' } }],
  ];

  test.each(invalidModeCases)('KRM-02 rotating an EXISTING active key with %s throws', (_label, opts) => {
    ks.rotateKey('krm-existing'); // provision — no mode needed
    expect(() => ks.rotateKey('krm-existing', opts)).toThrow(TypeError);
    expect(() => ks.rotateKey('krm-existing', opts)).toThrow(/opts\.mode is required/);
  });

  test('KRM-03: throwing on an invalid mode never mutates the key store', () => {
    ks.rotateKey('krm-unmutated');
    const before = ks.getKeysByClient('krm-unmutated');
    try { ks.rotateKey('krm-unmutated'); } catch {}
    const after = ks.getKeysByClient('krm-unmutated');
    expect(after).toEqual(before);
  });

  test('KRM-04: mode: "emergency" explicitly succeeds and revokes the outgoing key', () => {
    ks.rotateKey('krm-emergency');
    const result = ks.rotateKey('krm-emergency', { mode: 'emergency' });
    expect(result.mode).toBe('emergency');
    expect(result.previousKeyStatus).toBe('revoked');
  });

  test('KRM-05: mode: "graceful" explicitly succeeds and deprecates the outgoing key', () => {
    ks.rotateKey('krm-graceful');
    const result = ks.rotateKey('krm-graceful', { mode: 'graceful' });
    expect(result.mode).toBe('graceful');
    expect(result.previousKeyStatus).toBe('deprecated');
  });

  test('KRM-06: rotateKeyGracefully() never needs an explicit mode — it always supplies graceful internally', () => {
    ks.rotateKey('krm-graceful-helper');
    expect(() => ks.rotateKeyGracefully('krm-graceful-helper')).not.toThrow();
  });
});

describe('Part 7 — rotation mode is mandatory (async rotateKeyAsync)', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('KRM-07: first-time provisioning (no opts at all) still succeeds — no mode decision applies', async () => {
    await expect(ks.rotateKeyAsync('krm-async-provision')).resolves.toBeDefined();
  });

  test.each([
    ['omitted entirely', undefined],
    ['opts with no mode key', {}],
    ['null mode', { mode: null }],
    ['empty string mode', { mode: '' }],
    ['unknown string mode', { mode: 'emergency-ish' }],
  ])('KRM-08 rotating an EXISTING active key async with %s rejects', async (_label, opts) => {
    await ks.rotateKeyAsync('krm-async-existing'); // provision
    await expect(ks.rotateKeyAsync('krm-async-existing', opts)).rejects.toThrow(TypeError);
  });

  test('KRM-09: rejecting on an invalid mode never mutates the key store', async () => {
    await ks.rotateKeyAsync('krm-async-unmutated');
    const before = ks.getKeysByClient('krm-async-unmutated');
    try { await ks.rotateKeyAsync('krm-async-unmutated'); } catch {}
    const after = ks.getKeysByClient('krm-async-unmutated');
    expect(after).toEqual(before);
  });

  test('KRM-10: rotateKeyGracefullyAsync() never needs an explicit mode — it always supplies graceful internally', async () => {
    await ks.rotateKeyAsync('krm-async-graceful-helper');
    await expect(ks.rotateKeyGracefullyAsync('krm-async-graceful-helper')).resolves.toBeDefined();
  });
});
