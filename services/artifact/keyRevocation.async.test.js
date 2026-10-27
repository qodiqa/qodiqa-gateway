'use strict';

/**
 * remediation — Tests
 *
 * Native-signing revocation must propagate to the underlying cryptographic
 * provider (Vault Transit / HSM), not just update local metadata.
 *
 * Coverage:
 *   KRV-01…04   revokeKeyAsync — local provider (no native signing configured)
 *   KRV-05…12   revokeKeyAsync — native signing provider (capability negotiation,
 *               success, failure, unsupported capability, idempotency, audit)
 *   KRV-13…14   sync revokeKey() — backward compatibility / native-mode guard
 *   KRV-15…17   nativeSignLocked — revoke/sign concurrency
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-krev-test-'));
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

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

// ═════════════════════════════════════════════════════════════════════════════
// KRV-01…04  revokeKeyAsync — local provider (no native signing)
// ═════════════════════════════════════════════════════════════════════════════

describe('revokeKeyAsync — local provider (no native signing configured)', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('KRV-01: revokes and stamps nativeRevocation as not attempted/not supported', async () => {
    const { keyId } = await ks.rotateKeyAsync('local-client-1');
    const result = await ks.revokeKeyAsync(keyId);
    expect(result.status).toBe('revoked');
    expect(result.nativeRevocation).toEqual(expect.objectContaining({
      attempted: false,
      supported: false,
      reason:    'NO_NATIVE_SIGNING_PROVIDER_CONFIGURED',
    }));
  });

  test('KRV-02: a revoked key is never again returned as the active key', async () => {
    const { keyId } = await ks.rotateKeyAsync('local-client-2');
    await ks.revokeKeyAsync(keyId);
    expect(() => ks.getActiveKey('local-client-2')).toThrow(/no active key/);
  });

  test('KRV-03: revoking an already-revoked key is idempotent', async () => {
    const { keyId } = await ks.rotateKeyAsync('local-client-3');
    await ks.revokeKeyAsync(keyId);
    const second = await ks.revokeKeyAsync(keyId);
    expect(second.alreadyRevoked).toBe(true);
    expect(second.status).toBe('revoked');
  });

  test('KRV-04: revoking an unknown keyId rejects', async () => {
    await expect(ks.revokeKeyAsync('local-client-4:key_v99')).rejects.toThrow(/unknown keyId/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRV-05…12  revokeKeyAsync — native signing provider
// ═════════════════════════════════════════════════════════════════════════════

describe('revokeKeyAsync — native signing provider (Vault Transit / HSM style)', () => {
  let ks;
  let mockProvider;
  let keysPath;

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
      getRevocationCapabilities: jest.fn(() => ['destroy', 'disable']),
      revokeKey: jest.fn(async (keyName, opts) => ({
        method:   opts.method,
        provider: 'vault:transit:test',
        revokedAt: new Date().toISOString(),
        providerResponse: { deleted: true, keyName },
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

  test('KRV-05: revokeKeyAsync calls provider.revokeKey with the strongest supported method', async () => {
    const { keyId } = await ks.rotateKeyAsync('native-client-1');
    await ks.revokeKeyAsync(keyId);
    expect(mockProvider.revokeKey).toHaveBeenCalledWith(keyId, { method: 'destroy' });
  });

  test('KRV-06: on success, local record reflects the provider outcome and the key can never sign again', async () => {
    const { keyId } = await ks.rotateKeyAsync('native-client-2');
    const result = await ks.revokeKeyAsync(keyId);
    expect(result.nativeRevocation).toEqual(expect.objectContaining({
      attempted: true, supported: true, provider: 'vault:transit:test', method: 'destroy', success: true,
    }));
    expect(() => ks.getActiveKey('native-client-2')).toThrow(/no active key/);
    await expect(ks.nativeSignLocked(keyId, crypto.createHash('sha256').update('x').digest()))
      .rejects.toThrow(/not active/);
  });

  test('KRV-07: capability negotiation — a provider that only supports "disable" uses that method', async () => {
    _installMockKpf({ getRevocationCapabilities: jest.fn(() => ['disable']) });
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksLimited = require('./keyStore');

    const { keyId } = await ksLimited.rotateKeyAsync('native-client-3');
    const result = await ksLimited.revokeKeyAsync(keyId);
    expect(mockProvider.revokeKey).toHaveBeenCalledWith(keyId, { method: 'disable' });
    expect(result.nativeRevocation.method).toBe('disable');
  });

  test('KRV-08: provider revocation failure rejects, but the key stays locally revoked (fail-closed)', async () => {
    mockProvider.revokeKey = jest.fn(async () => { throw new Error('vault unreachable'); });
    const { keyId } = await ks.rotateKeyAsync('native-client-4');

    await expect(ks.revokeKeyAsync(keyId)).rejects.toMatchObject({ code: 'NATIVE_REVOCATION_FAILED' });

    // Fail-closed: QODIQA will never sign with this key again locally, even
    // though the provider revocation failed.
    expect(() => ks.getActiveKey('native-client-4')).toThrow(/no active key/);
    const [rec] = ks.getKeysByClient('native-client-4');
    expect(rec.status).toBe('revoked');
  });

  test('KRV-09: a provider with no supported revocation methods is refused explicitly, without falsely marking the key revoked', async () => {
    _installMockKpf({ getRevocationCapabilities: jest.fn(() => []) });
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksUnsupported = require('./keyStore');

    const { keyId } = await ksUnsupported.rotateKeyAsync('native-client-5');
    await expect(ksUnsupported.revokeKeyAsync(keyId)).rejects.toThrow(/no supported revocation method/);

    // Explicit, not silent: the key must NOT be reported as revoked when
    // QODIQA cannot back that claim up at the provider boundary.
    const active = ksUnsupported.getActiveKey('native-client-5');
    expect(active.keyId).toBe(keyId);
    expect(mockProvider.revokeKey).not.toHaveBeenCalled();
  });

  test('KRV-10: revoking an already-revoked native key does not re-invoke the provider', async () => {
    const { keyId } = await ks.rotateKeyAsync('native-client-6');
    await ks.revokeKeyAsync(keyId);
    expect(mockProvider.revokeKey).toHaveBeenCalledTimes(1);
    const second = await ks.revokeKeyAsync(keyId);
    expect(second.alreadyRevoked).toBe(true);
    expect(mockProvider.revokeKey).toHaveBeenCalledTimes(1);
  });

  test('KRV-11: KEY_REVOKED_NATIVE_SUCCESS audit event carries the full evidence set', async () => {
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

    const { keyId } = await ksLogged.rotateKeyAsync('native-client-7');
    await ksLogged.revokeKeyAsync(keyId, { reason: 'compromised', operator: 'operator:alice' });

    const [, , fields] = emitted.find(([, name]) => name === 'KEY_REVOKED_NATIVE_SUCCESS');
    expect(fields).toEqual(expect.objectContaining({
      clientId: 'native-client-7',
      keyId,
      provider: 'vault:transit:test',
      method:   'destroy',
      reason:   'compromised',
      operator: 'operator:alice',
      providerResponse: expect.objectContaining({ deleted: true }),
    }));

    jest.dontMock('../logger');
  });

  test('KRV-12: KEY_REVOKED_NATIVE_FAILED audit event carries the failure detail', async () => {
    const emitted = [];
    jest.doMock('../logger', () => ({ emit: (...args) => emitted.push(args) }));
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    _installMockKpf({ revokeKey: jest.fn(async () => { throw new Error('permission denied'); }) });
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ksLogged = require('./keyStore');

    const { keyId } = await ksLogged.rotateKeyAsync('native-client-8');
    await expect(ksLogged.revokeKeyAsync(keyId)).rejects.toThrow(/permission denied/);

    const [level, , fields] = emitted.find(([, name]) => name === 'KEY_REVOKED_NATIVE_FAILED');
    expect(level).toBe('ERROR');
    expect(fields).toEqual(expect.objectContaining({
      clientId: 'native-client-8',
      keyId,
      provider: 'vault:transit:test',
      method:   'destroy',
      error:    expect.stringContaining('permission denied'),
    }));

    jest.dontMock('../logger');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRV-18 revokeKeyAsync vs. a concurrent reload on the SAME instance
// ═════════════════════════════════════════════════════════════════════════════
//
// decoupled trust-store reload from rotation, so reload now runs on a
// timer independent of the caller. That reload can interleave with any
// in-flight async operation on this same instance — in particular, the
// native-provider round-trip inside revokeKeyAsync(). Before this test was
// written, revokeKeyAsync captured `_store[clientId]` once at the top of its
// locked callback and kept writing through that reference after `await
// provider.revokeKey(...)`. If reloadFromDisk() reassigned `_store` to a new
// object graph during that await, the post-provider-response write (the one
// that records success/failure and the provider's response) landed on the
// orphaned pre-reload object — silently discarded, even though the function
// still resolved successfully with the correct in-memory return value. This
// verifies the fix (services/artifact/keyStore.js `_liveClientStore()`):
// the outcome must survive being interleaved with a reload.

describe('revokeKeyAsync vs. concurrent reload on the same instance', () => {
  test('KRV-18: a reload firing mid-revocation does not discard the native-provider outcome', async () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();

    const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
    const _pairs = {};
    const revokeGate = deferred();

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
      getRevocationCapabilities: jest.fn(() => ['destroy']),
      // Blocks until the test explicitly releases it — this is the window
      // during which the test simulates this instance's own reload timer
      // firing concurrently with the in-flight revocation.
      revokeKey: jest.fn(async (keyName, opts) => {
        await revokeGate.promise;
        return {
          method: opts.method, provider: 'vault:transit:test',
          revokedAt: new Date().toISOString(),
          providerResponse: { deleted: true, keyName },
        };
      }),
    };
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));

    const ks = require('./keyStore');
    const { keyId } = await ks.rotateKeyAsync('race-reload-client');

    const revokePromise = ks.revokeKeyAsync(keyId);

    // Let the microtask queue drain so revokeKeyAsync reaches its `await
    // provider.revokeKey(...)` call (blocked on revokeGate) — at this point
    // the pre-await synchronous flip to 'revoked' has already been persisted.
    await Promise.resolve();
    await Promise.resolve();

    // Simulate this instance's independent reload timer (rotationScheduler's
    // reload half — now decoupled from rotation) firing while the
    // revocation above is still in flight.
    const reloadResult = ks.reloadFromDisk();
    expect(reloadResult.reloaded).toBe(true);

    // Now let the provider call complete and the revocation finish.
    revokeGate.resolve();
    const result = await revokePromise;

    expect(result.nativeRevocation).toEqual(expect.objectContaining({
      success: true, provider: 'vault:transit:test', method: 'destroy',
    }));

    // The outcome must be visible in THIS instance's live store, not just in
    // the function's return value...
    const inventory = ks.getInventory();
    const entry = inventory.entries.find(e => e.keyId === keyId);
    expect(entry.status).toBe('revoked');
    expect(entry.nativeRevocation).toEqual(expect.objectContaining({ success: true }));

    // ...and durably on disk, so every OTHER instance's reload picks up the
    // same outcome too.
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();
    const ksReloaded = require('./keyStore');
    const diskEntry = ksReloaded.getInventory().entries.find(e => e.keyId === keyId);
    expect(diskEntry.nativeRevocation).toEqual(expect.objectContaining({ success: true }));

    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRV-13…14  sync revokeKey() — backward compatibility
// ═════════════════════════════════════════════════════════════════════════════

describe('sync revokeKey() — backward compatibility', () => {
  test('KRV-13: works unchanged when no native signing provider is configured', () => {
    const ks = loadFreshKeyStore(makeTempPath());
    const { keyId } = ks.rotateKey('sync-client-1');
    ks.revokeKey(keyId);
    expect(() => ks.getActiveKey('sync-client-1')).toThrow(/no active key/);
  });

  test('KRV-14: refuses (throws) instead of silently skipping provider propagation when a native provider is active', async () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../secrets/secretsProvider')._clearCache();

    const mockProvider = {
      name: 'vault:transit:test',
      generateKeyPair: jest.fn(async (keyName) => {
        const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding:  { type: 'spki',  format: 'der' },
          privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });
        mockProvider._pairs = mockProvider._pairs || {};
        mockProvider._pairs[keyName] = { priv: Buffer.from(priv), pub: Buffer.from(pub) };
        return { publicKeyDer: Buffer.from(pub), keyName };
      }),
      sign: jest.fn(async (keyName, messageHash) => {
        const { sign: ed25519Sign } = require('../../src/infra/crypto/ed25519');
        return ed25519Sign(messageHash, mockProvider._pairs[keyName].priv);
      }),
      deprecateKey: jest.fn(async () => {}),
      getRevocationCapabilities: jest.fn(() => ['destroy']),
      revokeKey: jest.fn(async () => ({ method: 'destroy', provider: 'vault:transit:test', revokedAt: new Date().toISOString(), providerResponse: {} })),
    };
    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
    const ks = require('./keyStore');

    const { keyId } = await ks.rotateKeyAsync('sync-native-client');
    expect(() => ks.revokeKey(keyId)).toThrow(/revokeKeyAsync/);
    // Local state must be untouched by the refused call — still active.
    expect(ks.getActiveKey('sync-native-client').keyId).toBe(keyId);

    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRV-15…17  nativeSignLocked — revoke/sign concurrency
// ═════════════════════════════════════════════════════════════════════════════

describe('nativeSignLocked — revoke/sign concurrency', () => {
  let ks;
  let mockProvider;

  function _installMockKpf() {
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
        return ed25519Sign(messageHash, pair.priv);
      }),
      deprecateKey: jest.fn(async () => {}),
      getRevocationCapabilities: jest.fn(() => ['destroy']),
      revokeKey: jest.fn(async (keyName, opts) => ({
        method: opts.method, provider: 'vault:transit:test', revokedAt: new Date().toISOString(), providerResponse: { deleted: true },
      })),
      _pairs,
    };

    jest.doMock('../../src/infra/keys/keyProviderFactory', () => ({
      isNativeSigning: () => true,
      getNativeSigningProvider: () => mockProvider,
    }));
  }

  beforeEach(() => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = makeTempPath();
    require('../secrets/secretsProvider')._clearCache();
    _installMockKpf();
    ks = require('./keyStore');
  });

  afterEach(() => {
    jest.dontMock('../../src/infra/keys/keyProviderFactory');
  });

  test('KRV-15: a native sign that acquires the lock first completes with a valid signature even if a revoke is requested while it is in flight', async () => {
    const { verify: ed25519Verify } = require('../../src/infra/crypto/ed25519');
    const { keyId } = await ks.rotateKeyAsync('race-client-1');
    const key       = ks.getActiveKey('race-client-1');
    const hash      = crypto.createHash('sha256').update('probe payload').digest();

    const gate = deferred();
    const realSign = mockProvider.sign.getMockImplementation();
    mockProvider.sign = jest.fn(async (kn, h) => { await gate.promise; return realSign(kn, h); });

    const signPromise = ks.nativeSignLocked(keyId, hash);     // acquires the lock first
    const revokePromise = ks.revokeKeyAsync(keyId);           // queues behind the in-flight sign

    // Revoke must not have taken effect yet — sign is still holding the lock.
    await new Promise(r => setImmediate(r));
    expect(ks.getActiveKey('race-client-1').keyId).toBe(key.keyId);

    gate.resolve();
    const sig = await signPromise;
    expect(ed25519Verify(hash, sig, key.pubDer)).toBe(true);

    const revokeResult = await revokePromise;
    expect(revokeResult.status).toBe('revoked');
  });

  test('KRV-16: a sign requested after a revoke has started for the same key always observes the revoked status', async () => {
    const { keyId } = await ks.rotateKeyAsync('race-client-2');
    const hash = crypto.createHash('sha256').update('probe payload').digest();

    const revokePromise = ks.revokeKeyAsync(keyId);
    const signPromise   = ks.nativeSignLocked(keyId, hash);

    await expect(revokePromise).resolves.toEqual(expect.objectContaining({ status: 'revoked' }));
    await expect(signPromise).rejects.toThrow(/not active/);
  });

  test('KRV-17: nativeSignLocked refuses outright for an already-revoked key', async () => {
    const { keyId } = await ks.rotateKeyAsync('race-client-3');
    await ks.revokeKeyAsync(keyId);
    const hash = crypto.createHash('sha256').update('probe payload').digest();
    await expect(ks.nativeSignLocked(keyId, hash)).rejects.toThrow(/not active/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  Private key buffer is explicitly zeroed on deprecate/revoke
// ═════════════════════════════════════════════════════════════════════════════
//
// Previously the outgoing record's _privDer Buffer was simply dereferenced
// and left for GC. getActiveKey().privDer returns the SAME Buffer instance
// the store holds internally (see keyStore.js:1355) — captured here BEFORE
// the transition, then inspected after, to prove the underlying bytes were
// actually overwritten rather than merely unreferenced.

describe('private key material is explicitly zeroed on deprecate/revoke', () => {
  let ks;
  beforeEach(() => { ks = loadFreshKeyStore(makeTempPath()); });

  test('revokeKey (sync, local): outgoing privDer buffer is zeroed', async () => {
    await ks.rotateKeyAsync('zero-client-1'); // provisions the first active key
    const key = ks.getActiveKey('zero-client-1');
    expect(key.privDer.some(b => b !== 0)).toBe(true); // sanity: real key material, not already zero

    ks.revokeKey(key.keyId);

    expect(key.privDer.every(b => b === 0)).toBe(true);
  });

  test('revokeKeyAsync (local, no native provider): outgoing privDer buffer is zeroed', async () => {
    const { keyId } = await ks.rotateKeyAsync('zero-client-2');
    const key = ks.getActiveKey('zero-client-2');

    await ks.revokeKeyAsync(keyId);

    expect(key.privDer.every(b => b === 0)).toBe(true);
  });

  test('rotateKey emergency mode (explicit): the revoked outgoing key is zeroed, the new active key is untouched', async () => {
    await ks.rotateKeyAsync('zero-client-3');
    const outgoing = ks.getActiveKey('zero-client-3');

    const result = ks.rotateKey('zero-client-3', { mode: 'emergency' });
    const incoming = ks.getActiveKey('zero-client-3');

    expect(outgoing.privDer.every(b => b === 0)).toBe(true);
    expect(incoming.keyId).toBe(result.keyId);
    expect(incoming.privDer.some(b => b !== 0)).toBe(true);
  });

  test('rotateKey graceful mode: the deprecated outgoing key is zeroed even though it remains verifiable', async () => {
    await ks.rotateKeyAsync('zero-client-4');
    const outgoing = ks.getActiveKey('zero-client-4');

    ks.rotateKeyGracefully
      ? ks.rotateKeyGracefully('zero-client-4')
      : ks.rotateKey('zero-client-4', { mode: 'graceful' });

    expect(outgoing.privDer.every(b => b === 0)).toBe(true);
    // Still verifiable (deprecated, not revoked) — status transition doesn't
    // change, only the private material is gone.
    expect(ks.getKeyStatus(outgoing.keyId)).toBe('deprecated');
  });
});
