'use strict';

/**
 * VaultTransitSigningProvider — revocation unit tests
 *
 * src/infra/keys/providers/vault.js is the Vault Transit
 * NativeSigningProvider actually wired to production via keyProviderFactory →
 * keyStore.revokeKeyAsync. These tests exercise its revokeKey() directly
 * against a mocked node-vault client, independent of the higher-level
 * keyStore mock-provider tests in services/artifact/keyRevocation.async.test.js.
 */

function makeMockVaultClient(overrides = {}) {
  return {
    health: jest.fn(async () => ({ initialized: true, sealed: false })),
    read:   jest.fn(async () => ({ data: { latest_version: 3 } })),
    write:  jest.fn(async () => ({})),
    delete: jest.fn(async () => ({})),
    ...overrides,
  };
}

function loadProvider(vaultClient) {
  jest.resetModules();
  jest.doMock('node-vault', () => () => vaultClient, { virtual: true });
  const { VaultTransitSigningProvider } = require('../vault');
  return VaultTransitSigningProvider;
}

async function makeInitializedProvider(vaultClient, opts = {}) {
  const VaultTransitSigningProvider = loadProvider(vaultClient);
  const provider = new VaultTransitSigningProvider({ token: 'test-token', ...opts });
  await provider.initialize();
  return provider;
}

afterEach(() => {
  jest.dontMock('node-vault');
});

describe('VaultTransitSigningProvider.getRevocationCapabilities', () => {
  test('advertises both destroy and disable', async () => {
    const vaultClient = makeMockVaultClient();
    const provider = await makeInitializedProvider(vaultClient);
    expect(provider.getRevocationCapabilities()).toEqual(['destroy', 'disable']);
  });
});

describe('VaultTransitSigningProvider.revokeKey — method "destroy"', () => {
  test('flips deletion_allowed then deletes the Transit key', async () => {
    const vaultClient = makeMockVaultClient();
    const provider = await makeInitializedProvider(vaultClient);

    const result = await provider.revokeKey('default:key_v1', { method: 'destroy' });

    expect(vaultClient.write).toHaveBeenCalledWith(
      'transit/keys/default-key_v1/config',
      { deletion_allowed: true },
    );
    expect(vaultClient.delete).toHaveBeenCalledWith('transit/keys/default-key_v1');
    expect(result).toEqual(expect.objectContaining({
      method: 'destroy',
      provider: provider.name,
      providerResponse: { deleted: true, keyName: 'default-key_v1' },
    }));
  });

  test('defaults to "destroy" (the strongest supported method) when opts.method is omitted', async () => {
    const vaultClient = makeMockVaultClient();
    const provider = await makeInitializedProvider(vaultClient);
    const result = await provider.revokeKey('default:key_v1');
    expect(result.method).toBe('destroy');
    expect(vaultClient.delete).toHaveBeenCalled();
  });
});

describe('VaultTransitSigningProvider.revokeKey — method "disable"', () => {
  test('advances min_encryption_version past the latest key version without deleting it', async () => {
    const vaultClient = makeMockVaultClient({
      read: jest.fn(async () => ({ data: { latest_version: 5 } })),
    });
    const provider = await makeInitializedProvider(vaultClient);

    const result = await provider.revokeKey('default:key_v1', { method: 'disable' });

    expect(vaultClient.write).toHaveBeenCalledWith(
      'transit/keys/default-key_v1/config',
      { min_encryption_version: 6 },
    );
    expect(vaultClient.delete).not.toHaveBeenCalled();
    expect(result).toEqual(expect.objectContaining({
      method: 'disable',
      providerResponse: { minEncryptionVersion: 6, keyName: 'default-key_v1' },
    }));
  });
});

describe('VaultTransitSigningProvider.revokeKey — failure modes', () => {
  test('wraps and rethrows a Vault delete failure, attaching the underlying cause and method', async () => {
    const vaultClient = makeMockVaultClient({
      delete: jest.fn(async () => { throw new Error('permission denied'); }),
    });
    const provider = await makeInitializedProvider(vaultClient);

    await expect(provider.revokeKey('default:key_v1', { method: 'destroy' }))
      .rejects.toThrow(/method "destroy" failed.*permission denied/);

    try {
      await provider.revokeKey('default:key_v1', { method: 'destroy' });
      throw new Error('expected revokeKey to reject');
    } catch (err) {
      expect(err.cause).toBeInstanceOf(Error);
      expect(err.cause.message).toBe('permission denied');
      expect(err.method).toBe('destroy');
    }
  });

  test('rejects an unsupported revocation method', async () => {
    const vaultClient = makeMockVaultClient();
    const provider = await makeInitializedProvider(vaultClient);
    await expect(provider.revokeKey('default:key_v1', { method: 'archive' }))
      .rejects.toThrow(/unsupported revocation method "archive"/);
  });
});

// the shapes real Vault 1.20 returns, captured by the dev-mode emulator run
//Before the fix, every real ed25519 key failed here.
describe('VaultTransitSigningProvider — real Vault ed25519 wire shapes', () => {
  const crypto = require('crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawB64 = spki.subarray(12).toString('base64');            // Vault's form: base64 of the raw 32-byte key
  const keyRead = (pk) => jest.fn(async () => ({ data: { latest_version: 1, min_decryption_version: 1, keys: { 1: { public_key: pk } } } }));

  test('DEP11-U1 a raw base64 ed25519 public_key (what Vault returns) yields the matching SPKI DER', async () => {
    const provider = await makeInitializedProvider(makeMockVaultClient({ read: keyRead(rawB64) }));
    const { publicKeyDer } = await provider.getPublicKey('k');
    expect(Buffer.compare(publicKeyDer, spki)).toBe(0);
    expect((await provider.generateKeyPair('k')).publicKeyDer.equals(spki)).toBe(true);
  });

  test('DEP11-U2 a PEM public_key is still accepted', async () => {
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const provider = await makeInitializedProvider(makeMockVaultClient({ read: keyRead(pem) }));
    expect((await provider.getPublicKey('k')).publicKeyDer.equals(spki)).toBe(true);
  });

  test('DEP11-U3 a malformed, wrong-length, empty or non-ed25519 public_key is refused', async () => {
    const rsaPem = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' });
    for (const bad of ['', 'not base64!', Buffer.alloc(31).toString('base64'), Buffer.alloc(33).toString('base64'), rsaPem, undefined]) {
      const provider = await makeInitializedProvider(makeMockVaultClient({ read: keyRead(bad) }));
      await expect(provider.getPublicKey('k')).rejects.toThrow(/public_key|ed25519|no public_key/);
    }
  });

  test('DEP11-U4 sign() sends plain input (pure Ed25519 over the 32-byte hash), no RSA-only prehash parameters', async () => {
    const hash = crypto.randomBytes(32);
    const sig = crypto.sign(null, hash, privateKey);
    const write = jest.fn(async () => ({ data: { signature: 'vault:v1:' + sig.toString('base64') } }));
    const provider = await makeInitializedProvider(makeMockVaultClient({ write }));
    const out = await provider.sign('k', hash);
    expect(write).toHaveBeenCalledWith('transit/sign/k', { input: hash.toString('base64') });
    expect(crypto.verify(null, hash, publicKey, out)).toBe(true);
  });
});
