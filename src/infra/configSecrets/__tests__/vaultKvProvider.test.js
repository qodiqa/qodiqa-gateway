'use strict';

/**
 * VaultKvConfigSecretsProvider — unit tests against a mocked node-vault client.
 * No live Vault instance or real credentials are required — mirrors
 * src/infra/keys/providers/__tests__/vault.provider.test.js's mocking pattern.
 */

function makeMockVaultClient(overrides = {}) {
  return {
    health: jest.fn(async () => ({ initialized: true, sealed: false })),
    read:   jest.fn(async () => ({ data: { data: { REDIS_PASSWORD: 'super-secret-fixture-value' } } })),
    approleLogin: jest.fn(async () => ({ auth: { client_token: 'fixture-client-token' } })),
    ...overrides,
  };
}

function loadProvider(vaultClient) {
  jest.resetModules();
  jest.doMock('node-vault', () => () => vaultClient, { virtual: true });
  const { VaultKvConfigSecretsProvider } = require('../providers/vaultKv');
  return VaultKvConfigSecretsProvider;
}

afterEach(() => {
  jest.dontMock('node-vault');
});

describe('VaultKvConfigSecretsProvider — auth', () => {
  test('authenticates via AppRole when role_id + secret_id are provided', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ roleId: 'r1', secretId: 's1' });
    await provider.initialize();
    expect(vaultClient.approleLogin).toHaveBeenCalledWith({ role_id: 'r1', secret_id: 's1' });
  });

  test('authenticates via static token when only a token is provided', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 'static-token-fixture' });
    await expect(provider.initialize()).resolves.toBeUndefined();
    expect(vaultClient.approleLogin).not.toHaveBeenCalled();
  });

  test('throws a clear error when no credentials are configured at all', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({});
    await expect(provider.initialize()).rejects.toThrow(/no Vault credentials configured/i);
  });

  test('throws when node-vault is not installed', async () => {
    jest.resetModules();
    jest.doMock('node-vault', () => { throw new Error('Cannot find module'); }, { virtual: true });
    const { VaultKvConfigSecretsProvider } = require('../providers/vaultKv');
    const provider = new VaultKvConfigSecretsProvider({ token: 't' });
    await expect(provider.initialize()).rejects.toThrow(/node-vault is not installed/);
  });
});

describe('VaultKvConfigSecretsProvider — fetchSecrets', () => {
  test('reads the configured mount/path and returns the KV v2 data object verbatim', async () => {
    const vaultClient = makeMockVaultClient({
      read: jest.fn(async () => ({
        data: { data: { REDIS_PASSWORD: 'fixture-a', OPENAI_API_KEY: 'fixture-b' } },
      })),
    });
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't', mount: 'secret', path: 'qodiqa/app-config' });
    await provider.initialize();

    const secrets = await provider.fetchSecrets();

    expect(vaultClient.read).toHaveBeenCalledWith('secret/data/qodiqa/app-config');
    expect(secrets).toEqual({ REDIS_PASSWORD: 'fixture-a', OPENAI_API_KEY: 'fixture-b' });
  });

  test('defaults to mount "secret" and path "qodiqa/app-config" when unset', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    await provider.fetchSecrets();
    expect(vaultClient.read).toHaveBeenCalledWith('secret/data/qodiqa/app-config');
  });

  test('honors QODIQA_CONFIG_SECRETS_VAULT_MOUNT / _PATH env vars', async () => {
    const savedMount = process.env.QODIQA_CONFIG_SECRETS_VAULT_MOUNT;
    const savedPath  = process.env.QODIQA_CONFIG_SECRETS_VAULT_PATH;
    process.env.QODIQA_CONFIG_SECRETS_VAULT_MOUNT = 'kv2';
    process.env.QODIQA_CONFIG_SECRETS_VAULT_PATH  = 'custom/path';
    try {
      const vaultClient = makeMockVaultClient();
      const Provider = loadProvider(vaultClient);
      const provider = new Provider({ token: 't' });
      await provider.initialize();
      await provider.fetchSecrets();
      expect(vaultClient.read).toHaveBeenCalledWith('kv2/data/custom/path');
    } finally {
      if (savedMount === undefined) delete process.env.QODIQA_CONFIG_SECRETS_VAULT_MOUNT;
      else process.env.QODIQA_CONFIG_SECRETS_VAULT_MOUNT = savedMount;
      if (savedPath === undefined) delete process.env.QODIQA_CONFIG_SECRETS_VAULT_PATH;
      else process.env.QODIQA_CONFIG_SECRETS_VAULT_PATH = savedPath;
    }
  });

  test('throws when the secret has no usable data (missing/null)', async () => {
    const vaultClient = makeMockVaultClient({ read: jest.fn(async () => ({ data: null })) });
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    await expect(provider.fetchSecrets()).rejects.toThrow(/no usable data/);
  });

  test('throws when a value in the secret is not a plain string', async () => {
    const vaultClient = makeMockVaultClient({
      read: jest.fn(async () => ({ data: { data: { REDIS_PASSWORD: { nested: 'object' } } } })),
    });
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    await expect(provider.fetchSecrets()).rejects.toThrow(/non-string value/);
  });

  test('throws (does not silently return {}) when Vault read rejects — e.g. unreachable/403', async () => {
    const vaultClient = makeMockVaultClient({
      read: jest.fn(async () => { throw new Error('ECONNREFUSED 127.0.0.1:8200'); }),
    });
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    await expect(provider.fetchSecrets()).rejects.toThrow(/ECONNREFUSED/);
  });

  test('throws if fetchSecrets() is called before initialize()', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await expect(provider.fetchSecrets()).rejects.toThrow(/not initialized/);
  });
});

describe('VaultKvConfigSecretsProvider — healthCheck / shutdown', () => {
  test('healthCheck reports healthy when Vault responds', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    const result = await provider.healthCheck();
    expect(result.healthy).toBe(true);
  });

  test('healthCheck reports unhealthy without throwing when Vault is unreachable', async () => {
    const vaultClient = makeMockVaultClient({
      health: jest.fn(async () => { throw new Error('unreachable'); }),
    });
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    const result = await provider.healthCheck();
    expect(result.healthy).toBe(false);
  });

  test('shutdown clears the internal client reference', async () => {
    const vaultClient = makeMockVaultClient();
    const Provider = loadProvider(vaultClient);
    const provider = new Provider({ token: 't' });
    await provider.initialize();
    await provider.shutdown();
    await expect(provider.fetchSecrets()).rejects.toThrow(/not initialized/);
  });
});
