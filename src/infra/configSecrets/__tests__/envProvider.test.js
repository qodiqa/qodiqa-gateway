'use strict';

const { EnvConfigSecretsProvider } = require('../providers/env');

describe('EnvConfigSecretsProvider', () => {
  test('name is "env"', () => {
    expect(new EnvConfigSecretsProvider().name).toBe('env');
  });

  test('fetchSecrets() always returns an empty object regardless of process.env', async () => {
    const restore = process.env.REDIS_PASSWORD;
    process.env.REDIS_PASSWORD = 'whatever-is-already-set';
    try {
      const provider = new EnvConfigSecretsProvider();
      await expect(provider.fetchSecrets()).resolves.toEqual({});
    } finally {
      if (restore === undefined) delete process.env.REDIS_PASSWORD;
      else process.env.REDIS_PASSWORD = restore;
    }
  });

  test('healthCheck() reports healthy with no external dependency', async () => {
    const result = await new EnvConfigSecretsProvider().healthCheck();
    expect(result.healthy).toBe(true);
  });

  test('initialize() and shutdown() resolve without throwing', async () => {
    const provider = new EnvConfigSecretsProvider();
    await expect(provider.initialize()).resolves.toBeUndefined();
    await expect(provider.shutdown()).resolves.toBeUndefined();
  });
});
