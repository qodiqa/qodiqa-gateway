'use strict';

/**
 * configSecretsFactory — provider selection, apply()/process.env semantics,
 * fail-closed bootstrapOrExit(), and secret-leakage checks.
 *
 * See negativeFailClosed.test.js for's mandatory "production + secrets
 * manager unavailable + plaintext secret already in process.env → STARTUP
 * FAILS, never falls back" scenario — kept as its own file for auditability.
 */

const { ConfigSecretsProvider } = require('../providers/base');
const { MANAGED_CONFIG_SECRET_NAMES } = require('../managedSecrets');

const FIXTURE_SECRET_VALUE = 'fixture-secret-do-not-reuse-2f9a7c1e';

class FakeProvider extends ConfigSecretsProvider {
  constructor({ name = 'fake', secrets = {}, failWith = null } = {}) {
    super();
    this._name = name;
    this._secrets = secrets;
    this._failWith = failWith;
    this.initializeCalls = 0;
    this.fetchSecretsCalls = 0;
  }

  get name() { return this._name; }

  async initialize() {
    this.initializeCalls += 1;
    if (this._failWith === 'initialize') throw new Error('fake initialize failure');
  }

  async fetchSecrets() {
    this.fetchSecretsCalls += 1;
    if (this._failWith === 'fetch') throw new Error('fake fetch failure');
    return this._secrets;
  }

  async healthCheck() {
    return { healthy: !this._failWith, detail: 'fake' };
  }
}

function freshFactory() {
  jest.resetModules();
  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  const factory = require('../configSecretsFactory');
  const logger  = require('../../../../services/logger');
  return { factory, emitMock: logger.emit };
}

function withEnv(overrides, deletions = []) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    process.env[k] = overrides[k];
  }
  for (const k of deletions) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  return function restore() {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

describe('configSecretsFactory — provider selection', () => {
  test('defaults to "env" when QODIQA_CONFIG_SECRETS_PROVIDER is unset', async () => {
    const { factory } = freshFactory();
    const restore = withEnv({}, ['QODIQA_CONFIG_SECRETS_PROVIDER']);
    try {
      await factory.initialize();
      expect(factory.getProviderName()).toBe('env');
    } finally {
      restore();
    }
  });

  test('rejects an unknown provider name', async () => {
    const { factory } = freshFactory();
    const restore = withEnv({ QODIQA_CONFIG_SECRETS_PROVIDER: 'not-a-real-backend' });
    try {
      await expect(factory.initialize()).rejects.toThrow(/unknown config-secrets provider/);
    } finally {
      restore();
    }
  });

  test('selects vault-kv when configured (construction only — auth happens in initialize())', async () => {
    jest.resetModules();
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => ({ auth: { client_token: 't' } })),
    }), { virtual: true });
    const factory = require('../configSecretsFactory');
    const restore = withEnv({ QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv', VAULT_TOKEN: 'fixture-token' });
    try {
      await factory.initialize();
      expect(factory.getProviderName()).toMatch(/^vault-kv:/);
    } finally {
      restore();
      jest.dontMock('node-vault');
    }
  });

  test('initialize() is idempotent — a second call does not rebuild the provider', async () => {
    const { factory } = freshFactory();
    const restore = withEnv({}, ['QODIQA_CONFIG_SECRETS_PROVIDER']);
    try {
      await factory.initialize();
      const firstName = factory.getProviderName();
      await factory.initialize();
      expect(factory.getProviderName()).toBe(firstName);
    } finally {
      restore();
    }
  });
});

describe('configSecretsFactory — apply() with the "env" provider (no-op)', () => {
  test('never touches process.env, even when managed names are already set', async () => {
    const { factory } = freshFactory();
    const restoreProvider = withEnv({}, ['QODIQA_CONFIG_SECRETS_PROVIDER']);
    const restoreManaged  = withEnv({ REDIS_PASSWORD: 'already-here', OPENAI_API_KEY: 'already-here-too' });
    try {
      await factory.initialize();
      const result = await factory.apply();
      expect(result.appliedCount).toBe(0);
      expect(result.clearedCount).toBe(0);
      expect(process.env.REDIS_PASSWORD).toBe('already-here');
      expect(process.env.OPENAI_API_KEY).toBe('already-here-too');
    } finally {
      restoreManaged();
      restoreProvider();
    }
  });
});

describe('configSecretsFactory — apply() with a non-env provider', () => {
  test('sets process.env for every managed name the provider returns', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: { REDIS_PASSWORD: FIXTURE_SECRET_VALUE } }));
    const restore = withEnv({}, ['REDIS_PASSWORD']);
    try {
      const result = await factory.apply();
      expect(process.env.REDIS_PASSWORD).toBe(FIXTURE_SECRET_VALUE);
      expect(result.appliedCount).toBe(1);
    } finally {
      restore();
    }
  });

  test('DELETES a managed name already present in process.env when the provider does not return it — no silent fallback to a stale value', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: {} })); // provider reachable, but has nothing
    const restore = withEnv({ QODIQA_PG_PASSWORD: 'stale-plaintext-value-from-dotenv' });
    try {
      expect(process.env.QODIQA_PG_PASSWORD).toBe('stale-plaintext-value-from-dotenv');
      const result = await factory.apply();
      expect(process.env.QODIQA_PG_PASSWORD).toBeUndefined();
      expect(result.clearedCount).toBeGreaterThan(0);
    } finally {
      restore();
    }
  });

  test('only touches names in MANAGED_CONFIG_SECRET_NAMES — an unrelated env var is left alone', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: {} }));
    const restore = withEnv({ QODIQA_UNRELATED_TEST_VAR: 'untouched' });
    try {
      await factory.apply();
      expect(process.env.QODIQA_UNRELATED_TEST_VAR).toBe('untouched');
    } finally {
      restore();
    }
  });

  test('apply() throws before initialize() has run', async () => {
    const { factory } = freshFactory();
    await expect(factory.apply()).rejects.toThrow(/initialize\(\) must be called/);
  });

  test('apply() propagates a fetchSecrets() failure and does not modify process.env', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ failWith: 'fetch' }));
    const restore = withEnv({ REDIS_PASSWORD: 'unchanged-because-fetch-failed' });
    try {
      await expect(factory.apply()).rejects.toThrow(/fake fetch failure/);
      expect(process.env.REDIS_PASSWORD).toBe('unchanged-because-fetch-failed');
    } finally {
      restore();
    }
  });
});

describe('configSecretsFactory — bootstrapOrExit()', () => {
  let exitSpy;
  let stderrSpy;

  beforeEach(() => {
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  test('succeeds silently (no exit) for the default "env" provider', async () => {
    const { factory } = freshFactory();
    const restore = withEnv({}, ['QODIQA_CONFIG_SECRETS_PROVIDER']);
    try {
      await expect(factory.bootstrapOrExit()).resolves.toBeUndefined();
      expect(exitSpy).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  test('exits(1) when the configured provider is unknown', async () => {
    const { factory } = freshFactory();
    const restore = withEnv({ QODIQA_CONFIG_SECRETS_PROVIDER: 'not-a-real-backend' });
    try {
      await expect(factory.bootstrapOrExit()).rejects.toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(stderrSpy).toHaveBeenCalled();
      const written = stderrSpy.mock.calls.map(c => c[0]).join('\n');
      expect(written).toMatch(/\[FATAL\]/);
    } finally {
      restore();
    }
  });
});

describe('configSecretsFactory — no secret leakage through logging', () => {
  test('emit() calls during apply() never carry the actual secret value — only names/counts', async () => {
    const { factory, emitMock } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: { REDIS_PASSWORD: FIXTURE_SECRET_VALUE } }));
    const restore = withEnv({}, ['REDIS_PASSWORD']);
    try {
      await factory.apply();
      for (const call of emitMock.mock.calls) {
        const serialized = JSON.stringify(call);
        expect(serialized).not.toContain(FIXTURE_SECRET_VALUE);
      }
    } finally {
      restore();
    }
  });

  test('a thrown provider error message is never the secret value itself', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ failWith: 'fetch' }));
    try {
      await factory.apply();
    } catch (err) {
      expect(err.message).not.toContain(FIXTURE_SECRET_VALUE);
    }
  });
});

describe('configSecretsFactory — healthCheck / shutdown / test hooks', () => {
  test('healthCheck() reports not-initialized before any provider is set', async () => {
    const { factory } = freshFactory();
    const result = await factory.healthCheck();
    expect(result.healthy).toBe(false);
  });

  test('healthCheck() delegates to the active provider', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({}));
    const result = await factory.healthCheck();
    expect(result.healthy).toBe(true);
  });

  test('shutdown() resets isInitialized()/getProviderName() and calls the provider\'s shutdown', async () => {
    const { factory } = freshFactory();
    const provider = new FakeProvider({});
    provider.shutdown = jest.fn().mockResolvedValue(undefined);
    factory._setProvider(provider);
    expect(factory.isInitialized()).toBe(true);

    await factory.shutdown();

    expect(provider.shutdown).toHaveBeenCalledTimes(1);
    expect(factory.isInitialized()).toBe(false);
    expect(factory.getProviderName()).toBeNull();
  });

  test('_setProvider defaults to a non-"env" type — apply() patches/clears like a real external provider', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: {} }));
    const restore = withEnv({ REDIS_USERNAME: 'stale' });
    try {
      await factory.apply();
      expect(process.env.REDIS_USERNAME).toBeUndefined();
    } finally {
      restore();
    }
  });

  test('_setProvider(provider, "env") exercises the no-op apply() path with a fake provider', async () => {
    const { factory } = freshFactory();
    factory._setProvider(new FakeProvider({ secrets: {} }), 'env');
    const restore = withEnv({ REDIS_USERNAME: 'kept' });
    try {
      const result = await factory.apply();
      expect(result.appliedCount).toBe(0);
      expect(result.clearedCount).toBe(0);
      expect(process.env.REDIS_USERNAME).toBe('kept');
    } finally {
      restore();
    }
  });
});

describe('configSecretsFactory — MANAGED_CONFIG_SECRET_NAMES coverage sanity', () => {
  test('apply() with a provider returning every managed name sets every one of them', async () => {
    const { factory } = freshFactory();
    const secrets = {};
    for (const n of MANAGED_CONFIG_SECRET_NAMES) secrets[n] = `${FIXTURE_SECRET_VALUE}:${n}`;
    factory._setProvider(new FakeProvider({ secrets }));

    const restore = withEnv({}, MANAGED_CONFIG_SECRET_NAMES);
    try {
      const result = await factory.apply();
      expect(result.appliedCount).toBe(MANAGED_CONFIG_SECRET_NAMES.length);
      for (const n of MANAGED_CONFIG_SECRET_NAMES) {
        expect(process.env[n]).toBe(`${FIXTURE_SECRET_VALUE}:${n}`);
      }
    } finally {
      restore();
    }
  });
});
