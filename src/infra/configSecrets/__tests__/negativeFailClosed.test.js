'use strict';

/**
 * MANDATORY negative test: the most dangerous failure mode.
 *
 *   production + secrets manager unavailable + plaintext secret already
 *   sitting in process.env (e.g. loaded from a stale/leftover .env value)
 *   -> STARTUP MUST FAIL.
 *
 * It must NOT become: secrets manager unavailable -> silently continue with
 * the plaintext value already in process.env.
 *
 * This exercises the real VaultKvConfigSecretsProvider (not a fake), with
 * node-vault mocked to simulate each of the three ways "unavailable" can
 * happen: unreachable at auth time, unreachable at read time, and a
 * malformed/empty response. In every case, bootstrapOrExit() must call
 * process.exit(1) and the plaintext value already in process.env must be
 * provably unusable — proven here by showing the same code path
 * (configSecretsFactory.apply()) is NEVER reached, so it cannot patch OR
 * silently retain that value for a caller further down the startup chain.
 */

function freshFactory() {
  jest.resetModules();
  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  return require('../configSecretsFactory');
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

const DANGEROUS_PLAINTEXT_REDIS_PASSWORD = 'leftover-plaintext-from-dotenv-2f9a7c1e';

describe('negative test — production + Vault unavailable + plaintext env secret already present', () => {
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
    jest.dontMock('node-vault');
  });

  test('Vault unreachable at AUTH time (e.g. connection refused) -> process.exit(1), apply() never runs, plaintext value untouched but never applied', async () => {
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => { throw new Error('connect ECONNREFUSED 127.0.0.1:8200'); }),
    }), { virtual: true });
    const factory = freshFactory();
    const applySpy = jest.spyOn(factory, 'apply');

    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv',
      VAULT_ROLE_ID: 'fixture-role',
      VAULT_SECRET_ID: 'fixture-secret-id',
      REDIS_PASSWORD: DANGEROUS_PLAINTEXT_REDIS_PASSWORD,
    });
    try {
      await expect(factory.bootstrapOrExit()).rejects.toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
      // The dangerous plaintext value is still literally present (proving
      // the scenario is real) — but apply() never ran, so it was never used
      // as a substitute for the unreachable secrets manager.
      expect(process.env.REDIS_PASSWORD).toBe(DANGEROUS_PLAINTEXT_REDIS_PASSWORD);
      expect(applySpy).not.toHaveBeenCalled();
      expect(factory.isApplied()).toBe(false);
    } finally {
      restore();
      applySpy.mockRestore();
    }
  });

  test('Vault reachable but the KV read fails (e.g. 403 permission denied) -> process.exit(1), process.env is left exactly as it was', async () => {
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => ({ auth: { client_token: 'fixture-token' } })),
      read: jest.fn(async () => { throw new Error('Status 403: permission denied'); }),
    }), { virtual: true });
    const factory = freshFactory();

    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv',
      VAULT_ROLE_ID: 'fixture-role',
      VAULT_SECRET_ID: 'fixture-secret-id',
      REDIS_PASSWORD: DANGEROUS_PLAINTEXT_REDIS_PASSWORD,
    });
    try {
      await expect(factory.bootstrapOrExit()).rejects.toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
      // apply() DID start (initialize() succeeded) but its fetchSecrets()
      // call threw before any process.env mutation loop could run — the
      // plaintext value is provably not silently re-adopted as the answer.
      expect(process.env.REDIS_PASSWORD).toBe(DANGEROUS_PLAINTEXT_REDIS_PASSWORD);
      expect(factory.isApplied()).toBe(false);
    } finally {
      restore();
    }
  });

  test('Vault returns a malformed/empty response -> process.exit(1), never treated as "no secrets configured, fall back"', async () => {
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => ({ auth: { client_token: 'fixture-token' } })),
      read: jest.fn(async () => ({ data: null })), // no `data.data` at all
    }), { virtual: true });
    const factory = freshFactory();

    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv',
      VAULT_ROLE_ID: 'fixture-role',
      VAULT_SECRET_ID: 'fixture-secret-id',
      REDIS_PASSWORD: DANGEROUS_PLAINTEXT_REDIS_PASSWORD,
    });
    try {
      await expect(factory.bootstrapOrExit()).rejects.toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(factory.isApplied()).toBe(false);
    } finally {
      restore();
    }
  });

  test('the [FATAL] stderr message names the failure without ever printing the plaintext secret value', async () => {
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => { throw new Error('connect ECONNREFUSED 127.0.0.1:8200'); }),
    }), { virtual: true });
    const factory = freshFactory();

    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv',
      VAULT_ROLE_ID: 'fixture-role',
      VAULT_SECRET_ID: 'fixture-secret-id',
      REDIS_PASSWORD: DANGEROUS_PLAINTEXT_REDIS_PASSWORD,
    });
    try {
      await expect(factory.bootstrapOrExit()).rejects.toThrow('process.exit called');
      const written = stderrSpy.mock.calls.map(c => c[0]).join('\n');
      expect(written).toMatch(/\[FATAL\]/);
      expect(written).toMatch(/QODIQA_CONFIG_SECRETS_PROVIDER=vault-kv/);
      expect(written).not.toContain(DANGEROUS_PLAINTEXT_REDIS_PASSWORD);
    } finally {
      restore();
    }
  });

  test('CONTROL: with Vault reachable and returning the secret, the SAME plaintext value is legitimately overwritten (proves this is a real fail-closed gate, not an always-fails stub)', async () => {
    jest.doMock('node-vault', () => () => ({
      approleLogin: jest.fn(async () => ({ auth: { client_token: 'fixture-token' } })),
      read: jest.fn(async () => ({ data: { data: { REDIS_PASSWORD: 'fresh-value-from-vault' } } })),
    }), { virtual: true });
    const factory = freshFactory();

    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_CONFIG_SECRETS_PROVIDER: 'vault-kv',
      VAULT_ROLE_ID: 'fixture-role',
      VAULT_SECRET_ID: 'fixture-secret-id',
      REDIS_PASSWORD: DANGEROUS_PLAINTEXT_REDIS_PASSWORD,
    });
    try {
      await expect(factory.bootstrapOrExit()).resolves.toBeUndefined();
      expect(exitSpy).not.toHaveBeenCalled();
      expect(process.env.REDIS_PASSWORD).toBe('fresh-value-from-vault');
      expect(factory.isApplied()).toBe(true);
    } finally {
      restore();
    }
  });
});
