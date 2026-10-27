'use strict';

const { ResilientKekProvider } = require('../resilientKekProvider');
const circuitBreakerRegistry = require('../circuitBreaker');
const healthMonitorRegistry  = require('../healthMonitor');

afterEach(() => {
  circuitBreakerRegistry.resetAll();
  healthMonitorRegistry.resetAll();
});

let _seq = 0;
function uniqueName(label) {
  _seq += 1;
  return `mock-kek:${label}:${_seq}`;
}

function makeConfig(overrides = {}) {
  return {
    timeoutMs: 30,
    initTimeoutMs: 100,
    maxRetries: 3,
    initialBackoffMs: 2,
    maxBackoffMs: 10,
    retryJitter: false,
    cbFailureThreshold: 3,
    cbSuccessThreshold: 2,
    cbWindowMs: 60_000,
    cbRecoveryMs: 40,
    healthIntervalMs: 1_000_000,
    healthDegradedThreshold: 2,
    ...overrides,
  };
}

function makeMockKek(name, overrides = {}) {
  return {
    name,
    initialize: jest.fn(async () => {}),
    shutdown: jest.fn(async () => {}),
    getWrappingKey: jest.fn(async () => Buffer.alloc(32, 7)),
    rotateWrappingKey: jest.fn(async () => ({ version: 'v2' })),
    healthCheck: jest.fn(async () => ({ healthy: true, detail: 'ok' })),
    ...overrides,
  };
}

describe('ResilientKekProvider', () => {
  test('getWrappingKey() enforces a hard deadline against a hung KMS call', async () => {
    const config = makeConfig({ maxRetries: 1 });
    const inner = makeMockKek(uniqueName('hang'), { getWrappingKey: jest.fn(() => new Promise(() => {})) });
    const provider = new ResilientKekProvider(inner, config);

    const start = Date.now();
    await expect(provider.getWrappingKey()).rejects.toMatchObject({ isSigningTimeout: true });
    expect(Date.now() - start).toBeLessThan(200);
  });

  test('getWrappingKey() retries a transient failure and recovers', async () => {
    const config = makeConfig();
    let calls = 0;
    const inner = makeMockKek(uniqueName('retry'), {
      getWrappingKey: jest.fn(async () => {
        calls++;
        if (calls === 1) throw new Error('ECONNRESET');
        return Buffer.alloc(32, 9);
      }),
    });
    const provider = new ResilientKekProvider(inner, config);

    const kek = await provider.getWrappingKey();
    expect(kek).toEqual(Buffer.alloc(32, 9));
    expect(inner.getWrappingKey).toHaveBeenCalledTimes(2);
  });

  test('rotateWrappingKey() is never automatically retried, even on a transient failure', async () => {
    const config = makeConfig();
    const inner = makeMockKek(uniqueName('rotate'), {
      rotateWrappingKey: jest.fn(async () => { throw new Error('ECONNRESET'); }),
    });
    const provider = new ResilientKekProvider(inner, config);

    await expect(provider.rotateWrappingKey()).rejects.toThrow('ECONNRESET');
    expect(inner.rotateWrappingKey).toHaveBeenCalledTimes(1);
  });

  test('circuit breaker opens after repeated getWrappingKey failures and rejects further calls instantly', async () => {
    const config = makeConfig({ maxRetries: 1, cbFailureThreshold: 2 });
    const name = uniqueName('cb');
    const inner = makeMockKek(name, { getWrappingKey: jest.fn(async () => { throw new Error('ECONNRESET'); }) });
    const provider = new ResilientKekProvider(inner, config);

    for (let i = 0; i < config.cbFailureThreshold; i++) {
      await expect(provider.getWrappingKey()).rejects.toThrow();
    }

    const before = inner.getWrappingKey.mock.calls.length;
    await expect(provider.getWrappingKey()).rejects.toMatchObject({ code: 'SIGNING_CIRCUIT_OPEN' });
    expect(inner.getWrappingKey.mock.calls.length).toBe(before); // provider not contacted
  });

  test('healthCheck() never throws and reflects a resolved-unhealthy result', async () => {
    const config = makeConfig();
    const inner = makeMockKek(uniqueName('health'), {
      healthCheck: jest.fn(async () => ({ healthy: false, detail: 'KEK not loaded' })),
    });
    const provider = new ResilientKekProvider(inner, config);

    await expect(provider.healthCheck()).resolves.toEqual({ healthy: false, detail: 'KEK not loaded' });
  });

  test('name getter passes through to the inner provider', () => {
    const inner = makeMockKek('local:env:QODIQA_KEY_ENCRYPTION_KEY');
    const provider = new ResilientKekProvider(inner, makeConfig());
    expect(provider.name).toBe('local:env:QODIQA_KEY_ENCRYPTION_KEY');
  });
});
