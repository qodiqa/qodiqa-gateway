'use strict';

// (deterministic clock): the circuit breaker reads src/infra/time/monotonicClock (performance.timeOrigin +
// performance.now() from perf_hooks), which Jest's fake timers do not control, so a "frozen" test could still age the
// breaker past cbRecoveryMs on a loaded machine. In this file the monotonic clock is Date.now(): real time under real
// timers (unchanged behaviour), and the fake clock wherever a test calls jest.useFakeTimers().
jest.mock('../../../time/monotonicClock', () => ({
  monoNowMs: () => Date.now(),
  wallFromMono: (stamp) => (stamp ? stamp : null),
}));
// The Jest setup files already loaded the resilience modules with the real clock; load this file's copies afresh so they
// bind the clock above.
jest.resetModules();

const { ResilientSigningProvider } = require('../resilientSigningProvider');
const circuitBreakerRegistry = require('../circuitBreaker');
const healthMonitorRegistry  = require('../healthMonitor');
const metrics = require('../../../../observability/metrics');

afterEach(() => {
  circuitBreakerRegistry.resetAll();
  healthMonitorRegistry.resetAll();
  jest.restoreAllMocks();
});

let _seq = 0;
function uniqueName(label) {
  _seq += 1;
  return `mock:${label}:${_seq}`;
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
    healthIntervalMs: 1_000_000, // effectively disabled unless a test starts probing explicitly
    healthDegradedThreshold: 2,
    ...overrides,
  };
}

function makeMockProvider(name, overrides = {}) {
  return {
    name,
    initialize: jest.fn(async () => {}),
    shutdown: jest.fn(async () => {}),
    sign: jest.fn(async () => Buffer.from('signature')),
    getPublicKey: jest.fn(async () => ({ publicKeyDer: Buffer.from('pub'), status: 'active' })),
    generateKeyPair: jest.fn(async () => ({ publicKeyDer: Buffer.from('pub'), keyName: 'k' })),
    deprecateKey: jest.fn(async () => {}),
    revokeKey: jest.fn(async () => ({ method: 'destroy' })),
    getRevocationCapabilities: jest.fn(() => ['destroy']),
    healthCheck: jest.fn(async () => ({ healthy: true, detail: 'ok' })),
    ...overrides,
  };
}

function hangsForever() {
  return new Promise(() => {});
}

function failNTimesThenResolve(n, makeError, resolveValue) {
  let calls = 0;
  return jest.fn(async () => {
    calls++;
    if (calls <= n) throw makeError();
    return resolveValue;
  });
}

function labelKey(labels) {
  return Object.keys(labels).sort().map((k) => `${k}="${labels[k]}"`).join(',');
}
function readCounter(counter, labels) {
  return counter._values.get(labelKey(labels)) || 0;
}

describe('ResilientSigningProvider — sign() timeout enforcement', () => {
  test('a hung provider never blocks the caller past the configured deadline', async () => {
    const config = makeConfig({ maxRetries: 1 }); // isolate timeout behavior from retry
    const inner  = makeMockProvider(uniqueName('hang'), { sign: jest.fn(hangsForever) });
    const provider = new ResilientSigningProvider(inner, config);

    // on the test's own (fake) clock — the call is still pending 1 ms before the deadline and rejects at it
    jest.useFakeTimers();
    try {
      const start = Date.now();
      let settled = false;
      const p = provider.sign('key', Buffer.alloc(32)).finally(() => { settled = true; });
      p.catch(() => {});
      await jest.advanceTimersByTimeAsync(config.timeoutMs - 1);
      expect(settled).toBe(false);
      await jest.advanceTimersByTimeAsync(1);
      await expect(p).rejects.toMatchObject({ isSigningTimeout: true });
      expect(Date.now() - start).toBeLessThan(200);
    } finally {
      jest.useRealTimers();
    }
  });

  test('timeouts increment qodiqa_signing_timeouts_total for the provider/operation', async () => {
    const config = makeConfig({ maxRetries: 1 });
    const name = uniqueName('hang-metrics');
    const inner = makeMockProvider(name, { sign: jest.fn(hangsForever) });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.sign('key', Buffer.alloc(32))).rejects.toBeTruthy();
    expect(readCounter(metrics.signingTimeoutsTotal, { provider: name, operation: 'sign' })).toBe(1);
  });
});

describe('ResilientSigningProvider — bounded retry', () => {
  test('sign() recovers after transient failures within the retry budget', async () => {
    const config = makeConfig();
    const name = uniqueName('retry-ok');
    const inner = makeMockProvider(name, {
      sign: failNTimesThenResolve(2, () => new Error('socket hang up'), Buffer.from('final-sig')),
    });
    const provider = new ResilientSigningProvider(inner, config);

    const result = await provider.sign('key', Buffer.alloc(32));
    expect(result).toEqual(Buffer.from('final-sig'));
    expect(inner.sign).toHaveBeenCalledTimes(3); // 2 failures + 1 success
    expect(readCounter(metrics.signingRetrySuccessTotal, { provider: name, operation: 'sign' })).toBe(1);
  });

  test('sign() exhausts retries and throws after maxRetries attempts, all transient', async () => {
    const config = makeConfig();
    const name = uniqueName('retry-exhaust');
    const inner = makeMockProvider(name, { sign: jest.fn(async () => { throw new Error('ECONNRESET'); }) });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow('ECONNRESET');
    expect(inner.sign).toHaveBeenCalledTimes(config.maxRetries);
    expect(readCounter(metrics.signingRetryExhaustedTotal, { provider: name, operation: 'sign' })).toBe(1);
  });

  test('sign() never retries an authorization failure — fails on the first attempt', async () => {
    const config = makeConfig();
    const name = uniqueName('no-retry-authz');
    const inner = makeMockProvider(name, {
      sign: jest.fn(async () => { throw Object.assign(new Error('permission denied'), { statusCode: 403 }); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow('permission denied');
    expect(inner.sign).toHaveBeenCalledTimes(1);
  });

  test('sign() never retries a cryptographic (self-test) failure', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('no-retry-crypto'), {
      sign: jest.fn(async () => { throw new Error('signature verification failed'); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow('signature verification failed');
    expect(inner.sign).toHaveBeenCalledTimes(1);
  });

  test('getPublicKey() is retry-eligible like sign()', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('pubkey-retry'), {
      getPublicKey: failNTimesThenResolve(1, () => new Error('ETIMEDOUT'), { publicKeyDer: Buffer.from('p'), status: 'active' }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    const result = await provider.getPublicKey('key');
    expect(result.status).toBe('active');
    expect(inner.getPublicKey).toHaveBeenCalledTimes(2);
  });
});

describe('ResilientSigningProvider — mutating operations are NEVER auto-retried', () => {
  test('generateKeyPair() makes exactly one attempt even on a transient-classified failure', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('genkeypair'), {
      generateKeyPair: jest.fn(async () => { throw new Error('socket hang up'); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.generateKeyPair('key')).rejects.toThrow('socket hang up');
    expect(inner.generateKeyPair).toHaveBeenCalledTimes(1);
  });

  test('revokeKey() makes exactly one attempt even on a transient-classified failure', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('revoke'), {
      revokeKey: jest.fn(async () => { throw new Error('ECONNRESET'); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.revokeKey('key', { method: 'destroy' })).rejects.toThrow('ECONNRESET');
    expect(inner.revokeKey).toHaveBeenCalledTimes(1);
  });

  test('deprecateKey() makes exactly one attempt even on a transient-classified failure', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('deprecate'), {
      deprecateKey: jest.fn(async () => { throw new Error('ETIMEDOUT'); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    await expect(provider.deprecateKey('key')).rejects.toThrow('ETIMEDOUT');
    expect(inner.deprecateKey).toHaveBeenCalledTimes(1);
  });
});

describe('ResilientSigningProvider — circuit breaker integration', () => {
  test('opens after repeated failures, then rejects concurrent callers instantly without contacting the provider', async () => {
    const config = makeConfig({ maxRetries: 1, cbFailureThreshold: 3 });
    const name = uniqueName('cb-open');
    const inner = makeMockProvider(name, { sign: jest.fn(async () => { throw new Error('ECONNRESET'); }) });
    const provider = new ResilientSigningProvider(inner, config);

    // Freeze the clock before Phase A (not just around Phase B): the
    // breaker's _openedAt is stamped from Date.now() at the moment Phase A's
    // last failure flips it OPEN, and allowRequest()'s OPEN -> HALF_OPEN
    // transition later compares Date.now() - _openedAt against cbRecoveryMs
    // (40ms here). If real time were still elapsing during Phase A, any
    // scheduling delay between _openedAt being stamped and the Phase B burst
    // starting could itself eat into that 40ms budget, letting one of the
    // 200 concurrent callers through as a HALF_OPEN probe. Freezing time for
    // both phases guarantees _openedAt and the burst are read against the
    // exact same instant, so the breaker cannot age at all until this test
    // chooses to advance time (it doesn't).
    jest.useFakeTimers();
    try {
      // Phase A: sequentially drive the breaker OPEN.
      for (let i = 0; i < config.cbFailureThreshold; i++) {
        await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow();
      }
      const callsBeforeOpen = inner.sign.mock.calls.length;
      expect(callsBeforeOpen).toBe(config.cbFailureThreshold);

      // Phase B: many concurrent callers while OPEN — none should reach the provider.
      const start = Date.now();
      const results = await Promise.allSettled(
        Array.from({ length: 200 }, () => provider.sign('key', Buffer.alloc(32))),
      );
      const elapsed = Date.now() - start;

      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      expect(results.every((r) => r.reason.code === 'SIGNING_CIRCUIT_OPEN')).toBe(true);
      expect(inner.sign.mock.calls.length).toBe(callsBeforeOpen); // provider never contacted again
      expect(elapsed).toBeLessThan(50); // instant rejection, no waiting
    } finally {
      jest.useRealTimers();
    }
  });

  test('recovers to CLOSED after the provider comes back and passes the half-open probe(s)', async () => {
    const config = makeConfig({ maxRetries: 1, cbFailureThreshold: 2, cbSuccessThreshold: 2, cbRecoveryMs: 30 });
    const name = uniqueName('cb-recover');
    let healthy = false;
    const inner = makeMockProvider(name, {
      sign: jest.fn(async () => {
        if (!healthy) throw new Error('ECONNRESET');
        return Buffer.from('sig');
      }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    for (let i = 0; i < config.cbFailureThreshold; i++) {
      await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow();
    }

    healthy = true;
    await new Promise((r) => setTimeout(r, config.cbRecoveryMs + 10));

    await provider.sign('key', Buffer.alloc(32)); // half-open probe #1
    await provider.sign('key', Buffer.alloc(32)); // half-open probe #2 -> closes

    // Circuit is closed again: a burst of concurrent calls all succeed.
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => provider.sign('key', Buffer.alloc(32))),
    );
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });
});

describe('ResilientSigningProvider — health monitoring', () => {
  test('healthCheck() never throws even when the circuit is OPEN', async () => {
    const config = makeConfig({ maxRetries: 1, cbFailureThreshold: 2 });
    const inner = makeMockProvider(uniqueName('health-cb-open'), {
      sign: jest.fn(async () => { throw new Error('ECONNRESET'); }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    for (let i = 0; i < config.cbFailureThreshold; i++) {
      await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow();
    }

    const result = await provider.healthCheck();
    expect(result).toEqual(expect.objectContaining({ healthy: false }));
  });

  test('a provider that resolves { healthy: false } counts as a failure for the health monitor', async () => {
    const config = makeConfig();
    const inner = makeMockProvider(uniqueName('health-unhealthy-result'), {
      healthCheck: jest.fn(async () => ({ healthy: false, detail: 'KEK not loaded' })),
    });
    const provider = new ResilientSigningProvider(inner, config);

    const result = await provider.healthCheck();
    expect(result).toEqual({ healthy: false, detail: 'KEK not loaded' });
    // Not retried: "KEK not loaded" classifies as UNKNOWN (not transient).
    expect(inner.healthCheck).toHaveBeenCalledTimes(1);
  });

  test('initialize() wires active health probing that recovers state without real signing traffic', async () => {
    const config = makeConfig({ maxRetries: 1, cbFailureThreshold: 2, cbRecoveryMs: 20, healthIntervalMs: 15 });
    const name = uniqueName('active-probe');
    let healthy = false;
    const inner = makeMockProvider(name, {
      sign: jest.fn(async () => { throw new Error('ECONNRESET'); }),
      healthCheck: jest.fn(async () => ({ healthy, detail: healthy ? 'ok' : 'down' })),
    });
    const provider = new ResilientSigningProvider(inner, config);
    // the probe interval, the recovery window and the 200 ms wait all run on the fake clock, so a loaded machine
    // cannot starve the 15 ms interval of ticks inside the window.
    jest.useFakeTimers();
    try {
      await provider.initialize();

      for (let i = 0; i < config.cbFailureThreshold; i++) {
        await expect(provider.sign('key', Buffer.alloc(32))).rejects.toThrow();
      }
      expect(circuitBreakerRegistry.getCircuitBreaker(name, config).state).toBe('OPEN');

      healthy = true; // provider "comes back"
      // Active probing (healthIntervalMs=15) should pick this up on its own,
      // without any further sign() calls from application traffic.
      await jest.advanceTimersByTimeAsync(200);

      expect(healthMonitorRegistry.getHealthMonitor(name, config).state).toBe('healthy');
      await provider.shutdown();
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('ResilientSigningProvider — concurrency and chaos', () => {
  test('hundreds of concurrent sign() calls against an intermittently-failing provider complete with no hang and no unhandled rejections', async () => {
    const config = makeConfig({ maxRetries: 2, cbFailureThreshold: 1000 }); // keep breaker out of the way for this test
    const name = uniqueName('chaos');
    let call = 0;
    const inner = makeMockProvider(name, {
      sign: jest.fn(async () => {
        call++;
        const mod = call % 4;
        if (mod === 0) return hangsForever();               // simulated latency spike -> times out
        if (mod === 1) throw new Error('ECONNRESET');        // packet loss / connection reset
        return Buffer.from(`sig-${call}`);                    // healthy response
      }),
    });
    const provider = new ResilientSigningProvider(inner, config);

    const unhandled = [];
    const handler = (err) => unhandled.push(err);
    process.on('unhandledRejection', handler);

    // deadlines and retry backoffs run on the fake clock; "bounded" means every call has settled within 2,000 ms
    // of that clock (a real CPU stall no longer counts against the bound, a call that never settles still fails it).
    jest.useFakeTimers();
    let results; let elapsed;
    try {
      const start = Date.now();
      let settledAt = null;
      const all = Promise.allSettled(
        Array.from({ length: 200 }, () => provider.sign('key', Buffer.alloc(32))),
      ).then((r) => { settledAt = Date.now(); return r; });
      await jest.advanceTimersByTimeAsync(2_000);
      expect(settledAt).not.toBeNull(); // every call settled inside the 2,000 ms window
      results = await all;
      elapsed = settledAt - start;

      await jest.advanceTimersByTimeAsync(50); // let any stray microtasks surface
    } finally {
      jest.useRealTimers();
    }
    process.off('unhandledRejection', handler);

    expect(results.length).toBe(200);
    expect(elapsed).toBeLessThan(2_000); // bounded — nothing hangs indefinitely
    expect(unhandled).toHaveLength(0);
    expect(results.some((r) => r.status === 'fulfilled')).toBe(true);
  });
});
