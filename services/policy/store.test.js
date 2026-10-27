'use strict';

/**
 * services/policy/store.js — atomic admission regression suite (RATE-1).
 *
 * Covers checkAndIncrement() on both store implementations behind the same
 * contract the policy engine's RATE_LIMIT evaluator calls directly:
 *   - createStore()       in-memory, synchronous, used by the engine's own
 *                          test suite and dev/test injection.
 *   - createRedisStore()  Redis-backed; checkAndIncrement() submits
 *                          CHECK_AND_INCR_SCRIPT as a single EVAL. The mock
 *                          Redis client below actually interprets the two
 *                          Lua scripts' GET/INCR/EXPIRE semantics (rather
 *                          than returning a canned response) so these tests
 *                          exercise the real request/response wiring in
 *                          checkAndIncrement() against realistic behavior.
 */

jest.mock('../logger', () => ({ emit: jest.fn() }));
jest.mock('../../src/infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn(() => ({})),
  getConfigSummary: jest.fn(() => ({
    authConfigured: false, tlsEnabled: false, tlsVerified: false, urlRedacted: 'redis://[test]',
  })),
  isAuthError: jest.fn(() => false),
  isTlsError:  jest.fn(() => false),
}));

function makeMockRedisClient() {
  const map = new Map(); // key -> { value: string, expiresAt: number|null }

  function readValue(key) {
    const e = map.get(key);
    if (!e) return null;
    if (e.expiresAt !== null && Date.now() >= e.expiresAt) { map.delete(key); return null; }
    return e.value;
  }

  return {
    isReady: true,
    on: jest.fn(),
    connect:    jest.fn().mockResolvedValue(undefined),
    quit:       jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    ping:       jest.fn().mockResolvedValue('PONG'),
    set: jest.fn(async (key, value) => { map.set(key, { value, expiresAt: null }); return 'OK'; }),
    get: jest.fn(async (key) => readValue(key)),
    del: jest.fn(async (key) => { const had = map.has(key); map.delete(key); return had ? 1 : 0; }),

    // Faithfully interprets INCR_SCRIPT (1 ARGV: windowSeconds) and
    // CHECK_AND_INCR_SCRIPT (2 ARGV: windowSeconds, maxRequests) — the two
    // scripts are told apart by ARGV length, exactly as store.js calls them.
    eval: jest.fn(async (_script, { keys, arguments: args }) => {
      const key = keys[0];

      if (args.length === 2) {
        // CHECK_AND_INCR_SCRIPT
        const windowSeconds = Number(args[0]);
        const maxRequests   = Number(args[1]);
        const current = Number(readValue(key) ?? '0');
        if (current >= maxRequests) return [0, current];
        const existing = map.get(key);
        const count = existing ? Number(existing.value) + 1 : 1;
        map.set(key, {
          value:     String(count),
          expiresAt: count === 1 ? Date.now() + windowSeconds * 1000 : (existing?.expiresAt ?? null),
        });
        return [1, count];
      }

      // INCR_SCRIPT
      const windowSeconds = Number(args[0]);
      const existing = map.get(key);
      const count = existing ? Number(existing.value) + 1 : 1;
      map.set(key, {
        value:     String(count),
        expiresAt: count === 1 ? Date.now() + windowSeconds * 1000 : (existing?.expiresAt ?? null),
      });
      return count;
    }),

    _map: map,
  };
}

let mockClient;
jest.mock('redis', () => ({
  createClient: jest.fn(() => mockClient),
}));

const { createStore, createRedisStore, initialize, disconnect } = require('./store');

// ── In-memory store: checkAndIncrement() ────────────────────────────────────

describe('createStore().checkAndIncrement — in-memory atomic admission', () => {
  test('below limit → allowed', () => {
    const store  = createStore();
    const result = store.checkAndIncrement('k', 60, 5);
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
  });

  test('exactly at limit (Nth call, N = maxRequests) → allowed', () => {
    const store = createStore();
    store.checkAndIncrement('k', 60, 3); // 1
    store.checkAndIncrement('k', 60, 3); // 2
    const result = store.checkAndIncrement('k', 60, 3); // 3 — exactly at limit
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(3);
  });

  test('above limit (N+1th call) → denied, count unchanged', () => {
    const store = createStore();
    store.checkAndIncrement('k', 60, 2); // 1
    store.checkAndIncrement('k', 60, 2); // 2
    const result = store.checkAndIncrement('k', 60, 2); // 3 — over
    expect(result.allowed).toBe(false);
    expect(result.count).toBe(2); // denied call did not increment
  });

  test('TTL / window reset: counter restarts once windowSeconds has elapsed', () => {
    jest.useFakeTimers({ doNotFake: ['nextTick'] });
    try {
      jest.setSystemTime(0);
      const store = createStore();
      store.checkAndIncrement('k', 10, 1); // 1/1
      expect(store.checkAndIncrement('k', 10, 1).allowed).toBe(false); // 2 — over

      jest.setSystemTime(11_000); // past the 10s window

      const result = store.checkAndIncrement('k', 10, 1);
      expect(result.allowed).toBe(true);
      expect(result.count).toBe(1); // restarted, not carried over
    } finally {
      jest.useRealTimers();
    }
  });

  test('independent keys never share admission state', () => {
    const store = createStore();
    store.checkAndIncrement('a', 60, 1);
    const a2 = store.checkAndIncrement('a', 60, 1);
    const b1 = store.checkAndIncrement('b', 60, 1);
    expect(a2.allowed).toBe(false);
    expect(b1.allowed).toBe(true);
  });

  test('concurrent Promise.all burst: exactly maxRequests admitted', async () => {
    const store = createStore();
    const results = await Promise.all(
      Array.from({ length: 25 }, () => Promise.resolve(store.checkAndIncrement('burst', 60, 4)))
    );
    expect(results.filter(r => r.allowed).length).toBe(4);
  });

  test('concurrent burst with exactly one remaining slot admits exactly one', async () => {
    const store = createStore();
    store.checkAndIncrement('one-slot', 60, 3);
    store.checkAndIncrement('one-slot', 60, 3); // 2/3 consumed, 1 remaining

    const results = await Promise.all(
      Array.from({ length: 12 }, () => Promise.resolve(store.checkAndIncrement('one-slot', 60, 3)))
    );
    expect(results.filter(r => r.allowed).length).toBe(1);
  });

  test('concurrent burst with exactly two remaining slots admits exactly two', async () => {
    const store = createStore();
    store.checkAndIncrement('two-slot', 60, 6);
    store.checkAndIncrement('two-slot', 60, 6);
    store.checkAndIncrement('two-slot', 60, 6);
    store.checkAndIncrement('two-slot', 60, 6); // 4/6 consumed, 2 remaining

    const results = await Promise.all(
      Array.from({ length: 12 }, () => Promise.resolve(store.checkAndIncrement('two-slot', 60, 6)))
    );
    expect(results.filter(r => r.allowed).length).toBe(2);
  });

  test('high-concurrency admission: 200 simultaneous callers, limit 10 → exactly 10 admitted', async () => {
    const store = createStore();
    const results = await Promise.all(
      Array.from({ length: 200 }, () => Promise.resolve(store.checkAndIncrement('high-conc', 60, 10)))
    );
    expect(results.filter(r => r.allowed).length).toBe(10);
  });

  // audit closure (RATE-1 follow-up): a single concurrent-burst run
  // could pass by luck if admission were non-deterministic (e.g. dependent on
  // Promise microtask scheduling order). Repeating the burst across many
  // independent keys turns "passed once" into "passed every time" — zero
  // tolerance for intermittent oversubscription.
  test('repeated stress: 50 independent concurrent bursts, zero oversubscription in any run', async () => {
    const store = createStore();
    for (let i = 0; i < 50; i++) {
      const key = `stress-${i}`;
      const results = await Promise.all(
        Array.from({ length: 30 }, () => Promise.resolve(store.checkAndIncrement(key, 60, 7)))
      );
      expect(results.filter(r => r.allowed).length).toBe(7);
      expect(results.filter(r => !r.allowed).length).toBe(23);
    }
  });
});

// ── Redis-backed store: checkAndIncrement() ─────────────────────────────────

describe('createRedisStore().checkAndIncrement — Redis-backed atomic admission', () => {
  beforeEach(async () => {
    await disconnect();
    mockClient = makeMockRedisClient();
  });

  afterEach(async () => {
    await disconnect();
  });

  test('below limit → allowed', async () => {
    const store  = createRedisStore();
    const result = await store.checkAndIncrement('k', 60, 5);
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
  });

  test('exactly at limit (Nth call, N = maxRequests) → allowed', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('k', 60, 3); // 1
    await store.checkAndIncrement('k', 60, 3); // 2
    const result = await store.checkAndIncrement('k', 60, 3); // 3 — exactly at limit
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(3);
  });

  test('above limit (N+1th call) → denied, count unchanged', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('k', 60, 2);
    await store.checkAndIncrement('k', 60, 2);
    const result = await store.checkAndIncrement('k', 60, 2);
    expect(result.allowed).toBe(false);
    expect(result.count).toBe(2);
  });

  test('TTL / window expiration: counter restarts once windowSeconds has elapsed', async () => {
    jest.useFakeTimers({ doNotFake: ['nextTick'] });
    try {
      jest.setSystemTime(0);
      const store = createRedisStore();
      await store.checkAndIncrement('k', 10, 1); // 1/1
      expect((await store.checkAndIncrement('k', 10, 1)).allowed).toBe(false);

      jest.setSystemTime(11_000);

      const result = await store.checkAndIncrement('k', 10, 1);
      expect(result.allowed).toBe(true);
      expect(result.count).toBe(1);
    } finally {
      jest.useRealTimers();
    }
  });

  test('CHECK_AND_INCR_SCRIPT is submitted as a single EVAL call per admission check', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('single-eval-key', 60, 5);
    expect(mockClient.eval).toHaveBeenCalledTimes(1);
    expect(mockClient.get).not.toHaveBeenCalled(); // no separate read round trip
  });

  test('concurrent Promise.all burst: exactly maxRequests admitted, never more', async () => {
    const store = createRedisStore();
    const results = await Promise.all(
      Array.from({ length: 25 }, () => store.checkAndIncrement('burst', 60, 4))
    );
    expect(results.filter(r => r.allowed).length).toBe(4);
  });

  test('concurrent burst with exactly one remaining slot admits exactly one', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('one-slot', 60, 3);
    await store.checkAndIncrement('one-slot', 60, 3); // 2/3 consumed

    const results = await Promise.all(
      Array.from({ length: 12 }, () => store.checkAndIncrement('one-slot', 60, 3))
    );
    expect(results.filter(r => r.allowed).length).toBe(1);
  });

  test('concurrent burst with exactly two remaining slots admits exactly two', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('two-slot', 60, 6);
    await store.checkAndIncrement('two-slot', 60, 6);
    await store.checkAndIncrement('two-slot', 60, 6);
    await store.checkAndIncrement('two-slot', 60, 6); // 4/6 consumed

    const results = await Promise.all(
      Array.from({ length: 12 }, () => store.checkAndIncrement('two-slot', 60, 6))
    );
    expect(results.filter(r => r.allowed).length).toBe(2);
  });

  test('high-concurrency admission: 200 simultaneous callers, limit 10 → exactly 10 admitted', async () => {
    const store = createRedisStore();
    const results = await Promise.all(
      Array.from({ length: 200 }, () => store.checkAndIncrement('high-conc', 60, 10))
    );
    expect(results.filter(r => r.allowed).length).toBe(10);
  });

  // audit closure (RATE-1 follow-up): same rationale as the in-memory
  // repeated-stress test above, exercised against CHECK_AND_INCR_SCRIPT via
  // the Lua-interpreting mock so a flaky EVAL-call race would show up here.
  test('repeated stress: 50 independent concurrent bursts, zero oversubscription in any run', async () => {
    const store = createRedisStore();
    for (let i = 0; i < 50; i++) {
      const key = `stress-${i}`;
      const results = await Promise.all(
        Array.from({ length: 30 }, () => store.checkAndIncrement(key, 60, 7))
      );
      expect(results.filter(r => r.allowed).length).toBe(7);
      expect(results.filter(r => !r.allowed).length).toBe(23);
    }
  });

  test('Redis not ready → checkAndIncrement throws (fail-closed)', async () => {
    mockClient.isReady = false;
    const store = createRedisStore();
    // Force client construction against the not-ready mock.
    await expect(store.checkAndIncrement('k', 60, 5)).rejects.toThrow(/not connected/i);
  });

  test('EVAL throws → checkAndIncrement propagates the error (fail-closed)', async () => {
    const store = createRedisStore();
    await store.checkAndIncrement('warmup', 60, 5); // establish ready client
    mockClient.eval.mockRejectedValueOnce(new Error('ECONNRESET'));
    await expect(store.checkAndIncrement('warmup', 60, 5)).rejects.toThrow('ECONNRESET');
  });

  test('initialize() validates connectivity against the mock client', async () => {
    const result = await initialize();
    expect(result.ready).toBe(true);
  });
});
