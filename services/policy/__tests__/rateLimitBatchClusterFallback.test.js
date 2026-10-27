'use strict';

/**
 * CHECK_AND_INCR_BATCH_SCRIPT CROSSSLOT fallback ROUTING.
 *
 * Mirrors src/validation/__tests__/combinedPathRouting.test.js's own pattern
 * (item 17): isolate createRedisStore().checkAndIncrementBatch()'s routing
 * decision (single multi-key EVAL vs. a sequential per-key fallback) behind
 * a mock Redis client, so no real Redis connection is ever attempted.
 *
 * Unlike combinedPathRouting.test.js's canned-response mocks, the mock
 * client here (mirroring services/policy/store.test.js's own approach)
 * actually INTERPRETS both Lua scripts' GET/INCR/EXPIRE semantics against
 * an in-memory map, and optionally simulates a genuine Redis Cluster
 * CROSSSLOT rejection for any multi-key EVAL — so these tests prove not
 * just which code path ran, but that the fallback produces IDENTICAL
 * rate-limit admission results to the batch path it replaces under cluster
 * mode, and that a naive (un-fallback-guarded) multi-key call really would
 * have failed against the simulated cluster client.
 *
 * RLBF-01  Mock sanity: a multi-key EVAL against the CROSSSLOT-simulating
 *          client really does throw — proves the later "no error" results
 *          are meaningful, not an artifact of a mock that never fails.
 * RLBF-02  Standalone/default _haMode: batch path used — one EVAL call
 *          covering both keys, correct admission results.
 * RLBF-03  Cluster _haMode: falls back automatically — one EVAL call PER
 *          key, no CROSSSLOT thrown, correct admission results.
 * RLBF-04  Semantic equivalence: the same sequence of checks against
 *          independent standalone and cluster stores produces identical
 *          allowed/count sequences — the fallback is not just slot-safe,
 *          it rate-limits identically.
 * RLBF-05  Cluster fallback stops at the first denial — later keys in the
 *          run are never touched, mirroring the batch script's own
 *          documented short-circuit semantics.
 * RLBF-06  Standalone batch path's own short-circuit is unchanged by this
 *          fix (regression check).
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('../../../src/infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn(() => ({})),
  getConfigSummary: jest.fn(() => ({
    authConfigured: false, tlsEnabled: false, tlsVerified: false, urlRedacted: 'redis://[test]',
  })),
  isAuthError: jest.fn(() => false),
  isTlsError:  jest.fn(() => false),
}));

function makeMockRedisClient({ simulateCluster = false } = {}) {
  const map = new Map(); // key -> { value: string, expiresAt: number|null }

  function readValue(key) {
    const e = map.get(key);
    if (!e) return null;
    if (e.expiresAt !== null && Date.now() >= e.expiresAt) { map.delete(key); return null; }
    return e.value;
  }

  function checkAndIncr(key, windowSeconds, maxRequests) {
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

  const evalMock = jest.fn(async (_script, { keys, arguments: args }) => {
    if (keys.length >= 2) {
      // CHECK_AND_INCR_BATCH_SCRIPT shape.
      if (simulateCluster) {
        // Faithful to a real Redis Cluster rejecting a multi-key EVAL whose
        // keys don't share a hash slot — the exact failure mode this item
        // fixes. Thrown unconditionally for any multi-key call here, since
        // these are independent, differently-named rate-limit counters
        // (never guaranteed same-slot), matching the real gap.
        throw new Error("CROSSSLOT Keys in request don't hash to the same slot");
      }
      const results = [];
      for (let i = 0; i < keys.length; i++) {
        const windowSeconds = Number(args[2 * i]);
        const maxRequests   = Number(args[2 * i + 1]);
        const [allowed, count] = checkAndIncr(keys[i], windowSeconds, maxRequests);
        results.push(allowed, count);
        if (allowed === 0) break;
      }
      return results;
    }
    // CHECK_AND_INCR_SCRIPT shape (single key) — always safe under cluster,
    // real or simulated, since it only ever touches one key.
    const windowSeconds = Number(args[0]);
    const maxRequests   = Number(args[1]);
    return checkAndIncr(keys[0], windowSeconds, maxRequests);
  });

  return {
    isReady: true,
    on: jest.fn(),
    connect:    jest.fn().mockResolvedValue(undefined),
    quit:       jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    ping:       jest.fn().mockResolvedValue('PONG'),
    eval: evalMock,
    _map: map,
  };
}

let mockClient;
jest.mock('redis', () => ({
  createClient: jest.fn(() => mockClient),
}));

const { createRedisStore, disconnect } = require('../store');

afterEach(async () => {
  await disconnect();
});

describe('checkAndIncrementBatch() CROSSSLOT fallback routing', () => {

  test('RLBF-01 mock sanity: a multi-key EVAL against the CROSSSLOT-simulating client really throws', async () => {
    mockClient = makeMockRedisClient({ simulateCluster: true });
    await expect(
      mockClient.eval('irrelevant', { keys: ['k1', 'k2'], arguments: ['60', '5', '60', '5'] }),
    ).rejects.toThrow(/CROSSSLOT/);
  });

  test('RLBF-02 standalone (_haMode: "single"): batch path used, one EVAL call for 2 checks', async () => {
    mockClient = makeMockRedisClient({ simulateCluster: false });
    const store = createRedisStore({ _haMode: 'single' });

    const results = await store.checkAndIncrementBatch([
      { key: 'a', windowSeconds: 60, maxRequests: 5 },
      { key: 'b', windowSeconds: 60, maxRequests: 5 },
    ]);

    expect(mockClient.eval).toHaveBeenCalledTimes(1);
    expect(mockClient.eval.mock.calls[0][1].keys).toHaveLength(2);
    expect(results).toEqual([{ allowed: true, count: 1 }, { allowed: true, count: 1 }]);
  });

  test('RLBF-03 cluster (_haMode: "cluster"): falls back automatically, one EVAL call per key, no CROSSSLOT thrown', async () => {
    mockClient = makeMockRedisClient({ simulateCluster: true });
    const store = createRedisStore({ _haMode: 'cluster' });

    const results = await store.checkAndIncrementBatch([
      { key: 'a', windowSeconds: 60, maxRequests: 5 },
      { key: 'b', windowSeconds: 60, maxRequests: 5 },
    ]);

    expect(mockClient.eval).toHaveBeenCalledTimes(2);
    for (const call of mockClient.eval.mock.calls) {
      expect(call[1].keys).toHaveLength(1); // never a multi-key call under cluster
    }
    expect(results).toEqual([{ allowed: true, count: 1 }, { allowed: true, count: 1 }]);
  });

  test('RLBF-04 semantic equivalence: standalone and cluster produce identical allowed/count sequences for the same input', async () => {
    const checks = [
      { key: 'x', windowSeconds: 60, maxRequests: 2 },
      { key: 'y', windowSeconds: 60, maxRequests: 2 },
    ];

    mockClient = makeMockRedisClient({ simulateCluster: false });
    const standaloneStore = createRedisStore({ _haMode: 'single' });
    const standaloneRun1 = await standaloneStore.checkAndIncrementBatch(checks);
    const standaloneRun2 = await standaloneStore.checkAndIncrementBatch(checks);
    const standaloneRun3 = await standaloneStore.checkAndIncrementBatch(checks); // 3rd hit on 'x' (max 2) -> denied

    // _getRlClient() caches a module-level singleton — without disconnecting
    // first, the cluster half below would keep reusing the standalone run's
    // already-mutated client/map instead of the fresh one just assigned to
    // `mockClient` (caught live: this test's first draft omitted this and
    // clusterRun1 silently inherited standaloneRun1..3's own counter state).
    await disconnect();

    mockClient = makeMockRedisClient({ simulateCluster: true });
    const clusterStore = createRedisStore({ _haMode: 'cluster' });
    const clusterRun1 = await clusterStore.checkAndIncrementBatch(checks);
    const clusterRun2 = await clusterStore.checkAndIncrementBatch(checks);
    const clusterRun3 = await clusterStore.checkAndIncrementBatch(checks); // 3rd hit on 'x' -> denied

    expect(clusterRun1).toEqual(standaloneRun1);
    expect(clusterRun2).toEqual(standaloneRun2);
    expect(clusterRun3).toEqual(standaloneRun3);

    // Concretely: both denied at the same point, with the same pre-existing count.
    expect(standaloneRun3).toEqual([{ allowed: false, count: 2 }]);
    expect(clusterRun3).toEqual([{ allowed: false, count: 2 }]);
  });

  test('RLBF-05 cluster fallback stops at the first denial — later keys in the run are never touched', async () => {
    mockClient = makeMockRedisClient({ simulateCluster: true });
    const store = createRedisStore({ _haMode: 'cluster' });

    // Pre-exhaust key 'a' via a single-key call (mirrors real prior traffic).
    await store.checkAndIncrementBatch([{ key: 'a', windowSeconds: 60, maxRequests: 1 }]); // count=1, at limit
    mockClient.eval.mockClear();

    const results = await store.checkAndIncrementBatch([
      { key: 'a', windowSeconds: 60, maxRequests: 1 }, // already at limit -> denied
      { key: 'b', windowSeconds: 60, maxRequests: 5 }, // must never be evaluated
    ]);

    expect(results).toEqual([{ allowed: false, count: 1 }]); // only 1 result — run stopped early
    expect(mockClient.eval).toHaveBeenCalledTimes(1); // 'b' was never even called
    expect(mockClient._map.has('ratelimit:v1:b')).toBe(false); // 'b' counter untouched
  });

  test('RLBF-06 standalone batch path stops at the first denial too (unchanged pre-existing behavior)', async () => {
    mockClient = makeMockRedisClient({ simulateCluster: false });
    const store = createRedisStore({ _haMode: 'single' });

    await store.checkAndIncrementBatch([{ key: 'a', windowSeconds: 60, maxRequests: 1 }]);
    mockClient.eval.mockClear();

    const results = await store.checkAndIncrementBatch([
      { key: 'a', windowSeconds: 60, maxRequests: 1 },
      { key: 'b', windowSeconds: 60, maxRequests: 5 },
    ]);

    expect(results).toEqual([{ allowed: false, count: 1 }]);
    expect(mockClient.eval).toHaveBeenCalledTimes(1); // one batch EVAL, script itself stops early
    expect(mockClient._map.has('ratelimit:v1:b')).toBe(false);
  });
});
